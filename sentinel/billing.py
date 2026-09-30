"""Биллинг: тарифные планы, квоты, инвойсы.

Монетизация строится вокруг измеренного использования (UsageMeter из
tenancy.py): каждый тенант состоит на тарифном плане с месячными лимитами
аудитов и оптимизаций. Превышение лимита на бесплатном плане блокируется
(HTTP 402 на стороне API), на платных планах — тарифицируется по
overage-ставке и попадает в инвойс за месяц.

Платёжный провайдер намеренно не интегрирован: движок считает суммы и
формирует инвойсы, а выставление счетов/списание оставлено за внешней
интеграцией (Stripe/Paddle — выбор отложен).

Категории использования:
- "audits" — аудиты kind=code и kind=llm_flow;
- "optimizations" — прогоны Savings Autopilot (kind=optimize).

Учёт и квота: у асинхронного пути (POST /v1/audits, /v1/optimize) слот
квоты РЕЗЕРВИРУЕТСЯ под замком в момент submit (BillingEngine.reserve) и
снимается по завершению джоба — успех (_run_audit_and_register) или падение
(_notify_audit_failure). Это закрывает TOCTOU, из-за которого пачка
параллельных submit'ов проходила по неинкрементированному usage и лимит
free-плана обходился всплеском. Для синхронного /v1/audit квота точная и
резерв не нужен.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from .atomic_write import atomic_write_json
from .tenancy import Tenant, TenantManager, UsageMeter

CATEGORY_AUDITS = "audits"
CATEGORY_OPTIMIZATIONS = "optimizations"
CATEGORIES = (CATEGORY_AUDITS, CATEGORY_OPTIMIZATIONS)

DEFAULT_PLAN = "free"


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def category_for_kind(kind: Optional[str]) -> str:
    """Категория биллинга для kind флоу: optimize считается отдельно."""
    return CATEGORY_OPTIMIZATIONS if kind == "optimize" else CATEGORY_AUDITS


def current_period(now: Optional[_dt.datetime] = None) -> str:
    """Текущий расчётный период в формате 'YYYY-MM' (UTC)."""
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return f"{now.year:04d}-{now.month:02d}"


def parse_period(period: str) -> tuple[int, int]:
    """Разбирает 'YYYY-MM' в (year, month); бросает ValueError."""
    try:
        year_str, month_str = period.split("-")
        year, month = int(year_str), int(month_str)
    except (AttributeError, ValueError):
        raise ValueError(f"Period must be 'YYYY-MM', got: {period!r}")

    if year < 2000 or not 1 <= month <= 12:
        raise ValueError(f"Period must be 'YYYY-MM', got: {period!r}")

    return year, month


@dataclass(frozen=True)
class Plan:
    """Тарифный план: абонплата, месячные лимиты, overage-ставки.

    included[category] = None — без лимита;
    overage_usd[category] = None — превышение запрещено (жёсткая квота).
    """

    name: str
    display_name: str
    monthly_price_usd: float
    included: Mapping[str, Optional[int]]
    overage_usd: Mapping[str, Optional[float]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "monthly_price_usd": self.monthly_price_usd,
            "included": dict(self.included),
            "overage_usd": dict(self.overage_usd),
        }


PLANS: dict[str, Plan] = {
    "free": Plan(
        name="free",
        display_name="Free",
        monthly_price_usd=0.0,
        included={CATEGORY_AUDITS: 10, CATEGORY_OPTIMIZATIONS: 1},
        overage_usd={CATEGORY_AUDITS: None, CATEGORY_OPTIMIZATIONS: None},
    ),
    "pro": Plan(
        name="pro",
        display_name="Pro",
        monthly_price_usd=99.0,
        included={CATEGORY_AUDITS: 500, CATEGORY_OPTIMIZATIONS: 50},
        overage_usd={CATEGORY_AUDITS: 0.25, CATEGORY_OPTIMIZATIONS: 2.0},
    ),
    "enterprise": Plan(
        name="enterprise",
        display_name="Enterprise",
        monthly_price_usd=999.0,
        included={CATEGORY_AUDITS: None, CATEGORY_OPTIMIZATIONS: None},
        overage_usd={CATEGORY_AUDITS: None, CATEGORY_OPTIMIZATIONS: None},
    ),
}


@dataclass(frozen=True)
class QuotaCheck:
    """Результат проверки квоты тенанта для одной категории."""

    allowed: bool
    plan: str
    category: str
    used: int
    limit: Optional[int]
    reason: str = ""


@dataclass
class InvoiceLine:
    description: str
    quantity: int
    unit_price_usd: float

    @property
    def amount_usd(self) -> float:
        return round(self.quantity * self.unit_price_usd, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "quantity": self.quantity,
            "unit_price_usd": self.unit_price_usd,
            "amount_usd": self.amount_usd,
        }


@dataclass
class Invoice:
    """Месячный инвойс тенанта. status всегда 'open' — платёжного провайдера нет."""

    invoice_id: str
    tenant_id: str
    plan: str
    period: str
    lines: list[InvoiceLine]
    issued_at: str
    status: str = "open"

    @property
    def total_usd(self) -> float:
        return round(sum(line.amount_usd for line in self.lines), 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "invoice_id": self.invoice_id,
            "tenant_id": self.tenant_id,
            "plan": self.plan,
            "period": self.period,
            "lines": [line.to_dict() for line in self.lines],
            "total_usd": self.total_usd,
            "issued_at": self.issued_at,
            "status": self.status,
        }


class BillingEngine:
    """Тарифы, квоты и инвойсы поверх TenantManager + UsageMeter."""

    def __init__(
        self,
        tenant_manager: TenantManager,
        usage_meter: UsageMeter,
        invoices_file: Optional[str] = None,
    ):
        self.tenant_manager = tenant_manager
        self.usage_meter = usage_meter
        self.invoices_file = Path(
            invoices_file or os.getenv("INVOICES_FILE") or "invoices.json"
        )
        self._invoices: dict[str, Invoice] = {}
        self._lock = threading.Lock()
        # key: (tenant_id, period, category) -> number of in-flight reservations
        # (асинхронные аудиты уже приняты, но usage ещё не записан). Убирает
        # TOCTOU: N параллельных submit'ов не могут все разом пройти проверку по
        # неинкрементированному usage.
        self._reservations: dict[tuple[str, str, str], int] = {}
        self._load()

    # === Тарифы ===

    def get_plan(self, tenant_id: str) -> Plan:
        """План тенанта; неизвестный тенант или план -> free."""
        tenant = self.tenant_manager.get(tenant_id)
        plan_name = tenant.plan if tenant else DEFAULT_PLAN
        return PLANS.get(plan_name, PLANS[DEFAULT_PLAN])

    def set_plan(self, tenant_id: str, plan_name: str) -> Tenant:
        """Переводит тенант на другой план; неизвестный план -> ValueError."""
        if plan_name not in PLANS:
            raise ValueError(
                f"Unknown plan: {plan_name}. Available: {sorted(PLANS)}"
            )

        return self.tenant_manager.set_plan(tenant_id, plan_name)

    # === Квоты ===

    def usage_for_period(self, tenant_id: str, period: str) -> dict[str, int]:
        """Использование тенанта за период по категориям биллинга."""
        year, month = parse_period(period)
        counts = self.usage_meter.counts_for_month(tenant_id, year, month)

        usage = {category: 0 for category in CATEGORIES}

        for kind, count in counts.items():
            usage[category_for_kind(kind)] += count

        return usage

    def _reserved(self, tenant_id: str, period: str, category: str) -> int:
        with self._lock:
            return self._reservations.get((tenant_id, period, category), 0)

    def _effective_used(self, tenant_id: str, period: str, category: str) -> int:
        """Записанное использование + незакрытые резервы (аудиты в полёте)."""
        recorded = self.usage_for_period(tenant_id, period)[category]
        return recorded + self._reserved(tenant_id, period, category)

    def check_quota(self, tenant_id: str, kind: str) -> QuotaCheck:
        """Можно ли тенанту запустить флоу данного kind прямо сейчас.

        Учитывает незакрытые резервы: параллельные submit'ы видят друг друга и
        не могут одновременно пройти проверку по неинкрементированному usage.
        """
        plan = self.get_plan(tenant_id)
        category = category_for_kind(kind)
        limit = plan.included.get(category)
        used = self._effective_used(tenant_id, current_period(), category)

        if limit is None or used < limit:
            return QuotaCheck(True, plan.name, category, used, limit)

        if plan.overage_usd.get(category) is not None:
            return QuotaCheck(
                True,
                plan.name,
                category,
                used,
                limit,
                reason="quota exceeded; overage billing applies",
            )

        return QuotaCheck(
            False,
            plan.name,
            category,
            used,
            limit,
            reason=(
                f"Monthly quota exceeded: plan '{plan.name}' includes "
                f"{limit} {category}/month ({used} already used). "
                "Upgrade via POST /v1/billing/plan."
            ),
        )

    def reserve(self, tenant_id: str, kind: str) -> QuotaCheck:
        """Атомарно резервирует один слот квоты. True — можно запускать.

        Проверка и увеличение счётчика резервов идут под одним замком, поэтому
        N параллельных вызовов не могут все увидеть «used < limit» и пройти.
        Резерв снимается через release() при завершении/падении аудита; до
        этого момента слот считается занятым (recorded-usage ещё не появился).
        """
        plan = self.get_plan(tenant_id)
        category = category_for_kind(kind)
        limit = plan.included.get(category)
        period = current_period()

        with self._lock:
            recorded = self.usage_for_period(tenant_id, period)[category]
            reserved = self._reservations.get((tenant_id, period, category), 0)
            used = recorded + reserved

            hard_cap = limit is not None and used >= limit and plan.overage_usd.get(category) is None
            if hard_cap:
                return QuotaCheck(
                    False,
                    plan.name,
                    category,
                    used,
                    limit,
                    reason=(
                        f"Monthly quota exceeded: plan '{plan.name}' includes "
                        f"{limit} {category}/month ({used} already used). "
                        "Upgrade via POST /v1/billing/plan."
                    ),
                )

            self._reservations[(tenant_id, period, category)] = reserved + 1

        reason = ""
        if limit is not None and used >= limit:
            reason = "quota exceeded; overage billing applies"
        return QuotaCheck(True, plan.name, category, used, limit, reason=reason)

    def release(self, tenant_id: str, kind: str) -> None:
        """Снимает один резерв (аудит завершён/упал). Ничего не делает, если
        резерва не было — вызов идемпотентен и безопасен при повторе."""
        category = category_for_kind(kind)
        key = (tenant_id, current_period(), category)
        with self._lock:
            current = self._reservations.get(key, 0)
            if current <= 0:
                return
            if current == 1:
                self._reservations.pop(key, None)
            else:
                self._reservations[key] = current - 1

    def quota_status(self, tenant_id: str) -> dict[str, Any]:
        """Сводка квот по категориям за текущий период."""
        plan = self.get_plan(tenant_id)
        period = current_period()
        usage = self.usage_for_period(tenant_id, period)

        categories: dict[str, Any] = {}

        for category in CATEGORIES:
            limit = plan.included.get(category)
            used = usage[category]
            categories[category] = {
                "used": used,
                "limit": limit,
                "remaining": None if limit is None else max(0, limit - used),
                "overage_usd": plan.overage_usd.get(category),
            }

        return {"period": period, "categories": categories}

    # === Инвойсы ===

    def issue_invoice(self, tenant_id: str, period: Optional[str] = None) -> Invoice:
        """Формирует инвойс за период; идемпотентно (один инвойс на тенант+период)."""
        period = period or current_period()
        parse_period(period)  # валидация формата

        with self._lock:
            existing = next(
                (
                    invoice
                    for invoice in self._invoices.values()
                    if invoice.tenant_id == tenant_id and invoice.period == period
                ),
                None,
            )

            if existing is not None:
                return existing

            invoice = self._build_invoice(tenant_id, period)
            self._invoices[invoice.invoice_id] = invoice
            self._save()

        return invoice

    def get_invoice(
        self, invoice_id: str, tenant_id: Optional[str] = None
    ) -> Optional[Invoice]:
        """Инвойс по id; при заданном tenant_id чужой инвойс -> None (изоляция)."""
        invoice = self._invoices.get(invoice_id)

        if invoice is None:
            return None

        if tenant_id is not None and invoice.tenant_id != tenant_id:
            return None

        return invoice

    def list_invoices(self, tenant_id: Optional[str] = None) -> list[Invoice]:
        """Инвойсы (новые сверху), опционально одного тенанта."""
        invoices = [
            invoice
            for invoice in self._invoices.values()
            if tenant_id is None or invoice.tenant_id == tenant_id
        ]

        return sorted(invoices, key=lambda i: i.issued_at, reverse=True)

    # === Внутреннее ===

    def _build_invoice(self, tenant_id: str, period: str) -> Invoice:
        plan = self.get_plan(tenant_id)
        usage = self.usage_for_period(tenant_id, period)
        lines: list[InvoiceLine] = []

        if plan.monthly_price_usd > 0:
            lines.append(
                InvoiceLine(
                    description=f"{plan.display_name} plan subscription ({period})",
                    quantity=1,
                    unit_price_usd=plan.monthly_price_usd,
                )
            )

        for category in CATEGORIES:
            limit = plan.included.get(category)
            price = plan.overage_usd.get(category)

            if limit is None or price is None:
                continue

            overage = max(0, usage[category] - limit)

            if overage:
                lines.append(
                    InvoiceLine(
                        description=(
                            f"{category} overage: {overage} above "
                            f"{limit} included"
                        ),
                        quantity=overage,
                        unit_price_usd=price,
                    )
                )

        return Invoice(
            invoice_id=f"inv-{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            plan=plan.name,
            period=period,
            lines=lines,
            issued_at=_utcnow(),
        )

    def _load(self) -> None:
        if not self.invoices_file.exists():
            return

        try:
            with open(self.invoices_file, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return

        for item in data.get("invoices", []):
            invoice = Invoice(
                invoice_id=item["invoice_id"],
                tenant_id=item["tenant_id"],
                plan=item.get("plan", DEFAULT_PLAN),
                period=item["period"],
                lines=[
                    InvoiceLine(
                        description=line["description"],
                        quantity=line["quantity"],
                        unit_price_usd=line["unit_price_usd"],
                    )
                    for line in item.get("lines", [])
                ],
                issued_at=item.get("issued_at", _utcnow()),
                status=item.get("status", "open"),
            )
            self._invoices[invoice.invoice_id] = invoice

    def _save(self) -> None:
        data = {"invoices": [i.to_dict() for i in self._invoices.values()]}
        atomic_write_json(self.invoices_file, data)

"""Мульти-тенантность и учёт использования — фундамент SaaS/биллинга.

Каждый клиент (тенант) получает изолированное пространство: API-ключи
помечаются tenant_id, аудиты и квитанции тегируются тенантом, а все
запуски учитываются счётчиком использования (usage meter) — основой для
будущего биллинга (за аудит / % от подтверждённой экономии / подписка).

Хранилище прототипа — JSON/JSONL рядом с остальными данными проекта;
в продакшене заменяется PostgreSQL (модели уже спроектированы под это).
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import threading
import uuid

from .atomic_write import atomic_write_json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

DEFAULT_TENANT_ID = "default"
TENANT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class Tenant:
    """Организация-клиент."""

    tenant_id: str
    name: str
    plan: str = "free"
    created_at: str = field(default_factory=_utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "name": self.name,
            "plan": self.plan,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


class TenantManager:
    """Реестр тенантов с JSON-персистентностью."""

    def __init__(self, tenants_file: Optional[str] = None):
        self.tenants_file = Path(
            tenants_file or os.getenv("TENANTS_FILE") or "tenants.json"
        )
        self.tenants: dict[str, Tenant] = {}
        self._lock = threading.Lock()
        self._load()
        self._ensure_default()

    def _load(self) -> None:
        if not self.tenants_file.exists():
            return

        try:
            with open(self.tenants_file, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return

        for item in data.get("tenants", []):
            tenant = Tenant(
                tenant_id=item["tenant_id"],
                name=item.get("name", item["tenant_id"]),
                plan=item.get("plan", "free"),
                created_at=item.get("created_at", _utcnow()),
                metadata=item.get("metadata", {}),
            )
            self.tenants[tenant.tenant_id] = tenant

    def _save(self) -> None:
        data = {"tenants": [t.to_dict() for t in self.tenants.values()]}
        atomic_write_json(self.tenants_file, data)

    def _ensure_default(self) -> None:
        if DEFAULT_TENANT_ID not in self.tenants:
            self.tenants[DEFAULT_TENANT_ID] = Tenant(
                tenant_id=DEFAULT_TENANT_ID,
                name="Default (legacy keys & demo users)",
                plan="free",
            )
            self._save()

    def create(
        self,
        name: str,
        tenant_id: Optional[str] = None,
        plan: str = "free",
        metadata: Optional[dict[str, Any]] = None,
    ) -> Tenant:
        """Создаёт тенант; tenant_id генерируется, если не задан."""
        if tenant_id is None:
            tenant_id = uuid.uuid4().hex[:12]

        if not TENANT_ID_PATTERN.match(tenant_id):
            raise ValueError(
                "tenant_id must match ^[a-z0-9][a-z0-9_-]{1,63}$ "
                "(lowercase letters, digits, underscore, hyphen)"
            )

        with self._lock:
            if tenant_id in self.tenants:
                raise ValueError(f"Tenant already exists: {tenant_id}")

            tenant = Tenant(
                tenant_id=tenant_id,
                name=name,
                plan=plan,
                metadata=metadata or {},
            )
            self.tenants[tenant_id] = tenant
            self._save()

        return tenant

    def get(self, tenant_id: str) -> Optional[Tenant]:
        return self.tenants.get(tenant_id)

    def list(self) -> list[Tenant]:
        return list(self.tenants.values())

    def set_plan(self, tenant_id: str, plan: str) -> Tenant:
        """Меняет тарифный план тенанта; неизвестный тенант -> ValueError."""
        with self._lock:
            tenant = self.tenants.get(tenant_id)

            if tenant is None:
                raise ValueError(f"Tenant not found: {tenant_id}")

            tenant.plan = plan
            self._save()

        return tenant

    def set_metadata(self, tenant_id: str, key: str, value: Any) -> Tenant:
        """Устанавливает настройку в metadata тенанта; неизвестный -> ValueError."""
        with self._lock:
            tenant = self.tenants.get(tenant_id)

            if tenant is None:
                raise ValueError(f"Tenant not found: {tenant_id}")

            tenant.metadata[key] = value
            self._save()

        return tenant


class UsageMeter:
    """Счётчик использования: append-only JSONL событий по тенантам.

    Каждое событие — запуск аудита/оптимизации. Агрегаты строятся на
    чтении; в продакшене это заменяется таблицей usage_events.
    """

    def __init__(self, usage_file: Optional[str] = None):
        self.usage_file = Path(
            usage_file or os.getenv("USAGE_EVENTS_FILE") or "usage_events.jsonl"
        )
        self._lock = threading.Lock()

    def record(
        self,
        tenant_id: str,
        kind: str,
        mode: Optional[str] = None,
        savings_verified: Optional[bool] = None,
        savings_usd_per_1k: Optional[float] = None,
        event_key: Optional[str] = None,
    ) -> dict[str, Any]:
        """Записывает событие использования и возвращает его.

        ``event_key`` делает запись идемпотентной: если событие с таким ключом
        уже есть в jsonl, повторный вызов не дописывает вторую строку (возвращает
        существующее). Это закрывает двойной учёт при recover(): джоб мог успеть
        списать usage и упасть ДО записи completed — restart перезапустит его, и
        без ключа usage списывается дважды за один audit_id.
        """
        event = {
            "event_id": uuid.uuid4().hex,
            "tenant_id": tenant_id or DEFAULT_TENANT_ID,
            "kind": kind,
            "mode": mode,
            "savings_verified": savings_verified,
            "savings_usd_per_1k": savings_usd_per_1k,
            "recorded_at": _utcnow(),
        }
        if event_key is not None:
            event["event_key"] = event_key

        with self._lock:
            if event_key is not None:
                for existing in self._events():
                    if existing.get("event_key") == event_key:
                        return existing

            with open(self.usage_file, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, default=str) + "\n")

        return event

    def _events(self, tenant_id: Optional[str] = None) -> list[dict[str, Any]]:
        if not self.usage_file.exists():
            return []

        events: list[dict[str, Any]] = []

        with open(self.usage_file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if tenant_id is None or event.get("tenant_id") == tenant_id:
                    events.append(event)

        return events

    def summary(self, tenant_id: str) -> dict[str, Any]:
        """Агрегаты использования тенанта: счётчики по kind/mode."""
        events = self._events(tenant_id)

        by_kind: dict[str, int] = {}
        by_mode: dict[str, int] = {}
        verified_count = 0

        for event in events:
            kind = event.get("kind", "unknown")
            by_kind[kind] = by_kind.get(kind, 0) + 1

            mode = event.get("mode") or "unknown"
            by_mode[mode] = by_mode.get(mode, 0) + 1

            if event.get("savings_verified"):
                verified_count += 1

        return {
            "tenant_id": tenant_id,
            "total_events": len(events),
            "by_kind": by_kind,
            "by_mode": by_mode,
            "verified_savings_count": verified_count,
        }

    def counts_for_month(self, tenant_id: str, year: int, month: int) -> dict[str, int]:
        """Число событий тенанта за месяц по kind (основа квот и инвойсов)."""
        prefix = f"{year:04d}-{month:02d}"
        counts: dict[str, int] = {}

        for event in self._events(tenant_id):
            recorded_at = event.get("recorded_at") or ""

            if not recorded_at.startswith(prefix):
                continue

            kind = event.get("kind", "unknown")
            counts[kind] = counts.get(kind, 0) + 1

        return counts


def resolve_tenant_id(value: Optional[str]) -> str:
    """Нормализует tenant_id: пустое значение -> default-тенант."""
    return value or DEFAULT_TENANT_ID

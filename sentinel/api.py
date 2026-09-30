from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from sentinel.cryptographic_receipts import (
    KeyringVerifier,
    ReceiptGenerator,
)
import os
import sys
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, Depends, Request, Header
from pydantic import BaseModel, Field
from pydantic import BaseModel as PydanticBaseModel

from sia.constitutional_ai_layer import ConstitutionalAILayer
from sia.config import resolve_env
from sia.flow_runner import (
    build_preregistration_commitment,
    run_flow_audit,
    validate_api_flow,
)
from sia.models import Task
from sia.trust_level_manager import TrustLevelManager

from .audit_jobs import AuditJobManager
from .billing import PLANS, BillingEngine
from .database import AuditJobRecord, get_db_session
from .evidence_store import EvidenceStore
from .github_client import GitHubClient
from .outbound_webhooks import (
    EVENT_AUDIT_COMPLETED,
    EVENT_AUDIT_FAILED,
    OutboundWebhookDispatcher,
)
from .policy_engine import PolicyEngine
from .cryptographic_receipts import CryptographicReceipt
from .receipt_registry import ReceiptRegistry
from .tenancy import DEFAULT_TENANT_ID, TenantManager, UsageMeter
from .webhook_handler import WebhookHandler
from sentinel.security import SecurityMiddleware, RateLimiter
from sentinel.cors import setup_cors
from sentinel.anchoring import publish_checkpoint
# Ранний импорт auth-зависимостей: эндпоинты ниже (verify-change, network)
# определены до секции Proof-of-Savings, но тоже обязаны быть под авторизацией.
from sentinel.auth import (
    JWT_EXPIRATION_HOURS,
    User,
    UserRole,
    api_key_manager,
    get_current_user,
    jwt_manager,
    require_platform_admin,
    require_role,
)
# Initialize receipt generator (Ed25519 signing) and public verifier.
# Через resolve_env: секрет может лежать и в .env, а не только в окружении.
#
# Без ключа поведение зависит от SIA_STRICT_KEYS:
#   - strict (SIA_STRICT_KEYS=1, ставится в docker-compose.prod.yml): ПАДАЕМ на
#     старте. Эфемерный ключ в проде = квитанции не переживают рестарт (тихая
#     необратимая потеря доказательной базы), поэтому это ошибка конфигурации,
#     а не предупреждение.
#   - dev/тесты (по умолчанию): эфемерный ключ + громкое предупреждение в stderr
#     (stderr, а не stdout — в контейнере stdout буферизуется/теряется).
RECEIPT_SIGNING_KEY = resolve_env("RECEIPT_SIGNING_KEY")

_STRICT = (resolve_env("SIA_STRICT_KEYS") or "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)


def _require_persistent_keys_if_strict(strict: Optional[bool] = None) -> None:
    """В strict-режиме отсутствие постоянных ключей — фатальная ошибка старта.

    ``strict`` — переопределение для тестов; по умолчанию берётся значение
    SIA_STRICT_KEYS, вычисленное при импорте модуля.
    """
    if strict is None:
        strict = _STRICT
    if not strict:
        return
    missing = [
        name
        for name in (
            "RECEIPT_SIGNING_KEY",
            "JWT_SECRET_KEY",
            "EVIDENCE_SIGNING_KEY",
        )
        if not resolve_env(name)
    ]
    if missing:
        raise RuntimeError(
            "SIA_STRICT_KEYS is enabled but the following persistent secrets are "
            f"missing: {', '.join(missing)}. Ephemeral keys make receipts, tokens "
            "and evidence signatures unrecoverable across restarts. Set these "
            "secrets (env or .env) before starting in strict/production mode."
        )


_require_persistent_keys_if_strict()

if not RECEIPT_SIGNING_KEY:
    import secrets as _secrets
    import sys as _sys

    RECEIPT_SIGNING_KEY = _secrets.token_hex(32)
    print(
        "WARNING: RECEIPT_SIGNING_KEY not set — generated an ephemeral key; "
        "receipts will not survive restarts. Set RECEIPT_SIGNING_KEY in production "
        "(or enable SIA_STRICT_KEYS=1 to fail fast instead).",
        file=_sys.stderr,
    )

receipt_generator = ReceiptGenerator(RECEIPT_SIGNING_KEY, allow_ephemeral=True)
app = FastAPI(
    title="SIA Sentinel",
    description=(
        "Proof-of-Savings Protocol: neutral AI efficiency auditor. "
        "Replays workloads against cheaper configurations, proves quality "
        "equivalence with paired statistics, and issues independently "
        "verifiable Ed25519 attestations anchored in a tamper-evident ledger. "
        "Spec: docs/attestation-spec.md (sia-attestation/1)."
    ),
    version="0.7.0",
)
# Setup CORS
setup_cors(app)
# Add security middleware
rate_limiter = RateLimiter()
app.add_middleware(SecurityMiddleware, rate_limiter=rate_limiter)

# Deploy bootstrap: на свежем томе платформенного админа получить нечем
# (signup выдаёт админа тенанта, демо-логин в проде выключен), а анкоринг,
# чекпоинты, ротация и управление тенантами требуют именно его.
PLATFORM_ADMIN_API_KEY = os.getenv("PLATFORM_ADMIN_API_KEY")

if PLATFORM_ADMIN_API_KEY:
    api_key_manager.bootstrap_platform_admin(PLATFORM_ADMIN_API_KEY)

guard = ConstitutionalAILayer()
evidence_store = EvidenceStore()
policy_engine = PolicyEngine()

_trust_managers: dict[tuple[str, str], TrustLevelManager] = {}


class VerifyChangeRequest(BaseModel):
    agent_id: str = Field(..., description="Unique AI agent identifier")
    description: str = Field(..., description="What the agent is trying to do")
    target_path: str = Field(..., description="Target file path")
    target_symbol: Optional[str] = Field(
        default=None,
        description="Function/class symbol being modified",
    )
    current_code: str = Field(..., description="Current version of code")
    proposed_code: str = Field(..., description="AI-generated proposed code")
    allowed_paths: list[str] = Field(
        default_factory=list,
        description="Paths the agent is allowed to touch",
    )
    manifest: Optional[dict[str, Any]] = Field(
        default=None,
        description="Reproducibility manifest (environment, dataset/config hashes, seeds, pricing)",
    )


class RiskScoreRequest(BaseModel):
    agent_id: str
    target_path: str
    current_code: str
    proposed_code: str


class TrustInfoResponse(BaseModel):
    agent_id: str
    level: str
    success_streak: int
    failure_streak: int
    last_failure_reason: Optional[str]


def _get_trust_manager(agent_id: str, tenant_id: str = DEFAULT_TENANT_ID) -> TrustLevelManager:
    """TrustLevelManager агента, ИЗОЛИРОВАННЫЙ ПО ТЕНАНТУ.

    Состояние доверия — это история конкретного тенанта: сколько раз его агенты
    проходили/падали проверку. Раньше файл и кэш ключевались одним agent_id, и
    два тенанта с одинаковым agent_id делили одну историю (и могли её читать/
    портить друг другу). Ключ теперь (tenant_id, agent_id) — это и файл, и кэш.
    """
    cache_key = (tenant_id or DEFAULT_TENANT_ID, agent_id)
    if cache_key not in _trust_managers:
        Path("logs").mkdir(parents=True, exist_ok=True)
        safe_tenant = _safe_agent_id(tenant_id or DEFAULT_TENANT_ID)
        safe_id = _safe_agent_id(agent_id)
        state_file = Path("logs") / f"trust_{safe_tenant}_{safe_id}.json"

        _trust_managers[cache_key] = TrustLevelManager(
            state_file=str(state_file),
        )

    return _trust_managers[cache_key]



def _safe_agent_id(agent_id: str) -> str:
    """Sanitize agent_id for file system."""
    safe = "".join(
        c if c.isalnum() or c in "-_" else "_"
        for c in str(agent_id)
        if ord(c) >= 32 and c not in '<>:"/\\|?*' and c != chr(0)
    )
    return safe or "unknown_agent"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/verify-change", deprecated=True)
def verify_change(
    request: VerifyChangeRequest,
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.USER)),
) -> dict[str, Any]:
    """Legacy AI Code Change Firewall endpoint — not part of the
    Proof-of-Savings product surface; kept for existing integrations.
    """
    # Квота биллинга: verify-change — тоже аудит (категория code)
    _check_quota_or_402(user.tenant_id, "code")

    trust_manager = _get_trust_manager(request.agent_id, user.tenant_id)

    allowed_paths = tuple(
        request.allowed_paths if request.allowed_paths else [request.target_path]
    )

    task = Task(
        description=request.description,
        target_path=request.target_path,
        current_code=request.current_code,
        target_symbol=request.target_symbol,
        allowed_paths=allowed_paths,
    )

    # 1. Trust decision
    trust_decision = trust_manager.can_modify(task)

    # 2. Safety check
    try:
        safety_result = guard.check(request.proposed_code)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Safety check failed: {exc}",
        )

    safety_approved = bool(getattr(safety_result, "approved", False))
    violations = list(getattr(safety_result, "violations", []))
    warnings = list(getattr(safety_result, "warnings", []))

    # 3. Policy and risk assessment
    risk_assessment = policy_engine.assess_risk(
        agent_id=request.agent_id,
        target_path=request.target_path,
        current_code=request.current_code,
        proposed_code=request.proposed_code,
    )

    # 4. Combine decisions
    # require_human_review = ручная пауза: без подтверждения человеком
    # изменение не считается одобренным (иначе обязательная проверка
    # обходилась автоматическим approve — тот же класс дыры, что закрыт в
    # webhook_handler).
    needs_human = bool(risk_assessment.requires_human_review)
    approved = bool(
        trust_decision.allowed
        and safety_approved
        and risk_assessment.recommendation != "block"
        and not needs_human
    )

    reason: Optional[str] = None

    if not trust_decision.allowed:
        reason = getattr(trust_decision, "reason", "trust_denied")
    elif not safety_approved:
        reason = "; ".join(violations) or "safety_violation"
    elif risk_assessment.recommendation == "block":
        reason = f"policy_blocked: {', '.join(risk_assessment.matched_rules)}"
    elif needs_human:
        reason = (
            "human_review_required: "
            f"{', '.join(risk_assessment.matched_rules)}"
        )

    # 5. Update trust
    if approved:
        trust_manager.record_success(task)
    else:
        trust_manager.record_failure(
            task,
            reason or "verification_failed",
        )

    evidence_id = str(uuid.uuid4())
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    evidence = {
        "evidence_id": evidence_id,
        "created_at": created_at,
        "agent_id": request.agent_id,
        "tenant_id": user.tenant_id,
        "task_id": getattr(task, "task_id", None),
        "artifact_hashes": {
            "current_code_sha256": hashlib.sha256(request.current_code.encode("utf-8")).hexdigest(),
            "proposed_code_sha256": hashlib.sha256(request.proposed_code.encode("utf-8")).hexdigest(),
        },
        "trust": {
            "level": trust_manager.level.name,
            "allowed": bool(trust_decision.allowed),
            "reason": getattr(trust_decision, "reason", None),
            "success_streak": trust_manager.success_streak,
            "failure_streak": trust_manager.failure_streak,
        },
        "safety": {
            "approved": safety_approved,
            "violations": violations,
            "warnings": warnings,
        },
        "policy": {
            "risk_score": risk_assessment.risk_score,
            "risk_level": risk_assessment.risk_level,
            "matched_rules": risk_assessment.matched_rules,
            "warnings": risk_assessment.warnings,
            "requires_human_review": risk_assessment.requires_human_review,
            "recommendation": risk_assessment.recommendation,
        },
        "decision": {
            "approved": approved,
            "reason": reason,
        },
    }

    # Store with signature
    evidence = evidence_store.store(evidence)
    # Generate cryptographic receipt (manifest pins the reproducibility context)
    manifest = request.manifest
    if manifest is not None and len(json.dumps(manifest, default=str)) > 16_384:
        raise HTTPException(status_code=400, detail="Manifest too large (max 16 KB)")

    receipt = receipt_generator.generate_receipt(
        evidence_id=evidence_id,
        code=request.proposed_code,
        safety_approved=approved,
        trust_level=trust_manager.level.name,
        manifest=manifest,
    )

    # Add receipt to evidence
    evidence["cryptographic_receipt"] = receipt.to_dict()
    return evidence


@app.post("/v1/risk-score", deprecated=True)
def calculate_risk_score(
    request: RiskScoreRequest,
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.USER)),
) -> dict[str, Any]:
    """Legacy firewall endpoint — not part of the Proof-of-Savings surface."""
    # Метарика квоты, как и у соседнего /v1/verify-change: без неё политика
    # считалась бы неметрированной работой в обход месячного лимита.
    _check_quota_or_402(user.tenant_id, "code")

    risk_assessment = policy_engine.assess_risk(
        agent_id=request.agent_id,
        target_path=request.target_path,
        current_code=request.current_code,
        proposed_code=request.proposed_code,
    )

    return {
        "risk_score": risk_assessment.risk_score,
        "risk_level": risk_assessment.risk_level,
        "matched_rules": risk_assessment.matched_rules,
        "warnings": risk_assessment.warnings,
        "requires_human_review": risk_assessment.requires_human_review,
        "recommendation": risk_assessment.recommendation,
    }


@app.get("/v1/policies")
def list_policies(
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.VERIFIER, UserRole.USER)),
) -> list[dict[str, Any]]:
    """List all loaded policies."""
    return policy_engine.list_policies()


def _evidence_tenant_scope(user: User) -> Optional[str]:
    """Вычисляет tenant-фильтр для чтения legacy-evidence.

    Возвращает ``None`` для ролей, которые по замыслу видят все тенанты
    (platform-admin, VERIFIER — это роль внешнего аудитора), иначе — идентификатор
    тенанта вызывающего. Тенант видит ТОЛЬКО свою evidence; чужая (в т.ч. с
    другим tenant_id) не выдаётся и выглядит как «не найдено» (404), чтобы не
    подтверждать существование чужого evidence_id.
    """
    if user.is_platform_admin or user.role == UserRole.VERIFIER:
        return None
    return user.tenant_id


@app.get("/v1/verifications/{evidence_id}")
def get_verification(
    evidence_id: str,
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.VERIFIER, UserRole.USER)),
) -> dict[str, Any]:
    scope = _evidence_tenant_scope(user)
    evidence = evidence_store.get_by_id(evidence_id, tenant_id=scope)

    if evidence is None:
        raise HTTPException(status_code=404, detail="Verification not found")

    # Verify signature
    is_valid = evidence_store.verify(evidence)
    evidence["signature_valid"] = is_valid

    return evidence


@app.get("/v1/agents/{agent_id}/trust", response_model=TrustInfoResponse)
def get_agent_trust(
    agent_id: str,
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.VERIFIER, UserRole.USER)),
) -> TrustInfoResponse:
    trust_manager = _get_trust_manager(agent_id, user.tenant_id)

    return TrustInfoResponse(
        agent_id=agent_id,
        level=trust_manager.level.name,
        success_streak=trust_manager.success_streak,
        failure_streak=trust_manager.failure_streak,
        last_failure_reason=trust_manager.last_failure_reason,
    )


@app.get("/v1/agents/{agent_id}/history")
def get_agent_history(
    agent_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.VERIFIER, UserRole.USER)),
) -> list[dict[str, Any]]:
    """Get verification history for agent (tenant-isolated)."""
    scope = _evidence_tenant_scope(user)
    return evidence_store.get_by_agent(agent_id, limit=limit, tenant_id=scope)


@app.get("/v1/evidence")
def get_all_evidence(
    limit: int = Query(default=100, ge=1, le=1000),
    approved_only: bool = Query(default=False),
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.VERIFIER, UserRole.USER)),
) -> list[dict[str, Any]]:
    """Get all evidence with optional filtering (tenant-isolated)."""
    scope = _evidence_tenant_scope(user)
    return evidence_store.get_all(
        limit=limit, approved_only=approved_only, tenant_id=scope
    )


# === GitHub Webhook Integration ===


_webhook_handler: Optional[WebhookHandler] = None


def _get_webhook_handler() -> WebhookHandler:
    """Get or create webhook handler singleton."""
    global _webhook_handler

    if _webhook_handler is None:
        github_token = os.getenv("GITHUB_TOKEN")

        if not github_token:
            raise HTTPException(
                status_code=500,
                detail="GITHUB_TOKEN not configured",
            )

        github_client = GitHubClient(token=github_token)

        _webhook_handler = WebhookHandler(
            github_client=github_client,
            evidence_store=evidence_store,
            policy_engine=policy_engine,
        )

    return _webhook_handler


@app.post("/v1/webhooks/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None),
) -> dict[str, Any]:
    """
    Handle GitHub webhook events.

    Supported events:
    - pull_request (opened, synchronize, reopened)
    """
    # Read raw body for signature validation
    body = await request.body()

    # Handle ping event without requiring GitHubClient
    if x_github_event == "ping":
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        return {"status": "ok", "message": "Webhook ping received", "zen": payload.get("zen")}

    # Handle unsupported events early
    if x_github_event not in ("pull_request",):
        return {
            "status": "skipped",
            "reason": f"event_{x_github_event}_not_supported",
        }

    # Only create webhook handler for supported events
    try:
        handler = _get_webhook_handler()
    except HTTPException as exc:
        # GITHUB_TOKEN not configured
        return {
            "status": "error",
            "reason": exc.detail,
        }

    # Verify signature
    if not handler.verify_signature(body, x_hub_signature_256):
        raise HTTPException(
            status_code=401,
            detail="Invalid signature",
        )

    # Parse JSON payload
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid JSON: {exc}",
        )

    # Route by event type
    if x_github_event == "pull_request":
        result = handler.handle_pull_request(payload)
        return result

    return {
        "status": "skipped",
        "reason": f"event_{x_github_event}_not_supported",
    }
@app.post("/v1/verify-receipt")
def verify_receipt(request: dict) -> dict[str, Any]:
    """
    Verify cryptographic receipt.

    Receipts are signed with Ed25519: anyone holding the published
    public key can verify them without the signing secret or access
    to the original code.

    Args:
        request: Dict with receipt data

    Returns:
        Verification result
    """
    try:
        receipt_dict = request.get("receipt")
        if not receipt_dict:
            return {"valid": False, "error": "No receipt provided"}

        receipt = CryptographicReceipt(**receipt_dict)
        # C3: keyring знает все объявленные ключи — квитанции проверяемы
        # и после ротации (по kid)
        is_valid = receipt_keyring.verify(receipt)

        return {
            "valid": is_valid,
            "receipt_id": receipt.receipt_id,
            "evidence_id": receipt.evidence_id,
            "code_hash": receipt.code_hash,
            "safety_approved": receipt.safety_approved,
            "trust_level": receipt.trust_level,
            "timestamp": receipt.timestamp,
        }
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


@app.get("/v1/receipt-public-key")
def get_receipt_public_key() -> dict[str, Any]:
    """Public Ed25519 key for offline receipt verification by third parties."""
    return {"public_key": receipt_generator.get_public_key(), "algorithm": "Ed25519-SHA256"}


# === Proof-of-Savings Audit API ===

receipt_registry = ReceiptRegistry()
tenant_manager = TenantManager()
usage_meter = UsageMeter()
billing_engine = BillingEngine(tenant_manager, usage_meter)
webhook_dispatcher = OutboundWebhookDispatcher()

# C3: keyring-верификатор знает все объявленные в цепочке ключи, поэтому
# квитанции остаются проверяемыми после ротации. Fallback — текущий ключ
# (для legacy-квитанций без kid).
receipt_keyring = KeyringVerifier(receipt_generator.get_public_key())
receipt_keyring.add_key(receipt_generator.kid, receipt_generator.get_public_key())


def _hydrate_keyring_from_ledger() -> None:
    """Подтягивает ВСЕ ключи, уже объявленные в цепочке, в in-memory keyring.

    Ротация переключает активный генератор, но старые декларации ключей остаются
    в леджере навсегда. Без гидратации при рестарте процесса keyring содержал бы
    ТОЛЬКО текущий активный ключ, и квитанции, подписанные ключом ДО ротации,
    переставали бы проходить verify (key_for(kid) -> None) — то есть после
    рестарта система не смогла бы проверить собственную историю, что прямо
    противоречит гарантии «квитанции проверяемы после ротации».

    Идемпотентно и безопасно: неизвестные/битые декларации пропускаются, ошибка
    загрузки одного ключа не должна ломать старт сервиса.
    """
    try:
        declarations = receipt_registry.key_declarations()
    except Exception:  # леджер ещё не создан — не страшно
        return

    for declaration in declarations:
        decl = declaration.get("declaration") or {}
        kid = decl.get("kid")
        public_key = decl.get("public_key")

        if not kid or not public_key:
            continue

        try:
            receipt_keyring.add_key(kid, public_key)
        except (ValueError, TypeError):
            # Битая декларация не должна поднимать сервис; такая запись
            # останется недоверенной (verify вернёт False).
            continue


_hydrate_keyring_from_ledger()


def _ensure_key_declared() -> None:
    """C3: генезис-декларация активного ключа, если его ещё нет в цепочке.

    Вызывается перед анкором/ротацией: любое состояние леджера, которое
    уходит наружу для независимой проверки, обязано содержать декларацию
    ключа — иначе верификатор не восстановит таблицу kid→ключ.
    Идемпотентно: повторно не пишем.
    """
    if receipt_registry.resolve_key(receipt_generator.kid) is None:
        receipt_registry.register_key_declaration(
            kid=receipt_generator.kid,
            public_key=receipt_generator.get_public_key(),
            generator=receipt_generator,
        )


def _check_quota_or_402(tenant_id: str, kind: str) -> None:
    """Блокирует запуск при исчерпанной месячной квоте (HTTP 402)."""
    check = billing_engine.check_quota(tenant_id, kind)

    if not check.allowed:
        raise HTTPException(status_code=402, detail=check.reason)


def _reserve_quota_or_402(tenant_id: str, kind: str) -> None:
    """Атомарно резервирует слот квоты перед постановкой джоба в очередь.

    Для асинхронного пути одной проверки недостаточно: usage списывается только
    по завершении аудита, поэтому пачка параллельных submit'ов все прошли бы по
    неинкрементированному счётчику. Резерв держит слот занятым до завершения;
    снимается в _run_audit_and_register (успех) и _notify_audit_failure (падение).
    """
    check = billing_engine.reserve(tenant_id, kind)

    if not check.allowed:
        raise HTTPException(status_code=402, detail=check.reason)


# Квотные резервы асинхронных джобов хранятся в billing_engine по ключу
# (tenant, period, category). Снимать их нужно в обеих терминальных ветках
# (успех/падение), зная (tenant, kind). Успех знает flow -> kind напрямую;
# падение добирает kind из сохранённого flow_json джоба (см. _job_kind).
# Ключ резерва — намеренно НЕ audit_id в памяти: воркер может завершиться
# раньше, чем вызывающий успеет зарегистрировать audit_id, и такая запись осиротела
# бы навсегда (слот квоты утекает до конца месяца). Резерв снимается по
# производным данным джоба, поэтому гонки нет.


def _job_kind(audit_id: str, default: str = "code") -> str:
    """Достаёт kind джоба из сохранённого flow_json (для снятия резерва)."""
    with get_db_session() as db:
        record = (
            db.query(AuditJobRecord)
            .filter(AuditJobRecord.audit_id == audit_id)
            .first()
        )
        if record is None:
            return default
        return (record.flow_json or {}).get("kind", default)



class AuditRequest(BaseModel):
    flow: dict[str, Any] = Field(
        ...,
        description="Flow declaration, same schema as audit_cli --flow JSON",
    )


def _extract_paired_stats(report: dict[str, Any]) -> dict[str, Any]:
    """A5: компактная парная статистика вердикта для metadata аттестации.

    Разные kind несут парный блок в разных местах отчёта:
    llm_flow — equivalence.paired, code — paired, optimize — в финальном
    аудите лучшего кандидата.
    """
    paired: Optional[dict[str, Any]] = None

    if report.get("kind") == "optimize":
        best = (report.get("manifest") or {}).get("best")
        final_audits = report.get("final_audits") or {}
        if best and best in final_audits:
            paired = (final_audits[best].get("equivalence") or {}).get("paired")
    elif report.get("kind") == "code":
        paired = report.get("paired")
    else:
        paired = (report.get("equivalence") or {}).get("paired")

    if not isinstance(paired, dict):
        return {}

    return {
        "non_inferior": paired.get("non_inferior"),
        "delta": paired.get("delta"),
        "mcnemar_p": paired.get("mcnemar_p"),
        "minimum_detectable_difference": paired.get("minimum_detectable_difference"),
        "n_pairs": paired.get("n_pairs"),
        "b_old_pass_new_fail": paired.get("b_old_pass_new_fail"),
        "c_old_fail_new_pass": paired.get("c_old_fail_new_pass"),
        "ci_lower": paired.get("ci_lower"),
        "ci_upper": paired.get("ci_upper"),
        # R и n как объявленные до прогона пределы бюджета — рядом с MDD
        "declared_limits": paired.get("declared_limits"),
    }


def _run_audit_and_register(
    flow: dict[str, Any],
    tenant_id: str = DEFAULT_TENANT_ID,
    audit_id: str = "",
) -> dict[str, Any]:
    """Аудит + выпуск квитанции + регистрация в реестре + учёт использования.

    Общая часть синхронного эндпоинта и фонового воркера; бросает
    ValueError/KeyError при невалидном флоу. Для optimize-флоу claim
    берётся из recommendation.
    """
    report = run_flow_audit(flow)

    if report.get("kind") == "optimize":
        claim = report.get("recommendation") or {}
    else:
        claim = report.get("claim", {})

    receipt = receipt_generator.generate_receipt(
        evidence_id=f"audit-{report.get('name', 'flow')}",
        code=json.dumps(report, sort_keys=True, default=str),
        safety_approved=bool(claim.get("savings_verified")),
        trust_level="JUNIOR",
        manifest=report.get("manifest"),
    )

    # Параметры аудита в metadata квитанции: по ним сверяется
    # соответствие предрегистрации (dataset_sha256, delta, metric).
    prereg = report.get("preregistration") or {}
    metadata = {
        "tenant_id": tenant_id,
        "flow_name": report.get("name"),
        "kind": report.get("kind"),
        "mode": report.get("mode"),
        "savings_verified": claim.get("savings_verified"),
        "savings_ratio": claim.get("savings_ratio"),
    }
    if prereg:
        metadata["dataset_sha256"] = prereg.get("dataset_sha256")
        metadata["delta"] = prereg.get("delta")
        metadata["metric"] = prereg.get("metric")
        # Допуск реплея и правило его учёта: аттестация обязана нести
        # раскрытие вместе с обязательством (sia-preregistration/2)
        metadata["replay_tolerance"] = prereg.get("replay_tolerance")
        metadata["replay_tolerance_rule"] = prereg.get("replay_tolerance_rule")
        # Статус якоря и его проверяемый идентификатор: читатель
        # /v1/attestations/{id} обязан видеть и признание, и ссылку
        metadata["anchor_declaration"] = prereg.get("anchor_declaration")
        metadata["anchor_reference"] = prereg.get("anchor_reference")

    # A5: парная статистика (delta, mcnemar_p, MDD) публикуется в metadata,
    # чтобы аттестация несла методологию вердикта, а не только итог.
    paired = _extract_paired_stats(report)
    if paired:
        metadata["paired"] = paired

    registry_id = receipt_registry.register(receipt, metadata=metadata)

    # ANCHOR_AFTER_AUDIT=1: успешный аудит сам подписывает чекпойнт головы.
    # Выключено ПО УМОЛЧАНИЮ: поведение без флага не меняется. Крючок
    # закрывает класс «запись прожила без фиксации» (запись №2, 6 дней
    # 2026-09-07..13): до прод-крона cron_ledger.sh новый аудит оставлял
    # голову непокрытой, и никто не замечал. Ошибка чекпойнта НЕ валит
    # завершённый аудит (квитанция уже в цепи) — логируется и уходит
    # дальше; сторож cron'а увидит разрыв покрытия и позовёт человека.
    if os.getenv("ANCHOR_AFTER_AUDIT", "").strip() in ("1", "true", "yes"):
        try:
            receipt_registry.create_checkpoint(receipt_generator)
        except Exception as exc:  # noqa: BLE001
            print(
                f"[anchor-after-audit] checkpoint failed for {registry_id}: {exc}",
                file=sys.stderr,
            )

    usage_meter.record(
        tenant_id=tenant_id,
        kind=report.get("kind", "audit"),
        mode=report.get("mode"),
        savings_verified=claim.get("savings_verified"),
        savings_usd_per_1k=claim.get("savings_usd_per_1k_calls"),
        # Идемпотентный ключ для асинхронных джобов: audit_id переживает
        # recover(), поэтому перезапуск после падения НЕ списывает usage второй
        # раз. Синхронный путь audit_id пуст -> ключ не задаётся (обычная запись).
        event_key=f"audit:{audit_id}" if audit_id else None,
    )

    # Синхронный /v1/audit вызывает эту функцию без audit_id (audit_id == ""),
    # и квоту для него резервировать не нужно — там точная синхронная проверка.
    # Асинхронный воркер передаёт реальный audit_id: снимаем резерв, который
    # держал слот от submit до завершения, чтобы не было двойного счёта
    # (записанный usage + резерв).
    if audit_id:
        billing_engine.release(tenant_id, report.get("kind", "code"))

    webhook_dispatcher.dispatch(
        EVENT_AUDIT_COMPLETED,
        {
            "event": EVENT_AUDIT_COMPLETED,
            "audit_id": audit_id,
            "tenant_id": tenant_id,
            "status": "completed",
            "registry_id": registry_id,
            "flow_name": report.get("name"),
            "kind": report.get("kind"),
            "savings_verified": claim.get("savings_verified"),
            "occurred_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
    )

    return {
        "registry_id": registry_id,
        "report": report,
        "receipt": receipt.to_dict(),
    }


def _notify_audit_failure(audit_id: str, tenant_id: str, error: str) -> None:
    """Исходящий webhook audit.failed (доставка fire-and-forget).

    Также снимает квотный резерв павшего асинхронного джоба: слот занимался
    с момента submit и должен вернуться в лимит, иначе неудачные попытки
    «съедают» месячную квоту тенанта. kind берётся из сохранённого flow_json.

    Снятие резерва обёрнуто в try/except: это обработчик отказа, и сбой
    биллинга (или чтения джоба из БД) не должен глушить webhook audit.failed —
    иначе клиент вообще не узнает, что джоб упал.
    """
    try:
        billing_engine.release(tenant_id, _job_kind(audit_id))
    except Exception as exc:  # noqa: BLE001
        print(
            f"[quota-release] failed to release reservation for {audit_id}: {exc}",
            file=sys.stderr,
        )

    webhook_dispatcher.dispatch(
        EVENT_AUDIT_FAILED,
        {
            "event": EVENT_AUDIT_FAILED,
            "audit_id": audit_id,
            "tenant_id": tenant_id,
            "status": "failed",
            "error": error,
            "occurred_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
    )


audit_job_manager = AuditJobManager(_run_audit_and_register, on_failure=_notify_audit_failure)

# Перезапускаем джобы, прерванные крахом/рестартом процесса
_recovered_jobs = audit_job_manager.recover()

if _recovered_jobs:
    print(f"INFO: recovered {_recovered_jobs} interrupted audit job(s)")


@app.post("/v1/audit")
def run_pos_audit(
    request: AuditRequest,
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.USER)),
) -> dict[str, Any]:
    """Run a Proof-of-Savings audit and return a signed, registered receipt.

    The flow uses the same schema as audit_cli (kind: code | llm_flow).
    Live LLM endpoints must reference API keys via api_key_env, never inline.
    Requires an API key (X-API-Key) or JWT with admin/user role.
    """
    flow = dict(request.flow)
    flow.pop("_base_dir", None)

    _check_quota_or_402(user.tenant_id, flow.get("kind", "code"))

    try:
        validate_api_flow(flow)
        return _run_audit_and_register(flow, tenant_id=user.tenant_id)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# === Preregistration API ===


@app.post("/v1/preregistrations")
def create_preregistration(
    request: AuditRequest,
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.USER)),
) -> dict[str, Any]:
    """Коммитит обязательство аудита в цепочку ДО прогона.

    Предрегистрация фиксирует хеши параметров аудита (датасет, delta,
    метрика, конфигурации, цены) в тампер-эвидентной хеш-цепочке. После
    этого аудитор не может переставить ворота: вердикт обязан быть вынесен
    против заранее объявленных параметров. Возвращает preregistration_id,
    который затем связывается с квитанцией аудита.
    """
    flow = dict(request.flow)
    flow.pop("_base_dir", None)

    try:
        validate_api_flow(flow)
        commitment = build_preregistration_commitment(flow)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    commitment["tenant_id"] = user.tenant_id
    commitment["flow_name"] = flow.get("name")

    preregistration_id = receipt_registry.register_preregistration(commitment)

    return {
        "preregistration_id": preregistration_id,
        "commitment": commitment,
    }


@app.get("/v1/preregistrations/{preregistration_id}")
def get_preregistration(preregistration_id: str) -> dict[str, Any]:
    """Возвращает обязательство предрегистрации (публично, как и аттестации)."""
    prereg = receipt_registry.get_preregistration(preregistration_id)

    if prereg is None:
        raise HTTPException(
            status_code=404, detail=f"Preregistration not found: {preregistration_id}"
        )

    return prereg


@app.get("/v1/preregistrations/{preregistration_id}/verify/{registry_id}")
def verify_preregistration_link(
    preregistration_id: str, registry_id: str
) -> dict[str, Any]:
    """Проверяет, что квитанция аудита соответствует предрегистрации.

    Сверяет обязательство (dataset_sha256, delta, metric) с metadata
    квитанции и порядок в цепочке (предрегистрация предшествует квитанции).
    """
    receipt_entry = receipt_registry.get(registry_id)

    if receipt_entry is None:
        raise HTTPException(status_code=404, detail=f"Receipt not found: {registry_id}")

    return receipt_registry.verify_preregistration_link(
        preregistration_id, receipt_entry
    )


@app.post("/v1/audits", status_code=202)
def submit_pos_audit(
    request: AuditRequest,
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.USER)),
) -> dict[str, Any]:
    """Accept an audit for asynchronous execution; poll GET /v1/audits/{audit_id}.

    Long-running flows (live LLM endpoints) should use this instead of the
    synchronous POST /v1/audit.
    """
    flow = dict(request.flow)
    flow.pop("_base_dir", None)

    kind = flow.get("kind", "code")
    if kind not in ("code", "llm_flow", "optimize"):
        raise HTTPException(status_code=400, detail=f"Unknown flow kind: {kind}")

    try:
        validate_api_flow(flow)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    _reserve_quota_or_402(user.tenant_id, kind)

    audit_id = audit_job_manager.submit(flow, tenant_id=user.tenant_id)

    return {"audit_id": audit_id, "status": "pending"}


@app.get("/v1/audits/{audit_id}")
def get_audit_status(
    audit_id: str,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Status of an async audit: pending / running / completed / failed.

    Tenant-isolated: a client only sees jobs submitted under its own tenant.
    """
    snapshot = audit_job_manager.get(audit_id, tenant_id=user.tenant_id)

    if snapshot is None:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")

    return snapshot


@app.post("/v1/optimize", status_code=202)
def submit_optimization(
    request: AuditRequest,
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.USER)),
) -> dict[str, Any]:
    """Submit a Savings Autopilot run (kind=optimize); poll GET /v1/optimize/{audit_id}.

    Finds the cheapest model configuration that preserves quality on the
    provided dataset and checkers, then proves the savings with a full
    audit against the baseline.
    """
    flow = dict(request.flow)
    flow.pop("_base_dir", None)

    if flow.get("kind") != "optimize":
        raise HTTPException(
            status_code=400, detail="POST /v1/optimize requires kind='optimize'"
        )

    try:
        validate_api_flow(flow)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    _reserve_quota_or_402(user.tenant_id, "optimize")

    audit_id = audit_job_manager.submit(flow, tenant_id=user.tenant_id)

    return {"audit_id": audit_id, "status": "pending"}


@app.get("/v1/optimize/{audit_id}")
def get_optimization_status(
    audit_id: str,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Status of an async optimization (same job store as /v1/audits).

    Tenant-isolated: a client only sees jobs submitted under its own tenant.
    """
    snapshot = audit_job_manager.get(audit_id, tenant_id=user.tenant_id)

    if snapshot is None:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")

    return snapshot


# === Tenancy & Usage API ===


class CreateTenantRequest(PydanticBaseModel):
    name: str
    tenant_id: Optional[str] = None
    plan: str = "free"


@app.post("/v1/tenants", status_code=201)
def create_tenant(
    request: CreateTenantRequest,
    user: User = Depends(require_platform_admin),
) -> dict[str, Any]:
    """Create a tenant (organization). Platform admin only."""
    if request.plan not in PLANS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown plan: {request.plan}. Available: {sorted(PLANS)}",
        )

    try:
        tenant = tenant_manager.create(
            name=request.name,
            tenant_id=request.tenant_id,
            plan=request.plan,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"tenant": tenant.to_dict()}


@app.get("/v1/tenants")
def list_tenants(
    user: User = Depends(require_platform_admin),
) -> dict[str, Any]:
    """List all tenants. Platform admin only."""
    tenants = tenant_manager.list()

    return {"count": len(tenants), "tenants": [t.to_dict() for t in tenants]}


class SignupRequest(PydanticBaseModel):
    name: str
    tenant_id: Optional[str] = None


@app.post("/v1/signup", status_code=201)
def signup(request: SignupRequest) -> dict[str, Any]:
    """Self-service onboarding: create a tenant and its first admin API key.

    No authentication required. New tenants always start on the free plan;
    upgrades are handled by a platform admin. The returned api_key is shown
    only once — store it securely.
    """
    try:
        tenant = tenant_manager.create(
            name=request.name,
            tenant_id=request.tenant_id,
            plan="free",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    plain_key, key_obj = api_key_manager.create_key(
        name=f"{tenant.tenant_id}-admin",
        role=UserRole.ADMIN,
        tenant_id=tenant.tenant_id,
        is_platform_admin=False,
    )

    return {
        "tenant": tenant.to_dict(),
        "api_key": plain_key,
        "key_info": key_obj.to_dict(),
        "warning": "Store this key securely. It will not be shown again.",
    }


class TenantSettingsRequest(PydanticBaseModel):
    publish_attestations: Optional[bool] = None


@app.post("/v1/tenants/{tenant_id}/settings")
def update_tenant_settings(
    tenant_id: str,
    request: TenantSettingsRequest,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Update tenant settings.

    Доступ: платформенный админ или админ этого тенанта.
    Currently supported: publish_attestations — opt-in to the public
    attestation registry (default false).
    """
    if user.role != UserRole.ADMIN or not (
        user.is_platform_admin or user.tenant_id == tenant_id
    ):
        raise HTTPException(
            status_code=403, detail="Tenant admin or platform admin required"
        )

    if request.publish_attestations is None:
        raise HTTPException(status_code=400, detail="No settings provided")

    try:
        tenant = tenant_manager.set_metadata(
            tenant_id, "publish_attestations", bool(request.publish_attestations)
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return {"tenant": tenant.to_dict()}


def _require_tenant_admin_access(user: User, tenant_id: str) -> None:
    """Доступ к управлению тенантом: платформенный админ или админ этого тенанта."""
    if user.role != UserRole.ADMIN or not (
        user.is_platform_admin or user.tenant_id == tenant_id
    ):
        raise HTTPException(
            status_code=403, detail="Tenant admin or platform admin required"
        )


class CreateTenantAPIKeyRequest(PydanticBaseModel):
    name: str
    role: str = "user"
    expires_in_days: Optional[int] = None


@app.post("/v1/tenants/{tenant_id}/api-keys", status_code=201)
def create_tenant_api_key(
    tenant_id: str,
    request: CreateTenantAPIKeyRequest,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Create an API key for a tenant (tenant admin or platform admin).

    Created keys never carry platform privileges. Returns the plain key
    only once — store it securely.
    """
    _require_tenant_admin_access(user, tenant_id)

    if tenant_manager.get(tenant_id) is None:
        raise HTTPException(status_code=404, detail=f"Tenant not found: {tenant_id}")

    try:
        role = UserRole(request.role)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role. Valid roles: {[r.value for r in UserRole]}",
        )

    if role == UserRole.ANONYMOUS:
        raise HTTPException(status_code=400, detail="Cannot create anonymous keys")

    # VERIFIER — это фактически кросс-тенантное право чтения: _evidence_tenant_scope
    # для этой роли снимает tenant-фильтр (api.py:402), т.е. ключ видит evidence,
    # verifications и agent-history ВСЕХ тенантов. Выдать такое право из
    # self-service нельзя, иначе любой тенант проходит «signup -> выпустить
    # verifier-ключ -> читает аудиты конкурентов». Наружу роль выдаёт только
    # платформенный админ (он и так держит is_platform_admin=True).
    if role == UserRole.VERIFIER and not user.is_platform_admin:
        raise HTTPException(
            status_code=403,
            detail=(
                "Role 'verifier' grants cross-tenant read access and can only "
                "be issued by a platform admin."
            ),
        )

    plain_key, key_obj = api_key_manager.create_key(
        name=request.name,
        role=role,
        expires_in_days=request.expires_in_days,
        tenant_id=tenant_id,
        is_platform_admin=False,
    )

    return {
        "success": True,
        "api_key": plain_key,
        "key_info": key_obj.to_dict(),
        "warning": "Store this key securely. It will not be shown again.",
    }


@app.get("/v1/tenants/{tenant_id}/api-keys")
def list_tenant_api_keys(
    tenant_id: str,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """List a tenant's API keys (tenant admin or platform admin)."""
    _require_tenant_admin_access(user, tenant_id)

    keys = [
        k.to_dict()
        for k in api_key_manager.list_keys()
        if k.tenant_id == tenant_id
    ]

    return {"count": len(keys), "keys": keys}


@app.delete("/v1/tenants/{tenant_id}/api-keys/{key_id}")
def revoke_tenant_api_key(
    tenant_id: str,
    key_id: str,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Revoke a key of the tenant (tenant admin or platform admin)."""
    _require_tenant_admin_access(user, tenant_id)

    key_obj = next(
        (k for k in api_key_manager.list_keys() if k.key_id == key_id), None
    )

    if key_obj is None or key_obj.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail=f"Key not found: {key_id}")

    api_key_manager.revoke_key(key_id)

    return {"success": True, "message": f"Key {key_id} revoked"}


@app.get("/v1/usage")
def get_usage_summary(
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.USER)),
) -> dict[str, Any]:
    """Usage summary for the caller's tenant (basis for billing)."""
    return usage_meter.summary(user.tenant_id)


# === Billing API ===


class ChangePlanRequest(PydanticBaseModel):
    plan: str
    # B4: платформенный админ управляет любым тенантом; по умолчанию — свой.
    tenant_id: Optional[str] = None


class IssueInvoiceRequest(PydanticBaseModel):
    period: Optional[str] = None  # "YYYY-MM"; default = current month
    tenant_id: Optional[str] = None  # B4: целевой тенант для платформенного админа


@app.get("/v1/billing/plans")
def list_billing_plans() -> dict[str, Any]:
    """Catalog of available plans (public)."""
    plans = [plan.to_dict() for plan in PLANS.values()]

    return {"count": len(plans), "plans": plans}


@app.get("/v1/billing/plan")
def get_billing_plan(
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.USER)),
) -> dict[str, Any]:
    """Current plan and quota status for the caller's tenant."""
    plan = billing_engine.get_plan(user.tenant_id)

    return {
        "tenant_id": user.tenant_id,
        "plan": plan.to_dict(),
        "quota": billing_engine.quota_status(user.tenant_id),
    }


@app.post("/v1/billing/plan")
def change_billing_plan(
    request: ChangePlanRequest,
    user: User = Depends(require_platform_admin),
) -> dict[str, Any]:
    """Switch a tenant to another plan (platform admin only).

    B4: the admin may target any tenant via ``tenant_id``; omitted means
    the admin's own tenant.
    """
    if request.plan not in PLANS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown plan: {request.plan}. Available: {sorted(PLANS)}",
        )

    target_tenant = request.tenant_id or user.tenant_id

    try:
        tenant = billing_engine.set_plan(target_tenant, request.plan)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return {
        "tenant": tenant.to_dict(),
        "quota": billing_engine.quota_status(target_tenant),
    }


@app.get("/v1/billing/invoices")
def list_billing_invoices(
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.USER)),
) -> dict[str, Any]:
    """Invoices for the caller's tenant (newest first)."""
    invoices = billing_engine.list_invoices(user.tenant_id)

    return {
        "count": len(invoices),
        "invoices": [invoice.to_dict() for invoice in invoices],
    }


@app.post("/v1/billing/invoices", status_code=201)
def issue_billing_invoice(
    request: IssueInvoiceRequest,
    user: User = Depends(require_platform_admin),
) -> dict[str, Any]:
    """Issue an invoice for a tenant (platform admin only).

    B4: the admin may target any tenant via ``tenant_id``; omitted means
    the admin's own tenant. Idempotent per tenant+period: a repeat call
    returns the existing invoice.
    """
    target_tenant = request.tenant_id or user.tenant_id

    try:
        invoice = billing_engine.issue_invoice(target_tenant, request.period)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"invoice": invoice.to_dict()}


@app.get("/v1/billing/invoices/{invoice_id}")
def get_billing_invoice(
    invoice_id: str,
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.USER)),
) -> dict[str, Any]:
    """Fetch one invoice; tenants only see their own invoices."""
    invoice = billing_engine.get_invoice(invoice_id, tenant_id=user.tenant_id)

    if invoice is None:
        raise HTTPException(status_code=404, detail=f"Invoice not found: {invoice_id}")

    return {"invoice": invoice.to_dict()}


# === Outbound Webhooks API ===


class WebhookSubscribeRequest(PydanticBaseModel):
    url: str
    events: list[str]


@app.post("/v1/webhooks/subscriptions", status_code=201)
def create_webhook_subscription(
    request: WebhookSubscribeRequest,
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.USER)),
) -> dict[str, Any]:
    """Subscribe a URL to audit events for the caller's tenant.

    The HMAC secret is returned once — store it securely. Verify incoming
    deliveries with HMAC-SHA256 over the raw body (header X-SIA-Signature).
    """
    try:
        subscription = webhook_dispatcher.subscribe(
            tenant_id=user.tenant_id,
            url=request.url,
            events=request.events,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "subscription": subscription.to_dict(include_secret=True),
        "warning": "Store the secret securely. It will not be shown again.",
    }


@app.get("/v1/webhooks/subscriptions")
def list_webhook_subscriptions(
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.USER)),
) -> dict[str, Any]:
    """List the caller's tenant webhook subscriptions (secrets not shown)."""
    subscriptions = webhook_dispatcher.list(user.tenant_id)

    return {"count": len(subscriptions), "subscriptions": subscriptions}


@app.delete("/v1/webhooks/subscriptions/{subscription_id}")
def delete_webhook_subscription(
    subscription_id: str,
    user: User = Depends(require_role(UserRole.ADMIN, UserRole.USER)),
) -> dict[str, Any]:
    """Remove a webhook subscription (tenant-isolated)."""
    removed = webhook_dispatcher.unsubscribe(subscription_id, user.tenant_id)

    if not removed:
        raise HTTPException(
            status_code=404, detail=f"Subscription not found: {subscription_id}"
        )

    return {"deleted": True, "subscription_id": subscription_id}


@app.get("/v1/receipts")
def list_receipts(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    all_tenants: bool = Query(False, description="Platform admin only: list receipts of every tenant."),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """List registered Proof-of-Savings receipts (newest first).

    B1: authenticated only. A tenant sees its own receipts; the public
    showcase for opted-in tenants lives at /v1/attestations and /registry.
    Platform admins may pass all_tenants=true to see everything.
    """
    if all_tenants:
        if not user.is_platform_admin:
            raise HTTPException(status_code=403, detail="all_tenants requires platform admin")
        receipts = receipt_registry.list_receipts(limit=limit, offset=offset)
        total = receipt_registry.count_receipts()
    else:
        receipts = receipt_registry.list_for_tenant(user.tenant_id, limit=limit, offset=offset)
        total = receipt_registry.count_receipts(tenant_id=user.tenant_id)

    return {"count": len(receipts), "total": total, "receipts": receipts}


@app.get("/v1/receipts/{registry_id}")
def get_receipt(registry_id: str, user: User = Depends(get_current_user)) -> dict[str, Any]:
    """Fetch a full registry entry (receipt + metadata).

    B1: tenants may only fetch their own entries; platform admins may
    fetch any entry.
    """
    entry = receipt_registry.get(registry_id)

    if entry is None:
        raise HTTPException(status_code=404, detail=f"Receipt not found: {registry_id}")

    entry_tenant = (entry.get("metadata") or {}).get("tenant_id")
    if not user.is_platform_admin and entry_tenant != user.tenant_id:
        # Не раскрываем сам факт существования чужой записи.
        raise HTTPException(status_code=404, detail=f"Receipt not found: {registry_id}")

    return entry


@app.get("/v1/receipts/{registry_id}/verify")
def verify_registered_receipt(
    registry_id: str,
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Verify a stored receipt's Ed25519 signature with the public key."""
    entry = receipt_registry.get(registry_id)

    if entry is None:
        raise HTTPException(status_code=404, detail=f"Receipt not found: {registry_id}")

    entry_tenant = (entry.get("metadata") or {}).get("tenant_id")
    if not user.is_platform_admin and entry_tenant != user.tenant_id:
        raise HTTPException(status_code=404, detail=f"Receipt not found: {registry_id}")

    valid = receipt_registry.verify_stored(registry_id, receipt_keyring)

    if valid is None:
        raise HTTPException(status_code=404, detail=f"Receipt not found: {registry_id}")

    # C3: публичный ключ, которым подписана именно эта квитанция (по kid)
    receipt_kid = ((entry.get("receipt") or {}).get("kid"))
    signing_key = (
        receipt_registry.resolve_key(receipt_kid)
        if receipt_kid
        else receipt_generator.get_public_key()
    )

    return {
        "registry_id": registry_id,
        "valid": valid,
        "public_key": signing_key or receipt_generator.get_public_key(),
        "kid": receipt_kid,
        "algorithm": "Ed25519-SHA256",
    }


# === TrustChain Ledger API ===


@app.get("/v1/ledger/head")
def get_ledger_head() -> dict[str, Any]:
    """Current head of the receipt hash chain plus the Merkle tree head.

    C1: ``tree_size``/``root_hash`` cover every entry (RFC 6962-style
    accumulator), so an external auditor can verify inclusion and
    consistency proofs against this head.
    """
    head = receipt_registry.head()
    tree = receipt_registry.tree_head()

    if head is None:
        return {
            "seq": 0,
            "entry_hash": None,
            "registry_id": None,
            "registered_at": None,
            "tree_size": tree["tree_size"],
            "root_hash": tree["root_hash"],
        }

    return {**head, "tree_size": tree["tree_size"], "root_hash": tree["root_hash"]}


@app.get("/v1/ledger/inclusion/{registry_id}")
def get_inclusion_proof(registry_id: str) -> dict[str, Any]:
    """C1: Merkle inclusion proof for a registry entry.

    Returns the leaf index, entry hash, tree size/root and the audit
    path; verifiable independently (see sia-verifier).
    """
    proof = receipt_registry.inclusion_proof(registry_id)

    if proof is None:
        raise HTTPException(status_code=404, detail=f"Entry not found: {registry_id}")

    return proof


@app.get("/v1/ledger/consistency")
def get_consistency_proof(
    from_size: int = Query(..., alias="from", ge=0),
    to_size: Optional[int] = Query(None, alias="to", ge=0),
) -> dict[str, Any]:
    """C1: Merkle consistency proof between two tree heads.

    Proves the tree of size ``to`` (default: current) is an append-only
    extension of the tree of size ``from``.
    """
    proof = receipt_registry.consistency_proof(from_size, to_size)

    if proof is None:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid tree sizes: from={from_size}, to={to_size}",
        )

    return proof


@app.get("/v1/ledger/verify")
def verify_ledger(full: bool = Query(False)) -> dict[str, Any]:
    """Verify the receipt hash chain (tamper evidence).

    C2: incremental by default — only entries appended since the last
    successful verification are re-checked (plus an anchor check of the
    cached prefix). Pass ``full=true`` to re-verify from genesis.
    """
    result = receipt_registry.verify_chain(full=full)
    result["public_key"] = receipt_generator.get_public_key()
    return result


@app.post("/v1/ledger/checkpoint")
def create_ledger_checkpoint(
    user: User = Depends(require_platform_admin),
) -> dict[str, Any]:
    """Sign and store a checkpoint anchoring the current chain head.

    The signed commitment (seq, head_hash, tree head) can be published
    externally to freeze the ledger state at a point in time. Admin only.
    """
    checkpoint = receipt_registry.create_checkpoint(receipt_generator)

    if checkpoint is None:
        raise HTTPException(status_code=409, detail="Ledger is empty — nothing to anchor")

    return {"checkpoint": checkpoint}


@app.get("/v1/ledger/checkpoints")
def list_ledger_checkpoints(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    """List ledger checkpoints (newest first)."""
    checkpoints = receipt_registry.list_checkpoints(limit=limit)

    return {"count": len(checkpoints), "checkpoints": checkpoints}


class RotateKeyRequest(BaseModel):
    new_signing_key: Optional[str] = Field(
        default=None,
        description=(
            "Seed material for the new Ed25519 key. If omitted, a random "
            "key is generated and returned ONCE in the response."
        ),
    )


@app.post("/v1/ledger/keys/rotate")
def rotate_receipt_key(
    request: RotateKeyRequest,
    user: User = Depends(require_platform_admin),
) -> dict[str, Any]:
    """C3: rotate the receipt signing key.

    The new key is declared in the chain in a record signed by the
    CURRENT (still-active) key, so the chain of trust is unbroken and a
    verifier can reconstruct the kid→key table from the ledger alone.
    Old receipts stay verifiable via their kid. Platform admin only.

    If ``new_signing_key`` is omitted, a random key is generated; its
    seed is returned once — store it as the new RECEIPT_SIGNING_KEY.
    """
    global receipt_generator

    import secrets as _secrets

    new_material = request.new_signing_key or _secrets.token_hex(32)
    old_generator = receipt_generator
    new_generator = ReceiptGenerator(new_material)

    if new_generator.kid == old_generator.kid:
        raise HTTPException(status_code=409, detail="New key is identical to the current key")

    # Если текущий ключ ещё не объявлен в этом реестре, сначала пишем
    # генезис-декларацию — иначе цепочка доверия начнётся с подписанта,
    # которого нет в цепи
    _ensure_key_declared()

    # Декларация нового ключа, подписанная СТАРЫМ активным ключом
    declaration_id = receipt_registry.register_key_declaration(
        kid=new_generator.kid,
        public_key=new_generator.get_public_key(),
        generator=old_generator,
    )

    # Переключаем активный генератор и пополняем keyring
    receipt_generator = new_generator
    receipt_keyring.add_key(new_generator.kid, new_generator.get_public_key())

    return {
        "declaration_registry_id": declaration_id,
        "old_kid": old_generator.kid,
        "new_kid": new_generator.kid,
        "new_public_key": new_generator.get_public_key(),
        # Секрет возвращается один раз — только если сгенерирован сервером
        "new_signing_key": new_material if not request.new_signing_key else None,
        "warning": (
            "Store new_signing_key as RECEIPT_SIGNING_KEY now — it is not "
            "shown again."
            if not request.new_signing_key
            else None
        ),
    }


@app.get("/v1/ledger/keys")
def list_key_declarations() -> dict[str, Any]:
    """C3: all key declarations from the chain (kid → public key history)."""
    declarations = receipt_registry.key_declarations()

    return {
        "count": len(declarations),
        "active_kid": receipt_generator.kid,
        "declarations": declarations,
    }


@app.post("/v1/ledger/anchor")
def anchor_ledger_checkpoint(
    user: User = Depends(require_platform_admin),
) -> dict[str, Any]:
    """C4: create a checkpoint and publish it to external anchor storage.

    Transports are picked up from the environment: the file transport
    always (ANCHORS_DIR, default ``anchors/``), the HTTP transport when
    ANCHOR_URL is set. Admin only.

    Anchoring also writes the genesis key declaration (§3.2 spec), so the
    externally published state is self-describing: a verifier can rebuild
    the kid → key table from the anchored chain alone.
    """
    if receipt_registry.head() is None:
        raise HTTPException(status_code=409, detail="Ledger is empty — nothing to anchor")

    _ensure_key_declared()
    checkpoint = receipt_registry.create_checkpoint(receipt_generator)

    if checkpoint is None:
        raise HTTPException(status_code=409, detail="Ledger is empty — nothing to anchor")

    results = publish_checkpoint(checkpoint)

    return {
        "checkpoint": checkpoint,
        "anchors": results,
        "anchored": all(r["ok"] for r in results),
    }


# === Public Attestations ===

ATTESTATION_SCHEMA_VERSION = "1"
ATTESTATION_SPEC = "sia-attestation/1"  # см. docs/attestation-spec.md


def _build_attestation(registry_id: str) -> dict[str, Any]:
    """Собирает публичный аттестационный документ по записи реестра."""
    entry = receipt_registry.get(registry_id)

    if entry is None:
        raise HTTPException(status_code=404, detail=f"Attestation not found: {registry_id}")

    receipt_valid = receipt_registry.verify_stored(registry_id, receipt_keyring)
    chain = receipt_registry.verify_chain()
    metadata = entry.get("metadata", {})

    claim: dict[str, Any] = {
        "savings_verified": metadata.get("savings_verified"),
        "savings_ratio": metadata.get("savings_ratio"),
    }

    # A5: методология вердикта — парная статистика и предрегистрация —
    # публикуется в аттестации, а не остаётся только в коде.
    if metadata.get("paired"):
        claim["paired"] = metadata.get("paired")
    if metadata.get("delta") is not None or metadata.get("dataset_sha256"):
        claim["preregistration"] = {
            "dataset_sha256": metadata.get("dataset_sha256"),
            "delta": metadata.get("delta"),
            "metric": metadata.get("metric"),
            "replay_tolerance": metadata.get("replay_tolerance"),
            "replay_tolerance_rule": metadata.get("replay_tolerance_rule"),
            "anchor_declaration": metadata.get("anchor_declaration"),
            "anchor_reference": metadata.get("anchor_reference"),
        }

    # C3: issuer несёт тот ключ, которым подписана именно эта квитанция
    # (разрешается по kid из деклараций цепочки), а не текущий активный —
    # иначе после ротации старые аттестации не прошли бы независимую проверку.
    receipt_dict = entry.get("receipt") or {}
    receipt_kid = receipt_dict.get("kid")
    issuer_key = (
        receipt_registry.resolve_key(receipt_kid)
        if receipt_kid
        else receipt_generator.get_public_key()
    ) or receipt_generator.get_public_key()

    return {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "spec": ATTESTATION_SPEC,
        "attestation_id": registry_id,
        "issued_at": entry.get("registered_at"),
        "issuer": {
            "name": "SIA Sentinel",
            "public_key": issuer_key,
            "kid": receipt_kid,
            "algorithm": "Ed25519-SHA256",
        },
        "subject": {
            "flow_name": metadata.get("flow_name"),
            "kind": metadata.get("kind"),
            "mode": metadata.get("mode"),
        },
        "claim": claim,
        "receipt": entry.get("receipt"),
        "verification": {
            "receipt_signature_valid": receipt_valid,
            "ledger_chain_valid": chain["valid"],
            "ledger_entries": chain["entries"],
        },
    }


@app.get("/v1/attestations/{registry_id}")
def get_public_attestation(registry_id: str) -> dict[str, Any]:
    """Public, independently verifiable attestation document."""
    return _build_attestation(registry_id)


def _is_tenant_published(tenant_id: str) -> bool:
    """Opt-in флаг публикации: запись видна в публичном реестре только с согласия тенанта."""
    tenant = tenant_manager.get(tenant_id)
    return bool(tenant and tenant.metadata.get("publish_attestations"))


@app.get("/v1/attestations")
def list_public_attestations(
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)
) -> dict[str, Any]:
    """Public attestation registry: only tenants that opted into publishing.

    Individual attestations stay accessible by id (badges link to them);
    this index lists only opted-in tenants' records.
    """
    cards = receipt_registry.list_public(_is_tenant_published, limit=limit, offset=offset)

    return {"count": len(cards), "attestations": cards}


@app.get("/v1/attestations/{registry_id}/badge.svg")
def get_attestation_badge(registry_id: str):
    """SVG badge for embedding the verified savings claim."""
    from fastapi.responses import Response

    attestation = _build_attestation(registry_id)
    claim = attestation["claim"]
    verified = bool(claim.get("savings_verified")) and attestation["verification"]["receipt_signature_valid"]

    if verified and claim.get("savings_ratio") is not None:
        label = f"Savings {claim['savings_ratio'] * 100:.0f}% verified"
        color = "#2e7d32"
    else:
        label = "Savings not verified"
        color = "#c62828"

    width = 150 + len(label) * 7
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="24" role="img" '
        f'aria-label="Proof-of-Savings attestation">'
        f'<rect width="118" height="24" fill="#37474f"/>'
        f'<rect x="118" width="{width - 118}" height="24" fill="{color}"/>'
        f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="8" y="16">Proof-of-Savings</text>'
        f'<text x="126" y="16">{label}</text>'
        f'</g></svg>'
    )

    return Response(content=svg, media_type="image/svg+xml")


# === Verification Portal (HTML) ===


def _esc(value: Any) -> str:
    """Экранирование для inline-HTML."""
    import html

    return html.escape(str(value), quote=True)


# п.10: витрина реестра на двух языках (позицирование «made in KZ» —
# суверенный стандарт эффективности ИИ; страницы — дёшево, один раз).
# ?lang=kk|ru, дефолт en. Словарь только для статических надписей —
# сами данные (названия флоу, аттестации) языконезависимы.
PORTAL_TEXTS = {
    "en": {
        "title": "Proof-of-Savings Attestation",
        "registry_title": "Public Attestation Registry",
        "registry_intro": "Attestations published by tenants who opted in. Each entry is independently verifiable.",
        "verdict_verified": "VERIFIED",
        "verdict_not_verified": "NOT VERIFIED",
        "th_attestation": "Attestation", "th_flow": "Flow", "th_kind": "Kind",
        "th_verified": "Verified", "th_savings": "Savings", "th_issued": "Issued",
        "row_empty": "No published attestations yet.",
        "back_to_registry": "&larr; Public attestation registry",
        "lang_switch": "ҚАЗ | РУС | EN",
    },
    "kk": {
        "title": "Proof-of-Savings аттестаттауы",
        "registry_title": "Аттестаттаулардың қоғамдық тізілімі",
        "registry_intro": "Жариялауға келіскен қатысушылардың аттестаттаулары. Әрбір жазба тәуелсіз тексеруге болады.",
        "verdict_verified": "РАСТАЛДЫ",
        "verdict_not_verified": "РАСТАЛМАҒАН",
        "th_attestation": "Аттестаттау", "th_flow": "Ағын", "th_kind": "Түрі",
        "th_verified": "Тексерілген", "th_savings": "Үнем", "th_issued": "Шығарылған",
        "row_empty": "Әзірге жарияланған аттестаттау жоқ.",
        "back_to_registry": "&larr; Аттестаттаулардың қоғамдық тізілімі",
        "lang_switch": "ҚАЗ | РУС | EN",
    },
    "ru": {
        "title": "Аттестация Proof-of-Savings",
        "registry_title": "Публичный реестр аттестаций",
        "registry_intro": "Аттестации, опубликованные участниками с их согласия. Каждая запись проверяется независимо.",
        "verdict_verified": "ПОДТВЕРЖДЕНО",
        "verdict_not_verified": "НЕ ПОДТВЕРЖДЕНО",
        "th_attestation": "Аттестация", "th_flow": "Флоу", "th_kind": "Тип",
        "th_verified": "Проверено", "th_savings": "Экономия", "th_issued": "Выдано",
        "row_empty": "Опубликованных аттестаций пока нет.",
        "back_to_registry": "&larr; Публичный реестр аттестаций",
        "lang_switch": "ҚАЗ | РУС | EN",
    },
}


def _portal_texts(lang: Optional[str]) -> dict[str, str]:
    key = (lang or "en").lower()
    return PORTAL_TEXTS.get(key, PORTAL_TEXTS["en"])


@app.get("/attestations/{registry_id}")
def attestation_portal(registry_id: str, lang: Optional[str] = Query(None)):
    """Human verification portal: verdict, claim, badge embed, JSON links.

    п.10: ?lang=kk|ru|en — статические надписи портала на трёх языках
    (Казахстан — суверенный якорь сети; данные записей не переводятся).
    """
    from fastapi.responses import HTMLResponse

    t = _portal_texts(lang)
    attestation = _build_attestation(registry_id)
    claim = attestation["claim"]
    verification = attestation["verification"]
    subject = attestation["subject"]

    sig_ok = bool(verification.get("receipt_signature_valid"))
    chain_ok = bool(verification.get("ledger_chain_valid"))
    verified = sig_ok and chain_ok and bool(claim.get("savings_verified"))

    verdict = t["verdict_verified"] if verified else t["verdict_not_verified"]
    verdict_color = "#2e7d32" if verified else "#c62828"
    mark = lambda ok: "&#10003;" if ok else "&#10007;"  # noqa: E731

    ratio = claim.get("savings_ratio")
    ratio_text = f"{ratio * 100:.1f}%" if isinstance(ratio, (int, float)) else "n/a"

    badge_snippet = (
        f'<img src="{_esc(registry_id)}/badge.svg" alt="Proof-of-Savings attestation" />'
    )

    page = f"""<!DOCTYPE html>
<html lang="{_esc(lang or 'en')}">
<head>
<meta charset="utf-8" />
<title>Attestation {_esc(registry_id)} — SIA Sentinel</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem auto; max-width: 720px; color: #1c2733; }}
  .verdict {{ font-size: 1.6rem; font-weight: 700; color: {verdict_color}; }}
  .card {{ border: 1px solid #d7dee6; border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; }}
  .ok {{ color: #2e7d32; }} .bad {{ color: #c62828; }}
  code, pre {{ background: #f4f6f8; padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; }}
  pre {{ padding: 0.75rem; overflow-x: auto; }}
  a {{ color: #1565c0; }}
  table {{ border-collapse: collapse; }} td, th {{ text-align: left; padding: 4px 12px 4px 0; }}
</style>
</head>
<body>
<h1>{_esc(t["title"])}</h1>
<p class="verdict">{verdict}</p>

<div class="card">
  <table>
    <tr><th>Attestation ID</th><td><code>{_esc(registry_id)}</code></td></tr>
    <tr><th>Issued</th><td>{_esc(attestation.get("issued_at"))}</td></tr>
    <tr><th>Flow</th><td>{_esc(subject.get("flow_name"))} ({_esc(subject.get("kind"))}, {_esc(subject.get("mode"))})</td></tr>
    <tr><th>Savings verified</th><td>{_esc(claim.get("savings_verified"))}</td></tr>
    <tr><th>Savings ratio</th><td>{ratio_text}</td></tr>
    <tr><th>Issuer</th><td>{_esc(attestation["issuer"]["name"])} — <code>{_esc(attestation["issuer"]["public_key"])}</code></td></tr>
  </table>
</div>

<div class="card">
  <h2>Verification</h2>
  <p><span class="{'ok' if sig_ok else 'bad'}">{mark(sig_ok)}</span> Receipt signature (Ed25519)</p>
  <p><span class="{'ok' if chain_ok else 'bad'}">{mark(chain_ok)}</span> TrustChain ledger ({verification.get("ledger_entries")} entries)</p>
  <p>Spec: <code>{_esc(attestation.get("spec"))}</code> · <a href="/v1/attestations/{_esc(registry_id)}">JSON</a> · <a href="/v1/attestations/{_esc(registry_id)}/badge.svg">badge.svg</a></p>
</div>

<div class="card">
  <h2>Embed badge</h2>
  <pre>{_esc(badge_snippet)}</pre>
</div>

<p><a href="/registry">{t["back_to_registry"]}</a></p>
</body>
</html>"""

    return HTMLResponse(content=page)


@app.get("/registry")
def public_registry_portal(
    limit: int = Query(50, ge=1, le=200),
    lang: Optional[str] = Query(None),
):
    """Public HTML index of opted-in attestations (п.10: ?lang=kk|ru|en)."""
    from fastapi.responses import HTMLResponse

    t = _portal_texts(lang)
    cards = receipt_registry.list_public(_is_tenant_published, limit=limit)

    rows = []

    for card in cards:
        ratio = card.get("savings_ratio")
        ratio_text = f"{ratio * 100:.1f}%" if isinstance(ratio, (int, float)) else "n/a"
        verified = "&#10003;" if card.get("savings_verified") else "&#10007;"
        rows.append(
            "<tr>"
            f'<td><a href="/attestations/{_esc(card["registry_id"])}"><code>{_esc(card["registry_id"][:12])}…</code></a></td>'
            f"<td>{_esc(card.get('flow_name'))}</td>"
            f"<td>{_esc(card.get('kind'))}</td>"
            f"<td>{verified}</td>"
            f"<td>{ratio_text}</td>"
            f"<td>{_esc(card.get('issued_at'))}</td>"
            "</tr>"
        )

    body = "".join(rows) or f'<tr><td colspan="6">{_esc(t["row_empty"])}</td></tr>'

    page = f"""<!DOCTYPE html>
<html lang="{_esc(lang or 'en')}">
<head>
<meta charset="utf-8" />
<title>{_esc(t["registry_title"])} — SIA Sentinel</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem auto; max-width: 860px; color: #1c2733; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid #d7dee6; }}
  a {{ color: #1565c0; }}
</style>
</head>
<body>
<h1>{_esc(t["registry_title"])}</h1>
<p>{_esc(t["registry_intro"])}</p>
<table>
<tr><th>{_esc(t["th_attestation"])}</th><th>{_esc(t["th_flow"])}</th><th>{_esc(t["th_kind"])}</th><th>{_esc(t["th_verified"])}</th><th>{_esc(t["th_savings"])}</th><th>{_esc(t["th_issued"])}</th></tr>
{body}
</table>
</body>
</html>"""

    return HTMLResponse(content=page)


# === Authentication API ===


class CreateAPIKeyRequest(PydanticBaseModel):
    name: str
    role: str = "user"
    expires_in_days: Optional[int] = None
    tenant_id: Optional[str] = None


class LoginRequest(PydanticBaseModel):
    username: str
    password: str


@app.post("/v1/auth/api-keys")
async def create_api_key(
    request: CreateAPIKeyRequest,
    user: User = Depends(require_platform_admin),
) -> dict[str, Any]:
    """
    Create new API key for any tenant (platform admin only).

    Tenant admins manage their own keys via /v1/tenants/{tenant_id}/api-keys.
    Returns plain key only once - store it securely!
    """
    try:
        role = UserRole(request.role)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role. Valid roles: {[r.value for r in UserRole]}"
        )

    plain_key, key_obj = api_key_manager.create_key(
        name=request.name,
        role=role,
        expires_in_days=request.expires_in_days,
        tenant_id=request.tenant_id or user.tenant_id,
    )

    return {
        "success": True,
        "api_key": plain_key,  # Plain key shown only once!
        "key_info": key_obj.to_dict(),
        "warning": "Store this key securely. It will not be shown again.",
    }


@app.get("/v1/auth/api-keys")
async def list_api_keys(
    user: User = Depends(require_platform_admin),
) -> dict[str, Any]:
    """List all API keys across tenants (platform admin only)."""
    keys = api_key_manager.list_keys()

    return {
        "count": len(keys),
        "keys": [k.to_dict() for k in keys],
    }


@app.delete("/v1/auth/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    user: User = Depends(require_platform_admin),
) -> dict[str, Any]:
    """Revoke any API key (platform admin only)."""
    success = api_key_manager.revoke_key(key_id)

    if not success:
        raise HTTPException(status_code=404, detail=f"Key not found: {key_id}")

    return {"success": True, "message": f"Key {key_id} revoked"}


@app.post("/v1/auth/login")
async def login(request: LoginRequest) -> dict[str, Any]:
    """
    Login with username/password (demo only).

    In production, use proper auth with hashed passwords.
    Disabled unless ENABLE_DEMO_LOGIN=1 — demo credentials must never
    ship enabled by default.
    """
    if os.getenv("ENABLE_DEMO_LOGIN", "").lower() not in ("1", "true", "yes"):
        raise HTTPException(
            status_code=403,
            detail="Demo login is disabled. Set ENABLE_DEMO_LOGIN=1 to enable (development only).",
        )

    # Demo credentials - in production use proper auth
    demo_users: dict[str, dict[str, Any]] = {
        "admin": {"password": "admin123", "role": UserRole.ADMIN},
        "verifier": {"password": "verifier123", "role": UserRole.VERIFIER},
        "user": {"password": "user123", "role": UserRole.USER},
    }

    if request.username not in demo_users:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_info = demo_users[request.username]
    if request.password != user_info["password"]:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate JWT token
    token = jwt_manager.create_token(
        user_id=f"user-{request.username}",
        username=request.username,
        role=user_info["role"],
        permissions=["verify:read", "verify:write"] if user_info["role"] != UserRole.ANONYMOUS else [],
        # Демо-админ — админ платформы: управляет всеми тенантами
        is_platform_admin=request.username == "admin",
    )

    return {
        "success": True,
        "access_token": token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRATION_HOURS * 3600,
        "user": {
            "username": request.username,
            "role": user_info["role"].value,
        },
    }


@app.get("/v1/auth/me")
async def get_current_user_info(
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Get current authenticated user info."""
    return {
        "user": user.to_dict(),
    }


@app.get("/v1/auth/protected")
async def protected_endpoint(
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Protected endpoint - requires authentication."""
    return {
        "message": f"Hello, {user.username}!",
        "role": user.role.value,
        "permissions": user.permissions,
    }


@app.get("/v1/auth/admin-only")
async def admin_only_endpoint(
    user: User = Depends(require_role(UserRole.ADMIN)),
) -> dict[str, Any]:
    """Admin-only endpoint."""
    return {
        "message": "Welcome, admin!",
        "user": user.to_dict(),
    }


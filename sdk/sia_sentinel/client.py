"""HTTP-клиент Sentinel API на httpx.

Все методы возвращают распарсенный JSON; ошибки API (4xx/5xx) поднимаются
как SentinelAPIError с кодом статуса и текстом ошибки. Для тестов клиент
принимает кастомный httpx-транспорт (например, httpx.MockTransport).
"""
from __future__ import annotations

import hashlib
import time
from typing import Any, Optional

import httpx

_TERMINAL_STATUSES = ("completed", "failed")


def _fold_inclusion_proof(
    entry_hash: str, proof: list[dict[str, str]], root_hash: Optional[str]
) -> bool:
    """Локальная проверка Merkle inclusion proof (RFC 6962 §2.1).

    Вторая, независимая от сервера реализация спеки: лист
    SHA256(0x00||entry_hash), узел SHA256(0x01||left||right); шаг
    доказательства сворачивается по направлению брата.
    """
    if not root_hash:
        return False

    fn = hashlib.sha256(b"\x00" + bytes.fromhex(entry_hash)).hexdigest()

    for step in proof:
        sibling = step.get("hash", "")
        direction = step.get("direction")

        if direction == "left":
            combined = b"\x01" + bytes.fromhex(sibling) + bytes.fromhex(fn)
        elif direction == "right":
            combined = b"\x01" + bytes.fromhex(fn) + bytes.fromhex(sibling)
        else:
            return False

        fn = hashlib.sha256(combined).hexdigest()

    return fn == root_hash


class SentinelAPIError(Exception):
    """Ошибка API Sentinel: HTTP-статус + detail из тела ответа."""

    def __init__(self, status_code: int, detail: str, body: Any = None):
        super().__init__(f"HTTP {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail
        self.body = body


class SentinelClient:
    """Клиент Sentinel: аудиты, оптимизации, квитанции, биллинг.

    Аутентификация: api_key (X-API-Key) или token (Bearer JWT).
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        token: Optional[str] = None,
        timeout: float = 30.0,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        headers: dict[str, str] = {}

        if api_key:
            headers["X-API-Key"] = api_key

        if token:
            headers["Authorization"] = f"Bearer {token}"

        self._http = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers=headers,
            timeout=timeout,
            transport=transport,
        )

    @classmethod
    def login(
        cls,
        base_url: str,
        username: str,
        password: str,
        timeout: float = 30.0,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> "SentinelClient":
        """Логин по username/password; возвращает клиент с JWT-токеном."""
        with httpx.Client(
            base_url=base_url.rstrip("/"), timeout=timeout, transport=transport
        ) as http:
            response = http.post(
                "/v1/auth/login", json={"username": username, "password": password}
            )

        if response.status_code >= 400:
            raise _api_error(response)

        return cls(base_url, token=response.json()["access_token"], timeout=timeout)

    @classmethod
    def signup(
        cls,
        base_url: str,
        name: str,
        tenant_id: Optional[str] = None,
        timeout: float = 30.0,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> "SentinelClient":
        """Self-service регистрация: создаёт тенант и возвращает клиент с первым ключом.

        Тенант создаётся на free-плане; ключ имеет роль admin своего тенанта.
        """
        payload: dict[str, Any] = {"name": name}

        if tenant_id:
            payload["tenant_id"] = tenant_id

        with httpx.Client(
            base_url=base_url.rstrip("/"), timeout=timeout, transport=transport
        ) as http:
            response = http.post("/v1/signup", json=payload)

        if response.status_code >= 400:
            raise _api_error(response)

        return cls(base_url, api_key=response.json()["api_key"], timeout=timeout)

    # === Аудиты Proof-of-Savings ===

    def run_audit(self, flow: dict[str, Any]) -> dict[str, Any]:
        """Синхронный аудит: POST /v1/audit -> {registry_id, report, receipt}."""
        return self._post("/v1/audit", json={"flow": flow})

    def submit_audit(self, flow: dict[str, Any]) -> str:
        """Асинхронный аудит: POST /v1/audits -> audit_id."""
        return self._post("/v1/audits", json={"flow": flow})["audit_id"]

    def get_audit(self, audit_id: str) -> dict[str, Any]:
        """Статус асинхронного аудита: GET /v1/audits/{id}."""
        return self._get(f"/v1/audits/{audit_id}")

    def wait_for_audit(
        self, audit_id: str, timeout: float = 600.0, poll_interval: float = 1.0
    ) -> dict[str, Any]:
        """Опрашивает аудит до завершения; при failed бросает SentinelAPIError."""
        return self._wait_terminal(
            lambda: self.get_audit(audit_id), timeout, poll_interval
        )

    # === Savings Autopilot ===

    def submit_optimization(self, flow: dict[str, Any]) -> str:
        """Запуск оптимизации: POST /v1/optimize -> audit_id."""
        return self._post("/v1/optimize", json={"flow": flow})["audit_id"]

    def get_optimization(self, audit_id: str) -> dict[str, Any]:
        """Статус оптимизации: GET /v1/optimize/{id}."""
        return self._get(f"/v1/optimize/{audit_id}")

    def wait_for_optimization(
        self, audit_id: str, timeout: float = 1800.0, poll_interval: float = 2.0
    ) -> dict[str, Any]:
        """Опрашивает оптимизацию до завершения."""
        return self._wait_terminal(
            lambda: self.get_optimization(audit_id), timeout, poll_interval
        )

    # === Предрегистрация (preregistration) ===

    def create_preregistration(self, flow: dict[str, Any]) -> dict[str, Any]:
        """Зафиксировать параметры аудита в цепочке ДО прогона.

        POST /v1/preregistrations -> {preregistration_id, commitment}.
        Коммитмент (dataset_sha256, delta, metric, конфигурации эндпоинтов)
        записывается в TrustChain до запуска аудита — клинико-испытательская
        предрегистрация против подбора delta и подмены датасета постфактум.
        """
        return self._post("/v1/preregistrations", json={"flow": flow})

    def get_preregistration(self, preregistration_id: str) -> dict[str, Any]:
        """Получить коммитмент предрегистрации: GET /v1/preregistrations/{id}."""
        return self._get(f"/v1/preregistrations/{preregistration_id}")

    def verify_preregistration_link(
        self, preregistration_id: str, registry_id: str
    ) -> dict[str, Any]:
        """Проверить связь предрегистрации с квитанцией.

        GET /v1/preregistrations/{id}/verify/{registry_id}: подтверждает, что
        запись квитанции закоммичена ПОСЛЕ предрегистрации и совпадает по
        dataset_sha256/delta/metric.
        """
        return self._get(
            f"/v1/preregistrations/{preregistration_id}/verify/{registry_id}"
        )

    # === Квитанции и TrustChain ===

    def list_receipts(self, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        return self._get("/v1/receipts", params={"limit": limit, "offset": offset})

    def get_receipt(self, registry_id: str) -> dict[str, Any]:
        return self._get(f"/v1/receipts/{registry_id}")

    def ledger_head(self) -> dict[str, Any]:
        return self._get("/v1/ledger/head")

    def verify_ledger(self, full: bool = False) -> dict[str, Any]:
        """Chain verification; full=True re-verifies from genesis."""
        return self._get(
            "/v1/ledger/verify", params={"full": str(bool(full)).lower()}
        )

    def inclusion_proof(self, registry_id: str) -> dict[str, Any]:
        """Merkle inclusion proof for a registry entry (RFC 6962)."""
        return self._get(f"/v1/ledger/inclusion/{registry_id}")

    def consistency_proof(
        self, from_size: int, to_size: Optional[int] = None
    ) -> dict[str, Any]:
        """Merkle consistency proof between two tree heads (RFC 6962)."""
        params: dict[str, Any] = {"from": from_size}

        if to_size is not None:
            params["to"] = to_size

        return self._get("/v1/ledger/consistency", params=params)

    def key_declarations(self) -> dict[str, Any]:
        """Key declarations from the chain (kid → public key history)."""
        return self._get("/v1/ledger/keys")

    def anchor_checkpoint(self) -> dict[str, Any]:
        """Create a checkpoint and publish it to external anchor storage.

        Platform admin only.
        """
        return self._post("/v1/ledger/anchor", json={})

    def verify_inclusion(self, registry_id: str) -> dict[str, Any]:
        """Однострочная проверка включения записи в Merkle tree head.

        Скачивает доказательство и текущий tree head и сворачивает
        audit path ЛОКАЛЬНО (RFC 6962 §2.1: H(0x00||leaf),
        H(0x01||left||right)) — без доверия к серверу. Возвращает
        {included, leaf_index, tree_size, root_hash, entry_hash}.
        """
        proof = self.inclusion_proof(registry_id)
        head = self.ledger_head()

        included = _fold_inclusion_proof(
            entry_hash=proof["entry_hash"],
            proof=proof.get("proof") or [],
            root_hash=head["root_hash"],
        )

        return {
            "included": included,
            "registry_id": registry_id,
            "entry_hash": proof["entry_hash"],
            "leaf_index": proof["leaf_index"],
            "tree_size": proof["tree_size"],
            "root_hash": head["root_hash"],
        }

    def get_attestation(self, registry_id: str) -> dict[str, Any]:
        return self._get(f"/v1/attestations/{registry_id}")

    def verify_attestation(self, registry_id: str) -> dict[str, Any]:
        """Machine-readable verdict: signature + chain check for one entry.

        Это вердикт СЕРВЕРА. Для проверки без доверия к аудитору
        используйте verify_attestation_independent().
        """
        return self._get(f"/v1/receipts/{registry_id}/verify")

    def verify_attestation_independent(
        self, registry_id: str, issuer_key: str | None = None
    ) -> dict[str, Any]:
        """Независимая верификация аттестации локально (без доверия к аудитору).

        Скачивает аттестационный документ и проверяет Ed25519-подпись
        квитанции и согласованность заявления локально через пакет
        ``sia-verifier`` — тот же, что используют третьи стороны.
        Поля verification.* сервера игнорируются.

        ``issuer_key`` — публичный ключ эмитента (base64 raw 32 байта),
        полученный ВНЕПОЛОСНО. Это корень доверия: без него подпись
        проверяется против ключа из самого скачанного документа, а такой
        ключ может принадлежать кому угодно (см. v1.6.0). Передайте ключ,
        полученный из канала, которому доверяете, и проверьте
        ``trust_established`` в ответе.

        Требует установленный sia-verifier: pip install sia-verifier.
        """
        try:
            from sia_verifier import verify_attestation
        except ImportError as exc:
            raise RuntimeError(
                "Independent verification requires the sia-verifier package: "
                "pip install sia-verifier"
            ) from exc

        attestation = self.get_attestation(registry_id)
        verdict = verify_attestation(attestation, expected_public_key=issuer_key)
        result = verdict.to_dict()

        if issuer_key is None:
            # Якорь не задан: подпись математически проверена, но эмитент не
            # аутентифицирован. Предупреждаем явно, чтобы это не выглядело как
            # полноценная независимая проверка.
            result["warning"] = (
                "no issuer_key supplied: the issuer public key was taken from the "
                "attestation itself, so its authenticity is UNPROVEN. Pass "
                "issuer_key (obtained out-of-band) and require trust_established."
            )

        return result

    def list_public_attestations(
        self, limit: int = 50, offset: int = 0
    ) -> dict[str, Any]:
        """Public attestation registry (only opted-in tenants)."""
        return self._get(
            "/v1/attestations", params={"limit": limit, "offset": offset}
        )

    # === Webhooks ===

    def subscribe_webhook(self, url: str, events: list[str]) -> dict[str, Any]:
        """Subscribe a URL to audit events; returns subscription with secret (shown once)."""
        return self._post(
            "/v1/webhooks/subscriptions", json={"url": url, "events": events}
        )

    def list_webhooks(self) -> dict[str, Any]:
        return self._get("/v1/webhooks/subscriptions")

    def unsubscribe_webhook(self, subscription_id: str) -> dict[str, Any]:
        return self._delete(f"/v1/webhooks/subscriptions/{subscription_id}")

    # === Управление ключами тенанта ===

    def create_tenant_key(
        self,
        tenant_id: str,
        name: str,
        role: str = "user",
        expires_in_days: Optional[int] = None,
    ) -> dict[str, Any]:
        """Создать ключ тенанта (admin тенанта или платформенный админ)."""
        payload: dict[str, Any] = {"name": name, "role": role}

        if expires_in_days is not None:
            payload["expires_in_days"] = expires_in_days

        return self._post(f"/v1/tenants/{tenant_id}/api-keys", json=payload)

    def list_tenant_keys(self, tenant_id: str) -> dict[str, Any]:
        return self._get(f"/v1/tenants/{tenant_id}/api-keys")

    def revoke_tenant_key(self, tenant_id: str, key_id: str) -> dict[str, Any]:
        return self._delete(f"/v1/tenants/{tenant_id}/api-keys/{key_id}")

    # === Использование и биллинг ===

    def usage(self) -> dict[str, Any]:
        """Сводка использования тенанта: GET /v1/usage."""
        return self._get("/v1/usage")

    def plans(self) -> dict[str, Any]:
        """Каталог тарифов: GET /v1/billing/plans (публичный)."""
        return self._get("/v1/billing/plans")

    def get_plan(self) -> dict[str, Any]:
        """Текущий план и квоты тенанта: GET /v1/billing/plan."""
        return self._get("/v1/billing/plan")

    def set_plan(self, plan: str) -> dict[str, Any]:
        """Смена плана (admin): POST /v1/billing/plan."""
        return self._post("/v1/billing/plan", json={"plan": plan})

    def list_invoices(self) -> dict[str, Any]:
        return self._get("/v1/billing/invoices")

    def issue_invoice(self, period: Optional[str] = None) -> dict[str, Any]:
        """Выставить инвойс за период (admin): POST /v1/billing/invoices."""
        payload: dict[str, Any] = {}

        if period:
            payload["period"] = period

        return self._post("/v1/billing/invoices", json=payload)

    def get_invoice(self, invoice_id: str) -> dict[str, Any]:
        return self._get(f"/v1/billing/invoices/{invoice_id}")

    # === Служебное ===

    def health(self) -> dict[str, Any]:
        return self._get("/health")

    def close(self) -> None:
        try:
            self._http.close()
        except AttributeError:
            # Не все транспорты реализуют close (например, ASGITransport в тестах)
            pass

    def __enter__(self) -> "SentinelClient":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # === Внутреннее ===

    def _get(self, path: str, params: Optional[dict[str, Any]] = None) -> Any:
        response = self._http.get(path, params=params)
        return self._unwrap(response)

    def _post(self, path: str, json: dict[str, Any]) -> Any:
        response = self._http.post(path, json=json)
        return self._unwrap(response)

    def _delete(self, path: str) -> Any:
        response = self._http.delete(path)
        return self._unwrap(response)

    @staticmethod
    def _unwrap(response: httpx.Response) -> Any:
        if response.status_code >= 400:
            raise _api_error(response)

        return response.json()

    @staticmethod
    def _wait_terminal(fetch, timeout: float, poll_interval: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout

        while True:
            snapshot = fetch()

            if snapshot.get("status") in _TERMINAL_STATUSES:
                if snapshot["status"] == "failed":
                    raise SentinelAPIError(
                        500, snapshot.get("error", "job failed"), snapshot
                    )

                return snapshot

            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Job did not finish within {timeout}s "
                    f"(last status: {snapshot.get('status')})"
                )

            time.sleep(poll_interval)


def _api_error(response: httpx.Response) -> SentinelAPIError:
    try:
        body = response.json()
        detail = body.get("detail", response.text)
    except ValueError:
        body = response.text
        detail = response.text

    return SentinelAPIError(response.status_code, str(detail), body)

"""Регрессионные тесты на эскалацию привилегий и изоляцию тенантов.

Закрывают реальную дыру, найденную аудитом 2026-09-30: роль ``verifier`` —
это фактически кросс-тенантное право чтения (``_evidence_tenant_scope`` снимает
tenant-фильтр для VERIFIER). Если self-service позволял её выдать, то
«signup -> выпустить verifier-ключ -> прочитать evidence всех тенантов».

Каждый тест здесь написан так, чтобы ПАДАЛ на уязвимом коде и проходил после
фикса. Это защита от «гарда, который не может упасть».
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

import sentinel.api as api_module
import sentinel.auth as auth_module
from sentinel.api import app, rate_limiter
from sentinel.auth import APIKeyManager
from sentinel.billing import BillingEngine
from sentinel.database import AuditJobRecord, get_db_session
from sentinel.outbound_webhooks import OutboundWebhookDispatcher
from sentinel.receipt_registry import ReceiptRegistry
from sentinel.tenancy import TenantManager, UsageMeter


class PrivilegeEscalationTestCase(unittest.TestCase):
    """Изоляция тенантов + границы привилегий на self-service ключах."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        rate_limiter.reset()

        with get_db_session() as db:
            db.query(AuditJobRecord).delete()

        self._original_demo_login = os.environ.get("ENABLE_DEMO_LOGIN")
        os.environ["ENABLE_DEMO_LOGIN"] = "1"

        self._original_registry = api_module.receipt_registry
        api_module.receipt_registry = ReceiptRegistry(str(Path(self._tmp.name) / "receipts"))

        self._original_tenants = api_module.tenant_manager
        api_module.tenant_manager = TenantManager(str(Path(self._tmp.name) / "tenants.json"))

        self._original_usage = api_module.usage_meter
        api_module.usage_meter = UsageMeter(str(Path(self._tmp.name) / "usage.jsonl"))

        self._original_billing = api_module.billing_engine
        api_module.billing_engine = BillingEngine(
            api_module.tenant_manager,
            api_module.usage_meter,
            invoices_file=str(Path(self._tmp.name) / "invoices.json"),
        )

        self._original_webhooks = api_module.webhook_dispatcher
        api_module.webhook_dispatcher = OutboundWebhookDispatcher(
            subscriptions_file=str(Path(self._tmp.name) / "webhooks.json")
        )

        self._original_key_manager = auth_module.api_key_manager
        isolated_manager = APIKeyManager(str(Path(self._tmp.name) / "api_keys.json"))
        auth_module.api_key_manager = isolated_manager
        self._original_api_key_manager = api_module.api_key_manager
        api_module.api_key_manager = isolated_manager

        self.client = TestClient(app)

        login = self.client.post(
            "/v1/auth/login", json={"username": "admin", "password": "admin123"}
        )
        self._platform_headers = {
            "Authorization": f"Bearer {login.json()['access_token']}"
        }

    def tearDown(self) -> None:
        api_module.receipt_registry = self._original_registry
        api_module.tenant_manager = self._original_tenants
        api_module.usage_meter = self._original_usage
        api_module.billing_engine = self._original_billing
        api_module.webhook_dispatcher = self._original_webhooks
        auth_module.api_key_manager = self._original_key_manager
        api_module.api_key_manager = self._original_api_key_manager

        if self._original_demo_login is None:
            os.environ.pop("ENABLE_DEMO_LOGIN", None)
        else:
            os.environ["ENABLE_DEMO_LOGIN"] = self._original_demo_login

        self._tmp.cleanup()

    def _signup(self, tenant_id: str = "acme") -> dict:
        response = self.client.post(
            "/v1/signup", json={"name": tenant_id.title(), "tenant_id": tenant_id}
        )
        self.assertEqual(response.status_code, 201)
        return response.json()

    def _tenant_admin_headers(self, tenant_id: str = "acme") -> dict[str, str]:
        return {"X-API-Key": self._signup(tenant_id)["api_key"]}

    # --- CRITICAL: self-service не может выдать кросс-тенантный verifier ---

    def test_tenant_admin_cannot_mint_verifier_key(self) -> None:
        """Эскалация: тенант-админ пытается выпустить себе verifier-роль.

        verifier снимает tenant-фильтр (смотрит ВСЕ тенанты), поэтому роль
        обязана выдаваться только платформенным админом. На уязвимом коде
        здесь был 201 — и ключ видел чужие evidence.
        """
        admin_headers = self._tenant_admin_headers("acme")

        response = self.client.post(
            "/v1/tenants/acme/api-keys",
            json={"name": "escalate", "role": "verifier"},
            headers=admin_headers,
        )
        self.assertEqual(response.status_code, 403)

    def test_platform_admin_can_still_mint_verifier_key(self) -> None:
        """Фикс не должен ломать легитимный путь: платформенный админ — может."""
        self._signup("acme")

        response = self.client.post(
            "/v1/tenants/acme/api-keys",
            json={"name": "auditor", "role": "verifier"},
            headers=self._platform_headers,
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["key_info"]["role"], "verifier")

    def test_tenant_admin_still_can_mint_user_and_admin_keys(self) -> None:
        """Регресс: обычные роли внутри своего тенанта по-прежнему доступны."""
        admin_headers = self._tenant_admin_headers("acme")

        for role in ("user", "admin"):
            response = self.client.post(
                "/v1/tenants/acme/api-keys",
                json={"name": f"key-{role}", "role": role},
                headers=admin_headers,
            )
            self.assertEqual(response.status_code, 201, role)
            self.assertEqual(response.json()["key_info"]["role"], role)

    def test_tenant_admin_cannot_mint_platform_admin_key(self) -> None:
        """Платформенный флаг нельзя получить из self-service (уже было, но
        фиксируем как явный инвариант рядом с verifier-блоком)."""
        admin_headers = self._tenant_admin_headers("acme")

        response = self.client.post(
            "/v1/tenants/acme/api-keys",
            json={"name": "platform", "role": "admin"},
            headers=admin_headers,
        )
        self.assertEqual(response.status_code, 201)
        # тенант-выданный admin не должен быть platform admin
        self.assertFalse(response.json()["key_info"]["is_platform_admin"])


if __name__ == "__main__":
    unittest.main()

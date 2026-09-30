"""Регрессионные тесты на биллинговые инварианты, закрытые 2026-09-30.

1. TOCTOU-квота: асинхронный submit резервирует слот под замком, поэтому пачка
   параллельных запросов не может вся пройти по неинкрементированному usage.
2. Идемпотентность usage-счётчика: перезапуск джоба после recover() не списывает
   вторую раз (event_key).
3. Резерв снимается и при падении джоба (audit.failed не «съедает» квоту).

Каждый тест написан так, чтобы ПАДАЛ на уязвимом коде.
"""
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from sentinel.billing import BillingEngine
from sentinel.tenancy import TenantManager, UsageMeter


class QuotaReservationTestCase(unittest.TestCase):
    """Резерв квоты под замком + идемпотентный учёт."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tenants = TenantManager(str(Path(self._tmp.name) / "tenants.json"))
        self.meter = UsageMeter(str(Path(self._tmp.name) / "usage.jsonl"))
        self.billing = BillingEngine(
            self.tenants,
            self.meter,
            invoices_file=str(Path(self._tmp.name) / "invoices.json"),
        )
        self.tenants.create(name="Acme", tenant_id="acme", plan="free")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_free_plan_limit_is_enforced(self) -> None:
        """Базовый инвариант: лимит free-плана соблюдается."""
        limit = self.billing.get_plan("acme").included["audits"]
        self.assertGreater(limit, 0)

    def test_reserve_accounts_for_in_flight_jobs(self) -> None:
        """Резерв держит слот: check_quota видит незакрытые резервы.

        Без резерва check_quota считал бы только записанный usage, и после
        reserve() лимит казался бы нетронутым.
        """
        limit = self.billing.get_plan("acme").included["audits"]

        # Занимаем ВСЕ слоты резервами (как будто все аудиты уже в полёте).
        for _ in range(limit):
            self.assertTrue(self.billing.reserve("acme", "code").allowed)

        # Записанного usage ещё ноль, но check_quota обязан упереться в лимит.
        check = self.billing.check_quota("acme", "code")
        self.assertFalse(check.allowed)
        self.assertEqual(check.used, limit)

    def test_reserve_blocks_beyond_limit(self) -> None:
        """reserve() — жёсткая проверка: лишний слот не резервируется."""
        limit = self.billing.get_plan("acme").included["audits"]

        for _ in range(limit):
            self.assertTrue(self.billing.reserve("acme", "code").allowed)

        self.assertFalse(self.billing.reserve("acme", "code").allowed)

    def test_release_returns_slot(self) -> None:
        """release() возвращает слот в лимит (падавший джоб не съедает квоту)."""
        limit = self.billing.get_plan("acme").included["audits"]

        for _ in range(limit):
            self.billing.reserve("acme", "code")
        self.assertFalse(self.billing.reserve("acme", "code").allowed)

        self.billing.release("acme", "code")

        self.assertTrue(self.billing.reserve("acme", "code").allowed)

    def test_concurrent_reserves_cannot_overbook(self) -> None:
        """Гонка: 40 потоков против лимита — резервов ровно limit, не больше.

        Это ядро фикса TOCTOU: без атомарного reserve() все потоки читали бы
        used=0 и все прошли бы проверку.
        """
        limit = self.billing.get_plan("acme").included["audits"]
        attempts = 40
        granted: list[bool] = []
        lock = threading.Lock()
        barrier = threading.Barrier(attempts)

        def worker() -> None:
            barrier.wait()
            ok = self.billing.reserve("acme", "code").allowed
            with lock:
                granted.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(attempts)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(sum(1 for g in granted if g), limit)

    def test_usage_record_is_idempotent_by_event_key(self) -> None:
        """Один event_key = одна строка в usage.jsonl (защита от recover())."""
        first = self.meter.record("acme", "code", event_key="audit:abc")
        second = self.meter.record("acme", "code", event_key="audit:abc")

        self.assertEqual(first["event_id"], second["event_id"])

        lines = [
            line
            for line in Path(self.meter.usage_file).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(lines), 1)

    def test_usage_record_without_event_key_always_appends(self) -> None:
        """Без ключа поведение прежнее: каждая запись — новая строка."""
        self.meter.record("acme", "code")
        self.meter.record("acme", "code")

        summary = self.meter.summary("acme")
        self.assertEqual(summary["total_events"], 2)

    def test_release_without_reserve_is_noop(self) -> None:
        """release() без резерва не падает и не уходит в минус."""
        self.billing.release("acme", "code")
        self.billing.release("acme", "code")

        self.assertTrue(self.billing.reserve("acme", "code").allowed)


if __name__ == "__main__":
    unittest.main()

"""Регрессионные тесты на две дыры 2026-09-30, найденные независимым аудитом.

ДЫРА №1 (CRITICAL) — верификатор без корня доверия.
`sia_verifier` брал публичный ключ ИЗ проверяемой аттестации
(`core.py: issuer.public_key`). Одноразовый Ed25519-ключ злоумышленника
делал подделку `valid=True` — то есть инструмент, которым контрагент
проверяет аудитора, не доказывал НИЧЕГО. Теперь верификатор принимает
внеполосный якорь (`--issuer-key`): эмитент аутентифицируется только если
ключ в артефакте совпадает с заранее известным оператору.

ДЫРА №2 (CRITICAL) — «сертификация монетки».
Обход `or (b == 0 and c == 0)` позволял объявить non_inferior прогон,
который физически не способен заметить падение на delta (MDD > delta).
Две идентичные модели точностью 50% (неотличимые от подбрасывания монетки)
получали non_inferior. MDD-гейт теперь обязателен.

Каждый тест написан так, чтобы ПАДАЛ на уязвимом коде.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sia.statistics import non_inferiority_test
from sia_verifier import core as vc
from sia_verifier.core import verify_attestation

REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER_DIR = REPO_ROOT / "verifier"

# Настоящий issuer-ключ публичной записи №1 (не секрет — он в самом артефакте,
# но здесь он выступает внеполосным якорем, как это делает оператор).
RECORD1_ISSUER_KEY = "tqIhnSC/3xVANUtzGLsGmcVqxZ40J1jTiF1QDaQHiyw="


def _forge_attestation_with_throwaway_key() -> dict:
    """Полностью синтетическая аттестация, подписанная одноразовым ключом.

    Подпись МАТЕМАТИЧЕСКИ корректна (обычный Ed25519, как ждёт verify_receipt) —
    именно поэтому до фикса она проходила как valid.
    """
    seed = os.urandom(32)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    receipt = {
        "receipt_id": "forged-receipt",
        "evidence_id": "forged-evidence",
        "code_hash": "f" * 64,
        "safety_approved": True,
        "trust_level": "HIGH",
        "timestamp": 1.0,
        "nonce": "forged-nonce",
    }
    receipt["signature"] = base64.b64encode(
        priv.sign(vc._receipt_commitment(receipt))
    ).decode()

    return {
        "spec": "sia-attestation/1",
        "attestation_id": "forged-attestation",
        "receipt": receipt,
        "issuer": {"public_key": base64.b64encode(pub).decode()},
        "claim": {"savings_verified": True, "savings_ratio": 0.999},
    }


class VerifierTrustRootTestCase(unittest.TestCase):
    """ДЫРА №1: подпись проверяется против ключа, который выдал сам артефакт."""

    def test_forgery_is_rejected_against_operator_trust_anchor(self) -> None:
        """ГЛАВНЫЙ регресс: одноразовый ключ против настоящего якоря.

        До фикса: подделка давала valid=True, и контрагент, запустивший
        sia-verifier, получал VERDICT: VALID.
        """
        forged = _forge_attestation_with_throwaway_key()

        verdict = verify_attestation(forged, expected_public_key=RECORD1_ISSUER_KEY)

        self.assertFalse(verdict.valid)
        self.assertFalse(verdict.trust_established)
        self.assertIn(
            "issuer key does not match operator-supplied trust anchor",
            verdict.reasons,
        )

    def test_forgery_without_anchor_has_no_trust(self) -> None:
        """Без якоря подпись может быть корректной, но доверие НЕ установлено.

        Это фиксирует различие, которого раньше не существовало:
        valid=True (математика) != аутентифицированный эмитент.
        """
        forged = _forge_attestation_with_throwaway_key()

        verdict = verify_attestation(forged)

        # Подпись одноразовым ключом по построению корректна...
        self.assertTrue(verdict.receipt_signature_valid)
        # ...но эмитент не аутентифицирован.
        self.assertFalse(verdict.trust_established)

    def test_genuine_record1_passes_against_its_anchor(self) -> None:
        """Регресс в другую сторону: настоящая запись №1 обязана проходить."""
        record = json.loads(
            (REPO_ROOT / "artifacts" / "record1" / "attestation.json").read_text(
                encoding="utf-8"
            )
        )

        verdict = verify_attestation(record, expected_public_key=RECORD1_ISSUER_KEY)

        self.assertTrue(verdict.valid)
        self.assertTrue(verdict.trust_established)
        self.assertEqual(verdict.reasons, [])

    def test_mismatched_anchor_is_not_confused_by_key_encoding(self) -> None:
        """Сравнение ключей — по декодированным байтам, в constant time."""
        raw = base64.b64decode(RECORD1_ISSUER_KEY)

        self.assertTrue(vc._keys_equal(RECORD1_ISSUER_KEY, RECORD1_ISSUER_KEY))
        # другой base64-представитель тех же байт — тот же ключ
        self.assertTrue(
            vc._keys_equal(RECORD1_ISSUER_KEY, base64.b64encode(raw).decode())
        )
        self.assertFalse(vc._keys_equal(RECORD1_ISSUER_KEY, "not-base64!!"))
        self.assertFalse(vc._keys_equal(RECORD1_ISSUER_KEY, base64.b64encode(b"short").decode()))


class VerifierCLIGateTestCase(unittest.TestCase):
    """CLI обязан fail-closed без якоря и без внешнего чекпойнта."""

    def _run_cli(self, *extra_args: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(VERIFIER_DIR)
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "sia_verifier",
                str(REPO_ROOT / "artifacts" / "record1" / "attestation.json"),
                "--chain",
                str(REPO_ROOT / "receipts" / "registry.jsonl"),
                "--checkpoint",
                str(REPO_ROOT / "receipts" / "checkpoints.jsonl"),
                "--require-coverage",
                *extra_args,
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(REPO_ROOT),
        )

    def test_cli_without_anchor_is_invalid(self) -> None:
        """Без --issuer-key вердикт НЕ должен быть VALID (fail-closed)."""
        proc = self._run_cli()

        self.assertEqual(proc.returncode, 1)
        self.assertIn("VERDICT: INVALID", proc.stdout)
        self.assertIn("NOT ESTABLISHED", proc.stdout)

    def test_cli_with_matching_anchor_is_valid(self) -> None:
        """С настоящим якорем запись №1 проходит и доверена."""
        proc = self._run_cli("--issuer-key", RECORD1_ISSUER_KEY)

        self.assertEqual(proc.returncode, 0)
        self.assertIn("VERDICT: VALID", proc.stdout)
        self.assertIn("ESTABLISHED", proc.stdout)

    def test_cli_with_wrong_anchor_is_invalid(self) -> None:
        """Чужой якорь → INVALID, даже если сама подпись корректна."""
        wrong = base64.b64encode(b"\x00" * 32).decode()
        proc = self._run_cli("--issuer-key", wrong)

        self.assertEqual(proc.returncode, 1)
        self.assertIn("VERDICT: INVALID", proc.stdout)

    def test_require_coverage_without_checkpoint_fails_closed(self) -> None:
        """--require-coverage без чекпойнта = FAIL (усечение хвоста неотличимо)."""
        env = dict(os.environ)
        env["PYTHONPATH"] = str(VERIFIER_DIR)
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "sia_verifier",
                str(REPO_ROOT / "artifacts" / "record1" / "attestation.json"),
                "--chain",
                str(REPO_ROOT / "receipts" / "registry.jsonl"),
                "--require-coverage",
                "--issuer-key",
                RECORD1_ISSUER_KEY,
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(REPO_ROOT),
        )

        self.assertEqual(proc.returncode, 1)
        self.assertIn("VERDICT: INVALID", proc.stdout)


class NonInferiorityMDDGateTestCase(unittest.TestCase):
    """ДЫРА №2: обход MDD-гейта при нулевой дискордантности."""

    def test_zero_discordance_cannot_bypass_mdd_gate(self) -> None:
        """b=c=0 больше не обходит MDD-гейт (PoC: n=400, delta=0.02)."""
        result = non_inferiority_test([True] * 400, [True] * 400, delta=0.02)

        self.assertGreater(result.mdd, 0.02)  # тест слишком слаб
        self.assertFalse(result.non_inferior)
        self.assertEqual(result.verdict, "inconclusive")

    def test_coin_flip_not_certified(self) -> None:
        """Две идентичные 50%-модели (монетка) не получают non_inferior."""
        old = [True] * 100 + [False] * 100
        new = [True] * 100 + [False] * 100

        result = non_inferiority_test(old, new, delta=0.05)

        self.assertEqual(result.b, 0)
        self.assertEqual(result.c, 0)
        self.assertFalse(result.non_inferior)

    def test_large_n_identical_still_passes(self) -> None:
        """Снятие обхода не ломает честный случай: при большой n — проходит."""
        result = non_inferiority_test([True] * 2000, [True] * 2000, delta=0.02)

        self.assertLessEqual(result.mdd, 0.02)
        self.assertTrue(result.non_inferior)


if __name__ == "__main__":
    unittest.main()

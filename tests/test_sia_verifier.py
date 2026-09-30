"""Тесты независимого верификатора sia-verifier.

Ключевое свойство: верификатор принимает квитанции, созданные Sentinel
(источник истины), и отвергает любые подделки — без импорта кода
Sentinel в сам пакет.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Пакет верификатора лежит в verifier/ — добавляем в sys.path для тестов
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "verifier"))

from sia_verifier import (
    ATTESTATION_SPEC,
    verify_attestation,
    verify_chain,
    verify_checkpoint,
    verify_receipt,
)
from sia_verifier.__main__ import main as verifier_main

from sentinel.cryptographic_receipts import ReceiptGenerator
from sentinel.receipt_registry import ReceiptRegistry


def _build_attestation(entry: dict, public_key: str) -> dict:
    """Собирает аттестационный документ так же, как sentinel/api.py."""
    metadata = entry.get("metadata", {})
    return {
        "schema_version": "1",
        "spec": ATTESTATION_SPEC,
        "attestation_id": entry.get("registry_id"),
        "issued_at": entry.get("registered_at"),
        "issuer": {
            "name": "SIA Sentinel",
            "public_key": public_key,
            "algorithm": "Ed25519-SHA256",
        },
        "subject": {
            "flow_name": metadata.get("flow_name"),
            "kind": metadata.get("kind"),
            "mode": metadata.get("mode"),
        },
        "claim": {
            "savings_verified": metadata.get("savings_verified"),
            "savings_ratio": metadata.get("savings_ratio"),
        },
        "receipt": entry.get("receipt"),
        "verification": {
            "receipt_signature_valid": True,
            "ledger_chain_valid": True,
            "ledger_entries": 1,
        },
    }


class SiaVerifierTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.generator = ReceiptGenerator("verifier-test-key")
        self.public_key = self.generator.get_public_key()
        self.registry = ReceiptRegistry(str(Path(self._tmp.name) / "receipts"))

        receipt = self.generator.generate_receipt(
            evidence_id="audit-self-flow",
            code='{"report": "stub"}',
            safety_approved=True,
            trust_level="JUNIOR",
            manifest={"dataset_sha256": "a" * 64, "repetitions": 2},
        )
        self.registry_id = self.registry.register(
            receipt,
            metadata={
                "tenant_id": "sia",
                "flow_name": "self-flow",
                "kind": "llm_flow",
                "mode": "live",
                "savings_verified": True,
                "savings_ratio": 0.95,
            },
        )
        self.entry = self.registry.get(self.registry_id)
        self.attestation = _build_attestation(self.entry, self.public_key)

        # Якорь доверия для CLI-тестов (2026-09-30): CLI fail-closed без
        # --issuer-key, поэтому тесты, ожидающие VALID, передают тот же ключ,
        # которым подписана их собственная аттестация.
        self._anchor = ["--issuer-key", self.public_key]

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # === Подпись квитанции ===

    def test_real_sentinel_receipt_verifies(self) -> None:
        verdict = verify_attestation(self.attestation)

        self.assertTrue(verdict.valid, verdict.reasons)
        self.assertTrue(verdict.receipt_signature_valid)
        self.assertTrue(verdict.claim_consistent)
        self.assertTrue(verdict.spec_recognized)

    def test_verify_receipt_direct(self) -> None:
        self.assertTrue(verify_receipt(self.entry["receipt"], self.public_key))

    def test_tampered_receipt_rejected(self) -> None:
        forged = json.loads(json.dumps(self.attestation))
        forged["receipt"]["safety_approved"] = False

        verdict = verify_attestation(forged)

        self.assertFalse(verdict.valid)
        self.assertFalse(verdict.receipt_signature_valid)

    def test_receipt_id_swap_rejected(self) -> None:
        forged = json.loads(json.dumps(self.attestation))
        forged["receipt"]["receipt_id"] = "f" * 64

        self.assertFalse(verify_attestation(forged).valid)

    def test_manifest_tamper_rejected(self) -> None:
        forged = json.loads(json.dumps(self.attestation))
        forged["receipt"]["manifest"]["repetitions"] = 99

        self.assertFalse(verify_attestation(forged).valid)

    def test_wrong_public_key_rejected(self) -> None:
        other = ReceiptGenerator("another-key").get_public_key()
        forged = json.loads(json.dumps(self.attestation))
        forged["issuer"]["public_key"] = other

        verdict = verify_attestation(forged)

        self.assertFalse(verdict.valid)
        self.assertFalse(verdict.receipt_signature_valid)

    def test_seed_material_as_public_key_rejected(self) -> None:
        forged = json.loads(json.dumps(self.attestation))
        forged["issuer"]["public_key"] = "verifier-test-key"

        self.assertFalse(verify_attestation(forged).valid)

    # === Согласованность заявления ===

    def test_claim_mismatch_rejected(self) -> None:
        forged = json.loads(json.dumps(self.attestation))
        forged["claim"]["savings_verified"] = False

        verdict = verify_attestation(forged)

        self.assertFalse(verdict.valid)
        self.assertFalse(verdict.claim_consistent)

    def test_unknown_spec_rejected(self) -> None:
        forged = json.loads(json.dumps(self.attestation))
        forged["spec"] = "sia-attestation/99"

        verdict = verify_attestation(forged)

        self.assertFalse(verdict.valid)
        self.assertFalse(verdict.spec_recognized)

    def test_missing_receipt_rejected(self) -> None:
        forged = json.loads(json.dumps(self.attestation))
        forged.pop("receipt")

        self.assertFalse(verify_attestation(forged).valid)

    # === Хеш-цепочка ===

    def _export_chain(self) -> list[dict]:
        return self.registry._load_entries()

    def test_chain_verifies(self) -> None:
        verdict = verify_chain(self._export_chain(), attestation_id=self.registry_id)

        self.assertTrue(verdict.valid)
        self.assertEqual(verdict.entries, 1)
        self.assertTrue(verdict.contains_attestation)

    def test_chain_tamper_detected(self) -> None:
        entries = self._export_chain()
        entries[0]["receipt"]["manifest"]["repetitions"] = 99

        verdict = verify_chain(entries)

        self.assertFalse(verdict.valid)
        self.assertEqual(verdict.broken_at, 1)

    def test_chain_reorder_detected(self) -> None:
        self.registry.register(
            self.generator.generate_receipt(
                evidence_id="audit-second",
                code="x",
                safety_approved=True,
                trust_level="JUNIOR",
            )
        )
        entries = self._export_chain()
        entries.reverse()

        verdict = verify_chain(entries)

        self.assertFalse(verdict.valid)

    def test_chain_missing_attestation_flagged(self) -> None:
        verdict = verify_chain(self._export_chain(), attestation_id="nonexistent")

        self.assertTrue(verdict.valid)
        self.assertFalse(verdict.contains_attestation)

    # === Чекпоинты ===

    def test_checkpoint_verifies(self) -> None:
        checkpoint = self.registry.create_checkpoint(self.generator)

        self.assertTrue(verify_checkpoint(checkpoint, self.public_key))

    def test_checkpoint_tamper_rejected(self) -> None:
        checkpoint = self.registry.create_checkpoint(self.generator)
        checkpoint["head_hash"] = "f" * 64

        self.assertFalse(verify_checkpoint(checkpoint, self.public_key))

    # === CLI ===

    def test_cli_valid_exit_zero(self) -> None:
        att_path = Path(self._tmp.name) / "attestation.json"
        att_path.write_text(json.dumps(self.attestation), encoding="utf-8")

        self.assertEqual(verifier_main([str(att_path), *self._anchor]), 0)

    def test_cli_invalid_exit_one(self) -> None:
        forged = json.loads(json.dumps(self.attestation))
        forged["receipt"]["safety_approved"] = False
        att_path = Path(self._tmp.name) / "forged.json"
        att_path.write_text(json.dumps(forged), encoding="utf-8")

        self.assertEqual(verifier_main([str(att_path)]), 1)

    def test_cli_with_chain(self) -> None:
        att_path = Path(self._tmp.name) / "attestation.json"
        att_path.write_text(json.dumps(self.attestation), encoding="utf-8")
        chain_path = Path(self._tmp.name) / "registry.jsonl"
        chain_path.write_text(
            "\n".join(json.dumps(e) for e in self._export_chain()) + "\n",
            encoding="utf-8",
        )

        self.assertEqual(verifier_main([str(att_path), "--chain", str(chain_path), *self._anchor]), 0)

    def test_cli_missing_file_exit_two(self) -> None:
        self.assertEqual(verifier_main(["/nonexistent/attestation.json"]), 2)

    def test_cli_checkpoint_jsonl_journal_all_checked(self) -> None:
        self.registry.create_checkpoint(self.generator)
        self.registry.create_checkpoint(self.generator)
        att_path = Path(self._tmp.name) / "attestation.json"
        att_path.write_text(json.dumps(self.attestation), encoding="utf-8")

        self.assertEqual(
            verifier_main([
                str(att_path), "--checkpoint", str(self.registry.checkpoint_file),
                *self._anchor,
            ]),
            0,
        )

    def test_cli_checkpoint_jsonl_forged_snapshot_rejected(self) -> None:
        # Журнал не слабее своего худшего элемента: подмена ПЕРВОГО снимка
        # при валидном последнем обязана ронять вердикт всего файла.
        self.registry.create_checkpoint(self.generator)
        self.registry.create_checkpoint(self.generator)
        lines = self.registry.checkpoint_file.read_text(encoding="utf-8").splitlines()
        forged_first = json.loads(lines[0])
        forged_first["head_hash"] = "f" * 64
        self.registry.checkpoint_file.write_text(
            json.dumps(forged_first) + "\n" + lines[1] + "\n", encoding="utf-8"
        )
        att_path = Path(self._tmp.name) / "attestation.json"
        att_path.write_text(json.dumps(self.attestation), encoding="utf-8")

        self.assertEqual(
            verifier_main([
                str(att_path), "--checkpoint", str(self.registry.checkpoint_file),
            ]),
            1,
        )

    def test_cli_checkpoint_pretty_json_single_object(self) -> None:
        checkpoint = self.registry.create_checkpoint(self.generator)
        att_path = Path(self._tmp.name) / "attestation.json"
        att_path.write_text(json.dumps(self.attestation), encoding="utf-8")
        cp_path = Path(self._tmp.name) / "cp_pretty.json"
        # Pretty-printed многострочный одиночный JSON — прежний формат,
        # документированный в доке; обязан продолжать приниматься.
        cp_path.write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")

        self.assertEqual(
            verifier_main([str(att_path), "--checkpoint", str(cp_path), *self._anchor]),
            0,
        )

    def test_cli_coverage_lag_is_advisory_by_default(self) -> None:
        # Лаг покрытия = 1 (голова seq=2, чекпойнт seq=1): по умолчанию
        # вердикт VALID + видимый advisory — молчаливый VALID при
        # непокрытой голове был реальной дырой наблюдаемости.
        self.registry.register(
            self.generator.generate_receipt(
                evidence_id="audit-second", code="y",
                safety_approved=True, trust_level="JUNIOR",
            )
        )
        # журнал с чекпойнтом seq=1: берём снапшот до второй записи нельзя,
        # поэтому подписываем ГОВОРЯЩИЙ чекпойнт на старой голове: создаём
        # чекпойнт СЕЙЧАС (seq=2), затем регистрируем третью запись —
        # лаг появится у ПОСЛЕДНЕЙ головы.
        self.registry.create_checkpoint(self.generator)
        self.registry.register(
            self.generator.generate_receipt(
                evidence_id="audit-third", code="z",
                safety_approved=True, trust_level="JUNIOR",
            )
        )
        att_path = Path(self._tmp.name) / "attestation.json"
        att_path.write_text(json.dumps(self.attestation), encoding="utf-8")
        chain_path = Path(self._tmp.name) / "registry.jsonl"
        entries = self.registry._load_entries()  # noqa: SLF001
        chain_path.write_text(
            "\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8"
        )

        self.assertEqual(
            verifier_main([
                str(att_path), "--chain", str(chain_path),
                "--checkpoint", str(self.registry.checkpoint_file),
                *self._anchor,
            ]),
            0,
        )

    def test_cli_require_coverage_gate_fails_on_lag(self) -> None:
        # Тот же лаг, но с --require-coverage: вердикт INVALID, exit 1 —
        # ворота для прод-крона и ритуала «запись закрыта».
        self.registry.create_checkpoint(self.generator)
        self.registry.register(
            self.generator.generate_receipt(
                evidence_id="audit-second", code="y",
                safety_approved=True, trust_level="JUNIOR",
            )
        )
        att_path = Path(self._tmp.name) / "attestation.json"
        att_path.write_text(json.dumps(self.attestation), encoding="utf-8")
        chain_path = Path(self._tmp.name) / "registry.jsonl"
        entries = self.registry._load_entries()  # noqa: SLF001
        chain_path.write_text(
            "\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8"
        )

        self.assertEqual(
            verifier_main([
                str(att_path), "--chain", str(chain_path),
                "--checkpoint", str(self.registry.checkpoint_file),
                "--require-coverage",
            ]),
            1,
        )

    def test_cli_checkpoint_bom_prefixed_journal(self) -> None:
        # PowerShell `>`-редирект и notepad пишут UTF-8 BOM; соседние
        # инструменты пакета читают utf-8-sig — CLI не должен выделяться
        # отказом там, где rederive/replay/holdout работают.
        self.registry.create_checkpoint(self.generator)
        att_path = Path(self._tmp.name) / "attestation.json"
        att_path.write_text(json.dumps(self.attestation), encoding="utf-8")
        cp_path = Path(self._tmp.name) / "cp_bom.jsonl"
        cp_path.write_bytes(
            b"\xef\xbb\xbf" + self.registry.checkpoint_file.read_bytes()
        )

        self.assertEqual(
            verifier_main([str(att_path), "--checkpoint", str(cp_path), *self._anchor]),
            0,
        )

    def test_cli_attestation_bom_prefixed(self) -> None:
        att_path = Path(self._tmp.name) / "attestation_bom.json"
        att_path.write_bytes(
            b"\xef\xbb\xbf" + json.dumps(self.attestation).encode("utf-8")
        )

        self.assertEqual(verifier_main([str(att_path), *self._anchor]), 0)


if __name__ == "__main__":
    unittest.main()

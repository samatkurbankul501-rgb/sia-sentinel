"""Ядро независимой верификации стандарта ``sia-attestation/1``.

Реализация намеренно автономна: она повторяет правила построения
коммитментов и хеш-цепочки из спецификации, а не импортирует код
Sentinel, чтобы третья сторона могла проверить аттестацию, не доверяя
аудитору и не запуская его сервер.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ATTESTATION_SPEC = "sia-attestation/1"
GENESIS_HASH = "0" * 64
CHECKPOINT_PROTOCOL = "trustchain-checkpoint/1"
# v2: подпись чекпоинта покрывает и Merkle tree head (C1)
CHECKPOINT_PROTOCOL_V2 = "trustchain-checkpoint/2"
KNOWN_CHECKPOINT_PROTOCOLS = (CHECKPOINT_PROTOCOL, CHECKPOINT_PROTOCOL_V2)

# RFC 6962 §2.1: префиксы доменной сепарации хешей
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _canonical_json(value: dict[str, Any]) -> bytes:
    """Каноническая сериализация коммитмента (spec §2.1)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _load_public_key(value: str) -> Ed25519PublicKey:
    """Строгая загрузка публичного ключа: только base64 raw 32 байта.

    Сид-материал и любые другие форматы отклоняются — иначе секрет
    подписи, переданный вместо публичного ключа, был бы молча принят.
    """
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(
            "issuer.public_key must be a base64-encoded raw 32-byte Ed25519 public key"
        ) from exc

    if len(raw) != 32:
        raise ValueError(f"issuer.public_key must decode to exactly 32 bytes, got {len(raw)}")

    return Ed25519PublicKey.from_public_bytes(raw)


def _keys_equal(presented_b64: str, expected_b64: str) -> bool:
    """Строгое сравнение base64-ключей в постоянном времени.

    Сравниваются ДЕКОДИРОВАННЫЕ байты, а не текст: это снимает расхождения
    кодирования (одинаковый ключ, разный base64-представление) и даёт
    constant-time семантику через hmac.compare_digest. Если оба значения
    не декодируются как 32-байтовый raw Ed25519-ключ, сравнение даёт False —
    «мусор» не приравнивается к ключу.
    """
    try:
        presented = base64.b64decode(presented_b64, validate=True)
        expected = base64.b64decode(expected_b64, validate=True)
    except Exception:
        return False

    if len(presented) != 32 or len(expected) != 32:
        return False

    return hmac.compare_digest(presented, expected)


def _receipt_commitment(receipt: dict[str, Any]) -> bytes:
    """Коммитмент квитанции, покрытый подписью (spec §2.1).

    ``receipt_id`` входит в коммитмент: подпись нельзя перенести с одной
    квитанции на другую. C3: ``kid`` входит, когда задан (квитанции,
    выпущенные после введения ротации ключей).
    """
    commitment: dict[str, Any] = {
        "receipt_id": receipt.get("receipt_id"),
        "evidence_id": receipt.get("evidence_id"),
        "code_hash": receipt.get("code_hash"),
        "safety_approved": receipt.get("safety_approved"),
        "trust_level": receipt.get("trust_level"),
        "timestamp": receipt.get("timestamp"),
        "nonce": receipt.get("nonce"),
    }

    if receipt.get("manifest") is not None:
        commitment["manifest"] = receipt["manifest"]

    if receipt.get("kid") is not None:
        commitment["kid"] = receipt["kid"]

    return _canonical_json(commitment)


def verify_receipt(receipt: dict[str, Any], public_key_b64: str) -> bool:
    """Проверяет Ed25519-подпись квитанции публичным ключом.

    Возвращает True только при валидной подписи; любые ошибки формата
    дают False (вердикт, а не исключение).
    """
    try:
        public_key = _load_public_key(public_key_b64)
        signature = base64.b64decode(receipt.get("signature", ""), validate=True)
        public_key.verify(signature, _receipt_commitment(receipt))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


@dataclass
class AttestationVerdict:
    """Результат независимой проверки аттестации.

    ``trust_established`` (2026-09-30): подпись действительна САМА ПО СЕБЕ
    недостаточна — без операторского якоря доверия эмитент не аутентифицирован
    (одноразовый ключ даёт валидную подпись). Это поле делает различие
    явным: valid=True + trust_established=False означает «подпись корректна,
    но кто её выпустил — не доказано».
    """

    valid: bool
    receipt_signature_valid: bool
    claim_consistent: bool
    spec_recognized: bool
    trust_established: bool = False
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "receipt_signature_valid": self.receipt_signature_valid,
            "claim_consistent": self.claim_consistent,
            "spec_recognized": self.spec_recognized,
            "trust_established": self.trust_established,
            "reasons": list(self.reasons),
        }


def verify_attestation(
    attestation: dict[str, Any],
    expected_public_key: Optional[str] = None,
) -> AttestationVerdict:
    """Независимая проверка аттестационного документа.

    Проверяет подпись квитанции публичным ключом и согласованность
    заявления с подписанным полем ``safety_approved``. Поля ``verification.*``
    сервера намеренно игнорируются — они не входят в подписанный коммитмент и
    не являются доказательством.

    Корень доверия (2026-09-30): если передан ``expected_public_key``
    (внеполосный, заранее известный оператору публичный ключ эмитента), ключ в
    артефакте обязан совпасть с ним — и только тогда доверие установлено
    (``trust_established=True``). Без якоря проверка self-referential: подпись
    корректна, но эмитент не аутентифицирован (одноразовый ключ злоумышленника
    дал бы ``valid=True``).
    """
    reasons: list[str] = []

    spec = attestation.get("spec")
    spec_recognized = spec == ATTESTATION_SPEC
    if not spec_recognized:
        reasons.append(f"unrecognized spec: {spec!r} (expected {ATTESTATION_SPEC!r})")

    issuer = attestation.get("issuer") or {}
    public_key_b64 = issuer.get("public_key", "")
    trust_established = False
    trust_anchor_failed = False

    if expected_public_key is not None:
        if _keys_equal(public_key_b64, expected_public_key):
            trust_established = True
        else:
            reasons.append("issuer key does not match operator-supplied trust anchor")
            # Якорь задан, но не совпал: эмитент не тот, за кого себя выдаёт.
            # Подпись может быть математически корректной (одноразовый ключ
            # злоумышленника), но аутентификация эмитента провалена — вердикт
            # обязан быть False, а не просто сопровождаться причиной.
            trust_anchor_failed = True

    receipt = attestation.get("receipt")
    if not isinstance(receipt, dict):
        reasons.append("missing or malformed receipt")
        return AttestationVerdict(
            valid=False,
            receipt_signature_valid=False,
            claim_consistent=False,
            spec_recognized=spec_recognized,
            trust_established=trust_established,
            reasons=reasons,
        )

    signature_valid = verify_receipt(receipt, public_key_b64)
    if not signature_valid:
        reasons.append("receipt signature invalid for issuer.public_key")

    claim = attestation.get("claim") or {}
    claim_consistent = receipt.get("safety_approved") == claim.get("savings_verified")
    if not claim_consistent:
        reasons.append(
            "claim.savings_verified does not match signed receipt.safety_approved"
        )

    valid = (
        signature_valid
        and claim_consistent
        and spec_recognized
        and not trust_anchor_failed
    )

    return AttestationVerdict(
        valid=valid,
        receipt_signature_valid=signature_valid,
        claim_consistent=claim_consistent,
        spec_recognized=spec_recognized,
        trust_established=trust_established,
        reasons=reasons,
    )


def _entry_hash(seq: int, prev_hash: str, entry: dict[str, Any]) -> str:
    """Детерминированный хеш записи цепочки (spec §3)."""
    payload = {
        "seq": seq,
        "prev_hash": prev_hash,
        "registry_id": entry.get("registry_id"),
        "registered_at": entry.get("registered_at"),
        "receipt": entry.get("receipt"),
        "metadata": entry.get("metadata"),
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


@dataclass
class ChainVerdict:
    """Результат проверки хеш-цепочки TrustChain."""

    valid: bool
    entries: int
    legacy_entries: int
    broken_at: Optional[int]
    reason: Optional[str]
    contains_attestation: Optional[bool] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "entries": self.entries,
            "legacy_entries": self.legacy_entries,
            "broken_at": self.broken_at,
            "reason": self.reason,
            "contains_attestation": self.contains_attestation,
        }


def verify_chain(
    entries: list[dict[str, Any]],
    attestation_id: Optional[str] = None,
) -> ChainVerdict:
    """Проверяет выгрузку журнала TrustChain (append-only JSONL).

    ``entries`` — список записей в порядке журнала. Если задан
    ``attestation_id``, дополнительно проверяется, что запись с таким
    ``registry_id`` присутствует в цепочке.
    """
    expected_prev = GENESIS_HASH
    legacy_entries = 0
    found = attestation_id is None

    for position, entry in enumerate(entries, start=1):
        if attestation_id is not None and entry.get("registry_id") == attestation_id:
            found = True

        stored_hash = entry.get("entry_hash")

        if stored_hash:
            if entry.get("prev_hash") != expected_prev:
                return ChainVerdict(
                    valid=False,
                    entries=len(entries),
                    legacy_entries=legacy_entries,
                    broken_at=position,
                    reason="prev_hash mismatch (record removed, inserted or reordered)",
                    contains_attestation=found if found else None,
                )

            recomputed = _entry_hash(position, expected_prev, entry)

            if recomputed != stored_hash:
                return ChainVerdict(
                    valid=False,
                    entries=len(entries),
                    legacy_entries=legacy_entries,
                    broken_at=position,
                    reason="entry_hash mismatch (record content tampered)",
                    contains_attestation=found if found else None,
                )

            expected_prev = stored_hash
        else:
            legacy_entries += 1
            expected_prev = _entry_hash(position, expected_prev, entry)

    return ChainVerdict(
        valid=True,
        entries=len(entries),
        legacy_entries=legacy_entries,
        broken_at=None,
        reason=None,
        contains_attestation=found,
    )


def _checkpoint_commitment(checkpoint: dict[str, Any]) -> bytes:
    """Детерминированные байты, покрытые подписью чекпоинта (spec §3).

    v2 включает tree_size/root_hash в коммитмент; v1 — нет.
    """
    commitment = {
        "protocol": checkpoint.get("protocol"),
        "checkpoint_id": checkpoint.get("checkpoint_id"),
        "created_at": checkpoint.get("created_at"),
        "seq": checkpoint.get("seq"),
        "head_hash": checkpoint.get("head_hash"),
        "registry_id": checkpoint.get("registry_id"),
    }

    if checkpoint.get("protocol") == CHECKPOINT_PROTOCOL_V2:
        commitment["tree_size"] = checkpoint.get("tree_size")
        commitment["root_hash"] = checkpoint.get("root_hash")

        if checkpoint.get("kid") is not None:
            commitment["kid"] = checkpoint.get("kid")

    return _canonical_json(commitment)


def verify_checkpoint(checkpoint: dict[str, Any], public_key_b64: str) -> bool:
    """Проверяет подпись чекпоинта публичным ключом (v1 и v2)."""
    signature = checkpoint.get("signature")

    if not signature or checkpoint.get("protocol") not in KNOWN_CHECKPOINT_PROTOCOLS:
        return False

    try:
        public_key = _load_public_key(public_key_b64)
        public_key.verify(base64.b64decode(signature, validate=True), _checkpoint_commitment(checkpoint))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# === Ротация ключей (C3) ===


def verify_key_declarations(
    declarations: list[dict[str, Any]],
) -> tuple[bool, dict[str, str]]:
    """Восстанавливает таблицу kid → публичный ключ из деклараций цепочки.

    Каждая декларация — {declaration: {kid, public_key, ...}, signature,
    signer_kid}. Подпись покрывает канонический JSON декларации и ставится
    АКТИВНЫМ на момент записи ключом (signer_kid):

    - генезис-декларация подписана самим декларируемым ключом (self-signed);
    - при ротации новый ключ декларируется записью, подписанной старым
      (ещё активным) ключом, уже объявленным ранее в цепочке.

    Возвращает (все_подписи_валидны, {kid: public_key}). При первой же
    невалидной подписи или неизвестном signer_kid останавливается и
    возвращает False с таблицей, построенной до точки отказа.
    """
    keys: dict[str, str] = {}

    for record in declarations:
        declaration = record.get("declaration") or {}
        kid = declaration.get("kid")
        public_key_b64 = declaration.get("public_key")
        signature = record.get("signature")
        signer_kid = record.get("signer_kid")

        if not kid or not public_key_b64 or not signature:
            return False, keys

        # Публичный ключ подписанта: сам декларируемый ключ (генезис) либо
        # ранее объявленный ключ (ротация)
        signer_key_b64 = keys.get(str(signer_kid))

        if signer_key_b64 is None:
            if signer_kid == kid:
                signer_key_b64 = public_key_b64  # self-signed генезис
            else:
                return False, keys  # подписант не объявлен в цепочке

        try:
            signer_key = _load_public_key(signer_key_b64)
            signer_key.verify(
                base64.b64decode(signature, validate=True),
                _canonical_json(declaration),
            )
        except (InvalidSignature, ValueError, TypeError):
            return False, keys

        keys[kid] = public_key_b64

    return True, keys


def resolve_receipt_key(
    receipt: dict[str, Any],
    declarations: list[dict[str, Any]],
    fallback_public_key: Optional[str] = None,
) -> Optional[str]:
    """Публичный ключ для проверки квитанции с учётом ротации (C3).

    Если у квитанции есть ``kid``, ключ берётся из деклараций цепочки.
    Иначе (legacy-квитанция без kid) используется ``fallback_public_key``.
    """
    kid = receipt.get("kid")

    if kid is None:
        return fallback_public_key

    _, keys = verify_key_declarations(declarations)
    return keys.get(kid)


# === Merkle-доказательства (C1, RFC 6962) ===


def leaf_hash(entry_hash: str) -> str:
    """Хеш листа Merkle-дерева из entry_hash записи цепочки."""
    return hashlib.sha256(LEAF_PREFIX + bytes.fromhex(entry_hash)).hexdigest()


def _node_hash(left: str, right: str) -> str:
    return hashlib.sha256(
        NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right)
    ).hexdigest()


def verify_inclusion(
    entry_hash: str,
    leaf_index: int,
    tree_size: int,
    root_hash: str,
    proof: list[dict[str, str]],
) -> bool:
    """Проверяет inclusion proof записи в tree head (RFC 6962 §2.1.1).

    proof — список {"hash", "direction"} от листа к корню; direction —
    сторона брата ("left"|"right").
    """
    if leaf_index < 0 or tree_size <= 0 or leaf_index >= tree_size:
        return False

    fn = leaf_hash(entry_hash)

    for step in proof:
        sibling = step.get("hash", "")
        direction = step.get("direction")

        if direction == "left":
            fn = _node_hash(sibling, fn)
        elif direction == "right":
            fn = _node_hash(fn, sibling)
        else:
            return False

    return fn == root_hash


def _largest_power_of_two_less_than(n: int) -> int:
    k = 1

    while k * 2 < n:
        k *= 2

    return k


def verify_consistency(
    old_size: int,
    old_root: Optional[str],
    new_size: int,
    new_root: str,
    proof: list[str],
) -> bool:
    """Проверяет consistency proof между двумя tree heads (RFC 6962 §2.1.2).

    Рекурсивно восстанавливает оба корня из SUBPROOF и сверяет их.
    """
    if old_size < 0 or new_size < old_size:
        return False

    if old_size == 0:
        return True

    if old_size == new_size:
        return len(proof) == 0 and old_root == new_root

    if old_root is None:
        return False

    pos = 0

    def rec(start: int, end: int, old_count: int, complete: bool) -> tuple[str, str]:
        nonlocal pos
        n = end - start

        if old_count == n:
            if complete:
                return old_root, old_root  # type: ignore[return-value]

            if pos >= len(proof):
                raise ValueError("proof too short")

            h = proof[pos]
            pos += 1
            return h, h

        k = _largest_power_of_two_less_than(n)

        if old_count <= k:
            left_new, left_old = rec(start, start + k, old_count, complete)

            if pos >= len(proof):
                raise ValueError("proof too short")

            right = proof[pos]
            pos += 1
            return _node_hash(left_new, right), left_old

        right_new, right_old = rec(start + k, end, old_count - k, False)

        if pos >= len(proof):
            raise ValueError("proof too short")

        left = proof[pos]
        pos += 1
        return _node_hash(left, right_new), _node_hash(left, right_old)

    try:
        new_h, old_h = rec(0, new_size, old_size, True)
    except ValueError:
        return False

    return pos == len(proof) and new_h == new_root and old_h == old_root

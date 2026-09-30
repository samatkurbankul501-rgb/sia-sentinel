"""sia-verifier — независимый верификатор аттестаций Proof-of-Savings.

Минимальный пакет (только `cryptography` + stdlib), который проверяет
аттестации стандарта ``sia-attestation/1`` **без доверия к аудитору**:
нужен только сам документ аттестации и (опционально) выгрузка журнала
TrustChain. Никаких сетевых вызовов, никакого SDK Sentinel.

Что проверяется:

1. **Подпись квитанции** — Ed25519 (RFC 8032) над каноническим JSON
   коммитмента, восстановленного из полей квитанции (включая
   ``receipt_id``). Публичный ключ берётся из ``issuer.public_key``
   аттестации, но **аутентифицируется внеполосным якорем**: если оператор
   передал ``expected_public_key`` / ``--issuer-key``, ключ в документе
   обязан совпасть, и только тогда ``trust_established=True``. Без якоря
   проверка self-referential (одноразовый ключ дал бы валидную подделку),
   поэтому CLI с 1.6.0 fail-closed. Ключ принимается только в виде base64
   raw 32 байт.
2. **Согласованность заявления** — ``receipt.safety_approved`` должен
   совпадать с ``claim.savings_verified``: подпись покрывает именно
   ``safety_approved``, поэтому расхождение означает подделку заявления.
3. **Хеш-цепочка TrustChain** (опционально, по выгрузке журнала) —
   каждая запись пересчитывается из ``seq``, ``prev_hash`` и содержимого;
   удаление, вставка, перестановка или подмена записи ломают цепочку.
4. **Чекпоинты** — подписанные коммитменты на голову цепочки (v1) и на
   голову цепочки + Merkle tree head (v2).
5. **Merkle-доказательства** (RFC 6962) — ``verify_inclusion`` проверяет
   включение записи в tree head, ``verify_consistency`` — что дерево
   размера N является продолжением дерева размера M.

CLI (v1.6.0)::

    sia-verifier attestation.json --issuer-key <BASE64_PUBKEY> \
        [--chain registry.jsonl] [--checkpoint cp.json] [--require-coverage]
    sia-rederive  [--artifacts DIR] [--flow F] [--chain C] [--no-rekor]
    sia-replay    --flow F --record report1.json --replay report2.json
    sia-holdout   make|reveal|verify ...

Первая команда проверяет подпись/цепь/чекпоинт; вторая перевыводит сам
вердикт записи (формулы считаются локально, входы пришиты к подписи через
receipt.code_hash); третья исполняет задекларированный допуск
replay_tolerance — сравнение записи с независимым повторным прогоном
(Б2: односторонний допуск «к заявлению»); четвёртая — инструмент
внешнего аудитора holdout (п.8).
Все три доступны и как ``python -m sia_verifier.<module>``.

Программа и API возвращают вердикт; ненулевой код выхода при
невалидной аттестации позволяет встраивать проверку в CI.
"""
from __future__ import annotations

from .core import (
    ATTESTATION_SPEC,
    AttestationVerdict,
    ChainVerdict,
    leaf_hash,
    resolve_receipt_key,
    verify_attestation,
    verify_chain,
    verify_checkpoint,
    verify_consistency,
    verify_inclusion,
    verify_key_declarations,
    verify_receipt,
)

__version__ = "1.6.0"

__all__ = [
    "ATTESTATION_SPEC",
    "AttestationVerdict",
    "ChainVerdict",
    "leaf_hash",
    "resolve_receipt_key",
    "verify_attestation",
    "verify_chain",
    "verify_checkpoint",
    "verify_consistency",
    "verify_inclusion",
    "verify_key_declarations",
    "verify_receipt",
    "__version__",
]

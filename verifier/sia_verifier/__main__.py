"""CLI независимого верификатора аттестаций Proof-of-Savings.

Примеры::

    # Проверить аттестацию из файла (документ GET /v1/attestations/{id})
    # --issuer-key: внеполосный якорь доверия (ключ эмитента, известный
    # оператору ЗАРАНЕЕ). Без него вердикт fail-closed — см. ниже.
    python -m sia_verifier attestation.json --issuer-key <BASE64_PUBKEY>

    # Проверить аттестацию + хеш-цепочку журнала
    python -m sia_verifier attestation.json --chain registry.jsonl \
        --issuer-key <BASE64_PUBKEY>

    # Проверить подпись чекпойнта (одиночный JSON или JSONL-журнал
    # снимков — проверяются ВСЕ строки, не только последняя); с --chain
    # рядом печатается лаг покрытия: записи цепи сверх последнего
    # чекпойнта неопровержимы цепью, но не зафиксированы подписанным
    # чекпойнтом — это надо видеть, а не угадывать (запись №2 прожила
    # 6 дней в таком состоянии молча).
    python -m sia_verifier attestation.json --chain registry.jsonl \
        --checkpoint checkpoint.jsonl --require-coverage \
        --issuer-key <BASE64_PUBKEY>

Корень доверия (начиная с 1.6.0): подпись квитанции проверяется против
ключа, который оператор передал внеполосно (--issuer-key), а не против
ключа из самого проверяемого документа. Без якоря вердикт не может быть
VALID (fail-closed) — иначе одноразовый ключ злоумышленника дал бы
«валидную» подделку. --allow-self-declared-key возвращает нестрогий
режим (только для отладки; печатается issuer trust: NOT ESTABLISHED).

Код выхода: 0 — аттестация валидна, 1 — невалидна, 2 — ошибка ввода.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .core import verify_attestation, verify_chain, verify_checkpoint


def _load_json(path: Path) -> Any:
    # utf-8-sig: PowerShell `>`-редирект и notepad пишут BOM; соседние
    # инструменты пакета (rederive/replay/holdout) уже BOM-толерантны, и
    # файлы постороннего проходят тот же путь.
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    entries = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line:
            entries.append(json.loads(line))
    return entries


def _load_checkpoints(path: Path) -> list[dict[str, Any]]:
    """Чекпойнт-файл: одиночный JSON-объект или JSONL-журнал снимков.

    Журнал (registry пишет по строке-снимку на каждый чекпойнт) проверяется
    ЦЕЛИКОМ: подпись каждого снимка должна сойтись. Валидность только
    последнего снимка означала бы, что подписанную фиксацию середины
    истории можно подменить безнаказанно — журнал не слабее своего
    худшего элемента.
    """
    text = path.read_text(encoding="utf-8-sig")

    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        loaded = None

    if isinstance(loaded, dict):
        return [loaded]

    if isinstance(loaded, list):
        entries = loaded
    else:
        entries = _load_jsonl(path)

    if not entries or not all(isinstance(entry, dict) for entry in entries):
        raise ValueError("checkpoint file must contain JSON checkpoint object(s)")

    return entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sia-verifier",
        description="Independent verifier for sia-attestation/1 Proof-of-Savings attestations.",
    )
    parser.add_argument(
        "attestation",
        type=Path,
        help="Path to the attestation document JSON (GET /v1/attestations/{id})",
    )
    parser.add_argument(
        "--chain",
        type=Path,
        default=None,
        help="Optional TrustChain ledger export (registry.jsonl) to verify the hash chain",
    )
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=None,
        help="Optional checkpoint JSON or JSONL journal of snapshots to verify against the issuer public key",
    )
    parser.add_argument(
        "--require-coverage",
        action="store_true",
        help=(
            "Treat checkpoint coverage as a gate: the chain head must not "
            "extend beyond the latest signed checkpoint. Without the flag "
            "a lag is reported as an advisory (the chain legitimately grows "
            "between scheduled checkpoints); with it, an uncovered head "
            "fails the verdict. For production cron and 'record closed' "
            "rituals."
        ),
    )
    parser.add_argument(
        "--issuer-key",
        type=str,
        default=None,
        help=(
            "TRUST ANCHOR: base64 raw 32-byte Ed25519 public key of the issuer, "
            "obtained out-of-band (not from the attestation itself). When given, "
            "the attestation's issuer key MUST match it, otherwise the verdict "
            "fails. This is what makes verification independent of the auditee: "
            "without an anchor the signature is checked against a key the "
            "document itself supplies, so anyone can mint a 'valid' attestation "
            "with a throwaway key. Strongly recommended."
        ),
    )
    parser.add_argument(
        "--allow-self-declared-key",
        action="store_true",
        help=(
            "Permit a verdict of VALID when no --issuer-key is supplied (the "
            "signature is checked against the attestation's own self-declared key). "
            "The output still flags trust as NOT established. For debugging and "
            "for the author's own first-run; NOT for a counterparty."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the verdict as JSON instead of human-readable text",
    )

    args = parser.parse_args(argv)

    try:
        attestation = _load_json(args.attestation)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read attestation file: {exc}", file=sys.stderr)
        return 2

    verdict = verify_attestation(attestation, expected_public_key=args.issuer_key)
    result: dict[str, Any] = {"attestation": verdict.to_dict()}

    self_declared_key = (attestation.get("issuer") or {}).get("public_key", "")
    # Чекпойнты проверяем ЯКОРНЫМ ключом, если он задан; иначе — тем же
    # самообъявленным (режим отладки). При заданном якоре подпись чекпойнта
    # одноразовым ключом злоумышленника уже не пройдёт.
    issuer_key = args.issuer_key or self_declared_key
    attestation_id = attestation.get("attestation_id")

    if args.chain is not None:
        try:
            entries = _load_jsonl(args.chain)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read chain file: {exc}", file=sys.stderr)
            return 2

        chain_verdict = verify_chain(entries, attestation_id=attestation_id)
        result["chain"] = chain_verdict.to_dict()

    if args.checkpoint is not None:
        try:
            checkpoints = _load_checkpoints(args.checkpoint)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"error: cannot read checkpoint file: {exc}", file=sys.stderr)
            return 2

        checked = [verify_checkpoint(cp, issuer_key) for cp in checkpoints]
        result["checkpoint_valid"] = all(checked)
        result["checkpoint_count"] = len(checked)
        # Максимальный подписанный seq среди ПРОВЕРЕННЫХ снимков: покрытие
        # измеряется валидными фиксациями, а не количеством строк.
        result["checkpoint_max_seq"] = max(
            (int(cp.get("seq") or 0) for cp in checkpoints), default=0
        )

    # Лаг покрытия: записи цепи сверх последнего подписанного чекпойнта.
    # Совет по умолчанию (цепь легитимно растёт между чекпойнтами),
    # ворота при --require-coverage.
    if args.chain is not None and "checkpoint_valid" in result:
        head_seq = max((e.get("seq") or 0) for e in entries)
        cp_seq = result.get("checkpoint_max_seq") or 0
        lag = head_seq - cp_seq if head_seq > cp_seq else 0
        result["checkpoint_lag"] = lag

        if lag > 0:
            result["coverage_advisory"] = (
                f"{lag} chain entry(ies) beyond the latest signed checkpoint "
                f"(head seq={head_seq}, checkpoint seq={cp_seq})"
            )

    overall = verdict.valid
    if "chain" in result:
        overall = overall and result["chain"]["valid"]
        if result["chain"].get("contains_attestation") is False:
            overall = False
            result["chain"]["reason"] = (
                result["chain"].get("reason")
                or "attestation_id not found in the provided chain"
            )
    if "checkpoint_valid" in result:
        overall = overall and result["checkpoint_valid"]

    # Полнота цепи: без подписанного чекпойнта усечение хвоста неотличимо от
    # «полной» цепи (verify_chain валиден для любого префикса). Поэтому
    # --require-coverage БЕЗ файла чекпойнтов = fail-closed: оператор
    # потребовал доказательство полноты, а его предъявить нечем.
    if args.require_coverage and args.checkpoint is None:
        overall = False
        result["coverage_gate_error"] = (
            "--require-coverage needs an externally signed checkpoint "
            "(--checkpoint file); without it a truncated chain is "
            "indistinguishable from a complete one"
        )

    if args.require_coverage and result.get("checkpoint_lag", 0) > 0:
        overall = False

    # Доверие эмитенту: валидная подпись ≠ аутентифицированный эмитент. Без
    # якоря вердикт VALID не засчитывается контрагенту, если явно не
    # разрешено --allow-self-declared-key (режим отладки/первого прогона).
    if not verdict.trust_established and not args.allow_self_declared_key:
        overall = False
        result["trust_gate_error"] = (
            "no --issuer-key trust anchor supplied: the issuer key was taken "
            "from the attestation itself, so authenticity of the signer is "
            "unproven. Supply --issuer-key (or --allow-self-declared-key for "
            "debugging)."
        )


    if args.json:
        result["valid"] = overall
        print(json.dumps(result, indent=2))
    else:
        print(f"spec:                 {attestation.get('spec')}")
        print(f"attestation_id:       {attestation_id}")
        print(f"receipt signature:    {'VALID' if verdict.receipt_signature_valid else 'INVALID'}")
        print(f"claim consistent:     {'yes' if verdict.claim_consistent else 'NO'}")
        trust_label = (
            "ESTABLISHED (operator trust anchor matched)"
            if verdict.trust_established
            else "NOT ESTABLISHED (issuer key is self-declared — authenticity unproven)"
        )
        print(f"issuer trust:         {trust_label}")
        if "chain" in result:
            chain = result["chain"]
            print(f"chain:                {'VALID' if chain['valid'] else 'INVALID'} ({chain['entries']} entries)")
            if chain.get("contains_attestation") is False:
                print("chain membership:     attestation NOT FOUND in chain")
        if "checkpoint_valid" in result:
            count = result.get("checkpoint_count", 1)

            if count > 1:
                status = "VALID" if result["checkpoint_valid"] else "INVALID"
                print(f"checkpoint signatures: {status} ({count} checked)")
            else:
                print(f"checkpoint signature: {'VALID' if result['checkpoint_valid'] else 'INVALID'}")

        if result.get("checkpoint_lag", 0) > 0:
            note = (
                "coverage gap (GATE FAILED)"
                if args.require_coverage
                else "coverage gap (advisory — chain grows between checkpoints)"
            )
            print(f"checkpoint coverage:  {result['checkpoint_lag']} entry(ies) beyond "
                  f"the latest signed checkpoint — {note}")
        for reason in verdict.reasons:
            print(f"  - {reason}")
        print(f"VERDICT: {'VALID' if overall else 'INVALID'}")

    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())

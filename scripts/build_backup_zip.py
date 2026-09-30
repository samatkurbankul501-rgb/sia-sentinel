#!/usr/bin/env python3
"""Сборка критического бэкап-zip с ВСТРОЕННОЙ проверкой носителя.

Уроки дня 2026-09-13: три ручные сборки zip, и в ДВУХ внутри лежал
устаревший/битый wheel (v1 — без BOM-фикса; v3-предшественник — 1.3.1 при
текущей 1.5.0). Ручная сборка носителя = человек копирует файлы по списку
из памяти — процесс, который уже дважды ошибся.

Скрипт:
  1. Собирает zip по фиксированному манифесту (.env, леджер, чекпойнты,
     якорь, артефакты обеих записей, флоу, Rekor-полка, wheel+sdist
     ТЕКУЩЕГО диста — staleness невозможен по построению).
  2. Проверяет содержимое: целостность, чекпойнты в журнале, Rekor-дайджест,
     секреты по списку имён (значения НЕ печатаются и не логируются).
  3. ПРОГОНЯЕТ НОСИТЕЛЬ: распаковка во временный каталог → venv →
     pip install wheel ИЗ РАСПАКОВАННОЙ КОПИИ → sia-verifier на записи №1
     с --require-coverage. Zip, не прошедший симуляцию «флешка → чужая
     машина», НЕ создаётся (скрипт умирает с кодом 1 ДО перезаписи
     существующего бэкапа).
  4. Итог: путь к zip + напоминание «перенести на внешний носитель».

Запуск: python scripts/build_backup_zip.py [имя-выхода.zip]
По умолчанию: ~/Downloads/sia-critical-backup-YYYY-MM-DD.zip
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import venv as venv_mod
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

MANIFEST_FILES = [
    ".env",
    "receipts/registry.jsonl",
    "receipts/checkpoints.jsonl",
    "artifacts/record1/attestation.json",
    "artifacts/record1/report.json",
    "artifacts/demo-live/attestation.json",
    "artifacts/demo-live/report.json",
    "artifacts/demo-live/receipt.json",
    "flows/beacon.json",
    "flows/live_demo.json",
]
ANCHOR_GLOB = "anchors/*.json"
REKOR_PAYLOAD = (".cache/record1_payload.bin", "rekor/record1_payload.bin")

ENV_KEYS_EXPECTED = [
    "EVIDENCE_SIGNING_KEY", "NVIDIA_API_KEY", "LOG_LEVEL", "GITHUB_TOKEN",
    "GITHUB_WEBHOOK_SECRET", "RECEIPT_SIGNING_KEY", "GROQ_API_KEY",
    "PLATFORM_ADMIN_API_KEY",
]


def _dist_files(version: str) -> list[tuple[Path, str]]:
    dist = REPO_ROOT / "verifier" / "dist"
    files = [
        (dist / f"sia_verifier-{version}-py3-none-any.whl",
         f"verifier-dist/sia_verifier-{version}-py3-none-any.whl"),
        (dist / f"sia_verifier-{version}.tar.gz",
         f"verifier-dist/sia_verifier-{version}.tar.gz"),
    ]
    return files


def _readme(kid: str, pubkey: str, anchor_ref: str, version: str,
            checks: str, tests: str) -> str:
    return f"""SIA SENTINEL — КРИТИЧЕСКИЙ РЕЗЕРВНЫЙ ПАКЕТ ({_dt.date.today().isoformat()})
=================================================================================
Секреты и доказательная цепочка. ХРАНИТЬ НА USB / В МЕНЕДЖЕРЕ ПАРОЛЕЙ.
После переноса на внешний носитель — УДАЛИТЬ этот zip с диска.

СОСТАВ
------
- .env                        — RECEIPT_SIGNING_KEY и прочие секреты (КЛЮЧ №1)
- receipts/registry.jsonl     — хеш-цепь леджера
- receipts/checkpoints.jsonl  — все подписанные чекпойнты
- anchors/*.json              — файловые якоря чекпойнтов
- artifacts/record1/*, artifacts/demo-live/* — отчёты и аттестации записей
- flows/beacon.json, flows/live_demo.json   — зафиксированные флоу
- verifier-dist/sia_verifier-{version}* — сборка верификатора {version}
- rekor/record1_payload.bin   — каноничное обязательство (sha512 = af720aad…,
                                дайджест живой записи Rekor; НЕ секрет)

ИДЕНТИЧНОСТЬ ПОДПИСАНТА (НЕ секрет): kid {kid},
pubkey {pubkey}
Beacon anchor: {anchor_ref}

ВОССТАНОВЛЕНИЕ: распаковать в корень репозитория.
ПРОВЕРКА (выполнена СБОРЩИКОМ этого zip, из чистого venv, из РАСПАКОВАННОЙ
копии — «флешка → чужая машина»): {checks}
Статус сборки: {tests}

Сборщик: scripts/build_backup_zip.py — содержимое проверено программно,
устаревший dist в zip попасть не может (берётся текущий сборкой).
"""


def _collect(version: str) -> list[tuple[Path, str]]:
    entries: list[tuple[Path, str]] = []

    for rel in MANIFEST_FILES:
        src = REPO_ROOT / rel
        if not src.exists():
            raise SystemExit(f"FATAL: manifest file missing: {rel}")
        entries.append((src, rel))

    for anchor in sorted((REPO_ROOT / "anchors").glob("*.json")):
        entries.append((anchor, f"anchors/{anchor.name}"))

    payload_src, payload_dst = REKOR_PAYLOAD
    if not (REPO_ROOT / payload_src).exists():
        raise SystemExit(f"FATAL: Rekor payload missing: {payload_src}")
    entries.append((REPO_ROOT / payload_src, payload_dst))

    for src, dst in _dist_files(version):
        if not src.exists():
            raise SystemExit(f"FATAL: dist artifact missing: {src} — run release_verifier.py first")
        entries.append((src, dst))

    return entries


def _verify_contents(z: zipfile.ZipFile) -> None:
    assert z.testzip() is None, "corrupt zip"

    cps = [json.loads(line)["seq"] for line in
           z.read("receipts/checkpoints.jsonl").decode().splitlines() if line.strip()]
    live_cps = [json.loads(line)["seq"] for line in
                (REPO_ROOT / "receipts/checkpoints.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()]
    if cps != live_cps:
        raise SystemExit(f"FATAL: checkpoint journal mismatch zip={cps} live={live_cps}")

    digest = hashlib.sha512(z.read("rekor/record1_payload.bin")).hexdigest()
    if not digest.startswith("af720aad"):
        raise SystemExit(f"FATAL: rekor payload digest mismatch: {digest[:16]}")

    env_keys = [entry.split("=")[0] for entry in z.read(".env").decode().splitlines()
                if "=" in entry and not entry.startswith("#")]
    missing = [k for k in ENV_KEYS_EXPECTED if k not in env_keys]

    if missing:
        raise SystemExit(f"FATAL: .env missing keys: {missing}")


def _flash_drive_simulation(z: zipfile.ZipFile) -> str:
    tmp = Path(tempfile.mkdtemp(prefix="sia_zipbuild_"))

    try:
        z.extractall(tmp)
        venv_mod.create(str(tmp / "venv"), with_pip=True)
        scripts = tmp / "venv" / "Scripts"
        pip = scripts / "pip.exe"
        wheel = next((tmp / "verifier-dist").glob("*.whl"))

        result = subprocess.run([str(pip), "install", "--quiet", str(wheel)],
                                capture_output=True, text=True)
        if result.returncode != 0:
            print(result.stderr[-500:], file=sys.stderr)
            raise SystemExit("FATAL: pip install from restored copy failed")

        sv = scripts / "sia-verifier.exe"
        r = subprocess.run(
            [str(sv),
             str(tmp / "artifacts" / "record1" / "attestation.json"),
             "--chain", str(tmp / "receipts" / "registry.jsonl"),
             "--checkpoint", str(tmp / "receipts" / "checkpoints.jsonl"),
             "--require-coverage",
             "--issuer-key", "tqIhnSC/3xVANUtzGLsGmcVqxZ40J1jTiF1QDaQHiyw="],
            capture_output=True, text=True,
        )
        ok = r.returncode == 0 and "VERDICT: VALID" in r.stdout
        checked = next((ln for ln in r.stdout.splitlines() if "checked" in ln), "")

        if not ok:
            print(r.stdout[-500:], file=sys.stderr)
            raise SystemExit("FATAL: flash-drive simulation failed — zip NOT written")

        return f"sia-verifier --require-coverage → VALID ({checked.strip()})"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="build_backup_zip",
        description="Build the critical backup zip with a built-in flash-drive verification.",
    )
    parser.add_argument("output", nargs="?",
                        default=None, help="Output zip path (default ~/Downloads/sia-critical-backup-DATE.zip)")
    args = parser.parse_args()

    import re
    pyproject = (REPO_ROOT / "verifier" / "pyproject.toml").read_text(encoding="utf-8")
    version = re.search(r'version = "([\d.]+)"', pyproject).group(1)

    out = Path(args.output) if args.output else (
        Path.home() / "Downloads" / f"sia-critical-backup-{_dt.date.today().isoformat()}.zip"
    )

    # подписант и якорь из живого леджера (НЕ секреты)
    head_meta = {}
    anchor_ref = ""
    for line in (REPO_ROOT / "receipts" / "registry.jsonl").read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        md = entry.get("metadata") or {}
        if md.get("entry_type") == "key" and md.get("key_declaration"):
            head_meta = md["key_declaration"]
        if "anchor_reference" in json.dumps(md):
            anchor_ref = md.get("anchor_reference") or anchor_ref
    flow = json.loads((REPO_ROOT / "flows" / "beacon.json").read_text(encoding="utf-8-sig"))
    anchor_ref = flow.get("anchor_reference") or anchor_ref

    entries = _collect(version)
    print(f"collected {len(entries)} files (verifier {version})")

    # СНАЧАЛА собираем и проверяем во временный файл; живой бэкап не трогаем,
    # пока симуляция не прошла. Zip-хендл закрываем ДО чтений (testzip на
    # открытом-для-записи хендле недостоверен).
    tmp_out = out.with_suffix(".tmp.zip")

    def _readme_text(checks: str) -> str:
        return _readme(
            kid=head_meta.get("kid", "?"),
            pubkey=head_meta.get("public_key", "?"),
            anchor_ref=anchor_ref or "see flows/beacon.json",
            version=version,
            checks=checks,
            tests="verified at build time by scripts/build_backup_zip.py",
        )

    with zipfile.ZipFile(tmp_out, "w", zipfile.ZIP_DEFLATED) as z:
        for src, dst in entries:
            z.write(src, dst)

    # проверки содержимого и флешка-симуляция — на ЗАКРЫТОМ файле
    with zipfile.ZipFile(tmp_out) as z:
        _verify_contents(z)
        checks = _flash_drive_simulation(z)

    # вписываем README с фактом пройденной проверки
    with zipfile.ZipFile(tmp_out, "a") as z:
        z.writestr("README-backup.txt", _readme_text(checks))

    shutil.move(str(tmp_out), str(out))
    print(f"OK: {out} ({out.stat().st_size} bytes)")
    print(f"    {checks}")
    print("NEXT: скопировать на внешний носитель и удалить zip с этого диска.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

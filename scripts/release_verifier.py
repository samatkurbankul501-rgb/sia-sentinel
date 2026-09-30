#!/usr/bin/env python3
"""Релиз sia-verifier одной командой: бамп → сборка → проверка → чеклист.

Урок дня 2026-09-13: три ручных выпуска (1.4.0/1.4.1/1.5.0), и в ДВУХ из
них wheel устаревала в тот же день — ручной процесс выпуска не масштабируется
на человека, который параллельно закрывает дыры. Этот скрипт делает выпуск
механически безопасным:

  1. Бамп версии во всех маркерах (pyproject, __init__, CLI-лейбл) — сам
     (аргумент) или проверка текущих (без аргумента).
  2. Обновление docs/pypi-release-checklist.md — текущая незагруженная
     запись pointing на новую версию (дата, объём — из аргумента --notes).
  3. python -m build (чистые dist/ артефакты нужной версии).
  4. Чистый venv: pip install wheel → sia-verifier на обеих записях
     (артефакты записи №1 + live-demo) под --require-coverage →
     sia-rederive (десять проверок, живой Rekor; --skip-live-rekor для
     офлайна). Любой красный = отказ выпуска, код 1.
  5. Печать однострочного напоминания twine для оператора.

Оператор остаётся человеком только там, где он и должен быть: twine upload
(токен) и PyPI-страница. Загрузку скрипт НЕ делает — наружное действие
остаётся осознанным шагом оператора.

Запуск:
    python scripts/release_verifier.py 1.6.0 --notes "check 11: ..."
    python scripts/release_verifier.py --check   # только сверка маркеров
"""
from __future__ import annotations

import argparse
import datetime as _dt
import re
import shutil
import subprocess
import sys
import tempfile
import venv as venv_mod
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER_DIR = REPO_ROOT / "verifier"
CHECKLIST = REPO_ROOT / "docs" / "pypi-release-checklist.md"

MARKERS = [
    ("verifier/pyproject.toml", 'version = "{v}"'),
    ("verifier/sia_verifier/__init__.py", '__version__ = "{v}"'),
    ("verifier/sia_verifier/__init__.py", "CLI (v{v})::"),
]

# Артефакты для живой проверки (обе производственные записи)
VERIFY_TARGETS = [
    ("artifacts/record1/attestation.json", "record 1"),
    ("artifacts/demo-live/attestation.json", "record 2 (demo-live)"),
]
CHAIN = "receipts/registry.jsonl"
CHECKPOINTS = "receipts/checkpoints.jsonl"
# Якорь доверия (2026-09-30): верификатор fail-closed без внешнего ключа
# эмитента. Обе записи выпущены одним ключом; значение продублировано в CI.
ISSUER_KEY = "tqIhnSC/3xVANUtzGLsGmcVqxZ40J1jTiF1QDaQHiyw="


def _current_version() -> str:
    pyproject = (VERIFIER_DIR / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'version = "([\d.]+)"', pyproject)
    if not m:
        raise SystemExit("FATAL: no version in verifier/pyproject.toml")
    return m.group(1)


def _check_markers(version: str) -> list[str]:
    problems = []
    for rel, pattern in MARKERS:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        if pattern.format(v=version) not in text:
            problems.append(f"{rel}: missing marker {pattern.format(v=version)!r}")
    return problems


def _bump(old: str, new: str) -> None:
    for rel, pattern in MARKERS:
        path = REPO_ROOT / rel
        text = path.read_text(encoding="utf-8")
        old_marker = pattern.format(v=old)
        if old_marker not in text:
            raise SystemExit(f"FATAL: {rel}: old marker {old_marker!r} not found")
        path.write_text(text.replace(old_marker, pattern.format(v=new), 1), encoding="utf-8")


def _update_checklist(version: str, notes: str) -> None:
    text = CHECKLIST.read_text(encoding="utf-8")
    today = _dt.date.today().isoformat()
    # заменяем строку текущей незагруженной записи (первая «**X.Y.Z (date): собрана»)
    new_entry = (
        f"**{version} ({today}): собрана, загрузка на PyPI ЖДЁТ ОПЕРАТОРА.** {notes}\n"
    )
    text = re.sub(
        r"\*\*[\d.]+ \([\d-]+\): собрана, загрузка на PyPI ЖДЁТ ОПЕРАТОРА\.\*\*.*\n",
        new_entry,
        text,
        count=1,
    )
    CHECKLIST.write_text(text, encoding="utf-8")


def _build(version: str) -> None:
    dist = VERIFIER_DIR / "dist"
    if dist.exists():
        # артефакты прошлых версций не должны попасть в twine upload dist/*
        for stale in dist.glob("sia_verifier-*.whl"):
            stale.unlink()
        for stale in dist.glob("sia_verifier-*.tar.gz"):
            stale.unlink()

    result = subprocess.run(
        [sys.executable, "-m", "build"],
        cwd=str(VERIFIER_DIR), capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(result.stdout[-1500:], file=sys.stderr)
        print(result.stderr[-1500:], file=sys.stderr)
        raise SystemExit("FATAL: python -m build failed")

    wheel = dist / f"sia_verifier-{version}-py3-none-any.whl"

    if not wheel.exists():
        raise SystemExit(f"FATAL: expected wheel not found: {wheel}")

    print(f"  built: dist/sia_verifier-{version}-py3-none-any.whl")


def _verify_from_clean_venv(version: str, live_rekor: bool) -> None:
    wheel = VERIFIER_DIR / "dist" / f"sia_verifier-{version}-py3-none-any.whl"
    tmp = Path(tempfile.mkdtemp(prefix="sia_release_check_"))

    try:
        venv_mod.create(str(tmp / "venv"), with_pip=True)
        scripts = tmp / "venv" / "Scripts"
        pip = scripts / "pip.exe"

        result = subprocess.run(
            [str(pip), "install", "--quiet", str(wheel)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(result.stderr[-800:], file=sys.stderr)
            raise SystemExit("FATAL: clean-venv pip install failed")

        sv = scripts / "sia-verifier.exe"

        for att, label in VERIFY_TARGETS:
            r = subprocess.run(
                [str(sv),
                 str(REPO_ROOT / att),
                 "--chain", str(REPO_ROOT / CHAIN),
                 "--checkpoint", str(REPO_ROOT / CHECKPOINTS),
                 "--require-coverage",
                 "--issuer-key", ISSUER_KEY],
                capture_output=True, text=True,
            )
            ok = r.returncode == 0 and "VERDICT: VALID" in r.stdout

            if not ok:
                print(f"  [{label}] FAILED:\n{r.stdout}\n{r.stderr}", file=sys.stderr)
                raise SystemExit(f"FATAL: clean-venv sia-verifier failed on {label}")

            checked = [ln for ln in r.stdout.splitlines() if "checked" in ln]
            print(f"  [{label}] VALID {' '.join(checked)}")

        rd = scripts / "sia-rederive.exe"
        args = [str(rd)]

        if not live_rekor:
            args.append("--no-rekor")

        r = subprocess.run(args, capture_output=True, text=True, cwd=str(REPO_ROOT))
        ok = r.returncode == 0 and "REDERIVED:    YES" in r.stdout

        if not ok:
            print(r.stdout[-800:], file=sys.stderr)
            raise SystemExit("FATAL: clean-venv sia-rederive did not re-derive")

        rekor_mode = "live" if live_rekor else "--no-rekor (offline)"
        print(f"  [rederive] REDERIVED YES ({rekor_mode})")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="release_verifier",
        description="Bump, build, and verify a sia-verifier release; twine upload stays with the operator.",
    )
    parser.add_argument("version", nargs="?", help="New version, e.g. 1.6.0 (omit for --check)")
    parser.add_argument("--notes", default="", help="One-line change summary for the checklist entry")
    parser.add_argument("--check", action="store_true", help="Only verify marker synchronization")
    parser.add_argument("--skip-live-rekor", action="store_true",
                        help="Verify rederive with --no-rekor (offline release check)")
    args = parser.parse_args()

    current = _current_version()
    print(f"current version: {current}")

    problems = _check_markers(current)

    if problems:
        for p in problems:
            print(f"  DESYNC: {p}", file=sys.stderr)
        return 1
    print("  markers synchronized")

    if args.check or not args.version:
        return 0

    if args.version == current:
        print("  version unchanged — nothing to bump", file=sys.stderr)
        return 1

    if not args.notes:
        print("  --notes is required for a release (checklist honesty)", file=sys.stderr)
        return 1

    print(f"bumping {current} -> {args.version}")
    _bump(current, args.version)
    _update_checklist(args.version, args.notes)

    if _check_markers(args.version):
        # откатывать бамп не нужно: чек-режон ошибки — сразу видно
        print("  post-bump marker check failed", file=sys.stderr)
        return 1

    print("building…")
    _build(args.version)

    print("verifying from a clean venv…")
    _verify_from_clean_venv(args.version, live_rekor=not args.skip_live_rekor)

    print(f"\nRelease {args.version} is BUILT and VERIFIED.")
    print("Upload (operator, ~15 min, PyPI token in password manager):")
    print(f"  cd {VERIFIER_DIR}")
    print("  ..\\venv\\Scripts\\python.exe -m twine upload dist\\*")
    print("Protocol: docs/pypi-release-checklist.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

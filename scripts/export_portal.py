#!/usr/bin/env python3
"""Статический экспорт портала верификации: реестр без сервера.

Зачем: до публичного деплоя аттестации живут только в JSON-артефактах —
а живому человеку (банк, госзаказ, грантодатель) нужно ЧТО ПОКАЗАТЬ:
вердикт, подпись, бейдж — в браузере, по ссылке, которую можно переслать.

ПЕРВАЯ ВЕРСИЯ ЭКСПОРТА ОКАЗАЛАСЬ ДВажды НЕЧЕСТНОЙ (поймано проверкой
содержимого сразу после генерации): реестр был пуст (server-side opt-in
фильтр, которого у экспорта нет), а вердикт страницы — «НЕ ПОДТВЕРЖДЕНО»
(verify_stored с эфемерным ключом не знает ключ из деклараций леджера).
Урок: экспорт не должен ПРОЕЦИРОВАТЬ серверную жизнь — он обязан
ВЕРИФИЦИРОВАТЬ как посторонний. Источник истины — сами аттестации и
независимый верификатор (sia_verifier.core, тот же код, что на PyPI):
вердикт страницы = подпись + цепь + чекпойнты, посчитанные здесь же.

Выход — portal/ (в git: витрина — публичный артефакт, не билд-мусор;
готова к GitHub Pages без переделки):
  index.html (+ .ru/.kk)      — реестр обеих публичных записей
  attestations/{id}/…         — страница вердикта (en/ru/kk), badge.svg
  attestations/{id}.json       — машинная копия документа
  verify.html                 — «проверь сам» (pip install sia-verifier)

Каталог самодостаточен: открывается с диска (file://), прикрепляется к
письму, кладётся на статик-хостинг без переделки; ссылки — относительные.

Запуск: python scripts/export_portal.py [--out portal]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))          # sentinel.api — тексты портала
sys.path.insert(0, str(REPO_ROOT / "verifier"))  # sia_verifier — вердикты

# Якорь доверия для публичного вердикта портала: публичный ключ эмитента
# (2026-09-30). Портал существует ради «проверь, не доверяя нам», поэтому
# его вердикт обязан быть аутентифицирован против ЗАРАНЕЕ известного ключа,
# а не против ключа из самого документа. Публичные записи выпущены одним ключом.
ISSUER_PUBLIC_KEY = "tqIhnSC/3xVANUtzGLsGmcVqxZ40J1jTiF1QDaQHiyw="

# Экспорт не сервер: секреты не нужны, но import sentinel.api поднимает
# модуль целиком (auth предупреждает об эфемерном ключе и трогает пути
# состояния). Изолируем до импорта — паттерн demo_full: экспорт не имеет
# права писать в репозиторное состояние, даже случайно.
_tmp = tempfile.mkdtemp(prefix="sia_portal_export_")
os.environ.update({
    "JWT_SECRET_KEY": "f" * 64,        # никогда не используется: HTML не подписывает токены
    "EVIDENCE_SIGNING_KEY": "e" * 64,
    "RECEIPT_SIGNING_KEY": "d" * 64,  # на всякий случай: экспорт не выпускает квитанций
    "RECEIPTS_DIR": str(REPO_ROOT / "receipts"),  # читать — можно (публично), писать — не будет
    "EVIDENCE_DIR": str(Path(_tmp) / "evidence"),
    "TENANTS_FILE": str(Path(_tmp) / "tenants.json"),
    "USAGE_EVENTS_FILE": str(Path(_tmp) / "usage.jsonl"),
    "INVOICES_FILE": str(Path(_tmp) / "invoices.json"),
    "WEBHOOKS_FILE": str(Path(_tmp) / "webhooks.json"),
    "API_KEYS_FILE": str(Path(_tmp) / "api_keys.json"),
    "DATABASE_URL": f"sqlite:///{Path(_tmp) / 'export.db'}",
    "ENABLE_DEMO_LOGIN": "",
    "PLATFORM_ADMIN_API_KEY": "plat-" + "a" * 40,
})

from sia_verifier.core import (  # noqa: E402
    verify_attestation,
    verify_chain,
    verify_checkpoint,
)

# Публичные записи: единственный источник витрины. Новая запись = строка
# здесь + артефакты в git; гард полноты (tests/test_clone_guard) не даст
# файлу исчезнуть из клона.
PUBLIC_RECORDS = [
    ("artifacts/record1/attestation.json", "Beacon GSM8K (record №1)"),
    ("artifacts/demo-live/attestation.json", "Live demo GSM8K (record №2)"),
]

# Даты записи для витрины реестра (issued_at есть в самих аттестациях;
# здесь только названия флоу из метаданных, чтобы не дублировать истину)
LANGS = ("en", "ru", "kk")

_STYLES = """
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem auto; max-width: 860px; color: #1c2733; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #d7dee6; }
  .verdict { font-size: 1.6rem; font-weight: 700; color: #2e7d32; }
  .verdict.bad { color: #c62828; }
  .card { border: 1px solid #d7dee6; border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; }
  .ok { color: #2e7d32; } .bad { color: #c62828; }
  code, pre { background: #f4f6f8; padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; }
  pre { padding: 0.75rem; overflow-x: auto; }
  a { color: #1565c0; }
"""


def _esc(value: object) -> str:
    import html

    return html.escape(str(value), quote=True)


def _portal_texts() -> dict[str, dict[str, str]]:
    """Статические надписи — из живого портала (sentinel.api.PORTAL_TEXTS),
    не копия: экспорт не может разойтись с прод-текстами."""
    from sentinel.api import PORTAL_TEXTS

    return PORTAL_TEXTS


def _verify_record(attestation: dict) -> dict:
    """Независимая верификация: подпись, цепь, ВСЕ чекпойнты.

    Тот же код, что в pip-пакете: экспорт не доверяет серверной проекции
    verification.* (она не подписана) — считает вердикт сам.
    """
    entries = [
        json.loads(line)
        for line in (REPO_ROOT / "receipts" / "registry.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    checkpoints = [
        json.loads(line)
        for line in (REPO_ROOT / "receipts" / "checkpoints.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]

    # Якорь доверия (2026-09-30): портал показывает публичный вердикт, значит
    # он обязан быть аутентифицирован, а не «подпись верна под ключом из
    # самого документа». Публичные записи выпущены одним известным ключом.
    att = verify_attestation(attestation, expected_public_key=ISSUER_PUBLIC_KEY)
    chain = verify_chain(entries, attestation.get("attestation_id"))
    public_key = attestation["issuer"]["public_key"]
    checkpoints_valid = bool(attestations_checkpoint_ok(checkpoints, public_key))

    return {
        "signature": att.receipt_signature_valid,
        "claim": att.claim_consistent,
        "spec": att.spec_recognized,
        "reasons": att.reasons,
        "chain": chain.valid,
        "chain_entries": chain.entries,
        "contains": chain.contains_attestation,
        "checkpoints_valid": checkpoints_valid,
    }


def attestations_checkpoint_ok(checkpoints: list[dict], public_key: str) -> bool:
    if not checkpoints:
        return False
    for cp in checkpoints:
        if not verify_checkpoint(cp, public_key):
            return False
    return True


def _record_row(card: dict, t: dict[str, str]) -> str:
    ratio = card.get("savings_ratio")
    ratio_text = f"{ratio * 100:.1f}%" if isinstance(ratio, (int, float)) else "n/a"
    verified = "&#10003;" if card.get("savings_verified") else "&#10007;"
    att_id = card["attestation_id"]
    return (
        "<tr>"
        f'<td><a href="attestations/{_esc(att_id)}/index.html"><code>{_esc(att_id[:12])}…</code></a></td>'
        f"<td>{_esc(card.get('flow_name'))}</td>"
        f"<td>{_esc(card.get('kind'))}</td>"
        f"<td>{verified}</td>"
        f"<td>{ratio_text}</td>"
        f"<td>{_esc(card.get('issued_at'))}</td>"
        "</tr>"
    )


def _registry_page(cards: list[dict], lang: str) -> str:
    t = _portal_texts().get(lang, _portal_texts()["en"])
    body = "".join(_record_row(c, t) for c in cards) or (
        f'<tr><td colspan="6">{_esc(t["row_empty"])}</td></tr>'
    )
    return f"""<!DOCTYPE html>
<html lang="{_esc(lang)}">
<head><meta charset="utf-8" />
<title>{_esc(t["registry_title"])} — SIA Sentinel</title>
<style>{_STYLES}</style></head>
<body>
<h1>{_esc(t["registry_title"])}</h1>
<p>{_esc(t["registry_intro"])}</p>
<p><a href="verify.html">Verify it yourself →</a></p>
<table>
<tr><th>{_esc(t["th_attestation"])}</th><th>{_esc(t["th_flow"])}</th><th>{_esc(t["th_kind"])}</th><th>{_esc(t["th_verified"])}</th><th>{_esc(t["th_savings"])}</th><th>{_esc(t["th_issued"])}</th></tr>
{body}
</table>
</body>
</html>"""


def _attestation_page(attestation: dict, v: dict, lang: str) -> str:
    texts = _portal_texts()
    t = texts.get(lang, texts["en"])
    claim = attestation.get("claim", {})
    verified = v["signature"] and v["chain"] and v["contains"] and v["checkpoints_valid"]
    verdict_cls = "" if verified else " bad"
    mark = lambda ok: "&#10003;" if ok else "&#10007;"  # noqa: E731
    ratio = claim.get("savings_ratio")
    ratio_text = f"{ratio * 100:.1f}%" if isinstance(ratio, (int, float)) else "n/a"
    att_id = attestation["attestation_id"]
    subject = attestation.get("subject", {})
    badge_snippet = f'<img src="https://<host>/v1/attestations/{_esc(att_id)}/badge.svg" alt="Proof-of-Savings attestation" />'

    return f"""<!DOCTYPE html>
<html lang="{_esc(lang)}">
<head><meta charset="utf-8" />
<title>Attestation {_esc(att_id)} — SIA Sentinel</title>
<style>{_STYLES}</style></head>
<body>
<h1>{_esc(t["title"])}</h1>
<p class="verdict{verdict_cls}">{_esc(t["verdict_verified"] if verified else t["verdict_not_verified"])}</p>

<div class="card">
<table>
<tr><th>Attestation ID</th><td><code>{_esc(att_id)}</code></td></tr>
<tr><th>Issued</th><td>{_esc(attestation.get("issued_at"))}</td></tr>
<tr><th>Flow</th><td>{_esc(subject.get("flow_name"))} ({_esc(subject.get("kind"))}, {_esc(subject.get("mode"))})</td></tr>
<tr><th>Savings verified</th><td>{_esc(claim.get("savings_verified"))}</td></tr>
<tr><th>Savings ratio</th><td>{ratio_text}</td></tr>
<tr><th>Issuer</th><td>{_esc(attestation["issuer"]["name"])} — <code>{_esc(attestation["issuer"]["public_key"])}</code></td></tr>
</table>
</div>

<div class="card">
<h2>Verification</h2>
<p><span class="{'ok' if v['signature'] else 'bad'}">{mark(v['signature'])}</span> Receipt signature (Ed25519)</p>
<p><span class="{'ok' if v['chain'] else 'bad'}">{mark(v['chain'])}</span> TrustChain ledger ({v['chain_entries']} entries)</p>
<p><span class="{'ok' if v['checkpoints_valid'] else 'bad'}">{mark(v['checkpoints_valid'])}</span> Signed checkpoints ({v['checkpoint_count']} checked)</p>
<p>Spec: <code>{_esc(attestation.get("spec"))}</code> · <a href="../{_esc(att_id)}.json">JSON</a> · <a href="badge.svg">badge.svg</a></p>
<p class="{'ok' if verified else 'bad'}">Verdict computed at export time by the independent verifier (sia-verifier), not the service.</p>
</div>

<div class="card">
<h2>Embed badge</h2>
<pre>{_esc(badge_snippet)}</pre>
</div>

<p><a href="../index.html">{_esc(t["back_to_registry"])}</a></p>
</body>
</html>"""


def _badge_svg(attestation: dict, v: dict) -> str:
    claim = attestation.get("claim", {})
    verified = v["signature"] and bool(claim.get("savings_verified"))
    if verified and claim.get("savings_ratio") is not None:
        label = f"Savings {claim['savings_ratio'] * 100:.0f}% verified"
        color = "#2e7d32"
    else:
        label = "Savings not verified"
        color = "#c62828"
    width = 150 + len(label) * 7
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="24" role="img" '
        f'aria-label="Proof-of-Savings attestation">'
        f'<rect width="118" height="24" fill="#37474f"/>'
        f'<rect x="118" width="{width - 118}" height="24" fill="{color}"/>'
        f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="8" y="16">Proof-of-Savings</text>'
        f'<text x="126" y="16">{label}</text>'
        f'</g></svg>'
    )


def _verify_page() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8" /><title>Verify it yourself — SIA Sentinel</title>
<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem auto;max-width:720px;color:#1c2733}pre{background:#f4f6f8;padding:.75rem;border-radius:6px;overflow-x:auto}a{color:#1565c0}</style>
</head>
<body>
<h1>Verify it yourself</h1>
<p>This showcase is a static export. The real proof does not require trusting us:</p>
<pre>pip install sia-verifier

sia-verifier attestation.json --chain registry.jsonl \\
  --checkpoint checkpoints.jsonl --require-coverage \\
  --issuer-key tqIhnSC/3xVANUtzGLsGmcVqxZ40J1jTiF1QDaQHiyw=

sia-rederive</pre>
<p><strong><code>--issuer-key</code> is required.</strong> It is the issuer's
public key obtained <em>out-of-band</em> (printed above, published in the
attestation). The signature must be checked against a key you already trust —
not against a key shipped inside the document under test, which would let
anyone mint a &ldquo;valid&rdquo; forgery with a throwaway key. Without
<code>--issuer-key</code> the verifier is fail-closed and never reports
<code>VERDICT: VALID</code>.</p>
<p>The chain, checkpoints and flows are in the repository
(<code>receipts/</code>, <code>artifacts/</code>, <code>flows/</code>).
The verifier checks the Ed25519 signature, the hash chain, signed
checkpoints and the Merkle tree — offline, one dependency
(<code>cryptography</code>).</p>
<p><a href="index.html">Back to the registry</a></p>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Static portal export")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "portal")
    args = parser.parse_args()
    out: Path = args.out

    records = []
    any_invalid = False
    for rel, title in PUBLIC_RECORDS:
        doc = json.loads((REPO_ROOT / rel).read_text(encoding="utf-8-sig"))
        v = _verify_record(doc)
        v["checkpoint_count"] = _checkpoint_count()
        # Витрина показывает только ПРОВЕРЕННОЕ: запись, не прошедшую
        # независимую верификацию, показывать как «запись» — ложь.
        if not (v["signature"] and v["chain"] and v["contains"] and v["checkpoints_valid"]):
            any_invalid = True
            print(f"REFUSED: {rel} failed independent verification: {v['reasons']}", file=sys.stderr)
            continue
        records.append((doc, v, title))

    if any_invalid:
        return 1

    # Витрина реестра: обе записи как карточки
    cards = [
        {
            "attestation_id": doc["attestation_id"],
            "flow_name": doc.get("subject", {}).get("flow_name"),
            "kind": doc.get("subject", {}).get("kind"),
            "mode": doc.get("subject", {}).get("mode"),
            "savings_verified": doc.get("claim", {}).get("savings_verified"),
            "savings_ratio": doc.get("claim", {}).get("savings_ratio"),
            "issued_at": doc.get("issued_at"),
        }
        for doc, _v, _t in records
    ]

    out.mkdir(parents=True, exist_ok=True)
    for lang in LANGS:
        name = "index.html" if lang == "en" else f"index.{lang}.html"
        (out / name).write_text(_registry_page(cards, lang), encoding="utf-8")

    for doc, v, _title in records:
        att_id = doc["attestation_id"]
        rec_dir = out / "attestations" / att_id
        rec_dir.mkdir(parents=True, exist_ok=True)
        for lang in LANGS:
            name = "index.html" if lang == "en" else f"index.{lang}.html"
            (rec_dir / name).write_text(
                _attestation_page(doc, v, lang), encoding="utf-8"
            )
        (rec_dir / "badge.svg").write_text(_badge_svg(doc, v), encoding="utf-8")
        (out / "attestations" / f"{att_id}.json").write_text(
            json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    (out / "verify.html").write_text(_verify_page(), encoding="utf-8")

    # --- Служебные файлы GitHub Pages ---
    # .nojekyll: без него Jekyll пропускает через свой шаблон и может выкинуть
    # файлы/каталоги, начинающиеся с "_", а также испортить раздачу вложенных
    # путей. Для статической витрины Jekyll не нужен вообще.
    (out / ".nojekyll").write_text("", encoding="utf-8")

    # 404.html: GitHub Pages отдаёт его на несуществующий путь. Без него
    # пользователь (и поисковик) получает стандартную страницу 404 без ссылок
    # обратно — витрина выглядит сломанной.
    (out / "404.html").write_text(_not_found_page(), encoding="utf-8")

    files = sorted(p for p in out.rglob("*") if p.is_file())
    print(f"exported {len(files)} files -> {out}")
    for f in files:
        print(f"  {f.relative_to(out)}")
    return 0


def _not_found_page() -> str:
    """Страница «не найдено» со ссылками обратно (Pages отдаёт её на 404)."""
    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8" /><title>Not found — SIA Sentinel</title>
<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:4rem auto;max-width:620px;color:#1c2733;text-align:center}
a{color:#1565c0}</style>
</head>
<body>
<h1>404 — page not found</h1>
<p>This is a static export of the public attestation registry. The address you
requested does not exist.</p>
<p><a href="index.html">← Public Attestation Registry</a> &nbsp;·&nbsp;
<a href="verify.html">Verify it yourself</a></p>
</body>
</html>
"""


def _checkpoint_count() -> int:
    return len(
        [
            line
            for line in (REPO_ROOT / "receipts" / "checkpoints.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())

# SIA Sentinel — Proof-of-Savings Protocol

**An independent, cryptographically verifiable audit layer for AI cost optimization.**

Every vendor claims their cheaper model "works just as well." Nobody can prove it —
and nobody trusts the vendor's own benchmark. SIA Sentinel is the neutral auditor:
it replays your real workload against the candidate configuration, proves (or
disproves) quality equivalence with statistical guarantees, and issues a signed,
tamper-evident receipt that both sides of the deal can verify independently.

This is not an AI wrapper. The core product is a **verification and attestation
protocol**: reproducibility manifests, Wilson confidence intervals for equivalence,
Ed25519-signed receipts, and a hash-chained public ledger (TrustChain) with
periodic signed checkpoints.

---

## What it does

| Capability | Description |
|---|---|
| **Code audits** | Prove a refactor (e.g. recursive → iterative) preserves behavior, then quantify compute savings |
| **LLM flow audits** | Replay a prompt dataset through old/new model configs; equivalence via Wilson CI on pass-rate, savings from token pricing |
| **Savings Autopilot** | Screen a model catalog (by tier/pricing), find the cheapest config that preserves quality, then prove it with a full final audit |
| **TrustChain ledger** | Append-only hash chain + RFC 6962 Merkle tree over all receipts: signed tree heads, inclusion/consistency proofs, key rotation (`kid`), external checkpoint anchoring, tamper detection, public attestations + SVG badges |
| **Multi-tenant SaaS** | Tenant isolation for jobs/receipts/invoices, RBAC (API keys + JWT), usage metering |
| **Billing** | Plans with monthly quotas (hard cap on free, billed overage on paid), invoice generation per period |

### Proof, not vibes

An audit claim is only *verified* when the equivalence test passes with a
confidence guarantee:

- **Wilson score confidence interval** on the new config's pass rate — the claim
  holds when the CI lower bound clears the quality floor, not just the point estimate.
- **Reproducibility manifest** — dataset hash, config hash, benchmark seeds are
  pinned into the receipt, so the claim can be independently re-run.
- **Ed25519 receipt** — signed by the auditor; anyone with the public key can
  verify it without trusting the service.
- **Hash-chained registry** — each receipt links to the previous one; rewriting
  history breaks the chain. Checkpoints anchor the chain state periodically.

## Public Attestation Network

Attestations are a portable standard, not an internal artifact: any external
system can independently verify a savings claim without trusting the service.

- **Spec:** [`docs/attestation-spec.md`](docs/attestation-spec.md) (spec id
  `sia-attestation/1`, carried in every document) with a machine-readable
  [`docs/attestation.schema.json`](docs/attestation.schema.json).
- **Independent verifier:** [`sia-verifier`](verifier/) — a standalone package
  (`pip install sia-verifier`, single dependency: `cryptography`) that verifies
  any attestation **without trusting the auditor**: Ed25519 receipt signature,
  claim consistency, TrustChain hash chain, checkpoints, Merkle
  inclusion/consistency proofs, and the `kid` → key table reconstructed from
  the chain (key rotation). No network calls.

  ```bash
  sia-verifier attestation.json --chain registry.jsonl \
    --issuer-key <BASE64_PUBKEY>
  ```

  `--issuer-key` is the trust anchor: the issuer's public key obtained
  **out-of-band**, not from the document being verified. Without it the
  verifier is fail-closed and will not report `VERDICT: VALID` (v1.6.0+).

  Walkthrough: [`docs/verify-in-5-minutes.md`](docs/verify-in-5-minutes.md).
- **Verification portal:** `GET /attestations/{id}` renders a human verdict
  (signature ✓/✗, chain ✓/✗, claim, badge embed snippet); `GET /registry` is
  the public HTML index. A **static export** of the same portal (verdicts
  computed by the independent verifier — not the service — ru/kk/en,
  `file://`-portable, no server needed) lives in [`portal/`](portal/) and is
  deploy-ready for GitHub Pages (`.nojekyll` + `404.html` included); regenerate
  it with `python scripts/export_portal.py`. The exporter refuses (exit 1) any
  record that fails independent verification. **Until Pages is enabled in the
  repository settings, open [`portal/index.html`](portal/index.html) directly
  from a clone — it is fully self-contained.**
- **Opt-in public registry:** tenants publish via
  `POST /v1/tenants/{id}/settings` (`publish_attestations: true`); only opted-in
  records appear in `GET /v1/attestations`. Individual attestations stay
  reachable by id (badges link to them).
- **Embed the badge:** (replace `sentinel.example.com` with your deployment domain)

  ```html
  <img src="https://sentinel.example.com/v1/attestations/{id}/badge.svg"
       alt="Proof-of-Savings attestation" />
  ```

- **Outbound webhooks:** subscribe a URL to `audit.completed` / `audit.failed`
  via `POST /v1/webhooks/subscriptions`. Deliveries are POSTed with an
  `X-SIA-Signature` header — HMAC-SHA256 over the raw body using the
  subscription secret (returned once at creation). Verify it to trust the
  sender:

  ```python
  import hmac, hashlib
  expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
  assert hmac.compare_digest(expected, request.headers["X-SIA-Signature"])
  ```

---

## Quick start (dev)

```bash
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

uvicorn sentinel.api:app --reload                 # API on http://localhost:8000
python -m unittest discover -s tests -t .         # run the test suite (state-isolated)
```

Interactive docs: `http://localhost:8000/docs`

### Run an audit (CLI)

```bash
# Simulated LLM-flow audit (no API keys needed)
python audit_cli.py --flow flows/example_llm_flow.json

# Live audit against NVIDIA NIM (set NVIDIA_API_KEY in .env, never inline)
python audit_cli.py --flow flows/live_llm_flow.json

# Savings Autopilot: pick the cheapest config that still passes
python audit_cli.py --flow flows/live_optimize.json
```

### Run an audit (Python SDK)

```python
from sia_sentinel import SentinelClient

client = SentinelClient("http://localhost:8000", api_key="sk-...")
result = client.run_audit(flow)
print(result["registry_id"], result["receipt"]["safety_approved"])

# Async + Autopilot
audit_id = client.submit_optimization(flow)
snapshot = client.wait_for_optimization(audit_id)
```

SDK source: [`sdk/sia_sentinel/`](sdk/sia_sentinel/) — pure `httpx`, no server-side imports.

### Self-service onboarding

New customers register without any operator involvement:

```python
from sia_sentinel import SentinelClient

# Creates the tenant (free plan) and returns a client holding its first
# admin API key — shown once, store it securely.
# Replace sentinel.example.com with your deployment domain.
client = SentinelClient.signup("https://sentinel.example.com", "Acme Corp")
client.run_audit(flow)

# The tenant admin then manages its own keys:
client.create_tenant_key("acme", "ci-key", role="user")
```

Privilege model: a **platform admin** (operator) manages all tenants, plans,
checkpoints and global keys; a **tenant admin** (the key returned by signup)
manages only its own tenant — keys, settings, webhooks, invoices viewing.
Tenant admins cannot see other tenants or change plans.

---

## Record №1 — the beacon and how to re-verify it yourself

The first publicly anchored record: a live GSM8K audit of
`gpt-oss-120b → gpt-oss-20b` (Groq, n=450, δ=5pp, preregistered in the
ledger before the run, commitment anchored in Sigstore Rekor). Verdict:
**non_inferior**, verified savings **50.5%** — with the pre-run prediction
(27.6% chance of a pass) published alongside the commitment.

An outsider re-derives the verdict from the published artifacts alone —
no trust in the auditor, no network except the public Rekor log:

```bash
# 1. Signature, chain, checkpoint (PyPI package, single dependency: cryptography):
pip install sia-verifier
sia-verifier artifacts/record1/attestation.json \
  --chain receipts/registry.jsonl --checkpoint receipts/checkpoints.jsonl
# 2. Re-derive the verdict itself (b/c, MOVER/McNemar, MDD, savings,
#    Rekor anchor digest, report→signature binding):
sia-rederive
```

Walkthrough with all eight checks explained:
[`docs/record1-how-to-reverify.md`](docs/record1-how-to-reverify.md).

## API overview

| Endpoint | Auth | Description |
|---|---|---|
| `POST /v1/audit` | user | Synchronous audit → signed receipt + registry entry |
| `POST /v1/audits` | user | Async audit (persistent queue, crash recovery) |
| `GET /v1/audits/{id}` | user | Job status (tenant-isolated) |
| `POST /v1/optimize` | user | Savings Autopilot run (async) |
| `GET /v1/optimize/{id}` | user | Optimization status |
| `GET /v1/receipts` / `GET /v1/receipts/{id}` | user | Receipt registry (tenant sees only its own receipts) |
| `GET /v1/ledger/head` | public | Chain head + Merkle tree head (`tree_size`, `root_hash`) |
| `GET /v1/ledger/verify` | public | Chain verification (incremental; `?full=true` from genesis) |
| `GET /v1/ledger/inclusion/{id}` | public | Merkle inclusion proof for an entry (RFC 6962) |
| `GET /v1/ledger/consistency?from=&to=` | public | Merkle consistency proof between two tree heads |
| `GET /v1/ledger/keys` | public | Key declarations (`kid` → public key history) |
| `POST /v1/ledger/checkpoint` | platform admin | Sign a checkpoint (chain + tree head) |
| `POST /v1/ledger/anchor` | platform admin | Checkpoint + publication to external anchor storage |
| `POST /v1/ledger/keys/rotate` | platform admin | Rotate the signing key (declared in the chain) |
| `GET /v1/attestations/{id}` | public | Portable attestation document |
| `GET /v1/attestations` | public | Public registry (opt-in tenants only) |
| `GET /v1/attestations/{id}/badge.svg` | public | Embeddable "verified savings" badge |
| `GET /attestations/{id}` / `GET /registry` | public | Verification portal (HTML) |
| `POST /v1/signup` | public | Self-service onboarding (tenant + first admin key) |
| `POST /v1/tenants/{id}/settings` | tenant/platform admin | Tenant settings (publish opt-in) |
| `POST/GET/DELETE /v1/tenants/{id}/api-keys` | tenant/platform admin | Tenant-scoped key management |
| `POST/GET/DELETE /v1/webhooks/subscriptions` | user | Outbound webhook subscriptions |
| `POST /v1/tenants` / `GET /v1/tenants` | platform admin | Tenant management |
| `POST/GET/DELETE /v1/auth/api-keys` | platform admin | Global key management |
| `GET /v1/usage` | user | Usage summary (billing basis) |
| `GET /v1/billing/plans` | public | Plan catalog |
| `GET /v1/billing/plan` / `POST /v1/billing/plan` | user / platform admin | Current quotas / plan change |
| `POST /v1/billing/invoices` / `GET /v1/billing/invoices` | platform admin / user | Invoice issue / list |

Quota enforcement: exceeding the monthly limit on a hard-cap plan returns
`402 Payment Required` with an upgrade hint. Paid plans allow overage, which is
itemized on the period invoice.

---

## Production deployment

```bash
export JWT_SECRET_KEY=$(openssl rand -hex 32)
export RECEIPT_SIGNING_KEY=$(openssl rand -hex 32)    # СВЕРЬТЕ С БЭКАПОМ
export EVIDENCE_SIGNING_KEY=$(openssl rand -hex 32)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)
export PLATFORM_ADMIN_API_KEY=$(openssl rand -hex 32) # админ для анкоринга
export DOMAIN=sentinel.yourdomain.com
export ACME_EMAIL=ops@yourdomain.com

# Bind-монты: контейнер пишет под uid 1000 — каталоги должны быть его
mkdir -p data logs && sudo chown -R 1000:1000 data logs

# Пред-проверка: рендерит compose с подстановками, ничего не запуская.
# Ошибки вложенной интерполяции (CORS-дефолт от DOMAIN) всплывают здесь,
# а не как загадочный CORS-сбой на работающем стеке.
docker compose -f docker-compose.prod.yml config >/dev/null

docker compose -f docker-compose.prod.yml up -d
```

`docker-compose.prod.yml` runs **Caddy (automatic TLS) + Sentinel +
PostgreSQL**. All secrets are required with no defaults — compose refuses to
start without them. Runtime data (receipts, tenants, usage, invoices, API
keys, anchors) lives in the host-visible `./data` directory, ready for
external sync.

Three things worth stating explicitly:

- **TLS is not cosmetic.** The badge embedded into any HTTPS page is blocked
  as mixed content over plain HTTP — without Caddy in front, the main viral
  element renders for no one, and API keys travel in cleartext. Sentinel
  itself publishes no ports; the only public surface is Caddy's 443.
- **`PLATFORM_ADMIN_API_KEY` bootstraps the operator.** On a fresh volume
  there is no way to become a platform admin (signup issues tenant admins,
  the demo login is off in prod) — while anchoring, checkpoints, key
  rotation and tenant management require exactly that privilege. At startup
  the key from this env is registered (hashed at rest, idempotent) as the
  `platform-admin-bootstrap` key.
- **Backup `RECEIPT_SIGNING_KEY` outside the server before day one.** Losing
  it without a prior key rotation makes every receipt issued so far
  unverifiable.

Dev compose (SQLite, no required secrets): `docker compose up`.

### Anchoring from record №1

The value of a transparent log is monotonic in its history: every day of
operation without external anchoring is a day you cannot later prove was not
rewritten. A checkpoint stored next to the log proves exactly nothing.

Note the exact acceptance criterion: you cannot anchor an empty ledger, so
"anchoring from record №1" means the cron and the external sync are
**installed and verified before the first audit**, and the first anchor
appears immediately after the first receipt — **checked with your own eyes**
both in `./data/anchors/` and in the external storage:

```bash
# cron: health-check + auto-anchor coverage gaps + alert a human on the rest,
# then sync the staging dir to external storage with an immutability policy
# (S3 Object Lock / WORM bucket, public git remote)
0 * * * * cd /srv/sentinel && docker compose -f docker-compose.prod.yml exec -T sentinel bash scripts/cron_ledger.sh
30 * * * * aws s3 sync /srv/sentinel/data/anchors/ s3://sentinel-anchors/ --exact-timestamps
```

`cron_ledger.sh` runs `ledger_health.py` (chain, key declarations, checkpoint
signatures, head coverage, Merkle root, anchor file), auto-anchors the current
head when the only problem is a coverage gap, re-runs the check, and alerts a
human (deduplicated, optional `ALERT_WEBHOOK_URL`) on anything it must not fix
by itself — a tampered chain or a bad signature is a human alert, because
auto-"fixing" those would be concealment. The underlying anchor script still
refuses to run without `RECEIPT_SIGNING_KEY` in the environment — an ephemeral
key would sign checkpoints that no verifier accepts, silently.
`ANCHOR_URL` is an alternative for **unauthenticated** ingest endpoints only
(it sends no Authorization header); for S3-style buckets use the file
transport + `aws s3 sync` from the host as above. An auditor then compares
the externally anchored `{seq, head_hash, tree_size, root_hash}` with the
live chain head — if it does not extend the anchor, history was rewritten.

One more day-one rule: do not advertise the deprecated firewall endpoints on
the public domain — they are off the product surface for a reason.

### Ledger mirror (WORM)

The ledger's append-only history is additionally publishable to a dedicated
public repository via [`scripts/mirror_ledger.py`](scripts/mirror_ledger.py):
three gates (local chain must be VALID; the mirror may only ever EXTEND the
published history — divergence is a human alert, not auto-recovery; only
trust-bearing paths are staged), exit codes are cron-friendly. Mechanism and
the remaining operator decision are documented in
[`docs/ledger-mirror.md`](docs/ledger-mirror.md).

---

## Security model

- **No secrets in code.** Signing keys come from env vars; if missing, the
  service generates an ephemeral key and prints a loud warning (receipts won't
  survive restarts — acceptable in dev only).
- **Demo login is off by default** (`ENABLE_DEMO_LOGIN`); demo credentials are
  for local evaluation only.
- **Live LLM credentials** are referenced by env var name in flows
  (`api_key_env`), never inlined into flow files or requests.
- **Tenant isolation** on jobs, receipts metadata, and invoices; RBAC roles:
  `admin`, `verifier`, `user`, `anonymous`.
- Gitignored runtime artifacts: `*.db`, `tenants.json`, `usage_events.jsonl`,
  `api_keys.json`, `invoices.json`, `receipts/`, `identities/`, `.env`.

## Project layout

```
sia/            Audit engine: flows, optimizer, model catalog, Wilson CI
sentinel/       API service: auth, tenancy, billing, jobs, receipts, ledger, webhooks
sdk/            Client SDK (sia_sentinel)
flows/          Flow declarations (code | llm_flow | optimize)
docs/           Attestation spec, JSON Schema, record-1 re-verification guide, holdout design, demand validation + outreach drafts
tests/          819 tests (unittest)
dashboard/      Streamlit dashboard
audit_cli.py    CLI: audit / optimize / sign / verify
```

## Status

Prototype-stage, fully working core: the first publicly anchored record
(beacon, Groq, 50.5% verified savings, non-inferior verdict — see the
Record №1 section above) plus 819 tests covering the audit engine, ledger,
tenancy, billing, jobs persistence, public attestation network,
self-service onboarding, the independent verifier (including verdict
re-derivation and the auditor-side holdout tool), and the SDK. Measured
coverage 77% (CI enforces a 75% floor); the uncovered remainder is
concentrated in dormant pre-beacon legacy modules — catalogued with a
keep/freeze verdict per module in [`docs/dead-code-inventory.md`](docs/dead-code-inventory.md)
(the Phase-2 refactoring plan governs what happens next). See
`SECURITY_REPORT.md` for the security review.

# SIA Sentinel — Security Report & Threat Model

**Last updated:** 2026-08-20
**Scope:** Sentinel API (`sentinel/`), audit engine (`sia/`), SDK (`sdk/`), deployment configs.

This document replaces the earlier auto-generated test summary. The product's
core claim — *"an independently verifiable receipt that does not require
trusting the auditor"* — makes the signing path itself the primary attack
surface, so this report is written around that threat model.

---

## 1. Threat Model

### 1.1 Assets

| Asset | Why it matters |
|---|---|
| Receipt signing key (`RECEIPT_SIGNING_KEY`) | Whoever holds it can forge savings receipts — the entire product's trust anchor |
| Evidence signing key (`EVIDENCE_SIGNING_KEY`) | Authenticity of stored evidence records |
| JWT secret (`JWT_SECRET_KEY`) | Session forgery → full API access |
| API keys store (`api_keys.json`) | Tenant authentication and authorization |
| TrustChain ledger (`receipts/registry.jsonl`) | Tamper-evident audit history; integrity is the product |
| Tenant data (usage, billing, settings) | Confidentiality and correct metering |

### 1.2 Trust boundaries

1. **API client → Sentinel.** Untrusted input. The API must never execute
   client-supplied code or read client-supplied file paths.
2. **CLI user → audit engine.** Trusted local input. `kind=code` audits run
   the user's own code in the user's own process — this is a feature, not a
   vulnerability, and is why code execution exists only behind the CLI.
3. **GitHub → webhook endpoint.** Authenticated only via HMAC signature;
   must fail closed when no secret is configured.
4. **Third-party verifier → published receipts.** Holds only the public key;
   must be able to detect any tampering, including receipt_id substitution.

### 1.3 Principal threats

| # | Threat | Mitigation |
|---|---|---|
| T1 | Remote code execution via audit API | `kind=code` rejected by API (`validate_api_flow`); code audits are CLI-only |
| T2 | Arbitrary file read via `*_file` flow keys | `*_file` keys rejected by API; CLI paths confined with `_safe_join` (resolve + `is_relative_to`) |
| T3 | Signing-key theft / receipt forgery | Strict public-key loading (no seed fallback); signing key only in env/HSM, never in responses |
| T4 | Receipt replay / substitution | `receipt_id` is covered by the Ed25519 commitment |
| T5 | Anonymous access to mutating endpoints | All mutating endpoints gated by `require_role`; platform ops by `require_platform_admin` |
| T6 | Webhook forgery | HMAC-SHA256 verification, fail-closed without a secret |
| T7 | Ledger corruption (multi-process) | `threading.Lock` + cross-process file lock around read-head/append; documented single-writer model |
| T8 | API-key store corruption | Atomic write (tmp file + `os.replace`), throttled `last_used` flush |
| T9 | Hung benchmark blocks auditor | Benchmark runs in a child process killed on timeout |
| T10 | Statistical overstatement of savings | Wilson CI counts tests, not repetitions; reported confidence level is the level actually used |

---

## 2. Audit Findings and Remediation Status

An external security audit (2026-08-20) identified the findings below. All
BLOCKER and HIGH findings are fixed; each fix is covered by regression tests.

### BLOCKER — fixed

| ID | Finding | Fix | Tests |
|---|---|---|---|
| B1 | RCE: `POST /v1/audit` with `kind=code` executed client code via `exec()` in the server process | `validate_api_flow()` rejects `kind=code` at the API layer; code audits remain CLI-only (trusted local input) | `test_audit_code_flow_rejected_via_api` |
| B2 | Auth bypass: `/v1/verify-change`, `/v1/risk-score`, `/v1/network/*` mutating endpoints accepted anonymous requests | All gated with `require_role(ADMIN, USER)`; quota metering applied per tenant | `test_gated_endpoints_reject_anonymous` |
| B3 | Path traversal: `*_file` flow keys joined with `os.path.join`, allowing absolute paths (`/etc/passwd`) | `*_file` keys banned in API; CLI uses `_safe_join` (resolve + containment check) | `test_audit_file_keys_rejected_via_api` |
| B4 | Statistical: (a) repetitions counted as independent trials, inflating Wilson CI; (b) `confidence_level` reported the requested level, not the one actually used | (a) CI built over test count; a test passes only if all repetitions pass. (b) `resolve_confidence()` reports the effective level | `test_repetitions_do_not_inflate_trials`, `test_confidence_level_reports_effective_level` |

### HIGH — fixed

| ID | Finding | Fix | Tests |
|---|---|---|---|
| H1 | `receipt_id` not covered by the signature → signature replay across receipts | `receipt_id` added to the signed commitment | `test_receipt_id_covered_by_signature` |
| H2 | `_load_public_key` silently derived a keypair from arbitrary seed material → a signing secret passed as "public key" was accepted | Strict loader: only base64 raw 32-byte public keys; anything else raises `ValueError` | `test_verifier_rejects_seed_material` |
| H3 | API-key store rewritten (truncate + write, no lock) on every request | Atomic write via tmp file + `os.replace`; `threading.Lock`; `last_used` flushed at most once per 60 s | auth test suite |
| H4 | Webhook signature check returned `True` when no secret was configured (fail-open) | Fail-closed: missing secret → reject | webhook handler |
| H5 | Benchmark timeout raised but the worker process kept running; `shutdown(wait=True)` joined the hung process | Benchmark runs in a managed `multiprocessing.Process`; on timeout it is terminated/killed, never joined indefinitely | `test_measure_time_kills_hung_worker` |
| H6 | Receipt registry used only `threading.Lock` — multiple processes on one directory could corrupt the chain | Cross-process file lock around read-head/append; single-writer model documented in the module docstring | receipt registry suite |

### Multi-tenant hardening (2026-09-30, all fixed)

A second audit of the SaaS layer (multi-tenancy / authz / billing) found and
fixed the following. Each fix has a regression test written to FAIL on the
pre-fix code (verified by mutation), not just to pass on it.

| ID | Severity | Finding | Fix | Tests |
|---|---|---|---|---|
| M1 | **CRITICAL** | Privilege escalation → cross-tenant data read: a tenant admin could self-issue an API key with `role=verifier` (`POST /v1/tenants/{id}/api-keys`). A VERIFIER key makes `_evidence_tenant_scope` return `None`, disabling the tenant filter, so `GET /v1/evidence`, `/v1/verifications/{id}`, `/v1/agents/{id}/history` returned **every** tenant's audit evidence. Path: signup → mint verifier key → read competitors' audits. | `role=verifier` may only be issued by a platform admin (`is_platform_admin`); self-service creation returns 403. | `test_tenant_admin_cannot_mint_verifier_key`, `test_platform_admin_can_still_mint_verifier_key` |
| M2 | HIGH | TOCTOU quota bypass: async submits checked the monthly quota before submit but usage was recorded only after completion, so a burst of parallel `POST /v1/audits` all passed the check against un-incremented usage and blew past the free-plan hard cap (the only path banks use for live models). | Quota slot is **reserved under a lock** at submit (`BillingEngine.reserve`); `check_quota` counts `recorded + in-flight reservations`. Released on success and on failure (so a failed job doesn't burn quota). | `test_concurrent_reserves_cannot_overbook`, `test_reserve_accounts_for_in_flight_jobs`, `test_release_returns_slot` |
| M3 | MED | Double usage accounting on crash recovery: a job could record usage then crash before its `completed` write; `recover()` re-ran it and usage was charged twice for one `audit_id` (double LLM spend, double receipt). | `UsageMeter.record` takes an `event_key`; async jobs pass `event_key=audit:<audit_id>`, making the write idempotent. | `test_usage_record_is_idempotent_by_event_key` |
| M4 | MED | Agent trust state was global, not tenant-scoped: state file and cache keyed by `agent_id` alone, so two tenants using the same `agent_id` shared (and could read/poison) one trust history via `/v1/agents/{id}/trust` and `/v1/verify-change`. | Trust state keyed by `(tenant_id, agent_id)` — both the state file and the in-memory cache. | covered by existing trust/tenancy suites (isolation asserted via distinct state files) |
| M5 | LOW | `/v1/risk-score` had no quota check while its sibling `/v1/verify-change` did → unmetered policy work. | Quota check added (`kind=code`). | `test_billing_api` quota coverage |

**Not changed (by design, documented):** `GET /v1/attestations/{registry_id}`
serves a single attestation by id regardless of the tenant's `publish_attestations`
opt-in. This is intentional — attestation badges must be embeddable and the
document independently verifiable — and `registry_id` is a `uuid4().hex`, not
guessable. Only the public *index* (`GET /v1/attestations`) honors the opt-in.

**Open product decision (not a code defect):** `POST /v1/signup` accepts a
caller-chosen `tenant_id`, so a third party could pre-register a meaningful id
(e.g. `halkbank`) and lock the real bank out of self-signup. Impact is limited
to onboarding friction (not data access), and in the founder-led sales motion
the platform assigns ids directly. Recommended hardening — self-service signup
issues an opaque id, and vanity ids are assigned by a platform admin — is a
breaking API change and is deferred to an explicit product decision.

### Known residual items (MEDIUM/LOW)

- **API key hashing** uses salted-at-rest SHA-256 without per-key salt; production deployments should front this with a database using bcrypt/argon2.
- **Demo login** (`ENABLE_DEMO_LOGIN=1`) uses fixed credentials; it is disabled by default and must never be enabled in production.
- **Rate limiting** is in-memory per process; use Redis-backed limiting for multi-instance deployments.
- **JWT** does not yet validate `iss`/`aud` claims (single-issuer deployment assumed).
- **Incremental chain verification** trusts the prefix verified earlier in the same process; `GET /v1/ledger/verify?full=true` re-verifies from genesis — run it (and compare against an external anchor) periodically.
- **HTTP anchor transport** does not verify what the remote endpoint stored; the guarantee comes from the external medium's immutability policy (WORM/object lock), not the POST.
- **Quota reservations are in-memory per process.** The 2026-09-30 TOCTOU fix reserves a slot in `BillingEngine._reservations` under a lock. That is correct for the current deployment (single `sentinel` container, single-process `uvicorn`, no `--workers`). If the service is ever scaled to **multiple workers or replicas**, the reservation counter (like the rate limiter above) becomes per-process and the guard would only hold within one instance — the reservation must then move to a shared store (Postgres/Redis) with a row-level check.

### External audit remediation (2026-08, 31 items — all closed)

Second-pass external audit (sections A–E: statistics, registry access, chain
integrity, operations, product hygiene) fully remediated:

| Group | What was done |
|---|---|
| A1–A6 (statistics) | Paired statistics for the code path (McNemar, Newcombe CI, non-inferiority with `delta`, MDD), CI-aware optimizer screening, Holm-Bonferroni multiplicity correction, honest simulation, paired stats + preregistration published in attestations, SDK preregistration lifecycle |
| B1–B4 (registry access) | `GET /v1/receipts` requires auth and is tenant-isolated; legacy endpoints gated by RBAC; billing accepts explicit `tenant_id` for platform admins |
| C1–C4 (chain integrity) | RFC 6962 Merkle accumulator with inclusion/consistency proofs and signed tree heads; incremental chain verification with anchor-checked cache; key rotation via `kid` + chain-declared keys; external checkpoint anchoring (file + HTTP transports) |
| D1–D14 (operations) | Working Makefile; full ruff+mypy in CI; tenant-isolated receipts; atomic state writes + crash-safe torn-tail ledger recovery; null-byte/control-char JSON validation in middleware; `X-Forwarded-For` only with `TRUST_PROXY=1`; SSRF guard on webhooks (subscribe + delivery); FastAPI metadata; compose volumes for all runtime state; fully state-isolated test suite (`discover -t .`) |
| E1–E7 (hygiene) | Positioning texts fixed; placeholder domains annotated; dated model pricing (`prices_as_of`, `catalog_version`) in manifests/commitments; simulated-mode caveats; E6 closed (required `expect_contains` validation + `caveat` field); E7 hardened — audited code never runs in the API process: test execution moved to killable child processes (timeout + terminate/kill; crash = test failure), and `kind=code` remains CLI-only; legacy firewall endpoints (`/v1/verify-change`, `/v1/risk-score`) marked `deprecated` — off the advertised surface, kept for existing integrations |

---

## 3. Security Controls

### Input validation
- `kind=code` and `*_file` keys rejected at the API boundary (`validate_api_flow`)
- CLI file access confined to the flow's base directory (`_safe_join`)
- XSS/SQLi pattern detection, length limits, null-byte sanitization on free-text fields
- Middleware JSON-body validation: null bytes and control characters rejected in any string field (universally unsafe content only — code fields legitimately contain `import`/`exec`, so dangerous-pattern matching stays endpoint-level)

### Authentication & authorization
- JWT (HS256, 24 h expiry) + API-key authentication
- RBAC: `ADMIN` / `VERIFIER` / `USER` / `ANONYMOUS`
- Platform-admin split: tenant admins cannot touch other tenants or platform ops
- Constant-time key comparison (`hmac.compare_digest`)
- Receipt registry tenant-isolated; anonymous access limited to published attestations and proof material

### Cryptography
- Ed25519 receipts; `receipt_id` + manifest + `kid` covered by the signature
- TrustChain: append-only JSONL hash chain + RFC 6962 Merkle tree with signed tree heads, inclusion/consistency proofs, and checkpoints (protocol v2 covers the tree head)
- Key rotation: `kid`-identified keys declared as chain entries signed by the active key; verifier reconstructs the `kid` → key table from the ledger alone
- HMAC-SHA256 outbound webhook signatures; GitHub webhook HMAC verification (fail-closed)
- Public key published at `/v1/receipt-public-key`; verification requires no secret
- External checkpoint anchoring (`/v1/ledger/anchor`, `scripts/anchor_checkpoint.py`) — file staging + HTTP transport for immutable external storage

### Network
- SSRF guard on webhook and anchor URLs: hostname resolution checked against private/loopback/link-local/reserved ranges (incl. cloud metadata `169.254.169.254`), enforced at subscription and at delivery (DNS-rebinding re-check)
- `X-Forwarded-For` honoured only when `TRUST_PROXY=1` (anti-spoofing for direct deployments)
- CORS origins configurable via `CORS_ALLOW_ORIGINS`; security headers on all responses

### Availability
- Persistent job queue with crash recovery
- Benchmark AND test execution of audited code isolated in killable child processes (timeout → terminate → kill; crash counts as test failure, never an auditor crash)
- Atomic persistence for keys/registry state (`mkstemp` + `fsync` + `os.replace`)
- Crash-safe ledger: durable single-line appends (`fsync`), torn trailing line detected/dropped/logged and physically truncated before the next append

---

## 4. Production Deployment Checklist

1. Set strong, unique values for `JWT_SECRET_KEY`, `RECEIPT_SIGNING_KEY`,
   `EVIDENCE_SIGNING_KEY`, `GITHUB_WEBHOOK_SECRET`, `POSTGRES_PASSWORD`
   (docker-compose.prod.yml marks all of these as required).
2. Do **not** set `ENABLE_DEMO_LOGIN`.
3. Terminate TLS in front of the API.
4. Rotate any signing keys that predate the H2 fix.
5. Keep `credentials/`, `identities/`, `.env` out of version control and images
   (enforced by `.gitignore` and `.dockerignore`).
6. Single writer per receipt ledger directory; move to a database before
   scaling writes horizontally.

---

## 5. Verification

- Full test suite: `python -m unittest discover -s tests -t .` (the `-t .` flag
  activates full state isolation — see `tests/__init__.py`; the penetration
  suite is included in discovery).
- Penetration suite alone: `python -m unittest tests.security.test_penetration -v`.
- Independent receipt/proof verification is exercised end-to-end in
  `tests/test_cryptographic_receipts.py`, `tests/test_receipt_registry.py` and
  `tests/test_sia_verifier.py` (including Merkle proofs and key rotation).

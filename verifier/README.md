# sia-verifier

**Independent verifier for `sia-attestation/1` Proof-of-Savings attestations.**

This package lets *anyone* verify an AI cost-savings attestation **without
trusting the auditor**. It needs the attestation document and the issuer's
public key **that you obtained out-of-band** (see *Trust anchor* below) — not
a key handed to you by the document being checked. No network calls, no
Sentinel server, no SDK.

## Why this exists

A Proof-of-Savings attestation claims: *"this AI workload was audited, the
savings are real, and here is cryptographic proof."* The whole point of the
claim is that you should not have to take the auditor's word for it. This
verifier is the reference implementation of that promise:

- **Operator trust anchor** — the signature is checked against a key *you*
  supply (`--issuer-key`), not one the attestation introduces. Without an
  anchor, anyone could mint a throwaway key and produce a "valid" forgery.
- **Ed25519 receipt signature** — the receipt (including `receipt_id` and the
  reproducibility manifest) is signed; any tampering breaks the signature.
- **Claim consistency** — the public claim must match the signed
  `safety_approved` field; a forged claim fails verification.
- **TrustChain hash chain** (optional) — given a ledger export, every entry is
  recomputed; removal, insertion, reorder or content tampering breaks it.
- **Checkpoints** (optional) — signed commitments pinning the chain head.

## Install

```bash
pip install sia-verifier
```

Single dependency: `cryptography`. Python 3.9+.

## CLI

```bash
# Verify an attestation against an out-of-band issuer key (RECOMMENDED, fail-closed)
sia-verifier attestation.json --issuer-key <BASE64_PUBKEY>

# Also verify the hash chain from a ledger export
sia-verifier attestation.json --chain registry.jsonl --issuer-key <BASE64_PUBKEY>

# Also verify a signed checkpoint, and require chain coverage by it
sia-verifier attestation.json --chain registry.jsonl \
  --checkpoint checkpoints.jsonl --require-coverage --issuer-key <BASE64_PUBKEY>

# Machine-readable verdict
sia-verifier attestation.json --json --issuer-key <BASE64_PUBKEY>
```

Exit code `0` = valid, `1` = invalid, `2` = input error — safe to wire into CI.

### Trust anchor — why `--issuer-key` is required for trust

An Ed25519 signature only proves *who signed*, **if you already know the
signer's key**. If the verifier takes the key from the attestation itself, the
check is self-referential: anyone can generate a throwaway key, sign a
fabricated receipt claiming a 99% saving, and the document would verify against
the very key it shipped with. Versions before **1.6.0** did exactly that.

So from **1.6.0**:

- **With `--issuer-key`** — the key inside the attestation must match the key
  you supply. A mismatch fails the verdict. This is the mode a counterparty
  should use.
- **Without `--issuer-key`** — the verifier is **fail-closed**: it will *not*
  report `VERDICT: VALID`, and prints `issuer trust: NOT ESTABLISHED`. This
  prevents a self-declared key from ever masquerading as independent proof.
- `--allow-self-declared-key` — opt-in for debugging / the issuer's own first
  run. Never use it to accept a third party's attestation.

## Python API

```python
import json
from sia_verifier import verify_attestation

attestation = json.load(open("attestation.json"))
# supply the issuer key you trust, obtained out-of-band
verdict = verify_attestation(attestation, expected_public_key="<BASE64_PUBKEY>")

assert verdict.valid, verdict.reasons
assert verdict.receipt_signature_valid
assert verdict.claim_consistent
assert verdict.trust_established
```

## What is NOT verified (by design)

- The `verification.*` fields inside the attestation are the *server's* live
  opinion and are deliberately ignored — they are not part of the signed
  commitment.
- This verifier checks cryptographic integrity and issuer authenticity (with
  `--issuer-key`), **not** whether the audit methodology was sound or the
  savings real in the business sense. Methodology is documented in the
  attestation's reproducibility manifest; use `sia-rederive` / `sia-replay`
  for that.

## Specification

The full format is defined by the `sia-attestation/1` specification
(commitment construction, hash chain, checkpoints). See the SIA Sentinel
repository, `docs/attestation-spec.md`.

## License

MIT

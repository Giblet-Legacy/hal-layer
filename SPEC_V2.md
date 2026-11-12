# SPEC V2 — hal-layer (P15 HAL)

SPEC_V2.md — the specification for the P15 HAL V2 hardening layer.

Function:
    This document specifies `hal_v2.py`, a layer over the frozen
    `hal.py` (SPEC 1.0.0). It adds multi-operator separation through
    signed λ attestations, per-domain ladder thresholds, an
    outcome-to-λ-observation mapping for P14, and a wrapper that
    appends verified seals to a P4 ledger. SPEC.md remains
    authoritative for v1; nothing here changes v1 behaviour.

Layer:     P15 — HAL
Depends:   hal.py (P15 v1.0.0), sign_v2.py (P2 v2.0.0),
           envelope_v2.py (P1 v2.0.0), ledger_v2.py (P4 v2 candidate,
           only for `append_seal_to_ledger`)
Consumed:  SC-OS, The Cockpit, The Legacy
Version:   SPEC_V2 1.1.0
Licence:   MSL-1.0
Author:    James Gilbert (Giblets Forge)

## 1. Input Rules (all functions)

- A number is an `int` or `float`, never a `bool`.
- Non-number where a number is required → **TypeError**.
- NaN or ±inf → **ValueError**. (v1 classified NaN and +inf as
  AUTHORITY, and accepted an inf λ into a seal that then could not be
  signed.)
- SPEC.md §3.1/§3.2 said "ValueError if lam is not a number"; v1
  raises TypeError and its tests accept either. V2 keeps TypeError
  (stack convention, as P14 V2) and this is recorded as a correction.
- `action_type`, `subject_id`, `rationale`: non-empty `str`
  (TypeError / ValueError). A seal with no rationale is a signature
  without accountability.

## 2. The Ladder

Default thresholds are SPEC.md §1 unchanged:

    {"NOVICE": 0.60, "TRUSTED": 1.00, "SENIOR": 1.50, "AUTHORITY": 2.00}

A thresholds dict must have exactly those four keys, finite numbers,
strictly ascending, and `NOVICE >= 0.60`. A domain may raise the
quarantine line; it may never lower it below 0.60 (CLAUDE.md:
"Quarantine applies below 0.60").

### 2.1 LadderRegistry
Caller-owned; no module-level instance.
- `register(name, thresholds) -> dict` — name non-empty str.
  Same name + same thresholds → no-op. Different thresholds →
  ValueError (Immutable Rule). No unregister.
- `get(name) -> dict` — a copy; unknown → KeyError.
- `names() -> list` (sorted), `in`, `len`.

### 2.2 tier_for_lambda(lam, thresholds=None) -> str
### 2.3 can_validate(lam, thresholds=None) -> bool

## 3. Separation

`separation` stays honest:

| value | meaning |
|---|---|
| `"none"` | no attestation, or the λ attestation was signed by the validator's own key |
| `"attested"` | the validator's λ was attested by a **different** key, and that attestation is embedded in the seal and verifies |

### 3.1 attest_lambda(validator_key_id, lam, timestamp, attester_private_key) -> dict
A P2-signed capsule:

    {"type": "hal.lambda_attestation", "version": "1.1.0",
     "validator_key_id": did:key, "lambda": float, "timestamp": float,
     "signature": {...}}

`validator_key_id` must decode as a did:key (ValueError).

### 3.2 verify_attestation(attestation, attester_public_key=None) -> bool
Shape check, then P2 V2 verification under the key named in its own
`signature.key_id`. If `attester_public_key` is given, the signer must
also be that key. Never raises on malformed content.

## 4. The Seal (version 1.1.0)

| key | value |
|---|---|
| seal_version | `"1.1.0"` |
| algorithm | `"Ed25519"` |
| decision | `"approve"` or `"refuse"` |
| action_type, subject_id, rationale | non-empty str |
| validator_lambda | finite number |
| validator_tier | tier under `ladder.thresholds` |
| ladder | `{"domain": str or null, "thresholds": {...}}` |
| separation | §3 |
| lambda_attestation | null or the §3.1 capsule |
| timestamp | finite number |
| signature | added by `sign_seal` (P2) |

The validator's identity is `signature.key_id`. SPEC.md §2 listed a
top-level `key_id`; v1 never emitted one and V2 does not either — the
signed `signature.key_id` is the single source.

The ladder thresholds are recorded so the tier can be recomputed from
the seal alone.

### 4.1 create_seal(decision, action_type, subject_id, rationale, validator_lambda, timestamp, *, registry=None, domain=None, attestation=None, attester_public_key=None) -> dict
- `registry` and `domain` both or neither (ValueError);
  registry not a LadderRegistry → TypeError.
- Quarantined under the ladder → ValueError.
- With `attestation`: `attester_public_key` is required (the caller's
  trust decision); the attestation must verify under it, its `lambda`
  must equal `validator_lambda` exactly, and its `timestamp` must be
  ≤ the seal timestamp. Otherwise ValueError.

### 4.2 sign_seal(seal, private_key) -> dict
- private_key not Ed25519PrivateKey → TypeError.
- Seal must be a well-formed unsigned V2 seal → else ValueError.
- With an attestation, its `validator_key_id` must be the signer's
  did:key → else ValueError (no signing on another's attested λ).
- Signs via P2 V2 `sign_capsule`. Input never mutated.

### 4.3 verify_seal(seal, public_key, attester_public_key=None) -> bool
- public_key not Ed25519PublicKey → TypeError.
- V1 seals (no `seal_version`) are verified to SPEC.md: v1 shape,
  `separation == "none"`, tier recomputed from default thresholds,
  then P2 V2.
- V2 seals: full shape, tier recomputation, not quarantined,
  separation consistent with the attestation, attestation verifies
  and names the seal signer, then P2 V2.
- Anything malformed → False, never an exception.

## 5. Outcome → λ Observation

### 5.1 outcome_observation(seal, public_key, outcome, timestamp, deltas=None, confidence=1.0) -> dict
Returns a P14 observation `{"timestamp", "value", "confidence"}`.
It does not update λ — the caller feeds it into P14 `compute_lambda`.
(NOTES decision "no automatic λ updates" stands.)

- `seal` must verify under `public_key` → else ValueError.
- `outcome` in `deltas` (default `{"upheld": +0.10, "overturned": -0.25}`;
  trust is lost faster than earned). A deltas dict must have exactly
  those two keys, finite, `upheld >= 0`, `overturned <= 0`.
- `timestamp` ≥ seal timestamp (an outcome cannot precede its decision).
- `confidence` finite in [0, 1].
- `value = max(0.01, validator_lambda + delta)` (P11 requires value > 0).

## 6. Ledger

### 6.1 append_seal_to_ledger(ledger_path, seal, seal_public_key, ledger_private_key) -> dict
- `verify_seal(seal, seal_public_key)` must be True → else ValueError.
  Unverified seals never reach the ledger.
- Then P4 V2 `append_entry(ledger_path, seal, ledger_private_key)`;
  returns the entry. The ledger key may differ from the seal key.
- P4 is imported lazily, so the rest of HAL V2 works without it.

## 7. Known Limitations (P15 V2 1.1.0)

- An attestation proves a key vouched for a λ; whether that key is
  trustworthy is the caller's decision (`attester_public_key`).
- No attestation expiry. Only "not after the seal" is enforced.
- Outcome deltas are flat across tiers.
- The registry is in-memory per caller; persisting ladders is P9/P8's job.
- `append_seal_to_ledger` depends on P4 V2, which is an unfrozen
  candidate at the time of writing.

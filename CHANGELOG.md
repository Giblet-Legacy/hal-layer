# CHANGELOG — hal-layer (P15 HAL)

CHANGELOG.md — build history for P15 HAL, latest entry at top.

## [v1.1.0] — 2026-11-12

### Good
- Laptop audit per PROMPT_P15.md: v1 confirmed 18/18 green.
- `hal_v2.py` added as a layer over v1 (v1 untouched), specified in
  `SPEC_V2.md`, tested by `test_hal_v2.py`. 83/83 tests pass
  (18 v1 + 65 V2), from the repo root and from any other directory.
- All four suggested hardenings adopted:
  - Multi-operator separation: `attest_lambda` lets a different key
    sign a validator's λ; the attestation is embedded in the seal and
    re-verified. `separation` is `"attested"` only when that key
    differs from the seal signer; otherwise it stays `"none"`.
  - Outcome → λ: `outcome_observation` turns a verified seal plus
    `"upheld"`/`"overturned"` into a P14 observation (+0.10 / −0.25 by
    default). It does not update λ itself. A test feeds it to P14 V2.
  - Domain ladders: `LadderRegistry`; a domain may raise the
    quarantine line, never lower it below 0.60. Thresholds are
    recorded in the seal so the tier can be recomputed.
  - `append_seal_to_ledger` wraps P4 V2 and refuses unverified seals.
- `verify_seal` (V2) also verifies v1 seals, and rejects signed seals
  whose recorded tier does not match their λ.
- `conftest.py` puts the sibling layers on sys.path relative to the
  repo, so pytest runs from any directory.

### Bad
- Audit found v1 classifies NaN and +inf λ as AUTHORITY.
- v1 accepts an inf λ into a seal that then cannot be signed (P1
  refuses non-finite floats), breaking "every validation produces a
  signed seal".
- v1 seals any type for action_type/subject_id/rationale/timestamp
  (e.g. None, 123, "notatime").
- v1 resolves sibling paths against the CWD, so pytest failed outside
  the repo root (collection error). Fixed by `conftest.py`.
- README status still read "0.0.0-dev" after the v1.0.0 freeze, and
  the scaffold CHANGELOG entry had no header. Corrected.
- All v1 defects fixed in V2, not in v1 (Immutable Rule).

### Ugly
- SPEC.md §3.1/§3.2 say ValueError for a non-number λ; v1 raises
  TypeError and its tests accept either. V2 keeps TypeError (stack
  convention); recorded in SPEC_V2 §1 and NOTES.
- SPEC.md §2 lists a top-level `key_id` in the seal; v1 never emits
  one. V2 treats `signature.key_id` as the single source.
- v1 names P14 as its dependency but never calls it; the λ is taken
  on trust from the caller. V2 attestations are the answer to that.
- `append_seal_to_ledger` depends on P4 V2, still an unfrozen
  candidate. The phone needs P2 v2.0.0, P4 V2, and (for one test)
  P14 v1.1.0 checked out as siblings.

## [v1.0.0] — 2026-11-12

### Good
- `hal.py` implemented to SPEC v1.0.0.
- 18/18 pytest tests pass.
- Five-tier ladder enforced (QUARANTINED, NOVICE, TRUSTED, SENIOR, AUTHORITY).
- Quarantine applied below λ = 0.60.
- Signed seals (including refusals) via P2.
- `separation: "none"` recorded honestly for single-operator mode.

### Bad
- (none)

### Ugly
- (none)

## [0.0.0-dev] — scaffold

### Good
- Repository scaffolded: `Giblet-Legacy/hal-layer` created for P15.
- Depends on P14 Leighton Engine v1.0.0.

### Bad
- (none)

### Ugly
- (none)

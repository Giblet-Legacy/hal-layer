# NOTES — hal-layer (P15 HAL)

NOTES.md — open questions, divergences and decisions for P15 HAL.

## Open questions
- (none)

## Divergences from v1.2.1 specification
- (none)

## Decisions
- 2026-11-13 — Where a seal lives on a claim is now defined by P9
  SPEC_V3 §3: `substrate_v3.link_attestation` stores it as evidence
  of kind `attestation` (approve) or `refusal` (refuse). P15 is
  unchanged; consumers call `verify_seal` first, then link it, as
  well as appending it to the ledger. Recorded by the VS Code AI on
  James's delegation ("fix all 11 issues").
- Tier thresholds (0.60, 1.00, 1.50, 2.00) are the v1.0.0 defaults.
  These match the "quarantine below 0.60" rule from the architecture.
- `separation: "none"` is unconditional in v1.0.0. This is the
  honest record that single-operator mode cannot prove key
  separation. Papering over it with a fake "verified" flag would
  violate the stack's disclosure principles.
- Refusals produce seals. A refusal is an event, not silence. The
  alternative — logging only approvals — would let a validator
  quietly decline and leave no trace.
- The seal's `subject_id` is whatever the caller passes. In practice
  this is the content-addressed hash of the action being validated
  (capsule hash or ledger entry hash).
- No automatic λ updates from seal outcomes. That coupling lives in
  a consumer, not in P15.

## Decisions — V2 (v1.1.0, laptop audit)
- V2 is a new file (`hal_v2.py`); `hal.py` is frozen and untouched.
- Non-number λ → TypeError, NaN/inf → ValueError (stack convention,
  as P14 V2). This corrects the wording of SPEC.md §3.1/§3.2.
- The validator's identity is `signature.key_id`. No top-level
  `key_id` (SPEC.md §2 listed one; v1 never emitted it).
- Separation is proven, not claimed: `"attested"` requires an
  embedded λ attestation, signed by a key other than the seal signer,
  that verifies. A self-signed attestation records `"none"`.
- `create_seal` requires the caller to name the attester key it
  trusts. `verify_seal` checks attestation integrity on its own and
  pins the attester only if one is passed.
- Domain ladders may raise the quarantine line, never lower it below
  0.60. Re-registering a domain with different thresholds is refused.
- Outcome mapping returns a P14 observation and stops there; it does
  not update λ. This keeps the v1 decision above intact. Deltas are
  asymmetric (+0.10 upheld, −0.25 overturned): trust is lost faster
  than earned. Value floored at 0.01 (P11 requires value > 0).
- `rationale` must be non-empty in V2. A seal without a reason is a
  signature without accountability.
- `append_seal_to_ledger` verifies before appending; the ledger key
  may differ from the seal key. P4 is imported lazily.

## Open questions — V2
- Should attestations expire (max age relative to the seal)?
- Should outcome deltas scale by tier?

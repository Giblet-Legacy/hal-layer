# NOTES — hal-layer (P15 HAL)

NOTES.md — open questions, divergences and decisions for P15 HAL.

## Open questions
- (none)

## Divergences from v1.2.1 specification
- (none)

## Decisions
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

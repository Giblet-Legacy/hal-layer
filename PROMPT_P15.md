# P15 HAL — Laptop Audit Prompt

P15 hal-layer is frozen at v1.0.0 on the phone with 18/18 tests passing.

## Your Task

1. Pull `Giblet-Legacy/hal-layer`.
2. Audit against SPEC.md and CHANGELOG.md.
3. Run `pytest -q` — expect 18 passed.
4. If you find gaps, create `hal_v2.py` (do NOT edit v1).
5. Suggested V2 hardening: support multi-operator separation, add outcome-to-λ-delta mapping, add domain-specific ladder thresholds, add an `append_seal_to_ledger` function that wraps P4.
6. Push when green so the phone can verify.

# Forge Stack Context — P15 HAL

CLAUDE.md — Context briefing for AI assistants working in this repository.

## The Immutable Rule
Never rewrite a primitive. Add a layer.

## Dual-Device Workflow
We build on an S24 (Termux) and a laptop (VS Code). State is confirmed, never assumed. Always use LF line endings. Commit messages must be clear. We use the Good/Bad/Ugly CHANGELOG format (latest at top).

## Header Discipline
Every file MUST have a top header paragraph explaining its function.
Every function MUST have a numbered header.

## P15 Architecture Specifics
- Depends on `leighton_engine` (P14).
- The Human Accountability Layer.
- Five-tier ladder of validator roles gated by λ thresholds.
- Quarantine applies below 0.60.
- Every validation (including refusals) produces a signed seal.
- Single-operator mode records `separation: "none"` honestly.
- Named in homage to HAL 9000. Homage, not aspiration.

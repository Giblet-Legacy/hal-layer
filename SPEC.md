# SPEC — hal-layer (P15 HAL)

SPEC.md — the complete layer specification for P15 HAL.

Function:
    This document is the authoritative specification for primitive
    layer P15 of the Forge Stack. It defines the Human Accountability
    Layer: the five-tier ladder, quarantine, and signed seals.

Layer:     P15 — HAL
Depends:   P14 Leighton Engine
Consumed:  SC-OS, The Cockpit, The Legacy
Version:   SPEC 1.0.0
Licence:   MSL-1.0
Author:    James Gilbert (Giblets Forge)

## 1. The Five-Tier Ladder

Human validators are tiered by their current λ (the Leighton Weight
from P14). The tiers are:

    QUARANTINED  — λ < 0.60        (cannot validate)
    NOVICE       — 0.60 ≤ λ < 1.00
    TRUSTED      — 1.00 ≤ λ < 1.50
    SENIOR       — 1.50 ≤ λ < 2.00
    AUTHORITY    — λ ≥ 2.00

Quarantine applies below 0.60. A quarantined validator cannot
approve or refuse any action — the seal function raises ValueError.

Thresholds are fixed in v1.0.0. Governance per domain is a v2
concern.

## 2. The Signed Seal

Every human validation — including refusals — produces a signed
seal. A refusal is not silence; it is an event that must be
recorded.

Seal structure:

    {
      "algorithm": "Ed25519",
      "key_id": "did:key:z6Mk...",
      "decision": "approve" | "refuse",
      "action_type": str,
      "subject_id": str,
      "rationale": str,
      "validator_lambda": float,
      "validator_tier": str,
      "separation": "none",
      "timestamp": float
    }

The `separation` field records the single-operator fact: in v1, the
same did:key that signs a validator's own λ evidence also signs the
seal. `separation: "none"` is honest. It does not pretend to be
separation that does not exist.

## 3. Function Contracts

### 3.1 tier_for_lambda(lam: float) -> str
- Returns one of QUARANTINED, NOVICE, TRUSTED, SENIOR, AUTHORITY.
- Raises ValueError if lam is not a number.

### 3.2 can_validate(lam: float) -> bool
- Returns True if lam >= 0.60, False otherwise.
- Raises ValueError if lam is not a number.

### 3.3 create_seal(decision, action_type, subject_id, rationale, validator_lambda, timestamp) -> dict
- Builds the seal dict (unsigned).
- Raises ValueError if validator_lambda is quarantined.
- Raises ValueError if decision not in {"approve", "refuse"}.

### 3.4 sign_seal(seal: dict, private_key) -> dict
- Signs the seal via P2's sign_capsule.
- Returns the signed seal with `signature` populated.

### 3.5 verify_seal(seal: dict, public_key) -> bool
- Verifies the seal via P2's verify_capsule.
- Returns True if valid, False otherwise.

## 4. Known Limitations (P15 v1.0.0)

- Single-operator mode only. `separation: "none"` is set
  unconditionally. Multi-operator separation is a v2 concern.
- Ladder thresholds are fixed. Governance per domain is a v2
  concern.
- No coupling to a specific ledger. The caller is responsible
  for appending seals to P4/P8. P15 produces signed seals; storage
  is delegated.
- No outcome-to-λ-delta mapping. Recording the outcome of a
  validation and adjusting the validator's λ is a consumer concern
  for v1.

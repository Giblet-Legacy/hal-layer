"""
hal.py — P15 HAL primitive layer

Function:
    The Human Accountability Layer. Enforces the five-tier ladder,
    applies quarantine below λ = 0.60, and generates signed seals
    for every human validation, including refusals.

Public API:
    1. tier_for_lambda — Returns the tier for a given λ.
    2. can_validate    — Returns True if λ >= 0.60 (not quarantined).
    3. create_seal     — Builds an unsigned seal dict.
    4. sign_seal       — Signs the seal via P2.
    5. verify_seal     — Verifies the seal via P2.

Layer:    P15 — HAL
Depends:  P14 Leighton Engine, P2 Sign
Consumed: SC-OS, The Cockpit, The Legacy
Version:  1.0.0 (on freeze; 0.0.0-dev until then)
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import os
import sys

sys.path.insert(0, os.path.abspath('../envelope-layer'))
sys.path.insert(0, os.path.abspath('../sign-layer'))
import sign

_QUARANTINE_THRESHOLD = 0.60

# ---------------------------------------------------------------------------
# 1. tier_for_lambda
#    Maps λ to a tier. Quarantine below 0.60.
# ---------------------------------------------------------------------------
def tier_for_lambda(lam):
    if not isinstance(lam, (int, float)) or isinstance(lam, bool):
        raise TypeError("lambda must be a number")
    if lam < _QUARANTINE_THRESHOLD:
        return "QUARANTINED"
    if lam < 1.00:
        return "NOVICE"
    if lam < 1.50:
        return "TRUSTED"
    if lam < 2.00:
        return "SENIOR"
    return "AUTHORITY"

# ---------------------------------------------------------------------------
# 2. can_validate
#    Returns True if lam >= 0.60 (not quarantined).
# ---------------------------------------------------------------------------
def can_validate(lam):
    if not isinstance(lam, (int, float)) or isinstance(lam, bool):
        raise TypeError("lambda must be a number")
    return lam >= _QUARANTINE_THRESHOLD

# ---------------------------------------------------------------------------
# 3. create_seal
#    Builds the unsigned seal dict. Rejects quarantined validators
#    and invalid decision values.
# ---------------------------------------------------------------------------
def create_seal(decision, action_type, subject_id, rationale, validator_lambda, timestamp):
    if decision not in ("approve", "refuse"):
        raise ValueError(f"decision must be 'approve' or 'refuse', got {decision!r}")
    if not can_validate(validator_lambda):
        raise ValueError(
            f"validator λ={validator_lambda} is below quarantine threshold "
            f"({_QUARANTINE_THRESHOLD}); validation refused"
        )
    return {
        "algorithm": "Ed25519",
        "decision": decision,
        "action_type": action_type,
        "subject_id": subject_id,
        "rationale": rationale,
        "validator_lambda": validator_lambda,
        "validator_tier": tier_for_lambda(validator_lambda),
        "separation": "none",
        "timestamp": timestamp,
    }

# ---------------------------------------------------------------------------
# 4. sign_seal
#    Signs the seal via P2's sign_capsule. Returns the signed dict.
# ---------------------------------------------------------------------------
def sign_seal(seal, private_key):
    return sign.sign_capsule(seal, private_key)

# ---------------------------------------------------------------------------
# 5. verify_seal
#    Verifies the seal via P2's verify_capsule.
# ---------------------------------------------------------------------------
def verify_seal(seal, public_key):
    return sign.verify_capsule(seal, public_key)

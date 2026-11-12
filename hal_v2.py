"""
hal_v2.py — P15 HAL hardening layer (V2)

Function:
    A layer over hal.py (v1.0.0, frozen). It does not rewrite the
    primitive. It adds multi-operator separation through signed λ
    attestations, caller-owned per-domain ladder thresholds, a mapping
    from validation outcomes to P14 λ observations, and a wrapper that
    appends only verified seals to a P4 ledger. Every signature is made
    and checked by P2 V2 (sign_v2); nothing here re-implements crypto.
    Pure apart from append_seal_to_ledger: no clock reads, no
    module-level mutable state. Specified by SPEC_V2.md.

    Gaps in v1 closed here:
      - NaN and +inf λ were classified AUTHORITY.
      - An inf λ produced a seal that could not then be signed,
        breaking "every validation produces a signed seal".
      - action_type, subject_id, rationale and timestamp were not
        type-checked (None or ints were sealed).
      - Sibling import paths were resolved against the CWD, so pytest
        failed outside the repo root (fixed for v1 by conftest.py).
      - verify_seal checked only the signature, not that the recorded
        tier matched the recorded λ.

Public API:
    1. tier_for_lambda       — tier for λ under a ladder
    2. can_validate          — True if λ is not quarantined
    3. LadderRegistry        — caller-owned domain → thresholds map
    4. attest_lambda         — sign a λ attestation for a validator
    5. verify_attestation    — check an attestation (never raises on content)
    6. create_seal           — build an unsigned V2 seal
    7. sign_seal             — sign a V2 seal via P2 V2
    8. verify_seal           — verify a v1 or V2 seal
    9. outcome_observation   — seal outcome → P14 observation
    10. append_seal_to_ledger — verified seal → P4 V2 ledger entry

Layer:    P15 — HAL
Depends:  hal.py (P15 v1.0.0), sign_v2.py (P2 v2.0.0),
          envelope_v2.py (P1 v2.0.0), ledger_v2.py (P4 V2, lazy)
Consumed: SC-OS, The Cockpit, The Legacy
Version:  1.1.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import copy
import math
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _name in ("ledger-layer", "sign-layer", "envelope-layer"):
    _path = os.path.normpath(os.path.join(_HERE, "..", _name))
    if _path not in sys.path:
        sys.path.insert(0, _path)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import envelope_v2  # noqa: E402
import sign_v2  # noqa: E402

import hal  # noqa: E402,F401  (v1, kept importable alongside V2)

SEAL_VERSION = "1.1.0"
ATTESTATION_TYPE = "hal.lambda_attestation"
QUARANTINE_FLOOR = 0.60
TIER_KEYS = ("NOVICE", "TRUSTED", "SENIOR", "AUTHORITY")
DEFAULT_THRESHOLDS = {"NOVICE": 0.60, "TRUSTED": 1.00, "SENIOR": 1.50, "AUTHORITY": 2.00}
DEFAULT_OUTCOME_DELTAS = {"upheld": 0.10, "overturned": -0.25}
MIN_OBSERVATION_VALUE = 0.01

_DECISIONS = ("approve", "refuse")
_SEPARATIONS = ("none", "attested")
_V1_SEAL_KEYS = {
    "algorithm", "decision", "action_type", "subject_id", "rationale",
    "validator_lambda", "validator_tier", "separation", "timestamp",
}
_V2_SEAL_KEYS = _V1_SEAL_KEYS | {"seal_version", "ladder", "lambda_attestation"}
_ATTESTATION_KEYS = {"type", "version", "validator_key_id", "lambda", "timestamp", "signature"}


# ---------------------------------------------------------------------------
# 11. _is_number (internal)
#     int or float, never bool.
# ---------------------------------------------------------------------------
def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


# ---------------------------------------------------------------------------
# 12. _check_finite (internal)
#     TypeError for non-numbers, ValueError for NaN/±inf (SPEC_V2 §1).
# ---------------------------------------------------------------------------
def _check_finite(name, value):
    if not _is_number(value):
        raise TypeError(f"{name} must be a number, got {type(value).__name__}")
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite, got {value!r}")


# ---------------------------------------------------------------------------
# 13. _check_text (internal)
#     Non-empty str (SPEC_V2 §1).
# ---------------------------------------------------------------------------
def _check_text(name, value):
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{name} must not be empty")


# ---------------------------------------------------------------------------
# 14. _check_thresholds (internal)
#     SPEC_V2 §2. Returns a normalised copy; None → defaults.
# ---------------------------------------------------------------------------
def _check_thresholds(thresholds):
    if thresholds is None:
        return dict(DEFAULT_THRESHOLDS)
    if not isinstance(thresholds, dict):
        raise TypeError("thresholds must be a dict")
    if set(thresholds) != set(TIER_KEYS):
        raise ValueError(f"thresholds must have exactly the keys {TIER_KEYS}")
    for key in TIER_KEYS:
        _check_finite(f"thresholds[{key!r}]", thresholds[key])
    values = [thresholds[key] for key in TIER_KEYS]
    if any(a >= b for a, b in zip(values, values[1:])):
        raise ValueError("thresholds must be strictly ascending NOVICE < TRUSTED < SENIOR < AUTHORITY")
    if values[0] < QUARANTINE_FLOOR:
        raise ValueError(f"NOVICE threshold may not be below the quarantine floor {QUARANTINE_FLOOR}")
    return {key: thresholds[key] for key in TIER_KEYS}


# ---------------------------------------------------------------------------
# 15. _tier (internal)
#     Tier for an already-validated λ and thresholds.
# ---------------------------------------------------------------------------
def _tier(lam, thresholds):
    for key in reversed(TIER_KEYS):
        if lam >= thresholds[key]:
            return key
    return "QUARANTINED"


# ---------------------------------------------------------------------------
# 1. tier_for_lambda
#    SPEC_V2 §2.2. Default thresholds equal SPEC.md §1.
# ---------------------------------------------------------------------------
def tier_for_lambda(lam, thresholds=None):
    _check_finite("lambda", lam)
    return _tier(lam, _check_thresholds(thresholds))


# ---------------------------------------------------------------------------
# 2. can_validate
#    SPEC_V2 §2.3. True unless quarantined under the ladder.
# ---------------------------------------------------------------------------
def can_validate(lam, thresholds=None):
    return tier_for_lambda(lam, thresholds) != "QUARANTINED"


# ---------------------------------------------------------------------------
# 3. LadderRegistry
#    SPEC_V2 §2.1. Caller-owned. Re-registering with different
#    thresholds is refused (Immutable Rule). No unregister.
# ---------------------------------------------------------------------------
class LadderRegistry:
    # 3.1 __init__ — empty registry
    def __init__(self):
        self._ladders = {}

    # 3.2 register — add a domain ladder, or no-op if identical
    def register(self, name, thresholds):
        _check_text("name", name)
        normalised = _check_thresholds(thresholds)
        existing = self._ladders.get(name)
        if existing is not None and existing != normalised:
            raise ValueError(f"ladder {name!r} already registered with different thresholds")
        self._ladders[name] = normalised
        return dict(normalised)

    # 3.3 get — copy of a domain's thresholds; KeyError if unknown
    def get(self, name):
        if name not in self._ladders:
            raise KeyError(name)
        return dict(self._ladders[name])

    # 3.4 names — sorted domain names
    def names(self):
        return sorted(self._ladders)

    # 3.5 __contains__ / __len__
    def __contains__(self, name):
        return name in self._ladders

    def __len__(self):
        return len(self._ladders)


# ---------------------------------------------------------------------------
# 16. _decode_did (internal)
#     did:key → Ed25519PublicKey, or None if it does not decode.
# ---------------------------------------------------------------------------
def _decode_did(did):
    if not isinstance(did, str):
        return None
    try:
        key = envelope_v2.did_key_decode(did)
    except Exception:  # any decode failure means "not a did:key"
        return None
    return key if isinstance(key, Ed25519PublicKey) else None


# ---------------------------------------------------------------------------
# 17. _signer_did (internal)
#     signature.key_id of a signed capsule, or None.
# ---------------------------------------------------------------------------
def _signer_did(capsule):
    sig = capsule.get("signature") if isinstance(capsule, dict) else None
    return sig.get("key_id") if isinstance(sig, dict) else None


# ---------------------------------------------------------------------------
# 4. attest_lambda
#    SPEC_V2 §3.1. An attester signs "this validator's λ is lam at ts".
# ---------------------------------------------------------------------------
def attest_lambda(validator_key_id, lam, timestamp, attester_private_key):
    if not isinstance(attester_private_key, Ed25519PrivateKey):
        raise TypeError("attester_private_key must be Ed25519PrivateKey")
    _check_text("validator_key_id", validator_key_id)
    if _decode_did(validator_key_id) is None:
        raise ValueError("validator_key_id is not a valid did:key")
    _check_finite("lambda", lam)
    _check_finite("timestamp", timestamp)
    capsule = {
        "type": ATTESTATION_TYPE,
        "version": SEAL_VERSION,
        "validator_key_id": validator_key_id,
        "lambda": lam,
        "timestamp": timestamp,
    }
    return sign_v2.sign_capsule(capsule, attester_private_key)


# ---------------------------------------------------------------------------
# 5. verify_attestation
#    SPEC_V2 §3.2. Shape, then P2 V2 under the embedded signer key,
#    optionally pinned to attester_public_key. False on any problem.
# ---------------------------------------------------------------------------
def verify_attestation(attestation, attester_public_key=None):
    if attester_public_key is not None and not isinstance(attester_public_key, Ed25519PublicKey):
        raise TypeError("attester_public_key must be Ed25519PublicKey")
    if not isinstance(attestation, dict) or set(attestation) != _ATTESTATION_KEYS:
        return False
    if attestation["type"] != ATTESTATION_TYPE or attestation["version"] != SEAL_VERSION:
        return False
    if _decode_did(attestation["validator_key_id"]) is None:
        return False
    for key in ("lambda", "timestamp"):
        value = attestation[key]
        if not _is_number(value) or not math.isfinite(value):
            return False
    signer = _decode_did(_signer_did(attestation))
    if signer is None:
        return False
    if attester_public_key is not None and (
        envelope_v2.did_key_encode(attester_public_key) != _signer_did(attestation)
    ):
        return False
    return sign_v2.verify_capsule(attestation, signer)


# ---------------------------------------------------------------------------
# 18. _separation_for (internal)
#     "attested" only when a different key vouched for the λ.
# ---------------------------------------------------------------------------
def _separation_for(attestation):
    if attestation is None:
        return "none"
    if _signer_did(attestation) == attestation["validator_key_id"]:
        return "none"
    return "attested"


# ---------------------------------------------------------------------------
# 19. _v2_seal_problem (internal)
#     Returns a reason string if the V2 seal body is malformed, else None.
#     Shared by sign_seal (raises) and verify_seal (returns False).
# ---------------------------------------------------------------------------
def _v2_seal_problem(seal, signed):
    if not isinstance(seal, dict):
        return "seal must be a dict"
    expected = _V2_SEAL_KEYS | ({"signature"} if signed else set())
    if set(seal) != expected:
        return "seal keys do not match SPEC_V2 §4"
    if seal["seal_version"] != SEAL_VERSION or seal["algorithm"] != "Ed25519":
        return "unsupported seal_version or algorithm"
    if seal["decision"] not in _DECISIONS:
        return "decision must be 'approve' or 'refuse'"
    for key in ("action_type", "subject_id", "rationale"):
        if not isinstance(seal[key], str) or not seal[key]:
            return f"{key} must be a non-empty str"
    for key in ("validator_lambda", "timestamp"):
        if not _is_number(seal[key]) or not math.isfinite(seal[key]):
            return f"{key} must be a finite number"
    ladder = seal["ladder"]
    if not isinstance(ladder, dict) or set(ladder) != {"domain", "thresholds"}:
        return "ladder must be {domain, thresholds}"
    if ladder["domain"] is not None and (not isinstance(ladder["domain"], str) or not ladder["domain"]):
        return "ladder.domain must be null or a non-empty str"
    try:
        thresholds = _check_thresholds(ladder["thresholds"])
    except (TypeError, ValueError) as exc:
        return f"ladder.thresholds invalid: {exc}"
    tier = _tier(seal["validator_lambda"], thresholds)
    if tier == "QUARANTINED":
        return "validator is quarantined"
    if seal["validator_tier"] != tier:
        return "validator_tier does not match validator_lambda under the ladder"
    attestation = seal["lambda_attestation"]
    if attestation is not None:
        if not verify_attestation(attestation):
            return "lambda_attestation does not verify"
        if attestation["lambda"] != seal["validator_lambda"]:
            return "attested lambda differs from validator_lambda"
        if attestation["timestamp"] > seal["timestamp"]:
            return "attestation is dated after the seal"
    if seal["separation"] != _separation_for(attestation):
        return "separation does not match the attestation"
    return None


# ---------------------------------------------------------------------------
# 6. create_seal
#    SPEC_V2 §4.1. Builds an unsigned V2 seal.
# ---------------------------------------------------------------------------
def create_seal(decision, action_type, subject_id, rationale, validator_lambda, timestamp,
                *, registry=None, domain=None, attestation=None, attester_public_key=None):
    if decision not in _DECISIONS:
        raise ValueError(f"decision must be 'approve' or 'refuse', got {decision!r}")
    _check_text("action_type", action_type)
    _check_text("subject_id", subject_id)
    _check_text("rationale", rationale)
    _check_finite("validator_lambda", validator_lambda)
    _check_finite("timestamp", timestamp)

    if (registry is None) != (domain is None):
        raise ValueError("registry and domain must be given together")
    if registry is not None:
        if not isinstance(registry, LadderRegistry):
            raise TypeError("registry must be a LadderRegistry")
        thresholds = registry.get(domain)
    else:
        thresholds = dict(DEFAULT_THRESHOLDS)

    tier = _tier(validator_lambda, thresholds)
    if tier == "QUARANTINED":
        raise ValueError(
            f"validator λ={validator_lambda} is below the quarantine threshold "
            f"({thresholds['NOVICE']}); validation refused"
        )

    if attestation is not None:
        if attester_public_key is None:
            raise ValueError("attester_public_key is required with an attestation")
        if not verify_attestation(attestation, attester_public_key):
            raise ValueError("attestation does not verify under attester_public_key")
        if attestation["lambda"] != validator_lambda:
            raise ValueError("attested lambda differs from validator_lambda")
        if attestation["timestamp"] > timestamp:
            raise ValueError("attestation is dated after the seal")
        attestation = copy.deepcopy(attestation)
    elif attester_public_key is not None:
        raise ValueError("attester_public_key given without an attestation")

    return {
        "seal_version": SEAL_VERSION,
        "algorithm": "Ed25519",
        "decision": decision,
        "action_type": action_type,
        "subject_id": subject_id,
        "rationale": rationale,
        "validator_lambda": validator_lambda,
        "validator_tier": tier,
        "ladder": {"domain": domain, "thresholds": thresholds},
        "separation": _separation_for(attestation),
        "lambda_attestation": attestation,
        "timestamp": timestamp,
    }


# ---------------------------------------------------------------------------
# 7. sign_seal
#    SPEC_V2 §4.2. Well-formed unsigned seal, attested validator must be
#    the signer, then P2 V2 sign_capsule (which deep-copies the input).
# ---------------------------------------------------------------------------
def sign_seal(seal, private_key):
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be Ed25519PrivateKey")
    problem = _v2_seal_problem(seal, signed=False)
    if problem:
        raise ValueError(problem)
    attestation = seal["lambda_attestation"]
    signer = envelope_v2.did_key_encode(private_key.public_key())
    if attestation is not None and attestation["validator_key_id"] != signer:
        raise ValueError("attestation names a different validator than the signer")
    return sign_v2.sign_capsule(seal, private_key)


# ---------------------------------------------------------------------------
# 20. _v1_seal_ok (internal)
#     SPEC.md §2 shape for a v1 seal, with tier recomputed.
# ---------------------------------------------------------------------------
def _v1_seal_ok(seal):
    if set(seal) != _V1_SEAL_KEYS | {"signature"}:
        return False
    if seal["algorithm"] != "Ed25519" or seal["separation"] != "none":
        return False
    if seal["decision"] not in _DECISIONS:
        return False
    lam = seal["validator_lambda"]
    if not _is_number(lam) or not math.isfinite(lam):
        return False
    tier = _tier(lam, DEFAULT_THRESHOLDS)
    return tier != "QUARANTINED" and seal["validator_tier"] == tier


# ---------------------------------------------------------------------------
# 8. verify_seal
#    SPEC_V2 §4.3. v1 and V2 seals. False on any malformed content.
# ---------------------------------------------------------------------------
def verify_seal(seal, public_key, attester_public_key=None):
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be Ed25519PublicKey")
    if attester_public_key is not None and not isinstance(attester_public_key, Ed25519PublicKey):
        raise TypeError("attester_public_key must be Ed25519PublicKey")
    if not isinstance(seal, dict):
        return False
    if "seal_version" not in seal:
        return _v1_seal_ok(seal) and sign_v2.verify_capsule(seal, public_key)
    if _v2_seal_problem(seal, signed=True):
        return False
    attestation = seal["lambda_attestation"]
    if attestation is not None:
        if attestation["validator_key_id"] != _signer_did(seal):
            return False
        if attester_public_key is not None and not verify_attestation(attestation, attester_public_key):
            return False
    return sign_v2.verify_capsule(seal, public_key)


# ---------------------------------------------------------------------------
# 21. _check_deltas (internal)
#     SPEC_V2 §5.1. None → defaults.
# ---------------------------------------------------------------------------
def _check_deltas(deltas):
    if deltas is None:
        return dict(DEFAULT_OUTCOME_DELTAS)
    if not isinstance(deltas, dict):
        raise TypeError("deltas must be a dict")
    if set(deltas) != set(DEFAULT_OUTCOME_DELTAS):
        raise ValueError("deltas must have exactly the keys 'upheld' and 'overturned'")
    for key in deltas:
        _check_finite(f"deltas[{key!r}]", deltas[key])
    if deltas["upheld"] < 0 or deltas["overturned"] > 0:
        raise ValueError("deltas: upheld must be >= 0 and overturned <= 0")
    return dict(deltas)


# ---------------------------------------------------------------------------
# 9. outcome_observation
#    SPEC_V2 §5.1. A verified seal plus its outcome becomes one P14
#    observation. λ itself is not updated here.
# ---------------------------------------------------------------------------
def outcome_observation(seal, public_key, outcome, timestamp, deltas=None, confidence=1.0):
    deltas = _check_deltas(deltas)
    if outcome not in deltas:
        raise ValueError(f"outcome must be one of {sorted(deltas)}, got {outcome!r}")
    _check_finite("timestamp", timestamp)
    _check_finite("confidence", confidence)
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be in [0, 1]")
    if not verify_seal(seal, public_key):
        raise ValueError("seal does not verify; no observation derived")
    if timestamp < seal["timestamp"]:
        raise ValueError("outcome timestamp precedes the seal")
    value = max(MIN_OBSERVATION_VALUE, seal["validator_lambda"] + deltas[outcome])
    return {"timestamp": timestamp, "value": value, "confidence": confidence}


# ---------------------------------------------------------------------------
# 10. append_seal_to_ledger
#     SPEC_V2 §6.1. Verify, then P4 V2 append. P4 imported lazily.
# ---------------------------------------------------------------------------
def append_seal_to_ledger(ledger_path, seal, seal_public_key, ledger_private_key):
    if not verify_seal(seal, seal_public_key):
        raise ValueError("refusing to append: seal does not verify")
    import ledger_v2  # P4 V2, sibling ../ledger-layer
    return ledger_v2.append_entry(ledger_path, seal, ledger_private_key)

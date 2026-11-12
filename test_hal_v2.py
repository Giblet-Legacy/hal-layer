"""
test_hal_v2.py — P15 HAL V2 test suite

Function:
    Executable expression of SPEC_V2.md. Covers the v1 gaps closed by
    hal_v2.py, the ladder registry, λ attestations and separation,
    seal signing/verification (v1 and V2 seals), the outcome → P14
    observation mapping, and the P4 ledger wrapper. The P14 round-trip
    test is skipped if ../leighton-engine-layer is not checked out.

Layer:    P15 — HAL
Spec:     SPEC_V2.md 1.1.0
Licence:  MSL-1.0
"""

import copy
import json
import os
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import envelope_v2
import hal
import hal_v2
import sign_v2

NAN = float("nan")
INF = float("inf")


# ---------------------------------------------------------------------------
# 1. Fixtures and helpers
# ---------------------------------------------------------------------------
@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def attester():
    return Ed25519PrivateKey.generate()


def did(private_key):
    return envelope_v2.did_key_encode(private_key.public_key())


def make_seal(**overrides):
    args = dict(decision="approve", action_type="emit_claim", subject_id="abc123",
                rationale="verified", validator_lambda=1.5, timestamp=1000.0)
    args.update(overrides)
    return hal_v2.create_seal(**args)


def resign(seal, private_key):
    body = {k: v for k, v in seal.items() if k != "signature"}
    return sign_v2.sign_capsule(body, private_key)


# ── 2. tier_for_lambda / can_validate ─────────────────────────────────────
@pytest.mark.parametrize("lam,tier", [
    (0.0, "QUARANTINED"), (0.599, "QUARANTINED"), (0.60, "NOVICE"), (0.99, "NOVICE"),
    (1.00, "TRUSTED"), (1.49, "TRUSTED"), (1.50, "SENIOR"), (1.99, "SENIOR"),
    (2.00, "AUTHORITY"), (5, "AUTHORITY"), (-1.0, "QUARANTINED"),
])
def test_default_tiers_match_v1(lam, tier):
    assert hal_v2.tier_for_lambda(lam) == tier == hal.tier_for_lambda(lam)


@pytest.mark.parametrize("bad", [NAN, INF, -INF])
def test_non_finite_lambda_rejected(bad):
    with pytest.raises(ValueError):
        hal_v2.tier_for_lambda(bad)
    with pytest.raises(ValueError):
        hal_v2.can_validate(bad)


def test_v1_gap_nan_was_authority():
    # Documents the v1 defect that V2 closes.
    assert hal.tier_for_lambda(NAN) == "AUTHORITY"


@pytest.mark.parametrize("bad", ["1.0", None, True, [1.0]])
def test_non_number_lambda_type_error(bad):
    with pytest.raises(TypeError):
        hal_v2.tier_for_lambda(bad)


def test_can_validate_threshold():
    assert hal_v2.can_validate(0.60) is True
    assert hal_v2.can_validate(0.5999) is False


def test_custom_thresholds():
    t = {"NOVICE": 0.8, "TRUSTED": 1.2, "SENIOR": 1.6, "AUTHORITY": 3.0}
    assert hal_v2.tier_for_lambda(0.7, t) == "QUARANTINED"
    assert hal_v2.tier_for_lambda(2.5, t) == "SENIOR"
    assert hal_v2.can_validate(0.7, t) is False


@pytest.mark.parametrize("bad", [
    {"NOVICE": 0.5, "TRUSTED": 1.0, "SENIOR": 1.5, "AUTHORITY": 2.0},   # below floor
    {"NOVICE": 0.6, "TRUSTED": 0.6, "SENIOR": 1.5, "AUTHORITY": 2.0},   # not strictly ascending
    {"NOVICE": 0.6, "TRUSTED": 1.0, "SENIOR": 1.5},                     # missing key
    {"NOVICE": 0.6, "TRUSTED": 1.0, "SENIOR": 1.5, "AUTHORITY": INF},   # non-finite
])
def test_bad_thresholds_rejected(bad):
    with pytest.raises(ValueError):
        hal_v2.tier_for_lambda(1.0, bad)


# ── 3. LadderRegistry ─────────────────────────────────────────────────────
def test_registry_register_get_names():
    reg = hal_v2.LadderRegistry()
    t = {"NOVICE": 0.8, "TRUSTED": 1.2, "SENIOR": 1.6, "AUTHORITY": 3.0}
    assert reg.register("medical", t) == t
    assert reg.register("medical", dict(t)) == t  # identical → no-op
    assert "medical" in reg and len(reg) == 1 and reg.names() == ["medical"]
    got = reg.get("medical")
    got["NOVICE"] = 0.0
    assert reg.get("medical")["NOVICE"] == 0.8  # copy, not alias


def test_registry_conflict_and_unknown():
    reg = hal_v2.LadderRegistry()
    reg.register("d", hal_v2.DEFAULT_THRESHOLDS)
    with pytest.raises(ValueError):
        reg.register("d", {"NOVICE": 0.7, "TRUSTED": 1.0, "SENIOR": 1.5, "AUTHORITY": 2.0})
    with pytest.raises(KeyError):
        reg.get("nope")
    with pytest.raises(ValueError):
        reg.register("", hal_v2.DEFAULT_THRESHOLDS)


# ── 4. create_seal ────────────────────────────────────────────────────────
def test_create_seal_default_shape():
    seal = make_seal()
    assert seal["seal_version"] == "1.1.0"
    assert seal["validator_tier"] == "SENIOR"
    assert seal["separation"] == "none"
    assert seal["lambda_attestation"] is None
    assert seal["ladder"] == {"domain": None, "thresholds": hal_v2.DEFAULT_THRESHOLDS}
    assert "signature" not in seal


@pytest.mark.parametrize("field,bad,exc", [
    ("action_type", 123, TypeError), ("subject_id", None, TypeError),
    ("rationale", "", ValueError), ("timestamp", "now", TypeError),
    ("timestamp", NAN, ValueError), ("validator_lambda", INF, ValueError),
    ("decision", "maybe", ValueError),
])
def test_create_seal_field_validation(field, bad, exc):
    with pytest.raises(exc):
        make_seal(**{field: bad})


def test_v1_gap_inf_seal_unsignable(key):
    # Documents the v1 defect: an inf λ seal is created but cannot be signed.
    seal = hal.create_seal("approve", "a", "b", "c", INF, 1.0)
    with pytest.raises(ValueError):
        hal.sign_seal(seal, key)


def test_create_seal_quarantined():
    with pytest.raises(ValueError):
        make_seal(validator_lambda=0.59)


def test_create_seal_domain_ladder():
    reg = hal_v2.LadderRegistry()
    reg.register("medical", {"NOVICE": 1.0, "TRUSTED": 1.5, "SENIOR": 2.0, "AUTHORITY": 3.0})
    seal = make_seal(validator_lambda=1.5, registry=reg, domain="medical")
    assert seal["validator_tier"] == "TRUSTED"
    assert seal["ladder"]["domain"] == "medical"
    with pytest.raises(ValueError):  # NOVICE under default, quarantined in medical
        make_seal(validator_lambda=0.8, registry=reg, domain="medical")


def test_create_seal_registry_domain_pairing():
    reg = hal_v2.LadderRegistry()
    with pytest.raises(ValueError):
        make_seal(registry=reg)
    with pytest.raises(ValueError):
        make_seal(domain="x")
    with pytest.raises(TypeError):
        make_seal(registry={}, domain="x")
    with pytest.raises(KeyError):
        make_seal(registry=reg, domain="unregistered")


# ── 5. sign_seal / verify_seal ────────────────────────────────────────────
def test_sign_and_verify(key):
    seal = make_seal()
    signed = hal_v2.sign_seal(seal, key)
    assert "signature" not in seal  # input not mutated
    assert signed["signature"]["key_id"] == did(key)
    assert hal_v2.verify_seal(signed, key.public_key()) is True


def test_refusal_is_sealed(key):
    signed = hal_v2.sign_seal(make_seal(decision="refuse", validator_lambda=0.6), key)
    assert signed["decision"] == "refuse"
    assert hal_v2.verify_seal(signed, key.public_key()) is True


def test_verify_survives_json_round_trip(key):
    signed = hal_v2.sign_seal(make_seal(), key)
    assert hal_v2.verify_seal(json.loads(json.dumps(signed)), key.public_key()) is True


def test_verify_wrong_key_and_tamper(key):
    signed = hal_v2.sign_seal(make_seal(), key)
    assert hal_v2.verify_seal(signed, Ed25519PrivateKey.generate().public_key()) is False
    tampered = copy.deepcopy(signed)
    tampered["decision"] = "refuse"
    assert hal_v2.verify_seal(tampered, key.public_key()) is False


def test_verify_rejects_signed_but_inconsistent_tier(key):
    # A correctly signed seal whose tier does not match its λ is still rejected.
    seal = make_seal()
    seal["validator_tier"] = "AUTHORITY"
    assert hal_v2.verify_seal(resign(seal, key), key.public_key()) is False


@pytest.mark.parametrize("junk", [None, [], "x", {}, {"seal_version": "1.1.0"}])
def test_verify_malformed_is_false(key, junk):
    assert hal_v2.verify_seal(junk, key.public_key()) is False


def test_verify_wrong_key_type(key):
    with pytest.raises(TypeError):
        hal_v2.verify_seal(make_seal(), "not a key")


def test_sign_rejects_bad_key_and_bad_seal(key):
    with pytest.raises(TypeError):
        hal_v2.sign_seal(make_seal(), "not a key")
    bad = make_seal()
    bad["validator_tier"] = "AUTHORITY"
    with pytest.raises(ValueError):
        hal_v2.sign_seal(bad, key)
    with pytest.raises(ValueError):
        hal_v2.sign_seal(hal.create_seal("approve", "a", "b", "c", 1.0, 1.0), key)


def test_v1_seal_verifies_through_v2(key):
    v1 = hal.sign_seal(hal.create_seal("approve", "a", "b", "c", 1.0, 1.0), key)
    assert hal_v2.verify_seal(v1, key.public_key()) is True
    v1["validator_tier"] = "AUTHORITY"
    assert hal_v2.verify_seal(resign(v1, key), key.public_key()) is False


# ── 6. Attestation and separation ─────────────────────────────────────────
def test_attested_separation(key, attester):
    att = hal_v2.attest_lambda(did(key), 1.5, 900.0, attester)
    assert hal_v2.verify_attestation(att) is True
    assert hal_v2.verify_attestation(att, attester.public_key()) is True
    assert hal_v2.verify_attestation(att, key.public_key()) is False
    seal = make_seal(attestation=att, attester_public_key=attester.public_key())
    assert seal["separation"] == "attested"
    signed = hal_v2.sign_seal(seal, key)
    assert hal_v2.verify_seal(signed, key.public_key()) is True
    assert hal_v2.verify_seal(signed, key.public_key(), attester.public_key()) is True
    assert hal_v2.verify_seal(signed, key.public_key(), key.public_key()) is False


def test_self_attestation_is_honestly_none(key):
    att = hal_v2.attest_lambda(did(key), 1.5, 900.0, key)
    seal = make_seal(attestation=att, attester_public_key=key.public_key())
    assert seal["separation"] == "none"
    assert hal_v2.verify_seal(hal_v2.sign_seal(seal, key), key.public_key()) is True


def test_attestation_mismatches_refused(key, attester):
    att = hal_v2.attest_lambda(did(key), 1.5, 900.0, attester)
    with pytest.raises(ValueError):  # λ differs
        make_seal(validator_lambda=1.6, attestation=att, attester_public_key=attester.public_key())
    with pytest.raises(ValueError):  # attested after the seal
        make_seal(timestamp=800.0, attestation=att, attester_public_key=attester.public_key())
    with pytest.raises(ValueError):  # attester key required
        make_seal(attestation=att)
    with pytest.raises(ValueError):  # wrong attester key
        make_seal(attestation=att, attester_public_key=key.public_key())
    with pytest.raises(ValueError):  # attester key without attestation
        make_seal(attester_public_key=attester.public_key())


def test_cannot_sign_on_another_validators_attestation(key, attester):
    att = hal_v2.attest_lambda(did(key), 1.5, 900.0, attester)
    seal = make_seal(attestation=att, attester_public_key=attester.public_key())
    with pytest.raises(ValueError):
        hal_v2.sign_seal(seal, Ed25519PrivateKey.generate())


def test_tampered_attestation_inside_seal(key, attester):
    att = hal_v2.attest_lambda(did(key), 1.5, 900.0, attester)
    seal = make_seal(attestation=att, attester_public_key=attester.public_key())
    seal["lambda_attestation"]["lambda"] = 2.5
    seal["validator_lambda"] = 2.5
    seal["validator_tier"] = "AUTHORITY"
    assert hal_v2.verify_seal(resign(seal, key), key.public_key()) is False


def test_forged_separation_claim(key):
    seal = make_seal()
    seal["separation"] = "attested"
    assert hal_v2.verify_seal(resign(seal, key), key.public_key()) is False


def test_attest_lambda_validation(key, attester):
    with pytest.raises(ValueError):
        hal_v2.attest_lambda("did:key:junk", 1.0, 1.0, attester)
    with pytest.raises(ValueError):
        hal_v2.attest_lambda(did(key), NAN, 1.0, attester)
    with pytest.raises(TypeError):
        hal_v2.attest_lambda(did(key), 1.0, 1.0, "not a key")
    assert hal_v2.verify_attestation({"type": "x"}) is False


# ── 7. outcome_observation ────────────────────────────────────────────────
def test_outcome_observation_defaults(key):
    signed = hal_v2.sign_seal(make_seal(), key)
    up = hal_v2.outcome_observation(signed, key.public_key(), "upheld", 2000.0)
    down = hal_v2.outcome_observation(signed, key.public_key(), "overturned", 2000.0, confidence=0.5)
    assert up == {"timestamp": 2000.0, "value": pytest.approx(1.6), "confidence": 1.0}
    assert down == {"timestamp": 2000.0, "value": pytest.approx(1.25), "confidence": 0.5}


def test_outcome_observation_floor_and_custom(key):
    signed = hal_v2.sign_seal(make_seal(validator_lambda=0.6), key)
    obs = hal_v2.outcome_observation(signed, key.public_key(), "overturned", 2000.0,
                                     deltas={"upheld": 0.0, "overturned": -5.0})
    assert obs["value"] == hal_v2.MIN_OBSERVATION_VALUE


def test_outcome_observation_refusals(key):
    signed = hal_v2.sign_seal(make_seal(), key)
    pub = key.public_key()
    with pytest.raises(ValueError):
        hal_v2.outcome_observation(signed, pub, "ignored", 2000.0)
    with pytest.raises(ValueError):
        hal_v2.outcome_observation(signed, pub, "upheld", 999.0)
    with pytest.raises(ValueError):
        hal_v2.outcome_observation(signed, pub, "upheld", 2000.0, confidence=1.5)
    with pytest.raises(ValueError):
        hal_v2.outcome_observation(signed, pub, "upheld", 2000.0, deltas={"upheld": -1, "overturned": 0})
    with pytest.raises(ValueError):
        hal_v2.outcome_observation(make_seal(), pub, "upheld", 2000.0)  # unsigned


def test_outcome_feeds_p14(key):
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("leighton-engine-layer", "trust-layer", "weight-layer"):
        path = os.path.normpath(os.path.join(here, "..", name))
        if path not in sys.path:
            sys.path.insert(0, path)
    le = pytest.importorskip("leighton_engine_v2")
    signed = hal_v2.sign_seal(make_seal(), key)
    obs = hal_v2.outcome_observation(signed, key.public_key(), "upheld", 2000.0)
    result = le.compute_lambda([obs], k=0.001, reference_time=2000.0, computed_at=2000.0)
    assert result["lambda"] == pytest.approx(1.6)


# ── 8. append_seal_to_ledger ──────────────────────────────────────────────
def test_append_seal_to_ledger(tmp_path, key):
    ledger_v2 = pytest.importorskip("ledger_v2")
    ledger_key = Ed25519PrivateKey.generate()
    path = str(tmp_path / "seals.jsonl")
    s1 = hal_v2.sign_seal(make_seal(), key)
    s2 = hal_v2.sign_seal(make_seal(decision="refuse"), key)
    e1 = hal_v2.append_seal_to_ledger(path, s1, key.public_key(), ledger_key)
    hal_v2.append_seal_to_ledger(path, s2, key.public_key(), ledger_key)
    assert e1["record"] == s1
    assert ledger_v2.verify_ledger(path, ledger_key.public_key()) is True


def test_append_refuses_unverified_seal(tmp_path, key):
    path = str(tmp_path / "seals.jsonl")
    signed = hal_v2.sign_seal(make_seal(), key)
    with pytest.raises(ValueError):
        hal_v2.append_seal_to_ledger(path, signed, Ed25519PrivateKey.generate().public_key(), key)
    assert not os.path.exists(path)

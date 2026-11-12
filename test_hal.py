"""
test_hal.py — P15 HAL test suite

Function:
    Executable expression of SPEC.md. Written before hal.py per
    build discipline.

Layer:    P15 — HAL
Spec:     SPEC.md v1.0.0
Licence:  MSL-1.0
"""

import os
import sys
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.abspath('../envelope-layer'))
sys.path.insert(0, os.path.abspath('../sign-layer'))

import hal

@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()

# ── tier_for_lambda ──────────────────────────────────────────────────────
def test_tier_quarantined():
    assert hal.tier_for_lambda(0.0) == "QUARANTINED"
    assert hal.tier_for_lambda(0.59) == "QUARANTINED"
    assert hal.tier_for_lambda(0.599) == "QUARANTINED"

def test_tier_novice():
    assert hal.tier_for_lambda(0.60) == "NOVICE"
    assert hal.tier_for_lambda(0.99) == "NOVICE"

def test_tier_trusted():
    assert hal.tier_for_lambda(1.00) == "TRUSTED"
    assert hal.tier_for_lambda(1.49) == "TRUSTED"

def test_tier_senior():
    assert hal.tier_for_lambda(1.50) == "SENIOR"
    assert hal.tier_for_lambda(1.99) == "SENIOR"

def test_tier_authority():
    assert hal.tier_for_lambda(2.00) == "AUTHORITY"
    assert hal.tier_for_lambda(5.00) == "AUTHORITY"

def test_tier_rejects_non_number():
    with pytest.raises((TypeError, ValueError)):
        hal.tier_for_lambda("1.0")
    with pytest.raises((TypeError, ValueError)):
        hal.tier_for_lambda(None)

# ── can_validate ─────────────────────────────────────────────────────────
def test_can_validate_quarantined():
    assert hal.can_validate(0.0) is False
    assert hal.can_validate(0.59) is False

def test_can_validate_at_threshold():
    assert hal.can_validate(0.60) is True

def test_can_validate_above_threshold():
    assert hal.can_validate(1.50) is True
    assert hal.can_validate(5.00) is True

def test_can_validate_rejects_non_number():
    with pytest.raises((TypeError, ValueError)):
        hal.can_validate("1.0")

# ── create_seal ──────────────────────────────────────────────────────────
def test_create_seal_approve():
    seal = hal.create_seal(
        decision="approve",
        action_type="emit_claim",
        subject_id="abc123",
        rationale="verified against source",
        validator_lambda=1.5,
        timestamp=1000.0,
    )
    assert seal["algorithm"] == "Ed25519"
    assert seal["decision"] == "approve"
    assert seal["action_type"] == "emit_claim"
    assert seal["subject_id"] == "abc123"
    assert seal["rationale"] == "verified against source"
    assert seal["validator_lambda"] == 1.5
    assert seal["validator_tier"] == "SENIOR"
    assert seal["separation"] == "none"
    assert seal["timestamp"] == 1000.0

def test_create_seal_refuse():
    seal = hal.create_seal(
        decision="refuse",
        action_type="emit_claim",
        subject_id="abc123",
        rationale="insufficient evidence",
        validator_lambda=0.8,
        timestamp=1000.0,
    )
    assert seal["decision"] == "refuse"
    assert seal["validator_tier"] == "NOVICE"

def test_create_seal_rejects_quarantined():
    with pytest.raises(ValueError):
        hal.create_seal(
            decision="approve",
            action_type="emit_claim",
            subject_id="abc123",
            rationale="x",
            validator_lambda=0.5,
            timestamp=1000.0,
        )

def test_create_seal_rejects_invalid_decision():
    with pytest.raises(ValueError):
        hal.create_seal(
            decision="maybe",
            action_type="emit_claim",
            subject_id="abc123",
            rationale="x",
            validator_lambda=1.0,
            timestamp=1000.0,
        )

# ── sign_seal / verify_seal ──────────────────────────────────────────────
def test_sign_and_verify_seal(key):
    seal = hal.create_seal(
        decision="approve",
        action_type="emit_claim",
        subject_id="abc123",
        rationale="verified",
        validator_lambda=1.5,
        timestamp=1000.0,
    )
    signed = hal.sign_seal(seal, key)
    assert "signature" in signed
    assert signed["signature"]["algorithm"] == "Ed25519"
    assert signed["signature"]["key_id"].startswith("did:key:z6Mk")
    assert hal.verify_seal(signed, key.public_key()) is True

def test_verify_seal_wrong_key(key):
    seal = hal.create_seal(
        decision="approve",
        action_type="emit_claim",
        subject_id="abc123",
        rationale="verified",
        validator_lambda=1.5,
        timestamp=1000.0,
    )
    signed = hal.sign_seal(seal, key)
    other_key = Ed25519PrivateKey.generate()
    assert hal.verify_seal(signed, other_key.public_key()) is False

def test_verify_seal_tampered(key):
    seal = hal.create_seal(
        decision="approve",
        action_type="emit_claim",
        subject_id="abc123",
        rationale="verified",
        validator_lambda=1.5,
        timestamp=1000.0,
    )
    signed = hal.sign_seal(seal, key)
    signed["decision"] = "refuse"
    assert hal.verify_seal(signed, key.public_key()) is False

def test_sign_seal_refusal(key):
    seal = hal.create_seal(
        decision="refuse",
        action_type="emit_claim",
        subject_id="abc123",
        rationale="insufficient",
        validator_lambda=1.0,
        timestamp=1000.0,
    )
    signed = hal.sign_seal(seal, key)
    assert signed["decision"] == "refuse"
    assert hal.verify_seal(signed, key.public_key()) is True

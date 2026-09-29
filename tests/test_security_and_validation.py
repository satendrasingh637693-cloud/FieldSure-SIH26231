from pathlib import Path
import tempfile
import pandas as pd

from validation import validate_dataframe
from core import PROFILES, canonical_json, sign_payload, verify_signature


def test_multiple_profiles_loaded():
    assert len(PROFILES) >= 3
    assert {"DEMO-001", "DEMO-002", "DEMO-003"}.issubset(PROFILES)


def test_validation_catches_batch_leakage():
    df = pd.DataFrame([
        {"sample_id":"1","batch_id":"B1","split":"development","true_label":"NEGATIVE","predicted_label":"NEGATIVE","confidence":0.9},
        {"sample_id":"2","batch_id":"B1","split":"held_out","true_label":"POSITIVE","predicted_label":"POSITIVE","confidence":0.9},
    ])
    r = validate_dataframe(df)
    assert r["ok"]
    assert any("batch leakage" in w.lower() for w in r["warnings"])


def test_signature_payload_round_trip():
    payload = {"x": 1, "y": "demo"}
    sig = sign_payload(payload)
    assert verify_signature(payload, sig)
    assert not verify_signature({"x": 2, "y": "demo"}, sig)


def test_operator_specific_signature_round_trip():
    payload = {"operator": "OP-001", "event": "demo"}
    from core import sign_payload, init_db
    init_db()
    sig = sign_payload(payload, operator_id="OP-001", password="FieldSure@123")
    assert verify_signature(payload, sig, operator_id="OP-001")
    assert not verify_signature({"operator": "OP-002", "event": "demo"}, sig, operator_id="OP-001")

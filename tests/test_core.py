from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import canonical_json, sha256_bytes, sign_payload, verify_signature, classify_image, DEMO_PROFILE

BASE = Path(__file__).resolve().parents[1]


def test_sha256_deterministic():
    assert sha256_bytes(b"abc") == sha256_bytes(b"abc")
    assert sha256_bytes(b"abc") != sha256_bytes(b"abd")


def test_signature_round_trip():
    payload = {"a": 1, "b": "hello"}
    sig = sign_payload(payload)
    assert verify_signature(payload, sig)
    assert not verify_signature({"a": 2, "b": "hello"}, sig)


def test_canonical_json_is_stable():
    a = {"b": 2, "a": 1}
    b = {"a": 1, "b": 2}
    assert canonical_json(a) == canonical_json(b)


def test_synthetic_demo_labels():
    expected = {
        "demo_negative.jpg": "NEGATIVE",
        "demo_positive.jpg": "POSITIVE",
        "demo_inconclusive.jpg": "INCONCLUSIVE",
    }
    for name, label in expected.items():
        result = classify_image((BASE / "images" / name).read_bytes(), DEMO_PROFILE)
        assert result["result"] == label
        assert result["reference_card_ok"] is True

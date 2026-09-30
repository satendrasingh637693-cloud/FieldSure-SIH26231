from pathlib import Path
import sys

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

from core import PROFILES, classify_image, canonical_json, sha256_bytes, sign_payload, verify_signature, init_db


def main() -> int:
    init_db()
    expected = {
        "demo_negative.jpg": "NEGATIVE",
        "demo_positive.jpg": "POSITIVE",
        "demo_inconclusive.jpg": "INCONCLUSIVE",
    }
    for name, label in expected.items():
        result = classify_image((BASE / "images" / name).read_bytes(), PROFILES["DEMO-001"])
        print(f"{name}: {result['result']} (expected {label})")
        if result["result"] != label:
            return 1

    payload = {"scope": "fieldsure-smoke", "value": 1}
    signature = sign_payload(payload)
    if not verify_signature(payload, signature):
        print("Signature round-trip: FAIL")
        return 1
    if verify_signature({"scope": "fieldsure-smoke", "value": 2}, signature):
        print("Tampered payload acceptance: FAIL")
        return 1

    print("Profiles:", ", ".join(sorted(PROFILES)))
    print("SHA-256 sample:", sha256_bytes(canonical_json(payload)))
    print("Signature round-trip: PASS")

    try:
        from supabase_client import supabase_enabled
        print("Supabase configured:", supabase_enabled())
    except Exception as exc:
        print("Supabase status unavailable:", exc)

    print("FieldSure smoke test: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

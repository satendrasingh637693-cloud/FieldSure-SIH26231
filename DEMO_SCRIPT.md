# FieldSure — SIH P6 Demo Script (3–4 minutes)

## 1. Authenticate

Sign in as `OP-001`. Say: "Each operator has a separate identity and signing key."

## 2. Demonstrate multiple kit profiles

Open the kit selector and show `DEMO-001`, `DEMO-002` and `DEMO-003`. Say: "The application is profile-driven; real kits will use approved, versioned calibration profiles rather than one universal threshold."

## 3. Run a test

Capture or upload the synthetic demo card. Show reference-card PASS, test-region AUTO, result and capture-quality checks.

## 4. Secure evidence

Point out SHA-256 image hash, record hash, operator-specific signature key fingerprint and the Supabase-backed chained audit record.

## 5. Verify

Open Verify Record and show all checks PASS.

## 6. Tamper demo

Change only a stored `result` value using the controlled demo script. Re-run verification and show `TAMPERING / INTEGRITY FAILURE`.

## 7. Validation

Open Validation, upload the example CSV, and show the confusion matrix, per-class metrics, held-out count and leakage warnings.

## Closing sentence

"FieldSure is a software-only digital evidence companion for existing colorimetric field tests. It standardizes presumptive interpretation, binds each result to an operator and captured image, and makes post-hoc alteration detectable. Definitive chemical identification remains the responsibility of accredited laboratory confirmation."

## What not to claim

- Do not claim laboratory or legal validity.
- Do not claim 100% real-world accuracy.
- Do not claim DEMO thresholds work on real kits.
- Do not claim tampering is impossible; say it is detectable when cryptographic evidence is checked.

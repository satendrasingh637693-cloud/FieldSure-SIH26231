# FieldSure Architecture

## Core flow

Operator authentication -> camera/upload -> reference-card detection -> colour calibration -> test-region detection -> kit-profile classification -> evidence record -> SHA-256 image hash -> operator-specific Ed25519 signature -> Supabase DB + private evidence storage (with SQLite/local-file fallback) -> chained audit hash -> verification.

## Modules

- `app.py`: Streamlit UI, authentication session, operator/admin workflows.
- `core.py`: computer-vision pipeline, profile loading, authentication, key management, record creation and verification.
- `validation.py`: dataset checks, leakage screening, confusion matrix, per-class metrics and Wilson intervals.
- `data/kit_profiles.json`: versioned kit/profile definitions for the configurable prototype.
- `data/field_tests.db`: local SQLite fallback store.
- Supabase `tests` table: remote test metadata when configured.
- Supabase `fieldsure-evidence` bucket: private evidence images and operator key material when configured.
- `keys/operators/`: local cache of separate public keys and encrypted private keys per operator.

## Security model

Passwords are stored as PBKDF2-HMAC-SHA256 password verifiers. Each operator receives a separate Ed25519 keypair. Private keys are encrypted at rest using the authenticated operator password. Every new test is signed with the authenticated operator key. The record includes the image SHA-256 hash and previous-record hash. Verification checks image integrity, record integrity, signature validity and the complete chain.

## Scientific boundary

The demo profiles are illustrative. Real deployment requires manufacturer-defined kit specifications, calibrated reference materials, laboratory-confirmed ground truth, blinded held-out testing, repeatability/reproducibility studies and formal governance.

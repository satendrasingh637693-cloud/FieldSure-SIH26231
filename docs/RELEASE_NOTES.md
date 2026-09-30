# FieldSure Release Notes

## Current prototype

The connected prototype supports Supabase persistence when Streamlit secrets are configured. It stores test metadata in the remote `tests` table and captured evidence in the private `fieldsure-evidence` bucket. SQLite/local files remain available as a fallback when Supabase is unavailable.

## Final demonstration path

Login -> New Test -> reference-card/calibration analysis -> presumptive result -> signed record -> Supabase persistence -> History -> Verify Record -> evidence bundle export.

## Security boundary

This is a software proof-of-concept. It does not provide hardware-backed key storage, enterprise IAM, HSM, certificate authority, remote attestation, revocation infrastructure or a formal evidence-management system.

## Scientific boundary

DEMO profiles and synthetic images are illustrative. Real use requires kit-specific manufacturer specifications, validated calibration, laboratory-confirmed ground truth, blinded held-out evaluation, repeatability/reproducibility studies, predefined acceptance criteria and formal governance.

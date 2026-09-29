# FieldSure Security Model

## Authentication

- Operator credentials are stored as salted PBKDF2-HMAC-SHA256 verifiers.
- Operator roles are `OPERATOR` or `ADMIN`.
- Inactive accounts cannot sign in.

## Key separation

Each operator has a unique Ed25519 keypair. Private keys are stored as encrypted PKCS#8 PEM files. The public key is bundled with evidence for independent verification.

## Evidence integrity

The captured image receives a SHA-256 digest. A canonical test record is hashed and then signed. Each record points to the prior record hash, making retrospective modification detectable during chain verification.

## Limitations

This prototype does not include a hardware-backed keystore, certificate authority, HSM, enterprise IAM, key rotation protocol, revocation service or remote attestation. Those are deployment requirements for a high-assurance operational environment.

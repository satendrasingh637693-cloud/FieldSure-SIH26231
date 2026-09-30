# FieldSure V5 Fixed Changelog

## V5.0.1 — 2026-09-30

### Bug fix
- Fixed the New Test workflow by importing `create_test_record` in `app.py`.
- The Analyze and Secure Record action can now reach the record creation/signing path instead of raising `NameError: create_test_record is not defined`.

### Verification
- Python compilation check passed.
- Automated test suite: 8/8 passed.
- Smoke test: PASS.

### Persistence hardening — 2026-09-30
- Supabase-backed operator directory synchronization for creation and password changes.
- Supabase-first test history and verification with local fallback.
- Evidence ZIP export now retrieves remote evidence images and public keys.
- Remote audit-chain retrieval failures now fail verification instead of appearing as an empty valid chain.
- Test creation cleans up local/remote partial writes when remote persistence fails.
- Pinned Supabase SDK to 2.31.0 for reproducible deployment.

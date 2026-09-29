# FieldSure V5 Fixed Changelog

## V5.0.1 — 2026-09-30

### Bug fix
- Fixed the New Test workflow by importing `create_test_record` in `app.py`.
- The Analyze and Secure Record action can now reach the record creation/signing path instead of raising `NameError: create_test_record is not defined`.

### Verification
- Python compilation check passed.
- Automated test suite: 8/8 passed.
- Smoke test: PASS.

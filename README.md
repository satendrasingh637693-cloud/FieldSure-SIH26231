# SIH P6 — FieldSure

## Computer-vision-assisted field-test verification with cryptographically verifiable digital records

FieldSure is a software-only prototype companion for existing colorimetric field-test kits. It captures a test image, checks an in-frame reference card, performs configured colour analysis, generates a presumptive Positive/Negative/Inconclusive outcome, and protects the resulting digital record with image hashing, operator-specific signatures and a chained audit record.

### Prototype capabilities

- Camera capture or image upload
- Automatic reference-card patch detection for configured demo profiles
- Reference-card colour calibration
- Automatic test-region detection for the demonstration workflow
- Positive / Negative / Inconclusive demo classification
- Capture-quality diagnostics: blur, brightness and exposure warnings
- Multi-profile kit configuration via `data/kit_profiles.json`
- Operator login with roles (`OPERATOR`, `ADMIN`)
- PBKDF2-HMAC-SHA256 password verifiers
- Separate Ed25519 keypair for each operator
- Encrypted operator private keys at rest
- SHA-256 image integrity hashing
- Canonical record hashing
- Digital signature verification
- Tamper-evident chained audit verification
- Searchable test history via Supabase when configured, with local SQLite fallback
- Evidence JSON and ZIP bundle export
- Validation workflow with data-quality and batch-leakage screening
- Confusion matrix, sensitivity, specificity, PPV, NPV, F1 and Wilson intervals
- Windows setup/run scripts
- Offline dependency staging/install scripts
- Architecture, security, validation, deployment and operations documentation

## Scientific status

**This is not a scientifically validated forensic drug-testing system.** DEMO profiles and synthetic images are illustrative only. Real deployment requires kit-specific manufacturer specifications, validated reference materials, laboratory-confirmed ground truth, blinded held-out evaluation, repeatability/reproducibility testing, predefined acceptance criteria, uncertainty analysis and formal governance.

The application produces a **presumptive field-test interpretation** and does not establish chemical identity or replace accredited laboratory confirmation.

## Quick start — Windows / VS Code

### Option A: simple commands

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -c "from core import ensure_keys, init_db; ensure_keys(); init_db(); print('FieldSure setup complete')"
.\.venv\Scripts\python.exe generate_demo_images.py
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open the local URL shown by Streamlit, normally `http://localhost:8501`.

### Option B: setup script

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\setup_windows.ps1
.\run_windows.bat
```

### Demo credentials

- `OP-001` / `FieldSure@123`
- `ADMIN-001` / `Admin@123`

These credentials exist only to make the prototype easy to demonstrate. Change them before any real or shared deployment.

## Demo workflow

1. Sign in as `OP-001`.
2. Open **New Test**.
3. Select a configured kit profile.
4. Capture/upload a synthetic demo card.
5. Review reference-card status, test-region detection, colour evidence and capture-quality checks.
6. Save the secured test record.
7. Open **Verify Record** and show all checks passing.
8. Run the controlled tamper demo and verify the modified record.
9. Show the **TAMPERING / INTEGRITY FAILURE** result.
10. Open **Validation** and demonstrate the dataset quality checks and metrics.

See `DEMO_SCRIPT.md`.

## Multi-profile configuration

`data/kit_profiles.json` contains three demonstration profiles. Real kits should be represented by approved, versioned profile records containing validated reference specifications and decision parameters. Do not reuse DEMO thresholds on real kits.

## Validation workflow

Use a CSV with at least:

- `true_label`
- `predicted_label`

Recommended columns:

- `sample_id`
- `batch_id`
- `split` (`development` / `held_out`)
- `confidence`
- `kit_id`
- `reference_source`

The validator flags invalid labels, duplicate sample IDs, invalid confidence values and possible batch leakage across splits. It produces a confusion matrix, per-class metrics and descriptive Wilson 95% intervals.

## Supabase persistence

When `SUPABASE_URL` and `SUPABASE_SECRET_KEY` are configured through Streamlit secrets, test metadata is persisted in the `tests` table and evidence images are stored in the private `fieldsure-evidence` bucket. Operator authentication uses the remote `operators` table first and falls back to SQLite when the remote service is unavailable. Secrets and private keys must never be committed to source control.

## Offline deployment

Prepare a connected staging machine with:

```powershell
.\setup_windows.ps1
.\prepare_offline_bundle.ps1
```

Copy the entire project, including `offline_wheels/`, to the approved air-gapped environment.

On the air-gapped system:

```powershell
.\install_offline.ps1
.\run_windows.bat
```

See `docs/DEPLOYMENT.md` for the operating checklist.

## Security limitations

This prototype does not provide HSM/hardware-backed key storage, enterprise IAM, certificate authority, remote attestation, secure boot, key revocation infrastructure or a formal evidence-management system. Those controls would be required for a high-assurance operational deployment.

## Project structure

```text
FieldSure/
├── app.py
├── core.py
├── validation.py
├── generate_demo_images.py
├── tamper_demo.py
├── requirements.txt
├── run_windows.bat
├── setup_windows.ps1
├── prepare_offline_bundle.ps1
├── install_offline.ps1
├── data/
│   ├── kit_profiles.json
│   └── field_tests.db
├── images/
├── keys/
│   └── operators/
├── tests/
└── docs/
```

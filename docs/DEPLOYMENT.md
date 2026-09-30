# FieldSure Deployment & Air-Gapped Operation

## Connected staging machine

1. Install Python 3.11+.
2. Run `setup_windows.ps1`.
3. Run `prepare_offline_bundle.ps1` while connected to download dependency wheels into `offline_wheels/`.
4. Copy the entire FieldSure folder, including `offline_wheels/`, to the air-gapped system using approved removable media.

## Air-gapped machine

1. Run `install_offline.ps1`.
2. Verify that all required wheels are available locally and no internet connection is needed.
3. Review `data/kit_profiles.json` and deploy only approved, versioned profiles.
4. Provision operator accounts and protect the `keys/operators` directory with OS-level access controls.
5. Launch using `run_windows.bat`.

## Operational checklist

- Disable unnecessary network interfaces/services if required by local policy.
- Back up the SQLite database and image store using an approved process.
- Protect encrypted private keys and operator credentials.
- Do not treat DEMO profiles or synthetic images as operational validation.
- Verify evidence bundles independently before relying on them.

## Supabase-backed connected deployment

For the connected prototype, configure Streamlit secrets with:

```toml
SUPABASE_URL = "<project-url>"
SUPABASE_SECRET_KEY = "<secret-key>"
```

Use the private `fieldsure-evidence` storage bucket for test images and operator key material. Do not commit the secrets file, service key, private keys or operational database.

Before a release, verify the complete path: login -> New Test -> remote database/storage -> History -> Verify Record -> evidence bundle.

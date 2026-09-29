# SIH Release Checklist

## Prototype

- [ ] Login works for operator and admin accounts.
- [ ] At least three kit profiles are visible.
- [ ] Negative, positive and inconclusive demo images classify correctly.
- [ ] Camera capture works.
- [ ] Reference card is detected.
- [ ] Test region is auto-detected.
- [ ] Capture-quality guidance is visible.
- [ ] New record is signed with the operator-specific key.
- [ ] Verify Record shows all checks passing on an untampered record.
- [ ] Controlled tamper demo produces integrity failure.
- [ ] Evidence JSON and ZIP bundle downloads work.
- [ ] Validation CSV workflow produces a report.

## Claims discipline

- [ ] All demo metrics are labelled as demonstration/prototype metrics.
- [ ] No claim of laboratory validation is made.
- [ ] No claim of definitive chemical identification is made.
- [ ] No claim of legal admissibility is made.
- [ ] Real deployment limitations are stated.

## Packaging

- [ ] `build_release.ps1` excludes private keys and operational DB.
- [ ] `prepare_offline_bundle.ps1` is run on a connected staging machine if a self-contained air-gapped dependency bundle is required.
- [ ] `install_offline.ps1` is tested on the target offline machine.
- [ ] Demo credentials are changed for any non-demo use.

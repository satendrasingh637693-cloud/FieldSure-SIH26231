from __future__ import annotations

import io
import json
import zipfile
import hashlib
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

from supabase_client import supabase_enabled
from supabase_repository import download_operator_public_key, download_test_image

from core import (
    PROFILES,
    authenticate_operator,
    change_operator_password,
    classify_image,
    create_operator,
    create_test_record,
    ensure_keys,
    get_test,
    init_db,
    list_operators,
    list_tests,
    public_key_fingerprint,
    operator_public_path,
    simulate_tamper,
    verify_test,
)
from validation import validate_dataframe, report_as_dict

st.set_page_config(page_title="FieldSure | SIH P6", page_icon="🔬", layout="wide", initial_sidebar_state="expanded")

ensure_keys()
init_db()


def evidence_bundle_bytes(record: dict, analysis: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        evidence = {**record, "analysis": analysis}
        z.writestr(
            f"{record['test_id']}_evidence.json",
            json.dumps(evidence, indent=2, ensure_ascii=False),
        )

        image_path_value = str(record["image_path"])
        image_bytes = b""
        if supabase_enabled() and image_path_value.startswith("tests/"):
            image_bytes = download_test_image(image_path_value)
        else:
            image_path = Path(image_path_value)
            if image_path.exists():
                image_bytes = image_path.read_bytes()
        if image_bytes:
            z.writestr(f"{record['test_id']}_captured.jpg", image_bytes)

        op_id = str(record.get("signature_key_id") or record.get("operator_id"))
        public_key_path = operator_public_path(op_id)
        public_key_bytes = b""
        if public_key_path.exists():
            public_key_bytes = public_key_path.read_bytes()
        elif supabase_enabled():
            public_key_bytes = download_operator_public_key(op_id)
        if public_key_bytes:
            z.writestr("operator_public_key.pem", public_key_bytes)
    return buf.getvalue()


def public_key_fp(operator_id: str) -> str:
    return public_key_fingerprint(operator_id)


def logout() -> None:
    for k in ["authenticated", "operator_id", "display_name", "role", "operator_password", "last_test_id"]:
        st.session_state.pop(k, None)


# --------------------------- Authentication ---------------------------
if not st.session_state.get("authenticated"):
    st.markdown("<div style='max-width:760px;margin:5rem auto;'>", unsafe_allow_html=True)
    st.title("🔬 FieldSure")
    st.subheader("Secure field-test verification")
    st.caption("SIH P6 prototype — software-only digital companion for existing colorimetric field-test kits.")
    st.info("Demo accounts: OP-001 / FieldSure@123 and ADMIN-001 / Admin@123. Change these before any non-demo use.")
    with st.form("login_form"):
        op = st.text_input("Operator ID", value="OP-001")
        pw = st.text_input("Password / PIN", type="password")
        submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)
    if submitted:
        user = authenticate_operator(op, pw)
        if user:
            st.session_state.authenticated = True
            st.session_state.operator_id = user["operator_id"]
            st.session_state.display_name = user["display_name"]
            st.session_state.role = user["role"]
            st.session_state.operator_password = pw
            st.rerun()
        else:
            st.error("Invalid credentials or inactive operator account.")
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

operator_id = st.session_state["operator_id"]
role = st.session_state["role"]

# --------------------------- Styling ---------------------------
st.markdown(
    """
    <style>
    .main-title {font-size: 2.6rem; font-weight: 800; margin-bottom: 0.15rem;}
    .sub-title {font-size: 1.05rem; opacity: 0.75; margin-bottom: 1rem;}
    .pill {display:inline-block; padding:0.35rem 0.7rem; border-radius:999px; margin-right:0.45rem; font-size:0.85rem; border:1px solid rgba(128,128,128,0.25);}
    .note {padding:0.8rem 1rem; border-radius:0.7rem; background:rgba(255,193,7,0.12); border:1px solid rgba(255,193,7,0.25);}
    .secure {padding:0.8rem 1rem; border-radius:0.7rem; background:rgba(0,180,120,0.08); border:1px solid rgba(0,180,120,0.22);}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown('<div class="main-title">🔬 FieldSure</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Computer-vision-assisted field-test verification with cryptographically verifiable digital records</div>', unsafe_allow_html=True)
st.markdown(
    '<span class="pill">OFFLINE-FIRST</span><span class="pill">COMPUTER VISION</span><span class="pill">DIGITAL EVIDENCE</span><span class="pill">TAMPER-EVIDENT</span><span class="pill">MULTI-KIT</span>',
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("Signed-in operator")
    st.write(f"**{st.session_state['display_name']}**")
    st.caption(f"ID: {operator_id} · Role: {role}")
    st.caption(f"Key fingerprint: {public_key_fp(operator_id)}")
    if st.button("Sign out", use_container_width=True):
        logout()
        st.rerun()
    st.divider()
    if supabase_enabled():
        st.caption("Storage: Supabase DB + private evidence storage")
        st.caption("Remote persistence is enabled for records and evidence.")
    else:
        st.caption("Storage: local SQLite + local evidence files")
        st.caption("Supabase is not configured; local fallback is active.")

pages = ["New Test", "History", "Verify Record", "Validation"]
if role == "ADMIN":
    pages.append("Administration")
page = st.radio("Navigation", pages, horizontal=True)

# --------------------------- New Test ---------------------------
if page == "New Test":
    st.subheader("New Field Test")
    st.info("Use an existing colorimetric kit. For the prototype, DEMO profiles use synthetic images. Real deployment requires validated, kit-specific profiles and laboratory-confirmed ground truth.")

    left, right = st.columns([1.35, 1])
    with left:
        st.markdown("### 1. Capture / upload")
        image = st.camera_input("Take a test photo")
        if image is None:
            image = st.file_uploader("Or upload a test image", type=["jpg", "jpeg", "png"])
        if image is not None:
            st.image(image, caption="Captured image", width=560)

    with right:
        st.markdown("### 2. Kit + location")
        kit_labels = [f"{p.kit_id} — {p.name} v{p.version}" for p in PROFILES.values()]
        if "selected_kit_label" not in st.session_state:
            st.session_state["selected_kit_label"] = kit_labels[0]

        selected_label = st.selectbox(
        "Kit profile",
        kit_labels,
        key="selected_kit_label",
)

        kit_id = selected_label.split(" — ", 1)[0]
        profile = PROFILES[kit_id]

        st.caption(f"Selected kit ID: **{kit_id}**")
        st.caption(profile.description)
        lat = st.number_input("Latitude", value=22.7196, format="%.6f")
        lon = st.number_input("Longitude", value=75.8577, format="%.6f")
        acc = st.number_input("Location accuracy (m)", value=20.0, min_value=0.0)
        st.caption("Prototype metadata entry. A production mobile implementation should obtain these values from the device location source and display accuracy/permission status.")

    if image is not None:
        image_bytes = image.getvalue()
        if st.button("Analyze and Secure Record", type="primary", use_container_width=True):
            try:
                with st.spinner("Running calibrated colour analysis and securing evidence..."):
                    analysis = classify_image(image_bytes, profile)
                    record = create_test_record(
                        operator_id,
                        kit_id,
                        image_bytes,
                        analysis,
                        lat,
                        lon,
                        acc,
                        operator_password=st.session_state["operator_password"],
                    )
                st.session_state["last_test_id"] = record["test_id"]
                st.success(f"Record created: {record['test_id']}")

                a, b, c, d = st.columns(4)
                a.metric("Result", analysis["result"])
                b.metric("Confidence", f"{analysis['confidence']*100:.1f}%")
                c.metric("Reference card", "PASS" if analysis["reference_card_ok"] else "FAIL")
                d.metric("Test region", analysis.get("test_region_source", "N/A").replace("auto-detected", "AUTO").replace("guided-fallback", "GUIDED"))

                st.markdown("### Analysis evidence")
                e1, e2, e3 = st.columns(3)
                e1.metric("Positive distance", f"{analysis['positive_distance']:.2f}")
                e2.metric("Negative distance", f"{analysis['negative_distance']:.2f}")
                e3.metric("Inconclusive distance", f"{analysis['inconclusive_distance']:.2f}")

                st.markdown("### Capture quality")
                quality = analysis.get("capture_quality", {})
                q1, q2, q3, q4 = st.columns(4)
                (q1.success if quality.get("status") == "PASS" else q1.warning)(f"Capture quality {quality.get('status','REVIEW')}")
                q2.metric("Blur score", f"{quality.get('blur_score', 0):.1f}")
                q3.metric("Brightness", f"{quality.get('brightness_mean', 0):.1f}")
                q4.info("Presumptive result only")
                if quality.get("issues"):
                    st.warning("; ".join(quality["issues"]) + ". " + quality.get("recommendation", ""))
                else:
                    st.success(quality.get("recommendation", "Capture quality is acceptable for this prototype analysis."))

                st.markdown("### Digital evidence")
                st.code(record["record_hash"], language=None)
                st.caption(f"Signed by operator {record['operator_id']} using key fingerprint {public_key_fp(record['operator_id'])}.")
                bundle = evidence_bundle_bytes(record, analysis)
                d1, d2 = st.columns(2)
                d1.download_button(
                    "Download evidence record (JSON)",
                    data=json.dumps({**record, "analysis": analysis}, indent=2, ensure_ascii=False),
                    file_name=f"{record['test_id']}_evidence.json",
                    mime="application/json",
                    use_container_width=True,
                )
                d2.download_button(
                    "Download evidence bundle (ZIP)",
                    data=bundle,
                    file_name=f"{record['test_id']}_evidence_bundle.zip",
                    mime="application/zip",
                    use_container_width=True,
                )
                st.markdown('<div class="note"><b>Presumptive field-test result.</b> This prototype does not establish chemical identity or replace accredited laboratory confirmation. DEMO thresholds are illustrative.</div>', unsafe_allow_html=True)
            except Exception as exc:
                st.error(f"Analysis failed: {exc}")

# --------------------------- History ---------------------------
elif page == "History":
    st.subheader("Test History")
    search = st.text_input("Search by Test ID, operator, result or kit")
    scope_operator = None if role == "ADMIN" else operator_id
    rows = list_tests(search, operator_id=scope_operator)
    if rows:
        clean = []
        for r in rows:
            d = dict(r)
            v = verify_test(d["test_id"])
            clean.append({
                "Test ID": d["test_id"],
                "Operator": d["operator_id"],
                "Kit": d["kit_id"],
                "Result": d["result"],
                "Confidence": f"{d['confidence']*100:.1f}%",
                "UTC Time": d["timestamp"],
                "Integrity": "VALID" if v["all_ok"] else "TAMPERED",
            })
        df = pd.DataFrame(clean)
        total = len(df)
        positive = int((df["Result"] == "POSITIVE").sum())
        negative = int((df["Result"] == "NEGATIVE").sum())
        inconclusive = int((df["Result"] == "INCONCLUSIVE").sum())
        tampered = int((df["Integrity"] == "TAMPERED").sum())
        a, b, c, d, e = st.columns(5)
        a.metric("Total", total)
        b.metric("Positive", positive)
        c.metric("Negative", negative)
        d.metric("Inconclusive", inconclusive)
        e.metric("Integrity failures", tampered)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No test records found for this view.")

# --------------------------- Verify ---------------------------
# --------------------------- Verify ---------------------------
elif page == "Verify Record":
    st.subheader("Cryptographic Record Verification")

    scope_operator = None if role == "ADMIN" else operator_id
    rows = list_tests(operator_id=scope_operator)
    ids = [r["test_id"] for r in rows]

    if not ids:
        st.info("No test records available for verification.")
    else:
        default_id = st.session_state.get("last_test_id", ids[0])
        default_index = ids.index(default_id) if default_id in ids else 0

        tid = st.selectbox(
            "Select Test ID",
            ids,
            index=default_index,
        )

        verify_key = f"verify_result_{tid}"
        evidence_key = f"verify_evidence_{tid}"
        tamper_key = f"tamper_sim_{tid}"

        if st.button(
            "Verify Record",
            type="primary",
        ):
            result = verify_test(tid)
            st.session_state[verify_key] = result

            row = get_test(tid)
            st.session_state[evidence_key] = dict(row) if row else None

            st.session_state.pop(tamper_key, None)

        result = st.session_state.get(verify_key)
        evidence = st.session_state.get(evidence_key)

        if result is not None:
            st.metric(
                "Overall status",
                "VALID ✅"
                if result["all_ok"]
                else "TAMPERING / INTEGRITY FAILURE ❌",
            )

            checks = pd.DataFrame(
                [
                    ["Original image exists", result["image_exists"]],
                    ["Image SHA-256 matches", result["image_hash_ok"]],
                    ["Record hash matches", result["record_hash_ok"]],
                    ["Ed25519 signature valid", result["signature_ok"]],
                    ["Audit hash chain valid", result["audit_chain_ok"]],
                ],
                columns=["Check", "Status"],
            )

            checks["Status"] = checks["Status"].map(
                {
                    True: "PASS ✅",
                    False: "FAIL ❌",
                }
            )

            st.dataframe(
                checks,
                use_container_width=True,
                hide_index=True,
            )

            if result["all_ok"]:
                st.success(
                    "The current image, protected record and audit chain "
                    "are consistent with the stored cryptographic evidence."
                )
            else:
                st.error(
                    "At least one protected value no longer matches its "
                    "original cryptographic evidence. The record requires investigation."
                )

                if result.get("chain_failure_at"):
                    st.caption(
                        f"First audit-chain inconsistency detected at: "
                        f"{result['chain_failure_at']}"
                    )

            if evidence is not None:
                st.download_button(
                    "Download stored record (JSON)",
                    data=json.dumps(
                        evidence,
                        indent=2,
                        ensure_ascii=False,
                    ),
                    file_name=f"{tid}_stored_record.json",
                    mime="application/json",
                )

                st.json(evidence)

                with st.expander(
                    "Controlled tamper simulation "
                    "(does not modify stored data)"
                ):
                    st.caption(
                        "For demonstration only: this changes the result "
                        "in memory and checks the original cryptographic "
                        "evidence. The Supabase record is not edited."
                    )

                    if st.button(
                        "Simulate result tampering",
                        key=f"simulate-{tid}",
                    ):
                        st.session_state[tamper_key] = simulate_tamper(
                            evidence
                        )

                    sim = st.session_state.get(tamper_key)

                    if sim is not None:
                        st.error(
                            f"SIMULATED TAMPERING: "
                            f"{sim['original_result']} -> "
                            f"{sim['tampered_result']}"
                        )

                        sim_checks = pd.DataFrame(
                            [
                                [
                                    "Record hash still matches",
                                    sim["record_hash_matches"],
                                ],
                                [
                                    "Original Ed25519 signature still validates",
                                    sim["signature_valid"],
                                ],
                            ],
                            columns=["Check", "Status"],
                        )

                        sim_checks["Status"] = sim_checks["Status"].map(
                            {
                                True: "PASS ✅",
                                False: "FAIL ❌",
                            }
                        )

                        st.dataframe(
                            sim_checks,
                            use_container_width=True,
                            hide_index=True,
                        )

                        st.caption(
                            "No stored database row or evidence image "
                            "was modified by this simulation."
                        )
# --------------------------- Validation ---------------------------
elif page == "Validation":
    st.subheader("Validation & Data-Quality Workflow")
    st.warning("This is a validation framework, not proof of scientific validity for a real kit. Use laboratory-confirmed labels and an untouched held-out set before reporting deployment performance.")

    with st.expander("Study metadata checklist", expanded=True):
        c1, c2 = st.columns(2)
        kit_version = c1.text_input("Kit / profile version", value="DEMO-001 v1.0-demo")
        ground_truth = c2.text_input("Reference / ground-truth source", value="Synthetic demonstration labels")
        c3, c4 = st.columns(2)
        blinded = c3.checkbox("Held-out data are analyst-blinded", value=False)
        frozen = c4.checkbox("Profile/preprocessing frozen before final evaluation", value=False)
        st.caption("For real validation, these checklist fields should describe your actual study design; do not claim them unless true.")

    f = st.file_uploader("Validation CSV", type=["csv"])
    if f is not None:
        try:
            df = pd.read_csv(f)
            result = validate_dataframe(df)
            if not result["ok"]:
                for e in result["errors"]:
                    st.error(e)
            else:
                for w in result["warnings"]:
                    st.warning(w)
                st.success(f"Dataset checks passed for {result['rows']} rows.")
                st.markdown("### Confusion matrix")
                st.dataframe(result["confusion_matrix"], use_container_width=True)

                rows = []
                for label, m in result["per_class"].items():
                    rows.append({
                        "Class": label,
                        "Sensitivity": m["sensitivity"],
                        "Specificity": m["specificity"],
                        "PPV": m["ppv"],
                        "NPV": m["npv"],
                        "F1": m["f1"],
                        "Sensitivity 95% CI": f"{m['sensitivity_ci_low']:.3f}–{m['sensitivity_ci_high']:.3f}" if m['sensitivity_ci_low'] == m['sensitivity_ci_low'] else "N/A",
                        "Specificity 95% CI": f"{m['specificity_ci_low']:.3f}–{m['specificity_ci_high']:.3f}" if m['specificity_ci_low'] == m['specificity_ci_low'] else "N/A",
                    })
                st.markdown("### Per-class metrics")
                st.dataframe(pd.DataFrame(rows).set_index("Class"), use_container_width=True)
                st.metric("Overall accuracy", f"{result['overall_accuracy']*100:.2f}%")
                if result.get("held_out_rows") is not None:
                    st.metric("Held-out rows", result["held_out_rows"])
                st.caption("Wilson intervals are descriptive 95% intervals. They do not correct for clustered samples, repeated measures, or other study-design effects.")

                report = report_as_dict(result)
                report.update({"kit_version": kit_version, "ground_truth_source": ground_truth, "analyst_blinded": blinded, "profile_frozen": frozen})
                st.download_button("Download validation report (JSON)", data=json.dumps(report, indent=2, default=str), file_name="fieldsure_validation_report.json", mime="application/json")
        except Exception as exc:
            st.error(f"Validation failed: {exc}")

# --------------------------- Administration ---------------------------
elif page == "Administration":
    st.subheader("Administration & Operator Security")
    st.info("Demo security model: passwords are PBKDF2-HMAC-SHA256 hashed in SQLite, while each operator has a separate Ed25519 keypair with an encrypted private key. Runtime signing uses the authenticated operator password held only in session memory.")

    st.markdown("### Operator directory")
    ops = [dict(r) for r in list_operators()]
    if ops:
        st.dataframe(pd.DataFrame(ops), use_container_width=True, hide_index=True)

    st.markdown("### Create operator")
    with st.form("create_operator"):
        new_id = st.text_input("Operator ID")
        new_name = st.text_input("Display name")
        new_role = st.selectbox("Role", ["OPERATOR", "ADMIN"])
        new_pw = st.text_input("Initial password", type="password")
        submitted = st.form_submit_button("Create operator", type="primary")
    if submitted:
        try:
            if not new_id.strip() or not new_name.strip() or len(new_pw) < 8:
                st.error("Provide an ID, display name and a password of at least 8 characters.")
            else:
                create_operator(new_id.strip(), new_name.strip(), new_role, new_pw)
                st.success(f"Operator {new_id.strip()} created with a dedicated signing key.")
                st.rerun()
        except sqlite3.IntegrityError:
            st.error("That operator ID already exists.")
        except Exception as exc:
            st.error(f"Could not create operator: {exc}")

    st.markdown("### Change my password")
    with st.form("change_password"):
        old = st.text_input("Current password", type="password")
        new = st.text_input("New password", type="password")
        change = st.form_submit_button("Change password")
    if change:
        if len(new) < 8:
            st.error("New password must be at least 8 characters.")
        elif change_operator_password(operator_id, old, new):
            st.session_state["operator_password"] = new
            st.success("Password and encrypted private-key protection were updated.")
        else:
            st.error("Current password is incorrect.")

st.divider()
st.caption("FieldSure is a software proof-of-concept. DEMO profiles use illustrative thresholds. A real forensic deployment requires kit-specific manufacturer specifications, validated calibration, laboratory-confirmed ground truth, blinded held-out evaluation, repeatability/reproducibility studies, key-management controls and formal governance.")

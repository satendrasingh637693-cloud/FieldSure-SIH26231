from __future__ import annotations

import math
from typing import Any

import pandas as pd

LABELS = ["POSITIVE", "NEGATIVE", "INCONCLUSIVE"]
REQUIRED = {"true_label", "predicted_label"}
OPTIONAL = {"sample_id", "batch_id", "split", "confidence", "kit_id", "reference_source"}


def confusion_matrix(df: pd.DataFrame) -> pd.DataFrame:
    return pd.crosstab(df["true_label"], df["predicted_label"], dropna=False).reindex(
        index=LABELS, columns=LABELS, fill_value=0
    )


def _wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n <= 0:
        return float("nan"), float("nan")
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt((p * (1 - p) / n) + (z * z / (4 * n * n))) / den
    return max(0.0, centre - half), min(1.0, centre + half)


def one_vs_rest_metrics(df: pd.DataFrame, label: str) -> dict[str, Any]:
    y = df["true_label"]
    p = df["predicted_label"]
    tp = int(((y == label) & (p == label)).sum())
    fn = int(((y == label) & (p != label)).sum())
    fp = int(((y != label) & (p == label)).sum())
    tn = int(((y != label) & (p != label)).sum())
    sensitivity = tp / (tp + fn) if tp + fn else float("nan")
    specificity = tn / (tn + fp) if tn + fp else float("nan")
    ppv = tp / (tp + fp) if tp + fp else float("nan")
    npv = tn / (tn + fn) if tn + fn else float("nan")
    accuracy = (tp + tn) / (tp + tn + fp + fn) if tp + tn + fp + fn else float("nan")
    f1 = 2 * ppv * sensitivity / (ppv + sensitivity) if ppv == ppv and sensitivity == sensitivity and (ppv + sensitivity) else float("nan")
    sens_ci = _wilson(tp, tp + fn)
    spec_ci = _wilson(tn, tn + fp)
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "sensitivity": sensitivity,
        "specificity": specificity,
        "ppv": ppv,
        "npv": npv,
        "accuracy": accuracy,
        "f1": f1,
        "sensitivity_ci_low": sens_ci[0], "sensitivity_ci_high": sens_ci[1],
        "specificity_ci_low": spec_ci[0], "specificity_ci_high": spec_ci[1],
    }


def validate_dataframe(df: pd.DataFrame) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    missing = REQUIRED - set(df.columns)
    if missing:
        errors.append(f"Missing required columns: {sorted(missing)}")
        return {"ok": False, "errors": errors, "warnings": warnings}

    clean = df.copy()
    clean["true_label"] = clean["true_label"].astype(str).str.upper().str.strip()
    clean["predicted_label"] = clean["predicted_label"].astype(str).str.upper().str.strip()
    bad_true = sorted(set(clean["true_label"]) - set(LABELS))
    bad_pred = sorted(set(clean["predicted_label"]) - set(LABELS))
    if bad_true:
        errors.append(f"Invalid true_label values: {bad_true}")
    if bad_pred:
        errors.append(f"Invalid predicted_label values: {bad_pred}")

    if "sample_id" in clean.columns:
        dup = int(clean["sample_id"].duplicated().sum())
        if dup:
            errors.append(f"Duplicate sample_id rows detected: {dup}")
    if "batch_id" in clean.columns and "split" in clean.columns:
        split_norm = clean["split"].astype(str).str.lower().str.strip()
        clean["split_norm"] = split_norm
        mixed = clean.groupby("batch_id")["split_norm"].nunique()
        leakage_batches = mixed[mixed > 1].index.tolist()
        if leakage_batches:
            warnings.append("Potential batch leakage: the same batch_id appears in multiple dataset splits.")
    else:
        warnings.append("batch_id and split columns are absent; sample/batch-level leakage screening cannot be performed.")

    if "confidence" in clean.columns:
        vals = pd.to_numeric(clean["confidence"], errors="coerce")
        bad_conf = int(vals.isna().sum() + ((vals < 0) | (vals > 1)).sum())
        if bad_conf:
            errors.append(f"Invalid confidence values detected: {bad_conf} rows")
    else:
        warnings.append("confidence column absent; confidence calibration cannot be assessed.")

    result = {"ok": not errors, "errors": errors, "warnings": warnings, "rows": len(clean)}
    if result["ok"]:
        cm = confusion_matrix(clean)
        result["confusion_matrix"] = cm
        result["per_class"] = {label: one_vs_rest_metrics(clean, label) for label in LABELS}
        result["overall_accuracy"] = float((clean["true_label"] == clean["predicted_label"]).mean()) if len(clean) else float("nan")
        result["held_out_rows"] = int((clean.get("split_norm", pd.Series(dtype=str)) == "held_out").sum()) if "split_norm" in clean.columns else None
        if result["held_out_rows"] is not None and result["held_out_rows"] == 0:
            warnings.append("No held-out rows are present. Do not report this as final scientific performance.")
    return result


def report_as_dict(result: dict[str, Any]) -> dict[str, Any]:
    out = dict(result)
    cm = out.get("confusion_matrix")
    if isinstance(cm, pd.DataFrame):
        out["confusion_matrix"] = cm.to_dict()
    return out


def validate_csv(path: str) -> None:
    df = pd.read_csv(path)
    result = validate_dataframe(df)
    print(result)

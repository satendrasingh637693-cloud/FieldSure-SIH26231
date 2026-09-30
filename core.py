from __future__ import annotations
from supabase_client import get_supabase, supabase_enabled

from supabase_repository import (
    download_operator_private_key,
    download_operator_public_key,
    upload_operator_keys,
)

import base64
import hashlib
import hmac
import json
import re
import sqlite3
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import cv2
import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
IMAGE_DIR = BASE_DIR / "images"
KEY_DIR = BASE_DIR / "keys"
OPERATOR_KEY_DIR = KEY_DIR / "operators"
DB_PATH = DATA_DIR / "field_tests.db"
PRIVATE_KEY_PATH = KEY_DIR / "operator_ed25519_private.pem"  # legacy compatibility
PUBLIC_KEY_PATH = KEY_DIR / "operator_ed25519_public.pem"    # legacy compatibility
PROFILE_JSON_PATH = DATA_DIR / "kit_profiles.json"

for p in (DATA_DIR, IMAGE_DIR, KEY_DIR, OPERATOR_KEY_DIR):
    p.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class KitProfile:
    kit_id: str
    name: str
    version: str
    mode: str
    ref_rgb: Tuple[Tuple[int, int, int], ...]
    positive_lab: Tuple[float, float, float]
    negative_lab: Tuple[float, float, float]
    inconclusive_lab: Tuple[float, float, float]
    decision_margin: float = 7.0
    max_distance: float = 35.0
    negative_chroma_max: float = 7.0
    positive_chroma_min: float = 25.0
    description: str = ""


DEFAULT_PROFILES: tuple[KitProfile, ...] = (
    KitProfile(
        kit_id="DEMO-001",
        name="Generic Demonstration Colorimetric Kit",
        version="1.0-demo",
        mode="DEMO",
        ref_rgb=((220, 80, 80), (80, 180, 80), (80, 80, 220)),
        positive_lab=(137.0, 150.0, 147.0),
        negative_lab=(155.0, 130.0, 122.0),
        inconclusive_lab=(147.0, 130.0, 134.0),
        decision_margin=6.0,
        max_distance=35.0,
        negative_chroma_max=7.0,
        positive_chroma_min=25.0,
        description="Synthetic demonstration profile. Thresholds are illustrative and are not valid for a real forensic kit.",
    ),
    KitProfile(
        kit_id="DEMO-002",
        name="Generic Warm-Response Demonstration Kit",
        version="1.0-demo",
        mode="DEMO",
        ref_rgb=((230, 95, 85), (90, 175, 95), (95, 90, 225)),
        positive_lab=(137.0, 147.0, 143.0),
        negative_lab=(154.0, 132.0, 124.0),
        inconclusive_lab=(147.0, 132.0, 135.0),
        decision_margin=6.0,
        max_distance=36.0,
        negative_chroma_max=8.0,
        positive_chroma_min=27.0,
        description="Second configurable demo profile illustrating versioned kit-specific parameters.",
    ),
    KitProfile(
        kit_id="DEMO-003",
        name="Generic Cool-Response Demonstration Kit",
        version="1.0-demo",
        mode="DEMO",
        ref_rgb=((215, 85, 100), (75, 175, 85), (75, 85, 215)),
        positive_lab=(136.0, 148.0, 146.0),
        negative_lab=(156.0, 129.0, 121.0),
        inconclusive_lab=(148.0, 131.0, 134.0),
        decision_margin=6.0,
        max_distance=36.0,
        negative_chroma_max=7.5,
        positive_chroma_min=26.0,
        description="Third configurable demo profile illustrating profile-specific calibration boundaries.",
    ),
)


def _profile_to_json(profile: KitProfile) -> dict[str, Any]:
    d = asdict(profile)
    d["ref_rgb"] = [list(x) for x in profile.ref_rgb]
    d["positive_lab"] = list(profile.positive_lab)
    d["negative_lab"] = list(profile.negative_lab)
    d["inconclusive_lab"] = list(profile.inconclusive_lab)
    return d


def _profile_from_json(d: dict[str, Any]) -> KitProfile:
    return KitProfile(
        kit_id=d["kit_id"],
        name=d["name"],
        version=d.get("version", "1.0"),
        mode=d.get("mode", "DEMO"),
        ref_rgb=tuple(tuple(int(v) for v in x) for x in d["ref_rgb"]),
        positive_lab=tuple(float(v) for v in d["positive_lab"]),
        negative_lab=tuple(float(v) for v in d["negative_lab"]),
        inconclusive_lab=tuple(float(v) for v in d["inconclusive_lab"]),
        decision_margin=float(d.get("decision_margin", 7.0)),
        max_distance=float(d.get("max_distance", 35.0)),
        negative_chroma_max=float(d.get("negative_chroma_max", 7.0)),
        positive_chroma_min=float(d.get("positive_chroma_min", 25.0)),
        description=d.get("description", ""),
    )


def ensure_profile_config() -> None:
    if not PROFILE_JSON_PATH.exists():
        PROFILE_JSON_PATH.write_text(
            json.dumps([_profile_to_json(p) for p in DEFAULT_PROFILES], indent=2), encoding="utf-8"
        )


def load_profiles() -> dict[str, KitProfile]:
    ensure_profile_config()
    try:
        data = json.loads(PROFILE_JSON_PATH.read_text(encoding="utf-8"))
        parsed = [_profile_from_json(x) for x in data]
        profiles = {p.kit_id: p for p in parsed}
        if profiles:
            return profiles
    except Exception:
        pass
    return {p.kit_id: p for p in DEFAULT_PROFILES}


PROFILES = load_profiles()
DEMO_PROFILE = PROFILES["DEMO-001"]


def sanitize_id(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]", "_", value.strip())
    return clean[:64] or "UNKNOWN"


def operator_private_path(operator_id: str) -> Path:
    return OPERATOR_KEY_DIR / f"{sanitize_id(operator_id)}_ed25519_private.pem"


def operator_public_path(operator_id: str) -> Path:
    return OPERATOR_KEY_DIR / f"{sanitize_id(operator_id)}_ed25519_public.pem"


def _hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    if salt is None:
        salt = uuid.uuid4().bytes
    digest = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=310_000).derive(password.encode())
    return base64.b64encode(salt).decode("ascii"), base64.b64encode(digest).decode("ascii")


def _verify_password(password: str, salt_b64: str, digest_b64: str) -> bool:
    try:
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=310_000).derive(password.encode())
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def ensure_keys() -> None:
    """Ensure the legacy signing key exists locally and persist it remotely when enabled."""
    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        return

    if supabase_enabled():
        try:
            PRIVATE_KEY_PATH.write_bytes(
                download_operator_private_key("LEGACY")
            )
            PUBLIC_KEY_PATH.write_bytes(
                download_operator_public_key("LEGACY")
            )
            return
        except Exception:
            pass

    private = Ed25519PrivateKey.generate()
    public = private.public_key()

    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIVATE_KEY_PATH.write_bytes(private_bytes)
    PUBLIC_KEY_PATH.write_bytes(public_bytes)

    if supabase_enabled():
        upload_operator_keys("LEGACY", private_bytes, public_bytes)


def ensure_operator_keys(operator_id: str, password: str) -> None:
    private_path = operator_private_path(operator_id)
    public_path = operator_public_path(operator_id)

    if private_path.exists() and public_path.exists():
        return

    if supabase_enabled():
        try:
            private_path.write_bytes(
                download_operator_private_key(operator_id)
            )
            public_path.write_bytes(
                download_operator_public_key(operator_id)
            )
            return
        except Exception:
            pass

    private = Ed25519PrivateKey.generate()
    public = private.public_key()

    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode()
        ),
    )
    public_bytes = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)

    if supabase_enabled():
        upload_operator_keys(
            operator_id,
            private_bytes,
            public_bytes,
        )


def load_private_key(operator_id: str = "LEGACY", password: Optional[str] = None) -> Ed25519PrivateKey:
    if operator_id != "LEGACY" and password is not None:
        path = operator_private_path(operator_id)
        return serialization.load_pem_private_key(path.read_bytes(), password=password.encode())
    ensure_keys()
    return serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)


def load_public_key(operator_id: str = "LEGACY") -> Ed25519PublicKey:
    path = operator_public_path(operator_id) if operator_id != "LEGACY" else PUBLIC_KEY_PATH
    if not path.exists():
        raise FileNotFoundError(f"Public key not found for {operator_id}")
    return serialization.load_pem_public_key(path.read_bytes())


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_payload(payload: Dict[str, Any], operator_id: Optional[str] = None, password: Optional[str] = None) -> str:
    if operator_id and password:
        signature = load_private_key(operator_id, password).sign(canonical_json(payload))
    else:
        signature = load_private_key("LEGACY").sign(canonical_json(payload))
    return base64.b64encode(signature).decode("ascii")


def verify_signature(
    payload: Dict[str, Any], signature_b64: str, operator_id: Optional[str] = None
) -> bool:
    try:
        sig = base64.b64decode(signature_b64.encode("ascii"), validate=True)
        load_public_key(operator_id or "LEGACY").verify(sig, canonical_json(payload))
        return True
    except (InvalidSignature, ValueError, TypeError, FileNotFoundError):
        return False


def init_db() -> None:
    ensure_profile_config()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS operators (
                operator_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                public_key_fingerprint TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tests (
                test_id TEXT PRIMARY KEY,
                operator_id TEXT NOT NULL,
                kit_id TEXT NOT NULL,
                result TEXT NOT NULL,
                confidence REAL NOT NULL,
                timestamp TEXT NOT NULL,
                latitude REAL,
                longitude REAL,
                location_accuracy REAL,
                image_path TEXT NOT NULL,
                image_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                reference_card_ok INTEGER NOT NULL,
                analysis_notes TEXT NOT NULL,
                signature_key_id TEXT
            )
            """
        )
        cols = {r[1] for r in conn.execute("PRAGMA table_info(tests)").fetchall()}
        if "signature_key_id" not in cols:
            conn.execute("ALTER TABLE tests ADD COLUMN signature_key_id TEXT")
            conn.execute("UPDATE tests SET signature_key_id='LEGACY' WHERE signature_key_id IS NULL")
        conn.commit()
    finally:
        conn.close()
    seed_default_operators()


def seed_default_operators() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        count = conn.execute("SELECT COUNT(*) FROM operators").fetchone()[0]
        if count == 0:
            create_operator("OP-001", "Field Operator", "OPERATOR", "FieldSure@123", conn=conn)
            create_operator("ADMIN-001", "System Administrator", "ADMIN", "Admin@123", conn=conn)
        conn.commit()
    finally:
        conn.close()


def create_operator(
    operator_id: str,
    display_name: str,
    role: str,
    password: str,
    *,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    own = conn is None
    conn = conn or sqlite3.connect(DB_PATH)
    try:
        salt_b64, hash_b64 = _hash_password(password)
        ensure_operator_keys(operator_id, password)
        fingerprint = sha256_bytes(operator_public_path(operator_id).read_bytes())[:24]
        conn.execute(
            "INSERT INTO operators(operator_id,display_name,role,password_salt,password_hash,public_key_fingerprint,active,created_at) VALUES (?,?,?,?,?,?,1,?)",
            (operator_id, display_name, role, salt_b64, hash_b64, fingerprint, datetime.now(timezone.utc).isoformat()),
        )
        if own:
            conn.commit()
    finally:
        if own:
            conn.close()


def authenticate_operator(operator_id: str, password: str) -> Optional[dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM operators WHERE operator_id=? AND active=1", (operator_id.strip(),)).fetchone()
        if row is None or not _verify_password(password, row["password_salt"], row["password_hash"]):
            return None
        ensure_operator_keys(row["operator_id"], password)
        return dict(row)
    finally:
        conn.close()


def change_operator_password(operator_id: str, old_password: str, new_password: str) -> bool:
    user = authenticate_operator(operator_id, old_password)
    if not user:
        return False
    old_path = operator_private_path(operator_id)
    private = load_private_key(operator_id, old_password)
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(new_password.encode()),
    )
    old_path.write_bytes(private_bytes)
    salt_b64, hash_b64 = _hash_password(new_password)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("UPDATE operators SET password_salt=?, password_hash=? WHERE operator_id=?", (salt_b64, hash_b64, operator_id))
        conn.commit()
    finally:
        conn.close()
    return True


def list_operators() -> list[sqlite3.Row]:
    conn = get_db_connection()
    try:
        return conn.execute("SELECT operator_id,display_name,role,active,created_at,public_key_fingerprint FROM operators ORDER BY operator_id").fetchall()
    finally:
        conn.close()


def latest_record_hash() -> str:
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute("SELECT record_hash FROM tests ORDER BY rowid DESC LIMIT 1").fetchone()
        return row[0] if row else "GENESIS"
    finally:
        conn.close()


def get_db_connection() -> sqlite3.Connection:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _lab_from_rgb(rgb: np.ndarray) -> np.ndarray:
    rgb_u8 = np.clip(np.round(rgb), 0, 255).astype(np.uint8)
    bgr = rgb_u8[::-1]
    one = np.array([[bgr]], dtype=np.uint8)
    return cv2.cvtColor(one, cv2.COLOR_BGR2LAB)[0, 0].astype(np.float32)


def _box_score(x: int, y: int, w: int, h: int, img_w: int, img_h: int) -> float:
    area = w * h
    aspect = min(w / max(h, 1), h / max(w, 1))
    upper_left_bonus = 1.0 if (x + w / 2) < img_w * 0.55 and (y + h / 2) < img_h * 0.55 else 0.0
    return area * (0.55 + 0.45 * aspect) * (1.0 + 0.20 * upper_left_bonus)


def _detect_reference_patches(bgr: np.ndarray) -> Tuple[list[Tuple[int, int, int, int]], float]:
    h, w = bgr.shape[:2]
    upper = bgr[: int(0.52 * h), : int(0.72 * w)]
    hsv = cv2.cvtColor(upper, cv2.COLOR_BGR2HSV)
    mask = ((hsv[:, :, 1] > 85) & (hsv[:, :, 2] > 55)).astype(np.uint8) * 255
    mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, np.ones((3, 3), np.uint8))
    mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, np.ones((5, 5), np.uint8))
    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    candidates: list[Tuple[float, Tuple[int, int, int, int]]] = []
    for c in contours:
        x, y, cw, ch = cv2.boundingRect(c)
        area = cw * ch
        if area < 400 or cw < 18 or ch < 18:
            continue
        aspect = cw / max(ch, 1)
        if not (0.55 <= aspect <= 1.8):
            continue
        candidates.append((_box_score(x, y, cw, ch, upper.shape[1], upper.shape[0]), (x, y, cw, ch)))
    candidates.sort(reverse=True)
    boxes: list[Tuple[int, int, int, int]] = []
    for _, box in candidates:
        x, y, bw, bh = box
        too_close = False
        for ox, oy, ow, oh in boxes:
            cx, cy = x + bw / 2, y + bh / 2
            ocx, ocy = ox + ow / 2, oy + oh / 2
            dist = ((cx - ocx) ** 2 + (cy - ocy) ** 2) ** 0.5
            if dist < 0.60 * max(min(bw, bh), min(ow, oh)):
                too_close = True
                break
        if not too_close:
            boxes.append(box)
        if len(boxes) >= 3:
            break
    boxes.sort(key=lambda q: q[0])
    if len(boxes) != 3:
        return [], 999.0
    widths = np.array([q[2] for q in boxes], dtype=np.float32)
    alignment = float(np.std([q[1] + q[3] / 2 for q in boxes]))
    size_cv = float(np.std(widths) / max(np.mean(widths), 1.0))
    ref_means = []
    for x, y, bw, bh in boxes:
        p = upper[y + int(0.15 * bh): y + int(0.85 * bh), x + int(0.15 * bw): x + int(0.85 * bw)]
        ref_means.append(cv2.cvtColor(p, cv2.COLOR_BGR2RGB).mean(axis=(0, 1)))
    chromas = [float(np.linalg.norm(_lab_from_rgb(m)[1:] - 128.0)) for m in ref_means]
    chroma_ok = sum(c > 25 for c in chromas) == 3
    quality = alignment * 0.6 + size_cv * 50 + (0 if chroma_ok else 35)
    return boxes, float(quality)


def _detect_demo_test_region(bgr: np.ndarray) -> Optional[Tuple[int, int, int, int]]:
    h, w = bgr.shape[:2]
    x0, y0 = int(0.25 * w), int(0.20 * h)
    roi = bgr[y0:int(0.98 * h), x0:int(0.98 * w)]
    gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
    blur = cv2.GaussianBlur(gray, (5, 5), 0)
    edges = cv2.Canny(blur, 40, 130)
    edges = cv2.dilate(edges, np.ones((3, 3), np.uint8), iterations=1)
    contours, _ = cv2.findContours(edges, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
    candidates = []
    for c in contours:
        bx, by, bw, bh = cv2.boundingRect(c)
        if bw < 55 or bh < 55 or bw > 0.75 * w or bh > 0.75 * h:
            continue
        ar = bw / max(bh, 1)
        if not (0.72 <= ar <= 1.38):
            continue
        x, y = bx + x0, by + y0
        cx, cy = x + bw / 2, y + bh / 2
        if not (0.45 * w <= cx <= 0.90 * w and 0.38 * h <= cy <= 0.90 * h):
            continue
        candidates.append((bw * bh, (x, y, bw, bh)))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def _capture_quality(bgr: np.ndarray) -> Dict[str, Any]:
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    blur_score = float(cv2.Laplacian(gray, cv2.CV_64F).var())
    overexposed_ratio = float((gray >= 245).mean())
    underexposed_ratio = float((gray <= 10).mean())
    brightness = float(gray.mean())
    issues = []
    if blur_score < 80.0:
        issues.append("image may be blurred")
    if overexposed_ratio > 0.35:
        issues.append("large overexposed area")
    if underexposed_ratio > 0.20:
        issues.append("large underexposed area")
    status = "PASS" if not issues else "REVIEW"
    recommendation = (
        "Retake with the card straight, closer, and under even lighting."
        if issues else "Capture quality is acceptable for this prototype analysis."
    )
    return {
        "status": status,
        "blur_score": blur_score,
        "brightness_mean": brightness,
        "overexposed_ratio": overexposed_ratio,
        "underexposed_ratio": underexposed_ratio,
        "issues": issues,
        "recommendation": recommendation,
    }


def classify_image(image_bytes: bytes, profile: KitProfile = DEMO_PROFILE) -> Dict[str, Any]:
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    bgr = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if bgr is None:
        raise ValueError("Could not decode image")
    h, w = bgr.shape[:2]
    if min(h, w) < 120:
        raise ValueError("Image is too small for reliable analysis")

    quality = _capture_quality(bgr)
    ref_boxes, detection_quality = _detect_reference_patches(bgr)
    ref_ok = len(ref_boxes) == 3 and detection_quality <= 45.0

    if ref_ok:
        patch_means = []
        for x, y, bw, bh in ref_boxes:
            p = bgr[y + int(0.15 * bh): y + int(0.85 * bh), x + int(0.15 * bw): x + int(0.85 * bw)]
            rgb = cv2.cvtColor(p, cv2.COLOR_BGR2RGB)
            patch_means.append(tuple(float(v) for v in rgb.mean(axis=(0, 1))))
    else:
        ref_y1, ref_y2 = int(0.02 * h), int(0.28 * h)
        ref_x1, ref_x2 = int(0.02 * w), int(0.50 * w)
        card = bgr[ref_y1:ref_y2, ref_x1:ref_x2]
        if card.size == 0:
            raise ValueError("Reference-card region is unavailable")
        patch_means = []
        cw = card.shape[1]
        for i in range(3):
            x1 = int(i * cw / 3 + 0.08 * cw / 3)
            x2 = int((i + 1) * cw / 3 - 0.08 * cw / 3)
            p = card[int(0.12 * card.shape[0]):int(0.88 * card.shape[0]), x1:x2]
            rgb = cv2.cvtColor(p, cv2.COLOR_BGR2RGB)
            patch_means.append(tuple(float(v) for v in rgb.mean(axis=(0, 1))))

    expected = np.array(profile.ref_rgb, dtype=np.float32)
    observed = np.array(patch_means, dtype=np.float32)
    X = np.column_stack([observed, np.ones(3, dtype=np.float32)])
    channels = []
    for c in range(3):
        beta, *_ = np.linalg.lstsq(X, expected[:, c], rcond=None)
        channels.append(beta)
    channels = np.array(channels, dtype=np.float32)
    pred = X @ channels.T
    ref_err = float(np.mean(np.abs(pred - expected)))
    if not ref_ok:
        ref_ok = ref_err <= 55.0

    test_box = _detect_demo_test_region(bgr) if profile.mode == "DEMO" else None
    if test_box is not None:
        x, y, bw, bh = test_box
        ix1, ix2 = x + int(0.20 * bw), x + int(0.80 * bw)
        iy1, iy2 = y + int(0.20 * bh), y + int(0.80 * bh)
        test_bgr = bgr[iy1:iy2, ix1:ix2]
        roi_source = "auto-detected"
    else:
        tx1, tx2 = int(0.40 * w), int(0.68 * w)
        ty1, ty2 = int(0.42 * h), int(0.75 * h)
        test_bgr = bgr[ty1:ty2, tx1:tx2]
        roi_source = "guided-fallback"
    if test_bgr.size == 0:
        raise ValueError("Test region could not be extracted")

    test_hsv = cv2.cvtColor(test_bgr, cv2.COLOR_BGR2HSV)
    sat = test_hsv[:, :, 1]
    colour_mask = sat > 35
    selected_bgr = test_bgr[colour_mask] if float(colour_mask.mean()) > 0.10 else test_bgr.reshape(-1, 3)
    test_rgb = selected_bgr[:, ::-1].astype(np.float32)
    mean_rgb = test_rgb.mean(axis=0)
    corrected_rgb = np.array(
        [float(np.dot(np.r_[mean_rgb, 1.0], channels[c])) for c in range(3)], dtype=np.float32
    )
    corrected_rgb = np.clip(corrected_rgb, 0, 255).astype(np.uint8)
    lab = _lab_from_rgb(corrected_rgb)
    centroids = {
        "POSITIVE": np.array(profile.positive_lab, dtype=np.float32),
        "NEGATIVE": np.array(profile.negative_lab, dtype=np.float32),
        "INCONCLUSIVE": np.array(profile.inconclusive_lab, dtype=np.float32),
    }
    distances = {k: float(np.linalg.norm(lab - v)) for k, v in centroids.items()}

    raw_lab = _lab_from_rgb(np.clip(mean_rgb, 0, 255))
    chroma = float(np.linalg.norm(raw_lab[1:] - 128.0))
    if profile.mode == "DEMO":
        if not ref_ok:
            result, confidence = "INCONCLUSIVE", 0.0
        elif chroma <= profile.negative_chroma_max:
            result = "NEGATIVE"
            confidence = float(np.clip((profile.negative_chroma_max - chroma) / max(profile.negative_chroma_max, 1.0), 0.0, 1.0))
        elif chroma >= profile.positive_chroma_min:
            result = "POSITIVE"
            confidence = float(np.clip((chroma - profile.positive_chroma_min) / max(profile.positive_chroma_min - profile.negative_chroma_max, 1.0), 0.0, 1.0))
        else:
            result = "INCONCLUSIVE"
            confidence = float(np.clip(min((chroma - profile.negative_chroma_max) / 9.0, (profile.positive_chroma_min - chroma) / 9.0), 0.0, 1.0))
        notes = (
            f"Profile={profile.kit_id} v{profile.version}; reference detection={'AUTO' if len(ref_boxes)==3 else 'GUIDED-FALLBACK'}; "
            f"reference mean absolute calibration error={ref_err:.2f}; test region={roi_source}; "
            f"camera-robust demo CIELAB chroma={chroma:.2f}; calibrated LAB distances: "
            f"positive={distances['POSITIVE']:.2f}, negative={distances['NEGATIVE']:.2f}, inconclusive={distances['INCONCLUSIVE']:.2f}."
        )
    else:
        ordered = sorted(distances.items(), key=lambda kv: kv[1])
        result = ordered[0][0]
        closest, second = ordered[0][1], ordered[1][1]
        separation = second - closest
        if (not ref_ok) or closest > profile.max_distance:
            result = "INCONCLUSIVE"
        elif result != "INCONCLUSIVE" and separation < profile.decision_margin:
            result = "INCONCLUSIVE"
        confidence = float(np.clip(separation / (closest + second + 1e-9), 0.0, 1.0))
        notes = (
            f"Profile={profile.kit_id} v{profile.version}; reference mean absolute calibration error={ref_err:.2f}; "
            f"LAB distances: positive={distances['POSITIVE']:.2f}, negative={distances['NEGATIVE']:.2f}, inconclusive={distances['INCONCLUSIVE']:.2f}."
        )

    return {
        "result": result,
        "confidence": confidence,
        "reference_card_ok": ref_ok,
        "reference_error": ref_err,
        "reference_detection": "AUTO" if len(ref_boxes) == 3 else "GUIDED-FALLBACK",
        "reference_detection_quality": detection_quality,
        "test_region_source": roi_source,
        "positive_distance": distances["POSITIVE"],
        "negative_distance": distances["NEGATIVE"],
        "inconclusive_distance": distances["INCONCLUSIVE"],
        "corrected_rgb": tuple(int(v) for v in corrected_rgb),
        "capture_quality": quality,
        "notes": notes + f" Capture quality={quality['status']}; blur={quality['blur_score']:.1f}; brightness={quality['brightness_mean']:.1f}; overexposed={quality['overexposed_ratio']:.3f}; underexposed={quality['underexposed_ratio']:.3f}.",
    }


def create_test_record(
    operator_id: str,
    kit_id: str,
    image_bytes: bytes,
    analysis: Dict[str, Any],
    latitude: Optional[float],
    longitude: Optional[float],
    location_accuracy: Optional[float],
    operator_password: Optional[str] = None,
) -> Dict[str, Any]:
    init_db()
    if operator_password is None:
        raise ValueError("Authenticated operator password is required for a new signed record")
    if authenticate_operator(operator_id, operator_password) is None:
        raise ValueError("Operator authentication failed")
    timestamp = datetime.now(timezone.utc).isoformat()
    test_id = "TST-" + uuid.uuid4().hex[:10].upper()
    image_hash = sha256_bytes(image_bytes)
    image_path = IMAGE_DIR / f"{test_id}.jpg"
    image_path.write_bytes(image_bytes)
    previous_hash = latest_record_hash()
    unsigned = {
        "test_id": test_id,
        "operator_id": operator_id,
        "kit_id": kit_id,
        "result": analysis["result"],
        "confidence": round(float(analysis["confidence"]), 6),
        "timestamp": timestamp,
        "latitude": None if latitude is None else float(latitude),
        "longitude": None if longitude is None else float(longitude),
        "location_accuracy": None if location_accuracy is None else float(location_accuracy),
        "image_hash": image_hash,
        "previous_hash": previous_hash,
        "reference_card_ok": bool(analysis["reference_card_ok"]),
        "analysis_notes": analysis["notes"],
    }
    record_hash = sha256_bytes(canonical_json(unsigned))
    signed_payload = {**unsigned, "record_hash": record_hash}
    signature = sign_payload(signed_payload, operator_id=operator_id, password=operator_password)
    conn = get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO tests (
                test_id, operator_id, kit_id, result, confidence, timestamp,
                latitude, longitude, location_accuracy, image_path, image_hash,
                record_hash, previous_hash, signature, reference_card_ok, analysis_notes, signature_key_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                test_id, operator_id, kit_id, unsigned["result"], unsigned["confidence"], timestamp,
                latitude, longitude, location_accuracy, str(image_path), image_hash,
                record_hash, previous_hash, signature, int(unsigned["reference_card_ok"]), unsigned["analysis_notes"], operator_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return {**signed_payload, "signature": signature, "image_path": str(image_path), "signature_key_id": operator_id}


def list_tests(search: str = "", operator_id: Optional[str] = None) -> list[sqlite3.Row]:
    conn = get_db_connection()
    try:
        params: list[Any] = []
        where: list[str] = []
        if search:
            q = f"%{search}%"
            where.append("(test_id LIKE ? OR operator_id LIKE ? OR result LIKE ? OR kit_id LIKE ?)")
            params.extend([q, q, q, q])
        if operator_id:
            where.append("operator_id = ?")
            params.append(operator_id)
        sql = "SELECT * FROM tests" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY rowid DESC"
        return conn.execute(sql, tuple(params)).fetchall()
    finally:
        conn.close()


def get_test(test_id: str) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    try:
        return conn.execute("SELECT * FROM tests WHERE test_id = ?", (test_id,)).fetchone()
    finally:
        conn.close()


def _record_unsigned(rowd: dict[str, Any]) -> dict[str, Any]:
    return {
        "test_id": rowd["test_id"],
        "operator_id": rowd["operator_id"],
        "kit_id": rowd["kit_id"],
        "result": rowd["result"],
        "confidence": rowd["confidence"],
        "timestamp": rowd["timestamp"],
        "latitude": None if rowd["latitude"] is None else float(rowd["latitude"]),
        "longitude": None if rowd["longitude"] is None else float(rowd["longitude"]),
        "location_accuracy": None if rowd["location_accuracy"] is None else float(rowd["location_accuracy"]),
        "image_hash": rowd["image_hash"],
        "previous_hash": rowd["previous_hash"],
        "reference_card_ok": bool(rowd["reference_card_ok"]),
        "analysis_notes": rowd["analysis_notes"],
    }


def verify_test(test_id: str) -> Dict[str, Any]:
    row = get_test(test_id)
    if not row:
        return {"found": False}
    rowd = dict(row)
    image_path = Path(rowd["image_path"])
    image_exists = image_path.exists()
    image_hash_ok = image_exists and sha256_bytes(image_path.read_bytes()) == rowd["image_hash"]
    unsigned = _record_unsigned(rowd)
    recomputed_hash = sha256_bytes(canonical_json(unsigned))
    record_hash_ok = recomputed_hash == rowd["record_hash"]
    key_id = rowd.get("signature_key_id") or "LEGACY"
    signature_ok = verify_signature({**unsigned, "record_hash": rowd["record_hash"]}, rowd["signature"], operator_id=key_id if key_id != "LEGACY" else None)

    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT * FROM tests ORDER BY rowid ASC").fetchall()
    finally:
        conn.close()
    chain_ok = True
    chain_failure_at = None
    prev = "GENESIS"
    for r in rows:
        rd = dict(r)
        if rd["previous_hash"] != prev:
            chain_ok = False
            chain_failure_at = rd["test_id"]
            break
        ru = _record_unsigned(rd)
        if sha256_bytes(canonical_json(ru)) != rd["record_hash"]:
            chain_ok = False
            chain_failure_at = rd["test_id"]
            break
        prev = rd["record_hash"]

    return {
        "found": True,
        "image_exists": image_exists,
        "image_hash_ok": image_hash_ok,
        "record_hash_ok": record_hash_ok,
        "signature_ok": signature_ok,
        "audit_chain_ok": chain_ok,
        "chain_failure_at": chain_failure_at,
        "signature_key_id": key_id,
        "all_ok": all([image_hash_ok, record_hash_ok, signature_ok, chain_ok]),
        "recomputed_hash": recomputed_hash,
    }


def public_key_fingerprint(operator_id: str) -> str:
    path = operator_public_path(operator_id)
    if not path.exists():
        return "N/A"
    return sha256_bytes(path.read_bytes())[:24]

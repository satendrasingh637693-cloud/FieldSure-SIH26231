from typing import Any

from supabase_client import get_supabase


TEST_COLUMNS = [
    "test_id",
    "operator_id",
    "kit_id",
    "result",
    "confidence",
    "timestamp",
    "latitude",
    "longitude",
    "location_accuracy",
    "image_path",
    "image_hash",
    "record_hash",
    "previous_hash",
    "signature",
    "reference_card_ok",
    "analysis_notes",
    "signature_key_id",
]


def save_test_record(record: dict[str, Any]) -> None:
    db = get_supabase()
    if db is None:
        raise RuntimeError("Supabase is not configured")

    row = {column: record.get(column) for column in TEST_COLUMNS}
    row["confidence"] = round(float(record.get("confidence", 0.0)), 6)
    row["reference_card_ok"] = int(bool(record.get("reference_card_ok")))
    if row["latitude"] is not None:
        row["latitude"] = float(row["latitude"])
    if row["longitude"] is not None:
        row["longitude"] = float(row["longitude"])
    if row["location_accuracy"] is not None:
        row["location_accuracy"] = float(row["location_accuracy"])

    db.table("tests").upsert(
        row,
        on_conflict="test_id",
    ).execute()


def delete_test_record(test_id: str) -> None:
    db = get_supabase()
    if db is None:
        raise RuntimeError("Supabase is not configured")

    db.table("tests").delete().eq("test_id", test_id).execute()


def get_test_record(test_id: str) -> dict[str, Any] | None:
    db = get_supabase()
    if db is None:
        return None

    response = (
        db.table("tests")
        .select("*")
        .eq("test_id", test_id)
        .limit(1)
        .execute()
    )

    return response.data[0] if response.data else None

EVIDENCE_BUCKET = "fieldsure-evidence"


def upload_test_image(test_id: str, image_bytes: bytes) -> str:
    db = get_supabase()
    if db is None:
        raise RuntimeError("Supabase is not configured")

    path = f"tests/{test_id}.jpg"

    db.storage.from_(EVIDENCE_BUCKET).upload(
        path,
        image_bytes,
        file_options={
            "content-type": "image/jpeg",
            "upsert": "true",
        },
    )

    return path


def download_test_image(storage_path: str) -> bytes:
    db = get_supabase()
    if db is None:
        raise RuntimeError("Supabase is not configured")

    return db.storage.from_(EVIDENCE_BUCKET).download(storage_path)


def delete_test_image(storage_path: str) -> None:
    db = get_supabase()
    if db is None:
        raise RuntimeError("Supabase is not configured")

    db.storage.from_(EVIDENCE_BUCKET).remove([storage_path])

OPERATOR_COLUMNS = [
    "operator_id",
    "display_name",
    "role",
    "password_salt",
    "password_hash",
    "public_key_fingerprint",
    "active",
    "created_at",
]


def save_operator(operator: dict[str, Any]) -> None:
    db = get_supabase()
    if db is None:
        raise RuntimeError("Supabase is not configured")

    row = {column: operator.get(column) for column in OPERATOR_COLUMNS}

    db.table("operators").upsert(
        row,
        on_conflict="operator_id",
    ).execute()


def update_operator(operator: dict[str, Any]) -> None:
    """Persist the supplied operator record to the remote operator directory."""
    save_operator(operator)


def get_operator(operator_id: str) -> dict[str, Any] | None:
    db = get_supabase()
    if db is None:
        return None

    response = (
        db.table("operators")
        .select("*")
        .eq("operator_id", operator_id)
        .limit(1)
        .execute()
    )

    return response.data[0] if response.data else None


def list_operators_remote() -> list[dict[str, Any]]:
    db = get_supabase()
    if db is None:
        return []

    response = (
        db.table("operators")
        .select("*")
        .order("operator_id")
        .execute()
    )

    return response.data or []

def _operator_key_path(operator_id: str, filename: str) -> str:
    safe_id = (
        str(operator_id)
        .strip()
        .replace("/", "_")
        .replace("\\", "_")
        .replace("..", "_")
    )
    return f"operators/{safe_id}/{filename}"


def upload_operator_keys(
    operator_id: str,
    private_key_bytes: bytes,
    public_key_bytes: bytes,
) -> tuple[str, str]:
    db = get_supabase()
    if db is None:
        raise RuntimeError("Supabase is not configured")

    private_path = _operator_key_path(operator_id, "private_key.pem")
    public_path = _operator_key_path(operator_id, "public_key.pem")

    db.storage.from_(EVIDENCE_BUCKET).upload(
        private_path,
        private_key_bytes,
        file_options={
            "content-type": "application/x-pem-file",
            "upsert": "true",
        },
    )

    db.storage.from_(EVIDENCE_BUCKET).upload(
        public_path,
        public_key_bytes,
        file_options={
            "content-type": "application/x-pem-file",
            "upsert": "true",
        },
    )

    return private_path, public_path


def download_operator_private_key(operator_id: str) -> bytes:
    db = get_supabase()
    if db is None:
        raise RuntimeError("Supabase is not configured")

    path = _operator_key_path(operator_id, "private_key.pem")
    return db.storage.from_(EVIDENCE_BUCKET).download(path)


def download_operator_public_key(operator_id: str) -> bytes:
    db = get_supabase()
    if db is None:
        raise RuntimeError("Supabase is not configured")

    path = _operator_key_path(operator_id, "public_key.pem")
    return db.storage.from_(EVIDENCE_BUCKET).download(path)


def delete_operator_keys(operator_id: str) -> None:
    db = get_supabase()
    if db is None:
        raise RuntimeError("Supabase is not configured")

    private_path = _operator_key_path(operator_id, "private_key.pem")
    public_path = _operator_key_path(operator_id, "public_key.pem")

    db.storage.from_(EVIDENCE_BUCKET).remove(
        [private_path, public_path]
    )

def latest_test_record_hash() -> str:
    db = get_supabase()
    if db is None:
        return "GENESIS"

    response = (
        db.table("tests")
        .select("record_hash")
        .order("timestamp", desc=True)
        .order("test_id", desc=True)
        .limit(1)
        .execute()
    )

    return response.data[0]["record_hash"] if response.data else "GENESIS"


def list_test_records(
    search: str = "",
    operator_id: str | None = None,
) -> list[dict[str, Any]]:
    db = get_supabase()
    if db is None:
        return []

    response = (
        db.table("tests")
        .select("*")
        .order("timestamp", desc=True)
        .order("test_id", desc=True)
        .execute()
    )

    rows = response.data or []

    if operator_id:
        rows = [
            row for row in rows
            if row.get("operator_id") == operator_id
        ]

    if search:
        search_lower = search.lower()
        rows = [
            row
            for row in rows
            if any(
                search_lower in str(row.get(field, "")).lower()
                for field in ("test_id", "operator_id", "result", "kit_id")
            )
        ]

    return rows
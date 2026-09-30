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
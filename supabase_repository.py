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
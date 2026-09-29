from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

DB_PATH = Path("data") / "field_tests.db"

parser = argparse.ArgumentParser(description="Deliberately modify one stored result for a SIH tamper-detection demo.")
parser.add_argument("test_id", nargs="?", help="Existing test ID. If omitted, the newest test is used.")
parser.add_argument("--result", default="POSITIVE", choices=["POSITIVE", "NEGATIVE", "INCONCLUSIVE"])
args = parser.parse_args()

conn = sqlite3.connect(DB_PATH)
try:
    test_id = args.test_id
    if not test_id:
        row = conn.execute("SELECT test_id FROM tests ORDER BY rowid DESC LIMIT 1").fetchone()
        if row is None:
            raise SystemExit("No test records exist. Create a test first.")
        test_id = row[0]

    row = conn.execute("SELECT result FROM tests WHERE test_id = ?", (test_id,)).fetchone()
    if row is None:
        raise SystemExit(f"Test ID not found: {test_id}")

    print("Original result:", row[0])
    conn.execute("UPDATE tests SET result = ? WHERE test_id = ?", (args.result, test_id))
    conn.commit()
    print("Tampering completed.")
    print("Changed result to:", args.result)
finally:
    conn.close()

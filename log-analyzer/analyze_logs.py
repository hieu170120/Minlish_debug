"""Import instrumentation assessments from Logcat or JSONL using the stdlib."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
import sys

BASE = Path(__file__).resolve().parent
DEFAULT_INPUT = BASE / "samples" / "instrumentation-events.jsonl"
DEFAULT_DB = BASE / "output" / "security_events.db"
RESULTS = {"DETECTED", "NOT_DETECTED", "INCONCLUSIVE"}
SERVICES = {"LISTENER_OBSERVED", "NOT_OBSERVED", "INCONCLUSIVE"}
TAG = re.compile(r"\bMinLishSecurityLab(?:\(\s*\d+\s*\))?\s*:\s*(.*)$")
NOISE = re.compile(r"^(?:---------|\d{2}-\d{2}\s+\d{2}:\d{2}:|[VDIWEFAS]/|[VDIWEFAS]\s+[^:]+:)")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})")


def parse_line(line):
    """Return five stored fields, None for documented noise, or ValueError."""
    text = line.strip()
    if not text:
        return None
    if not text.startswith(("{", "[")):
        tagged = TAG.search(text)
        if tagged:
            text = tagged.group(1)
        elif NOISE.match(text):
            return None
    try:
        event = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        raise ValueError("malformed JSON or excessive nesting") from None
    if not isinstance(event, dict):
        raise ValueError("JSON event must be an object")
    if event.get("event_type") == "ROOT_ASSESSMENT":
        return None  # Preserve the original instrumentation-only scope.
    if event.get("event_type") != "INSTRUMENTATION_ASSESSMENT":
        raise ValueError("missing or unsupported event_type")
    if "schema_version" in event and (type(event["schema_version"]) is not int or event["schema_version"] != 1):
        raise ValueError("unsupported schema_version")
    for field, allowed in (("result", RESULTS), ("process_result", RESULTS), ("local_service", SERVICES)):
        value = event.get(field)
        if field != "result" and value is None:
            continue
        if not isinstance(value, str) or value not in allowed:
            raise ValueError(f"missing or invalid {field}")
    stamp = event.get("timestamp")
    if not isinstance(stamp, str) or not TIMESTAMP.fullmatch(stamp):
        raise ValueError("timestamp must be timezone-aware ISO-8601, with at most six fractional digits")
    try:
        moment = datetime.fromisoformat(stamp).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ValueError("invalid timestamp") from None
    # Canonical UTC keys retain microseconds and deduplicate equivalent offsets.
    stamp = moment.isoformat(timespec="microseconds")[:-6].rstrip("0").rstrip(".") + "Z"
    return (event["event_type"], stamp, event["result"], event.get("process_result"), event.get("local_service"))


def import_events(input_path, db_path, diagnostics=None):
    diagnostics = sys.stderr if diagnostics is None else diagnostics
    input_path, db_path = Path(input_path), Path(db_path)
    if not input_path.is_file():
        raise ValueError(f"input file not found: {input_path}")
    if input_path.resolve() == db_path.resolve() or (db_path.exists() and input_path.samefile(db_path)):
        raise ValueError("input and database must be different files")
    counts = dict.fromkeys(("accepted", "rejected", "duplicate", "conflicting_duplicate", "ignored"), 0)
    with input_path.open(encoding="utf-8-sig") as source:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(db_path)) as conn, conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    result TEXT NOT NULL,
                    process_result TEXT,
                    local_service TEXT,
                    PRIMARY KEY (event_type, timestamp)
                )
            """)
            for number, line in enumerate(source, 1):
                try:
                    row = parse_line(line)
                except ValueError as error:
                    counts["rejected"] += 1
                    print(f"Line {number}: rejected ({error})", file=diagnostics)
                    continue
                if row is None:
                    counts["ignored"] += 1
                    continue
                existing = conn.execute(
                    "SELECT result, process_result, local_service FROM security_events WHERE event_type = ? AND timestamp = ?",
                    row[:2],
                ).fetchone()
                if existing is None:
                    conn.execute(
                        "INSERT INTO security_events (event_type, timestamp, result, process_result, local_service) VALUES (?, ?, ?, ?, ?)",
                        row,
                    )
                    counts["accepted"] += 1
                elif existing == row[2:]:
                    counts["duplicate"] += 1
                else:
                    counts["conflicting_duplicate"] += 1
                    print(f"Line {number}: conflicting duplicate; existing row kept", file=diagnostics)
            summary = conn.execute("SELECT result, COUNT(*) FROM security_events GROUP BY result ORDER BY result").fetchall()
            # ponytail: small lab timelines fit memory; stream rows if captures outgrow it.
            timeline = conn.execute("SELECT timestamp, result FROM security_events ORDER BY timestamp").fetchall()
    return counts, summary, timeline


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, default=DEFAULT_INPUT, help="Logcat or JSONL file (default: bundled sample)")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite output (default: script-relative output/security_events.db)")
    args = parser.parse_args(argv)
    try:
        counts, summary, timeline = import_events(args.input, args.db)
    except (OSError, UnicodeError, ValueError, sqlite3.Error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print("Import:", " ".join(f"{key}={value}" for key, value in counts.items()))
    print("\nDatabase result summary:")
    for result, count in summary:
        print(f"{result}: {count}")
    print("\nEvent timeline:")
    for stamp, result in timeline:
        print(f"{stamp} -> {result}")
    print(f"\nSQLite database: {args.db}")
    print(f"Stored events: {len(timeline)}")
    return 2 if counts["rejected"] or counts["conflicting_duplicate"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

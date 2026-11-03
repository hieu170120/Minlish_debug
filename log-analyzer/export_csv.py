"""Export the existing event timeline query to a new CSV file."""

import argparse
from contextlib import closing
import csv
from pathlib import Path
import sqlite3
import sys

from analyze_logs import DEFAULT_DB

COLUMNS = ("timestamp", "event_type", "result", "process_result", "local_service")
QUERY = """
SELECT timestamp, event_type, result, process_result, local_service
FROM security_events
ORDER BY timestamp ASC;
"""


def export_csv(db_path, output_path):
    db_path, output_path = Path(db_path), Path(output_path)
    if not db_path.is_file():
        raise ValueError(f"database not found: {db_path}")
    if output_path.exists():
        raise ValueError("output already exists; choose a new --output path (no files were overwritten)")
    with closing(sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        # ponytail: small lab exports fit memory; stream the cursor for large datasets.
        rows = conn.execute(QUERY).fetchall()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(COLUMNS)
        writer.writerows(rows)
    return len(rows)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--output", type=Path, default=DEFAULT_DB.with_name("security_report.csv"))
    args = parser.parse_args(argv)
    try:
        count = export_csv(args.db, args.output)
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(f"CSV report created: {args.output}")
    print(f"Total exported events: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# MinLish Security Log Analyzer

A small Python/SQLite workflow for importing **instrumentation assessments**, summarizing results, and exporting a CSV timeline. It uses only the Python standard library. This is event analysis, not proof that a device is secure or that instrumentation was prevented.

## Requirements

- Python **3.12**; no pip packages, Android SDK, Frida, Firebase, network connection, or external SQLite executable is required for the bundled example.
- A writable output directory. Keep raw evidence and original databases separate from generated output.

## Reproduce from a clean checkout

Open a terminal at the repository root and change into this directory:

```powershell
cd log-analyzer
python -B -m unittest -v test_analyzer
python -B analyze_logs.py
python -B export_csv.py
```

Defaults are resolved relative to the scripts, not to the author's computer:

| Purpose | Default |
| --- | --- |
| Input | `samples/instrumentation-events.jsonl` |
| SQLite database | `output/security_events.db` |
| CSV output | `output/security_report.csv` |

Historical root-level database/CSV artifacts from the original workspace are not bundled. Defaults write only beneath output/. No mandatory path outside the checkout remains.

Explicit arguments, from this directory:

```powershell
python -B analyze_logs.py samples/instrumentation-events.jsonl --db output/custom/events.db
python -B export_csv.py --db output/custom/events.db --output output/custom/report.csv
```

User-supplied relative paths are resolved against the terminal's current directory; absolute paths also work. Invoke a script by its full path from another directory to use its script-relative defaults. `--help` lists arguments.

Import appends new records without replacing old ones. Export opens SQLite read-only and **refuses an existing output file**, including the database itself. To export again, choose a fresh `--output` filename. The tool does not delete prior runs or automatically reset databases. To repeat the entire workflow from scratch, use a new database/output directory; do not delete historical evidence.

## Input formats and scope

Each event must fit on one line. Supported forms include:

- Raw JSONL: one JSON object per line, as produced by `adb logcat -v raw` after removing buffer headers.
- Tagged threadtime output: a line ending in `I MinLishSecurityLab: { ... }`.
- Tagged brief output: `I/MinLishSecurityLab( 123): { ... }`.

Blank lines, buffer headers, recognizable unrelated Logcat lines, and `ROOT_ASSESSMENT` objects are counted as **ignored**. This intentionally preserves the original analyzer's instrumentation-only scope. Other unsupported event types, malformed JSON, non-object JSON, and invalid required fields are rejected. Unrecognized text is rejected rather than silently discarded.

Required fields:

| Field | Accepted values |
| --- | --- |
| `event_type` | `INSTRUMENTATION_ASSESSMENT` |
| `timestamp` | A real ISO-8601 date/time with `T`, seconds, timezone `Z` or `+/-HH:MM`, and optional 1–6 fractional digits |
| `result` | `DETECTED`, `NOT_DETECTED`, `INCONCLUSIVE` |

Optional fields:

- `process_result`: one of the same assessment values, or null/omitted.
- `local_service`: `LISTENER_OBSERVED`, `NOT_OBSERVED`, `INCONCLUSIVE`, or null/omitted.
- `schema_version`: when supplied, integer `1` (not Boolean).

Timestamps normalize to UTC, retaining up to microsecond precision. Equivalent timezone representations share the same database key. The bundled events retain their original timestamps.

Additional fields such as `signals`, `checks`, and `source` remain in the sample for context, but are **not stored or validated by this summary analyzer**. It does not recompute detector verdicts or verify that every combination of fields is semantically consistent.

## SQLite schema and duplicate policy

The existing five-column schema and parameterized SQL are retained:

```sql
CREATE TABLE security_events (
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    result TEXT NOT NULL,
    process_result TEXT,
    local_service TEXT,
    PRIMARY KEY (event_type, timestamp)
);
```

Counters are mutually exclusive for each input line:

- `accepted`: valid event inserted as a new database row.
- `rejected`: malformed/invalid input; line number and a generic reason are sent to stderr without echoing raw input.
- `duplicate`: the same key and the same three persisted result fields already exist.
- `conflicting_duplicate`: the key exists but a persisted result field differs. The existing row is kept and the conflict is reported.
- `ignored`: documented noise or root assessments outside this analyzer's scope.

Duplicate comparison covers the **five stored columns**, not the full JSON payload. Different signal metadata with identical stored values is the same summary record. There is no automatic schema migration, payload archive, or overwrite/upsert behavior. Review a backup before explicitly selecting an older database; legacy keys with noncanonical timestamp strings are not rewritten automatically.

Valid rows are committed even when other lines are rejected or conflicting. Fatal file/encoding/SQLite failures return a controlled error; database changes in the current transaction are rolled back. Import exit codes: `0` for success (including identical reimports), `2` when any line was rejected or conflicting, `1` for a fatal operational error. Export returns `0` on success and `1` on a controlled error. Check both counters and exit status when using automation.

## Sample provenance and expected results

The four bundled events are a sanitized, field-whitelisted extraction of the existing captured Logcat artifact `T05-server-only-evidence.txt`. That filename describes a capture, **not a guarantee that every buffered event came from the server-only state**. Original raw evidence was not modified and is not required to run this example.

Original capture SHA-256: `41069a6c7f118267dbc01414aeb1ce2e3a2f685be71dd150615c87291e11d068`.

| UTC timestamp on 2026-10-30 | Recorded state/context | Result |
| --- | --- | --- |
| `05:25:58.079Z` | Server-only observation; process checks negative | `INCONCLUSIVE` |
| `05:43:37.634Z` | Attached observation; memory/thread positive; port incomplete | `DETECTED` |
| `06:11:50.289Z` | Later baseline; process/port negative | `NOT_DETECTED` |
| `06:18:19.418Z` | Later server-only observation | `INCONCLUSIVE` |

This is a **mixed-state historical sample**, not four server-only tests, four independent attachments, or a newly executed security experiment. It contains typed detector fields only: no log prefix/PID, memory addresses, raw maps, raw thread names, credentials, tokens, personal records, or persistent device identifiers. Detector names and results are not proof of the underlying test setup independently of the original experiment evidence.

First import into an empty database:

```text
Import: accepted=4 rejected=0 duplicate=0 conflicting_duplicate=0 ignored=0
DETECTED: 1
INCONCLUSIVE: 2
NOT_DETECTED: 1
Stored events: 4
```

The summary is over **all rows in the selected database**, not just newly accepted lines. The timeline prints the stored UTC timestamps/results. CSV has one header and exactly **four data rows**, with columns `timestamp,event_type,result,process_result,local_service`; null optional fields export as empty cells.

Run the importer a second time against the same database:

```powershell
python -B analyze_logs.py
```

Expected: `accepted=0 rejected=0 duplicate=4 conflicting_duplicate=0 ignored=0`; database row count remains four.

## SQL queries without installing the SQLite CLI

The original `queries.sql` and `detected_events.sql` are unchanged. From this directory:

```powershell
python -B -c "import sqlite3; from pathlib import Path; db=sqlite3.connect('file:output/security_events.db?mode=ro',uri=True); print(db.execute(Path('queries.sql').read_text()).fetchall()); db.close()"
python -B -c "import sqlite3; from pathlib import Path; db=sqlite3.connect('file:output/security_events.db?mode=ro',uri=True); print(db.execute(Path('detected_events.sql').read_text()).fetchall()); db.close()"
```

Expected summary: `INCONCLUSIVE=2`, `DETECTED=1`, `NOT_DETECTED=1`; equal-count row ordering is unspecified by the original query. The detected query returns exactly the event at `2026-10-30T05:43:37.634Z`, with process `DETECTED` and local service `INCONCLUSIVE`.

## Tests, safety, and limitations

`python -B -m unittest -v test_analyzer` uses seven standard-library tests with disposable databases underneath `output/`. They cover both input formats, invalid records and excessively nested JSON, diagnostics, exact/conflicting duplicates, reimports, timestamp normalization, SQL persistence/queries, CSV rows/overwrite refusal, path collisions, missing files, invalid UTF-8, exit codes, and invocation from another working directory. Test-only synthetic invalid records are not runtime evidence.

This is a small offline summary tool: it does not authenticate logs, assess bypass resistance, ingest multiline JSON, preserve per-signal details in SQLite, or stream CSV exports of arbitrarily large databases. Input is read line by line; the summary timeline and export are held in memory. Add streaming output only if dataset size requires it. The tool assumes UTF-8 text and a valid compatible SQLite schema; do not point it at unrelated or untrusted databases.

The local `.gitignore` excludes generated `output/`, bytecode caches, a local `raw/` folder, and common credential filenames. Keep source, tests, SQL, this README, and the sanitized sample under version control. Historical root-level DB/CSV files are not silently hidden or overwritten. Ignore rules do not sanitize content or remove previously committed secrets: review staged files and publication copies before publishing. No Firebase, Android, detector, or assessment-report changes are needed to run this directory.

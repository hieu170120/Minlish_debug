import csv
from contextlib import closing
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from analyze_logs import BASE, DEFAULT_INPUT, import_events, parse_line
from export_csv import export_csv


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        output = BASE / "output"
        output.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="test-", dir=output)
        self.folder = Path(temporary.name).resolve()
        self.folder.relative_to(BASE)  # Verify cleanup stays within the authorized folder.
        self.addCleanup(temporary.cleanup)
        self.db = self.folder / "events.db"
        self.event = json.loads(DEFAULT_INPUT.read_text(encoding="utf-8-sig").splitlines()[0])

    def ingest(self, events):
        source = self.folder / "input.jsonl"
        source.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
        return import_events(source, self.db, io.StringIO())

    def test_sample_persistence_queries_and_export(self):
        counts, summary, timeline = import_events(DEFAULT_INPUT, self.db)
        self.assertEqual(counts, dict(accepted=4, rejected=0, duplicate=0, conflicting_duplicate=0, ignored=0))
        expected = {"INCONCLUSIVE": 2, "DETECTED": 1, "NOT_DETECTED": 1}
        self.assertEqual(dict(summary), expected)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(dict(conn.execute((BASE / "queries.sql").read_text()).fetchall()), expected)
            detected = conn.execute((BASE / "detected_events.sql").read_text()).fetchall()
            self.assertEqual(len(detected), 1)
            self.assertEqual(detected[0][0], "2026-10-30T05:43:37.634Z")
        target = self.folder / "report.csv"
        self.assertEqual(export_csv(self.db, target), 4)
        with target.open(newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source))
        self.assertEqual(len(rows), 4)
        self.assertEqual([r["timestamp"] for r in rows], [t for t, _ in timeline])
        original = target.read_bytes()
        with self.assertRaises(ValueError):
            export_csv(self.db, target)
        self.assertEqual(target.read_bytes(), original)
        self.assertEqual(import_events(DEFAULT_INPUT, self.db)[0]["duplicate"], 4)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0], 4)

    def test_logcat_formats_and_noise(self):
        raw = json.dumps(self.event)
        for line in [raw, f"10-30 13:18:19.418 123 456 I MinLishSecurityLab: {raw}",
                     f"I/MinLishSecurityLab( 123): {raw}"]:
            self.assertEqual(parse_line(line), parse_line(raw))
        for line in ["", "--------- beginning of main", "10-30 13:00:00.000 123 456 I OtherTag: text",
                     json.dumps({"event_type": "ROOT_ASSESSMENT"})]:
            self.assertIsNone(parse_line(line))

    def test_invalid_inputs_are_counted_without_raw_data_in_diagnostics(self):
        invalid = [[], None, 1, "sensitive-value", {}, dict(self.event, result=[]),
                   dict(self.event, result="INVALID"), dict(self.event, timestamp="2026-02-30T00:00:00Z"),
                   dict(self.event, timestamp="2026-10-30T00:00:00"), dict(self.event, process_result="BAD"),
                   dict(self.event, local_service="BAD"), dict(self.event, schema_version=True),
                   {k: v for k, v in self.event.items() if k != "timestamp"},
                   {k: v for k, v in self.event.items() if k != "result"}]
        source = self.folder / "bad.jsonl"
        source.write_text("{broken\n" + "[" * 2000 + "\n" + "\n".join(json.dumps(e) for e in invalid) + "\n" + json.dumps(self.event), encoding="utf-8")
        diagnostics = io.StringIO()
        counts, _, _ = import_events(source, self.db, diagnostics)
        self.assertEqual(counts["rejected"], len(invalid) + 2)
        self.assertEqual(counts["accepted"], 1)
        self.assertIn("Line 1: rejected", diagnostics.getvalue())
        self.assertNotIn("sensitive-value", diagnostics.getvalue())

    def test_duplicates_and_conflicts_never_replace_existing_values(self):
        counts, _, _ = self.ingest([self.event, self.event, dict(self.event, result="DETECTED")])
        self.assertEqual((counts["accepted"], counts["duplicate"], counts["conflicting_duplicate"]), (1, 1, 1))
        counts, _, _ = self.ingest([dict(self.event, local_service="NOT_OBSERVED")])
        self.assertEqual(counts["conflicting_duplicate"], 1)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute("SELECT result,local_service FROM security_events").fetchone(),
                             (self.event["result"], self.event["local_service"]))

    def test_equivalent_timestamps_and_microsecond_precision(self):
        first = dict(self.event, timestamp="2026-11-01T07:00:00.123456+07:00")
        same = dict(first, timestamp="2026-11-01T00:00:00.123456Z")
        later = dict(first, timestamp="2026-11-01T00:00:00.123457Z")
        counts, _, _ = self.ingest([first, same, later])
        self.assertEqual((counts["accepted"], counts["duplicate"]), (2, 1))

    def test_missing_files_and_path_collision_do_not_create_or_damage_files(self):
        with self.assertRaises(ValueError):
            import_events(self.folder / "missing", self.db)
        self.assertFalse(self.db.exists())
        with self.assertRaises(ValueError):
            export_csv(self.db, self.folder / "out.csv")
        self.assertFalse(self.db.exists())
        source = self.folder / "input.jsonl"
        source.write_text(json.dumps(self.event), encoding="utf-8")
        before = source.read_bytes()
        with self.assertRaises(ValueError):
            import_events(source, source)
        self.assertEqual(source.read_bytes(), before)

    def test_cli_works_from_another_directory_and_returns_controlled_errors(self):
        command = [sys.executable, "-B", str(BASE / "analyze_logs.py"), str(DEFAULT_INPUT), "--db", str(self.db)]
        run = subprocess.run(command, cwd=self.folder, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("accepted=4", run.stdout)
        run = subprocess.run(command, cwd=self.folder, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("duplicate=4", run.stdout)
        source = self.folder / "bad.jsonl"
        source.write_text("{broken", encoding="utf-8")
        command[3] = str(source)
        run = subprocess.run(command, cwd=self.folder, capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertIn("rejected=1", run.stdout)
        self.assertNotIn("Traceback", run.stderr)
        source.write_bytes(b"\xff")
        run = subprocess.run(command, cwd=self.folder, capture_output=True, text=True)
        self.assertEqual(run.returncode, 1)
        self.assertNotIn("Traceback", run.stderr)
        target = self.folder / "cli.csv"
        export = subprocess.run([sys.executable, "-B", str(BASE / "export_csv.py"), "--db", str(self.db),
                                 "--output", str(target)], cwd=self.folder, capture_output=True, text=True)
        self.assertEqual(export.returncode, 0, export.stderr)
        self.assertIn("Total exported events: 4", export.stdout)


if __name__ == "__main__":
    unittest.main()

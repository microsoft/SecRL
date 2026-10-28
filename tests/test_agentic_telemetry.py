# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import csv
import json
import tempfile
import unittest
from pathlib import Path

import duckdb

from secgym.qagen.agentic.telemetry import attach_baseline, scan_csv, stage_csv


class TelemetryInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.con = duckdb.connect(config={"memory_limit": "256MB", "threads": 1})
        self.addCleanup(self.con.close)

    def source(self, header, rows):
        path = self.root / "input.csv"
        with path.open("w", newline="") as stream:
            writer = csv.writer(stream, delimiter="❖")
            writer.writerow(header)
            writer.writerows(rows)
        return path

    def test_valid_json_numeric_and_time_columns(self):
        path = self.source(["TimeGenerated", "Value", "Details"], [
            ["2024-06-20T11:00:00Z", "1", json.dumps({"x": "quoted value"})],
        ])
        result = scan_csv(self.con, path, {"TimeGenerated": "datetime", "Value": "long", "Details": "dynamic"},
                          {"TimeGenerated", "Value", "Details"})
        self.assertEqual(result.rows, 1)
        self.assertEqual(result.findings, ())

    def test_bad_casts_and_non_json_are_visible_not_repaired(self):
        path = self.source(["Count", "Rate", "Flag", "Details"], [
            ["1.5", "NaN", "yes", "{'x': 1}"],
        ])
        result = scan_csv(self.con, path, {"Count": "int", "Rate": "real", "Flag": "bool", "Details": "dynamic"},
                          {"Count", "Rate", "Flag", "Details"})
        self.assertEqual(len(result.findings), 4)
        self.assertTrue(all(f.rows == 1 and f.sample_record_ordinals == (1,) for f in result.findings))

    def test_extra_nonempty_columns_are_not_dropped(self):
        path = self.source(["Known", "Extra"], [["a", "important"], ["b", ""]])
        result = scan_csv(self.con, path, {"Known": "string", "Extra": "string"}, {"Known"})
        self.assertEqual(result.extra_columns, ("Extra",))
        self.assertEqual(result.findings[0].rows, 1)
        self.assertEqual(result.findings[0].kind, "extra_column_nonempty")

    def test_unknown_source_column_is_reported(self):
        path = self.source(["Known", "Unknown"], [["a", "b"]])
        result = scan_csv(self.con, path, {"Known": "string"}, {"Known"})
        self.assertEqual(result.columns_missing_metadata, ("Unknown",))

    def test_metadata_columns_missing_from_file_are_explicit(self):
        path = self.source(["Known"], [["a"]])
        result = scan_csv(self.con, path, {"Known": "string", "Absent": "string"}, {"Known"})
        self.assertEqual(result.metadata_columns_absent_from_file, ("Absent",))

    def test_csv_parse_failure_is_not_silently_skipped(self):
        path = self.root / "bad.csv"
        path.write_text('A❖B\n"unclosed❖field\n')
        with self.assertRaises(ValueError):
            scan_csv(self.con, path, {"A": "string", "B": "string"}, {"A", "B"})

    def test_transfer_preserves_json_closing_bracket_and_embedded_text(self):
        text = json.dumps([{"Type": "Task", "ApplicationInstance": 0}])
        command = 'powershell -command "quoted"\nsecond line ❖ delimiter'
        path = self.source(["ActivityObjects", "Command"], [[text, command]])
        stage_csv(self.con, path, "CloudAppEvents")
        row = self.con.execute("SELECT ActivityObjects,Command FROM input_rows").fetchone()
        self.assertEqual(row, (text, command))
        self.assertTrue(self.con.execute("SELECT json_valid(ActivityObjects) FROM input_rows").fetchone()[0])

    def test_source_record_cannot_be_shadowed_by_input(self):
        path = self.source(["source_record", "Value"], [["wrong", "a"]])
        with self.assertRaisesRegex(ValueError, "reserved"):
            stage_csv(self.con, path, "Synthetic")

    def test_case_alias_audit_uses_original_metadata_not_duckdb_suffixes(self):
        path = self.source(["pop_s", "POP_s"], [["A", ""], ["", "B"]])
        result = scan_csv(self.con, path, {"pop_s": "string", "POP_s": "string"},
                          {"pop_s", "POP_s_1"}, table="AzureDiagnostics")
        self.assertEqual(result.columns_missing_metadata, ())
        self.assertEqual(result.metadata_columns_absent_from_file, ())
        self.assertEqual(result.extra_columns, ())
        self.assertEqual(result.canonical_columns, ("pop_s",))

    def test_attach_readonly_handles_quoted_filename(self):
        db = self.root / "base'line.duckdb"
        with duckdb.connect(str(db)) as con:
            con.execute("CREATE TABLE t(x INTEGER)")
        attach_baseline(self.con, db)
        with self.assertRaises(duckdb.Error):
            self.con.execute("INSERT INTO baseline.t VALUES (1)")


if __name__ == "__main__":
    unittest.main()

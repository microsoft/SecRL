# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import duckdb

from secgym.qagen.agentic.columns import column_bindings
from secgym.qagen.agentic.dynamic import (
    MAX_TREE_DEPTH, MAX_VALUE_CHARACTERS, initialize_decision_tables,
    normalize_dynamic_fields, normalize_dynamic_stream, normalize_dynamic_value,
)
from secgym.qagen.agentic.sources import reconcile_sources
from test_agentic_sources import fixture_sources, write_csv


ROOT = Path(__file__).resolve().parents[1]


class DynamicValueTests(unittest.TestCase):
    def test_valid_json_is_byte_for_byte_unchanged(self):
        values = [
            '{"x": 1, "y": [true, false, null]}', ' [ {"unicode": "\\u00e9"} ] ',
            '"command with \'quotes\'"', "0", "false", "null", "-0.0",
        ]
        for raw in values:
            with self.subTest(raw=raw):
                result = normalize_dynamic_value(raw, "dynamic")
                self.assertEqual(result.status, "unchanged")
                self.assertEqual(result.normalized_value, raw)

    def test_known_file_type_literal_is_repaired(self):
        result = normalize_dynamic_value("{'FileType':'PortableExecutable'}", "dynamic")
        self.assertEqual(result.status, "repaired")
        self.assertEqual(result.normalized_value, '{"FileType":"PortableExecutable"}')

    def test_nested_json_compatible_literal_preserves_types(self):
        raw = "{'a': [True, False, None, -2, +3, -0.0, 1.25], 'b': {'c': 'quote \\' and path \\\\'}}"
        result = normalize_dynamic_value(raw, "dynamic")
        self.assertEqual(result.status, "repaired", result.reason)
        assert result.normalized_value is not None
        value = json.loads(result.normalized_value)
        self.assertEqual([type(v) for v in value["a"]], [bool, bool, type(None), int, int, float, float])
        self.assertEqual(value["b"]["c"], "quote ' and path \\")

    def test_empty_values_remain_missing_not_repair_events(self):
        for raw in (None, ""):
            result = normalize_dynamic_value(raw, "dynamic")
            self.assertEqual(result.status, "unchanged")
            self.assertEqual(result.normalized_value, raw)

    def test_non_dynamic_fields_are_never_repaired(self):
        for kind in ("string", "guid", "unknown"):
            for raw in ("{'FileType':'Error'}", "powershell 'quoted text'", "N/A", "{malformed"):
                with self.subTest(kind=kind, raw=raw):
                    result = normalize_dynamic_value(raw, kind)
                    self.assertEqual(result.status, "unchanged")
                    self.assertEqual(result.normalized_value, raw)

    def test_tuple_set_bytes_complex_and_numeric_keys_are_quarantined(self):
        for raw in ("{'x': (1, 2)}", "{1, 2}", "{'x': b'abc'}", "{'x': 1+2j}",
                    "{1: 'x'}", "{True: 'x'}", "{None: 'x'}"):
            with self.subTest(raw=raw):
                result = normalize_dynamic_value(raw, "dynamic")
                self.assertEqual(result.status, "quarantined")
                self.assertIsNone(result.normalized_value)

    def test_duplicate_keys_are_not_silently_discarded(self):
        for raw in ('{"x":1,"x":2}', "{'x':1,'x':2}", '{"nested":{"a":1,"a":1}}',
                    "{'x': 1, '\\x78': 1}"):
            with self.subTest(raw=raw):
                result = normalize_dynamic_value(raw, "dynamic")
                self.assertEqual(result.status, "quarantined")
                self.assertIn("duplicate", result.reason)

    def test_expressions_names_and_calls_are_not_executed(self):
        values = ("mark()", "[x for x in []]", "{'x': 1+2}", "{'x': unknown}",
                  "{**{'x':1}}", "{'x': str(1)}", "f'{1}'", "__import__('os')")
        for raw in values:
            with self.subTest(raw=raw):
                self.assertEqual(normalize_dynamic_value(raw, "dynamic").status, "quarantined")

    def test_nonfinite_values_are_quarantined(self):
        for raw in ('{"x":NaN}', '{"x":Infinity}', '{"x":1e400}', "{'x': 1e400}"):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_dynamic_value(raw, "dynamic").status, "quarantined")

    def test_float_precision_loss_is_not_accepted_as_repair(self):
        for raw in ("{'x':0.1234567890123456789}", "{'x':1e-400}", "{'x':-1e-400}"):
            with self.subTest(raw=raw):
                result = normalize_dynamic_value(raw, "dynamic")
                self.assertEqual(result.status, "quarantined")
                self.assertIn("precision", result.reason)

    def test_unpaired_unicode_surrogate_is_quarantined(self):
        for raw in ('"\\ud800"', "{'x':'\\ud800'}"):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_dynamic_value(raw, "dynamic").status, "quarantined")

    def test_size_and_depth_limits_are_explicit(self):
        result = normalize_dynamic_value("x" * (MAX_VALUE_CHARACTERS + 1), "dynamic")
        self.assertEqual(result.reason, "value_exceeds_size_limit")
        deep = "[" * (MAX_TREE_DEPTH + 2) + "0" + "]" * (MAX_TREE_DEPTH + 2)
        result = normalize_dynamic_value(deep, "dynamic")
        self.assertEqual(result.status, "quarantined")
        self.assertIn("structural", result.reason)

    def test_repair_is_idempotent(self):
        first = normalize_dynamic_value("{'a': True, 'b': [None, 1.0]}", "dynamic")
        second = normalize_dynamic_value(first.normalized_value, "dynamic")
        self.assertEqual(second.status, "unchanged")
        self.assertEqual(first.normalized_value, second.normalized_value)

    def test_whitespace_only_does_not_masquerade_as_known_absence(self):
        self.assertEqual(normalize_dynamic_value("   ", "dynamic").status, "quarantined")


class DynamicStreamTests(unittest.TestCase):
    def setUp(self):
        self.con = duckdb.connect(config={"threads": 1, "memory_limit": "256MB"})
        self.addCleanup(self.con.close)
        self.con.execute("CREATE TEMP TABLE input_rows(source_record BIGINT,Details VARCHAR,Command VARCHAR)")
        initialize_decision_tables(self.con)
        self.bindings = column_bindings(["Details", "Command"], "Synthetic")

    def run_stream(self):
        return normalize_dynamic_stream(
            self.con, relation="input_rows", table="Synthetic", source_id="fixture-source",
            locator="source_record", bindings=self.bindings,
            metadata={"Details": "dynamic", "Command": "string"}, target="normalized",
        )

    def test_only_repaired_dynamic_fields_change(self):
        self.con.executemany("INSERT INTO input_rows VALUES (?,?,?)", [
            (1, "{'FileType':'Error'}", "powershell 'quoted'"),
            (2, '{"x": 1}', "{'leave':'alone'}"), (3, None, "unchanged"),
            (4, "{'FileType':'Error'}", "another"),
        ])
        result = self.run_stream()
        self.assertEqual(result["outcomes"]["repaired"], 2)
        rows = self.con.execute("SELECT Details,Command FROM normalized ORDER BY _source_record").fetchall()
        self.assertEqual(rows, [('{"FileType":"Error"}', "powershell 'quoted'"),
                                ('{"x": 1}', "{'leave':'alone'}"), (None, "unchanged"),
                                ('{"FileType":"Error"}', "another")])
        self.assertEqual(self.con.execute("SELECT count(*) FROM dynamic_decisions").fetchone()[0], 1)
        self.assertEqual(self.con.execute("SELECT count(*) FROM field_changes").fetchone()[0], 2)
        self.assertEqual(self.con.execute("SELECT Details FROM input_rows WHERE source_record=1").fetchone()[0],
                         "{'FileType':'Error'}")

    def test_quarantine_has_explicit_field_level_metadata_and_raw_value(self):
        raw = "{'x': (1,2)}"
        self.con.execute("INSERT INTO input_rows VALUES (1,?,'other evidence remains')", [raw])
        result = self.run_stream()
        self.assertEqual(result["outcomes"]["quarantined"], 1)
        self.assertEqual(self.con.execute("SELECT Details,Command FROM normalized").fetchone(),
                         (None, "other evidence remains"))
        original, normalized, status, reason = self.con.execute(
            "SELECT original_value,normalized_value,status,reason FROM dynamic_decisions"
        ).fetchone()
        self.assertEqual(original, raw)
        self.assertIsNone(normalized)
        self.assertEqual(status, "quarantined")
        self.assertIn("Tuple", reason)
        self.assertEqual(self.con.execute("SELECT status FROM field_changes").fetchone()[0], "quarantined")

    def test_valid_stream_is_not_copied_or_rewritten(self):
        self.con.execute("INSERT INTO input_rows VALUES (1,'{\"x\": 1}','original')")
        result = self.run_stream()
        self.assertIsNone(result["normalized_table"])
        self.assertEqual(self.con.execute("SELECT count(*) FROM dynamic_decisions").fetchone()[0], 0)

    def test_missing_or_duplicate_source_locators_fail(self):
        for rows in ([(None, "{}", "")], [(1, "{}", ""), (1, "{}", "")]):
            self.con.execute("DELETE FROM input_rows")
            self.con.executemany("INSERT INTO input_rows VALUES (?,?,?)", rows)
            with self.subTest(rows=rows), self.assertRaisesRegex(ValueError, "source record locator"):
                self.run_stream()

    def test_actual_json_string_data_is_not_reinterpreted_as_an_object(self):
        raw = json.dumps("{'x':1}")
        self.con.execute("INSERT INTO input_rows VALUES (1,?,'')", [raw])
        result = self.run_stream()
        self.assertEqual(result["outcomes"]["unchanged"], 1)
        self.assertIsNone(result["normalized_table"])


class DynamicBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db, self.exports = fixture_sources(self.root, all_cases=True)
        with duckdb.connect(str(self.db)) as con:
            con.execute("CREATE TABLE DynamicEvents(_rid BIGINT,Details VARCHAR,Command VARCHAR)")
            con.execute("INSERT INTO DynamicEvents VALUES (1,'{\"key\": 1}','untouched')")
        write_csv(self.exports / "incident_34/DynamicEvents.csv",
                  [{"Details": "{'key': 1}", "Command": "{'leave':'unchanged'}"}],
                  {"Details": "dynamic", "Command": "string"})
        self.bundle = self.root / "i1"
        reconcile_sources(self.db, self.exports, self.bundle)

    def test_full_bundle_hashes_provenance_and_unchanged_inputs(self):
        sha = hashlib.sha256(self.db.read_bytes()).hexdigest()
        output = self.root / "dynamic"
        result = normalize_dynamic_fields(self.bundle, output)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["summary"]["dynamic_field_outcomes"]["repaired"], 1)
        self.assertEqual(result["summary"]["materialized_streams"], 1)
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), sha)
        self.assertEqual(hashlib.sha256((output / "dynamic_fields.duckdb").read_bytes()).hexdigest(),
                         result["database"]["sha256"])
        self.assertTrue((output / "dynamic_report.json").exists())
        self.assertIsNone(next(s for s in result["streams"] if s["source_locator_kind"] == "duckdb_rid")["normalized_table"])
        with self.assertRaisesRegex(ValueError, "already exists"):
            normalize_dynamic_fields(self.bundle, output)

    def test_changed_input_is_not_normalized_under_old_snapshot(self):
        with duckdb.connect(str(self.db)) as con:
            con.execute("UPDATE DynamicEvents SET Command='changed'")
        output = self.root / "changed"
        with self.assertRaisesRegex(ValueError, "input hashes"):
            normalize_dynamic_fields(self.bundle, output)
        self.assertFalse(output.exists())

    def test_quarantines_get_nonzero_cli_status_and_preserved_report(self):
        write_csv(self.exports / "incident_34/DynamicEvents.csv",
                  [{"Details": "{'a': (1,2)}", "Command": "keep"}],
                  {"Details": "dynamic", "Command": "string"})
        fresh = self.root / "fresh-i1"
        reconcile_sources(self.db, self.exports, fresh)
        output = self.root / "quarantine"
        result = subprocess.run([
            sys.executable, "-m", "secgym.qagen.agentic", "normalize-dynamic-fields",
            "--source-bundle", str(fresh), "--output", str(output),
        ], cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads((output / "dynamic_report.json").read_text())
        self.assertEqual(report["status"], "complete_with_quarantines")
        self.assertEqual(report["summary"]["dynamic_field_outcomes"]["quarantined"], 1)


if __name__ == "__main__":
    unittest.main()

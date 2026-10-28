# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import duckdb

from secgym.qagen.agentic.columns import (
    BASELINE_ORIGINAL_NAMES, DIAGNOSTIC_ALIASES, canonical_groups, checked_projection, column_bindings,
)
from secgym.qagen.agentic.sources import reconcile_sources
from secgym.qagen.agentic.telemetry import normalize_diagnostics, stage_csv
from test_agentic_sources import fixture_sources


class ColumnAliasTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.con = duckdb.connect(config={"memory_limit": "256MB", "threads": 1})
        self.addCleanup(self.con.close)

    def stage(self, header, rows, table="AzureDiagnostics"):
        path = self.root / "diagnostics.csv"
        with path.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.writer(stream, delimiter="❖")
            writer.writerow(header)
            writer.writerows(rows)
        return stage_csv(self.con, path, table)

    def project(self, bindings, table="AzureDiagnostics"):
        sql = checked_projection(self.con, "input_rows", bindings, "source_record", table=table)
        return self.con.execute(f"SELECT {sql} FROM input_rows ORDER BY source_record")

    def test_empty_one_populated_and_equal_values_consolidate(self):
        bindings = self.stage(["pop_s", "POP_s"], [
            ["", ""], ["one", ""], ["", "two"], ["same", "same"],
        ])
        cursor = self.project(bindings)
        self.assertEqual([c[0] for c in cursor.description], ["pop_s"])
        self.assertEqual(cursor.fetchall(), [(None,), ("one",), ("two",), ("same",)])

    def test_conflicting_values_fail_without_first_wins(self):
        bindings = self.stage(["probeUrl_s", "probeURL_s"], [["https://a", "https://b"]])
        with self.assertRaisesRegex(ValueError, "conflicting nonempty aliases.*probeUrl_s.*1"):
            self.project(bindings)

    def test_values_are_not_casefolded_trimmed_or_repaired(self):
        bindings = self.stage(["pop_s", "POP_s"], [["ABC", "abc"]])
        with self.assertRaises(ValueError):
            self.project(bindings)
        bindings = self.stage(["pop_s", "POP_s"], [[" x ", "x"]])
        with self.assertRaises(ValueError):
            self.project(bindings)
        bindings = self.stage(["pop_s", "POP_s", "Command"], [["", " x ", "quote ' text \""]])
        self.assertEqual(self.project(bindings).fetchone(), (" x ", "quote ' text \""))

    def test_all_seven_alias_groups_have_one_consistent_name(self):
        names = [name for aliases in DIAGNOSTIC_ALIASES.values() for name in aliases]
        bindings = self.stage(names, [[""] * len(names)])
        cursor = self.project(bindings)
        self.assertEqual([c[0] for c in cursor.description], list(DIAGNOSTIC_ALIASES))
        self.assertEqual(len(bindings), 14)

    def test_baseline_suffixes_map_to_known_original_names(self):
        names = ["_rid"] + [aliases[0] for aliases in DIAGNOSTIC_ALIASES.values()] + list(BASELINE_ORIGINAL_NAMES)
        bindings = column_bindings(names, "AzureDiagnostics", baseline=True)
        self.assertEqual(len(canonical_groups(bindings)), 8)
        for binding in bindings:
            if binding.storage_name in BASELINE_ORIGINAL_NAMES:
                self.assertEqual(binding.original_name, BASELINE_ORIGINAL_NAMES[binding.storage_name])

    def test_canonical_schema_is_idempotent(self):
        bindings = column_bindings(list(DIAGNOSTIC_ALIASES), "AzureDiagnostics")
        self.assertTrue(all(b.original_name == b.canonical_name == b.storage_name for b in bindings))

    def test_unapproved_case_collisions_are_not_silently_merged(self):
        bindings = self.stage(["Other", "other"], [["a", "a"]])
        with self.assertRaisesRegex(ValueError, "unapproved"):
            self.project(bindings)

    def test_alias_policy_does_not_apply_to_other_tables(self):
        bindings = self.stage(["pop_s", "POP_s"], [["a", "b"]], table="Other")
        with self.assertRaisesRegex(ValueError, "unapproved"):
            self.project(bindings, table="Other")
        bindings = self.stage(["pop_s"], [[""]], table="Other")
        self.assertEqual(self.project(bindings, table="Other").fetchone(), ("",))

    def test_real_suffix_column_is_not_overwritten_during_staging(self):
        bindings = self.stage(["pop_s", "POP_s", "POP_s_1"], [["a", "", "separate"]])
        self.assertEqual(bindings[1].storage_name, "POP_s_2")
        self.assertEqual(self.project(bindings).fetchone(), ("a", "separate"))

    def test_duplicate_and_empty_headers_fail(self):
        for names in (["pop_s", "pop_s"], ["pop_s", " "]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                column_bindings(names, "AzureDiagnostics")

    def test_alias_type_disagreement_fails(self):
        self.con.execute('CREATE TEMP TABLE input_rows(source_record BIGINT,pop_s INTEGER,"POP_s_1" VARCHAR)')
        self.con.execute("INSERT INTO input_rows VALUES (1,1,'1')")
        bindings = column_bindings(["pop_s", "POP_s_1"], "AzureDiagnostics", baseline=True)
        with self.assertRaisesRegex(ValueError, "requires text"):
            self.project(bindings)


class DiagnosticMaterializationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db, self.exports = fixture_sources(self.root, all_cases=True)
        with duckdb.connect(str(self.db)) as con:
            con.execute('CREATE TABLE AzureDiagnostics(_rid BIGINT,pop_s VARCHAR,"POP_s_1" VARCHAR,Command VARCHAR)')
            con.execute("INSERT INTO AzureDiagnostics VALUES (1,'A',NULL,'original'),(2,NULL,'B','other')")
        path = self.exports / "incident_34/AzureDiagnostics.csv"
        path.with_suffix(".meta").write_text(json.dumps({"pop_s": "string", "POP_s": "string", "Command": "string"}))
        with path.open("w", newline="") as stream:
            writer = csv.writer(stream, delimiter="❖")
            writer.writerow(["pop_s", "POP_s", "Command"])
            writer.writerows([["A", "", "original"], ["", "B", "other"], ["same", "same", "two origins"]])
        self.bundle = self.root / "i1"
        reconcile_sources(self.db, self.exports, self.bundle)

    def test_materialization_preserves_values_and_original_field_origins(self):
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        output = self.root / "normalized"
        report = normalize_diagnostics(self.bundle, output)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["imported_rows"], 2)
        self.assertEqual(report["csv_rows"], 3)
        self.assertEqual(report["populated_value_mismatches"], 0)
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)
        with duckdb.connect(str(output / "diagnostics.duckdb"), read_only=True) as con:
            baseline = con.execute("SELECT pop_s,Command FROM imported.AzureDiagnostics ORDER BY _source_record").fetchall()
            self.assertEqual(baseline, [("A", "original"), ("B", "other")])
            self.assertEqual(con.execute("SELECT pop_s FROM csv_exports.AzureDiagnostics ORDER BY _source_record").fetchall(),
                             [("A",), ("B",), ("same",)])
            columns = [r[0] for r in con.execute("DESCRIBE imported.AzureDiagnostics").fetchall()]
            self.assertNotIn("POP_s_1", columns)
            self.assertEqual(con.execute("SELECT count(*) FROM alias_origins").fetchone()[0], 6)
        self.assertTrue((output / "column_maps.json").is_file())
        self.assertEqual(hashlib.sha256((output / "diagnostics.duckdb").read_bytes()).hexdigest(),
                         report["database"]["sha256"])
        with self.assertRaisesRegex(ValueError, "already exists"):
            normalize_diagnostics(self.bundle, output)

    def test_changed_inputs_are_rejected_before_output(self):
        with duckdb.connect(str(self.db)) as con:
            con.execute("UPDATE AzureDiagnostics SET POP_s_1='conflict' WHERE _rid=1")
        output = self.root / "changed"
        with self.assertRaisesRegex(ValueError, "input hashes"):
            normalize_diagnostics(self.bundle, output)
        self.assertFalse(output.exists())

    def test_conflict_has_no_success_completion_marker(self):
        with duckdb.connect(str(self.db)) as con:
            con.execute("UPDATE AzureDiagnostics SET POP_s_1='conflict' WHERE _rid=1")
        fresh = self.root / "conflicted-i1"
        reconcile_sources(self.db, self.exports, fresh)
        output = self.root / "conflicted-output"
        with self.assertRaisesRegex(ValueError, "conflicting nonempty"):
            normalize_diagnostics(fresh, output)
        self.assertFalse((output / "column_report.json").exists())


if __name__ == "__main__":
    unittest.main()

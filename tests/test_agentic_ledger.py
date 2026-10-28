# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import duckdb

from secgym.qagen.agentic.columns import column_bindings
from secgym.qagen.agentic.dynamic import normalize_dynamic_fields
from secgym.qagen.agentic.ledger import (
    ColumnSpec, TableSpec, append_stream, build_ledger, canonical_dynamic,
    assert_matching_payloads, core_value, create_observation_table, exact_integer, initialize_ledger, prepare_stream,
)
from secgym.qagen.agentic.sources import reconcile_sources
from test_agentic_sources import fixture_sources, write_csv


class CanonicalIdentityTests(unittest.TestCase):
    def test_dynamic_key_order_and_whitespace_normalize(self):
        self.assertEqual(canonical_dynamic(' { "b": 2, "a": [1,true] } '),
                         canonical_dynamic('{"a":[1,true],"b":2}'))

    def test_dynamic_numeric_tokens_never_round(self):
        value = '{"x":0.12345678901234567890123456789,"huge":123456789012345678901234567890}'
        self.assertIn("0.12345678901234567890123456789", canonical_dynamic(value))
        self.assertIn("123456789012345678901234567890", canonical_dynamic(value))
        self.assertNotEqual(canonical_dynamic('{"x":1.0}'), canonical_dynamic('{"x":1}'))
        self.assertNotEqual(canonical_dynamic('{"x":1e0}'), canonical_dynamic('{"x":1.0}'))

    def test_dynamic_arrays_and_text_remain_distinct(self):
        self.assertNotEqual(canonical_dynamic('["a","b"]'), canonical_dynamic('["b","a"]'))
        self.assertNotEqual(canonical_dynamic('{"x":"A"}'), canonical_dynamic('{"x":"a"}'))
        self.assertNotEqual(canonical_dynamic('{"x":" a"}'), canonical_dynamic('{"x":"a"}'))

    def test_duplicate_json_keys_fail(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            canonical_dynamic('{"x":1,"x":2}')

    def test_nullable_scalar_converters_handle_blank_and_null_explicitly(self):
        for value in (None, ""):
            self.assertIsNone(exact_integer(value))
            self.assertIsNone(canonical_dynamic(value))
        for value in ("not-an-integer", "1.5", " "):
            with self.subTest(value=value), self.assertRaises(ValueError):
                exact_integer(value)
        self.assertEqual(exact_integer("0"), 0)
        self.assertEqual(canonical_dynamic("null"), "null")

    def test_core_values_preserve_json_types_and_reject_wrong_scalar_types(self):
        details = ColumnSpec(name="Entities", sql_type="VARCHAR", dynamic=False)
        self.assertEqual(core_value([{"x": True}], details), '[{"x":true}]')
        self.assertEqual(core_value("string-valued JSON", details), '"string-valued JSON"')
        count = ColumnSpec(name="IncidentNumber", sql_type="INTEGER", dynamic=False)
        with self.assertRaises(ValueError):
            core_value(True, count)
        self.assertEqual(core_value(34, count), 34)


class ExactStreamTests(unittest.TestCase):
    def setUp(self):
        self.con = duckdb.connect(config={"threads": 1, "memory_limit": "256MB"})
        self.addCleanup(self.con.close)
        self.con.execute("SET TimeZone='UTC'")
        initialize_ledger(self.con)
        self.con.execute("""
            CREATE TABLE _field_changes(source_id VARCHAR,table_name VARCHAR,source_record BIGINT,
              column_name VARCHAR,raw_value_sha256 VARCHAR,status VARCHAR)
        """)
        self.spec = TableSpec(
            table="Events", schema_id="test-schema", columns=(
                ColumnSpec(name="Command", sql_type="VARCHAR", dynamic=False),
                ColumnSpec(name="Details", sql_type="VARCHAR", dynamic=True),
                ColumnSpec(name="Number", sql_type="BIGINT", dynamic=False),
                ColumnSpec(name="Timestamp", sql_type="TIMESTAMPTZ", dynamic=False),
            ),
        )
        create_observation_table(self.con, self.spec)

    def stage(self, source, rows, names=None):
        if names is None:
            names = ["Command", "Details", "Number", "Timestamp"]
        self.con.execute("DROP TABLE IF EXISTS raw_rows")
        ddl = ",".join(f'"{n}" VARCHAR' for n in names)
        self.con.execute(f"CREATE TEMP TABLE raw_rows(source_record BIGINT,{ddl})")
        placeholders = ",".join("?" for _ in range(len(names) + 1))
        self.con.executemany(f"INSERT INTO raw_rows VALUES ({placeholders})",
                             [(i, *row) for i, row in enumerate(rows, 1)])
        bindings = column_bindings(names, "Events")
        prepare_stream(self.con, self.spec, "raw_rows", bindings, "source_record", source)
        return append_stream(self.con, self.spec, source, "csv_record_ordinal")

    def test_duplicates_merge_with_all_source_origins(self):
        first = self.stage("source-a", [
            ['cmd "x"', '{"b":2,"a":1}', "1", "2024-01-01T00:00:00Z"],
            ['cmd "x"', '{"a":1,"b":2}', "1.0", "2024-01-01T01:00:00+01:00"],
        ])
        second = self.stage("source-b", [['cmd "x"', '{"a":1,"b":2}', "1", "2024-01-01T00:00:00Z"]])
        self.assertEqual(first["new_observations"], 1)
        self.assertEqual(second["new_observations"], 0)
        self.assertEqual(self.con.execute("SELECT count(*) FROM Events").fetchone()[0], 1)
        self.assertEqual(self.con.execute("SELECT count(*) FROM _origins").fetchone()[0], 3)

    def test_command_quotes_spaces_and_case_are_not_merged(self):
        for i, command in enumerate(['cmd "x"', "cmd 'x'", 'cmd  "x"', 'CMD "x"']):
            self.stage(f"source-{i}", [[command, "{}", "1", "2024-01-01T00:00:00Z"]])
        self.assertEqual(self.con.execute("SELECT count(*) FROM Events").fetchone()[0], 4)

    def test_actual_values_and_time_differences_remain_distinct(self):
        self.stage("a", [["cmd", "{}", "1", "2024-01-01T00:00:00Z"]])
        self.stage("b", [["cmd", "{}", "2", "2024-01-01T00:00:00Z"]])
        self.stage("c", [["cmd", "{}", "1", "2024-01-01T00:00:00.000001Z"]])
        self.assertEqual(self.con.execute("SELECT count(*) FROM Events").fetchone()[0], 3)

    def test_missing_column_is_distinct_from_known_null(self):
        self.stage("a", [["cmd", "{}", "", "2024-01-01T00:00:00Z"]])
        self.stage("b", [["cmd", "{}", "2024-01-01T00:00:00Z"]], ["Command", "Details", "Timestamp"])
        self.assertEqual(self.con.execute("SELECT count(*) FROM Events").fetchone()[0], 2)

    def test_noninteger_cast_cannot_round_silently(self):
        with self.assertRaises(duckdb.Error):
            self.stage("a", [["cmd", "{}", "1.5", "2024-01-01T00:00:00Z"]])

    def test_quarantined_null_cannot_merge_with_actual_missing_value(self):
        self.stage("valid", [["cmd", "", "1", "2024-01-01T00:00:00Z"]])
        self.con.execute("INSERT INTO _field_changes VALUES ('broken','Events',1,'Details','raw-hash','quarantined')")
        self.stage("broken", [["cmd", "", "1", "2024-01-01T00:00:00Z"]])
        self.assertEqual(self.con.execute("SELECT count(*) FROM Events").fetchone()[0], 2)
        self.assertEqual(self.con.execute("SELECT count(*) FROM Events WHERE _field_quality<>'[]'").fetchone()[0], 1)

    def test_hash_collision_fails_closed(self):
        self.stage("a", [["one", "{}", "1", "2024-01-01T00:00:00Z"]])
        existing = self.con.execute("SELECT _observation_id FROM Events").fetchone()[0]
        self.con.execute("UPDATE keyed_rows SET Command='different'")
        self.con.execute("UPDATE keyed_rows SET _observation_id=?", [existing])
        with self.assertRaisesRegex(ValueError, "collision"):
            append_stream(self.con, self.spec, "b", "csv_record_ordinal")

    def test_collision_within_incoming_stream_fails_closed(self):
        self.stage("a", [["one", "{}", "1", "2024-01-01T00:00:00Z"]])
        self.con.execute("DELETE FROM Events")
        self.con.execute("INSERT INTO keyed_rows SELECT * REPLACE ('other' AS Command,2 AS _source_record) FROM keyed_rows")
        with self.assertRaisesRegex(ValueError, "collision"):
            append_stream(self.con, self.spec, "b", "csv_record_ordinal")

    def test_order_does_not_affect_identity(self):
        rows = [["a", "{}", "1", "2024-01-01T00:00:00Z"], ["b", "{}", "2", "2024-01-01T00:00:00Z"]]
        self.stage("first", rows)
        first = self.con.execute("SELECT _observation_id FROM Events ORDER BY 1").fetchall()
        self.stage("second", list(reversed(rows)))
        self.assertEqual(self.con.execute("SELECT _observation_id FROM Events ORDER BY 1").fetchall(), first)

    def test_wide_comparisons_check_every_column_batch(self):
        names = [f"column_{i}" for i in range(45)]
        definition = ",".join(f"{name} VARCHAR" for name in names)
        self.con.execute(f"CREATE TEMP TABLE wide_left(_observation_id VARCHAR,{definition})")
        self.con.execute(f"CREATE TEMP TABLE wide_right(_observation_id VARCHAR,{definition})")
        values = ["same-id"] + ["same"] * len(names)
        placeholders = ",".join("?" for _ in values)
        self.con.execute(f"INSERT INTO wide_left VALUES ({placeholders})", values)
        self.con.execute(f"INSERT INTO wide_right VALUES ({placeholders})", values)
        assert_matching_payloads(self.con, "wide_left", "wide_right", names)
        self.con.execute("UPDATE wide_right SET column_44='different'")
        with self.assertRaisesRegex(ValueError, "collision"):
            assert_matching_payloads(self.con, "wide_left", "wide_right", names)


class LedgerBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db, self.exports = fixture_sources(self.root, all_cases=True)
        with duckdb.connect(str(self.db)) as con:
            con.execute("CREATE TABLE Events(_rid BIGINT,Timestamp TIMESTAMPTZ,Details VARCHAR,Command VARCHAR)")
            con.execute("INSERT INTO Events VALUES (1,'2024-06-26 11:00:00Z','{\"kind\":\"file\"}',?)", ['cmd "x"'])
        write_csv(self.exports / "incident_34/Events.csv", [
            {"Timestamp": "2024-06-26T11:00:00Z", "Details": "{'kind':'file'}", "Command": 'cmd "x"'},
            {"Timestamp": "2024-06-26T11:00:00Z", "Details": '{"kind":"file"}', "Command": "cmd 'x'"},
        ], {"Timestamp": "datetime", "Details": "dynamic", "Command": "string"})
        self.bundle = self.root / "i1"
        reconcile_sources(self.db, self.exports, self.bundle)
        self.repairs = self.root / "repairs"
        normalize_dynamic_fields(self.bundle, self.repairs)

    def test_complete_bundle_and_latest_only_core(self):
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        output = self.root / "ledger"
        report = build_ledger(self.bundle, self.repairs, output)
        self.assertEqual(report["status"], "complete")
        with duckdb.connect(str(output / "observations.duckdb"), read_only=True) as con:
            self.assertEqual(con.execute("SELECT count(*) FROM Events").fetchone()[0], 2)
            self.assertEqual(con.execute("SELECT count(*) FROM _origins WHERE table_name='Events'").fetchone()[0], 3)
            self.assertEqual(con.execute("SELECT count(*) FROM _field_changes").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT count(*) FROM SecurityIncident").fetchone()[0], 10)
            self.assertEqual(con.execute("SELECT count(*) FROM _cases").fetchone()[0], 10)
            self.assertEqual(con.execute("SELECT count(*) FROM _historical_memberships").fetchone()[0], 0)
            self.assertEqual(con.execute("SELECT count(*) FROM SecurityIncident WHERE AlertIds IS NULL").fetchone()[0], 0)
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)
        self.assertEqual(hashlib.sha256((output / "observations.duckdb").read_bytes()).hexdigest(),
                         report["database"]["sha256"])
        self.assertTrue((output / "ledger_report.json").exists())
        with self.assertRaisesRegex(ValueError, "already exists"):
            build_ledger(self.bundle, self.repairs, output)

    def test_tampered_repair_database_is_rejected(self):
        with duckdb.connect(str(self.repairs / "dynamic_fields.duckdb")) as con:
            con.execute("DELETE FROM field_changes")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            build_ledger(self.bundle, self.repairs, self.root / "tampered")

    def test_failed_build_does_not_publish_completion_report(self):
        output = self.root / "failed"
        with patch("secgym.qagen.agentic.ledger.append_stream", side_effect=ValueError("fixture failure")):
            with self.assertRaisesRegex(ValueError, "fixture failure"):
                build_ledger(self.bundle, self.repairs, output)
        self.assertFalse((output / "ledger_report.json").exists())


if __name__ == "__main__":
    unittest.main()

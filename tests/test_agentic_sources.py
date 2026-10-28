# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import csv
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import duckdb

from secgym.qagen.agentic.contracts import SELECTED_INCIDENTS
from secgym.qagen.agentic.sources import (
    Origin, build_cases, derive_memberships, make_catalog, make_observation,
    membership, normalize_row, read_core, reconcile_observations, reconcile_sources,
)


ROOT = Path(__file__).resolve().parents[1]
INCIDENT_META = {
    "TenantId": "string", "IncidentNumber": "int", "IncidentName": "string",
    "TimeGenerated": "datetime", "Classification": "string", "Status": "string",
    "AlertIds": "dynamic", "FirstActivityTime": "datetime", "LastActivityTime": "datetime",
}
ALERT_META = {
    "TenantId": "string", "SystemAlertId": "string", "TimeGenerated": "datetime",
    "StartTime": "datetime", "EndTime": "datetime", "AlertName": "string",
    "Entities": "string", "ExtendedProperties": "string",
}


def incident(number=34, alerts=("a",), time="2024-06-26T12:00:00Z", classification="TruePositive"):
    return {
        "TenantId": "tenant-a", "IncidentNumber": number, "IncidentName": f"incident-guid-{number}",
        "TimeGenerated": time, "Classification": classification, "Status": "Closed",
        "AlertIds": json.dumps(list(alerts)), "FirstActivityTime": "2024-06-26T11:00:00Z",
        "LastActivityTime": "2024-06-26T12:00:00Z",
    }


def alert(identifier="a", time="2024-06-26T12:00:00Z"):
    return {
        "TenantId": "tenant-a", "SystemAlertId": identifier, "TimeGenerated": time,
        "StartTime": "2024-06-26T11:00:00Z", "EndTime": "2024-06-26T12:00:00Z",
        "AlertName": "Synthetic alert", "Entities": "[]", "ExtendedProperties": "{}",
    }


def observation(row, locator="fixture:1", source="fixture-source", table="SecurityIncident"):
    return make_observation(
        row, INCIDENT_META if table == "SecurityIncident" else ALERT_META, table,
        Origin(source_id=source, locator=locator),
    )


def reconcile(rows, table="SecurityIncident"):
    observed = [observation(row, f"fixture:{i}", table=table) for i, row in enumerate(rows, 1)]
    return reconcile_observations(observed, [], len(rows))


def write_csv(path, rows, meta):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.with_suffix(".meta").write_text(json.dumps(meta), encoding="utf-8")
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=tuple(meta), delimiter="❖")
        writer.writeheader()
        writer.writerows(rows)


def fixture_sources(root, *, all_cases=False):
    db = root / "inputs/baseline/tenant.duckdb"
    db.parent.mkdir(parents=True)
    exports = root / "inputs/incidents"
    inc_rows = [incident(n, (f"a-{n}",)) for n in SELECTED_INCIDENTS] if all_cases else [incident()]
    alert_rows = [alert(f"a-{n}") for n in SELECTED_INCIDENTS] if all_cases else [alert()]
    with duckdb.connect(str(db)) as con:
        con.execute("""
            CREATE TABLE SecurityIncident(
             _rid BIGINT,TenantId VARCHAR,IncidentNumber INTEGER,IncidentName VARCHAR,
             TimeGenerated TIMESTAMPTZ,Classification VARCHAR,Status VARCHAR,AlertIds VARCHAR,
             FirstActivityTime TIMESTAMPTZ,LastActivityTime TIMESTAMPTZ)
        """)
        con.execute("""
            CREATE TABLE SecurityAlert(
             _rid BIGINT,TenantId VARCHAR,SystemAlertId VARCHAR,TimeGenerated TIMESTAMPTZ,
             StartTime TIMESTAMPTZ,EndTime TIMESTAMPTZ,AlertName VARCHAR,Entities VARCHAR,ExtendedProperties VARCHAR)
        """)
        con.executemany("INSERT INTO SecurityIncident VALUES (?,?,?,?,?,?,?,?,?,?)",
                        [(i, *row.values()) for i, row in enumerate(inc_rows, 1)])
        con.executemany("INSERT INTO SecurityAlert VALUES (?,?,?,?,?,?,?,?,?)",
                        [(i, *row.values()) for i, row in enumerate(alert_rows, 1)])
        con.execute("CREATE TABLE DeviceProcessEvents(_rid BIGINT,Timestamp TIMESTAMPTZ,DeviceName VARCHAR)")
        con.execute("INSERT INTO DeviceProcessEvents VALUES (1,'2024-06-26 11:15:00+00','host-a')")
        con.execute("CREATE TABLE EmptyOperational(_rid BIGINT,Timestamp TIMESTAMPTZ)")
    write_csv(exports / "incident_34/SecurityIncident.csv", inc_rows, INCIDENT_META)
    write_csv(exports / "incident_34/SecurityAlert.csv", alert_rows, ALERT_META)
    return db, exports


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


class ReconciliationTests(unittest.TestCase):
    def test_latest_whole_row_does_not_fill_null_from_old_label(self):
        old = incident(classification="TruePositive")
        new = incident(alerts=("b",), time="2024-06-27T12:00:00Z", classification=None)
        result = reconcile([old, new])
        latest = result.latest[("tenant-a", "34")]
        self.assertIsNone(latest.fields()["Classification"])
        self.assertEqual(membership(latest), ("b",))

    def test_exact_duplicate_has_one_observation_and_both_origins(self):
        first = observation(incident(), "csv-record:1", "csv")
        second = observation({**incident(), "_rid": 17, "rn": "100"}, "SecurityIncident#rid:17", "db")
        self.assertEqual(first.observation_id, second.observation_id)
        result = reconcile_observations([first, second], [], 2)
        self.assertEqual(len(result.latest), 1)
        self.assertEqual(len(result.references), 1)
        self.assertEqual(len(result.references[0].origins), 2)

    def test_same_time_label_conflict_blocks_only_that_incident(self):
        result = reconcile([incident(), incident(classification="FalsePositive"), incident(38)])
        self.assertNotIn(("tenant-a", "34"), result.latest)
        self.assertIn(("tenant-a", "38"), result.latest)
        self.assertEqual(result.issues[0].code, "latest_row_conflict")
        self.assertIn("Classification", result.issues[0].fields)

    def test_same_time_membership_conflict_is_not_resolved_by_row_id(self):
        result = reconcile([incident(alerts=("a",)), {**incident(alerts=("b",)), "_rid": 999}])
        self.assertFalse(result.latest)
        self.assertEqual(result.issues[0].fields, ("AlertIds",))

    def test_membership_order_does_not_create_false_conflict(self):
        result = reconcile([incident(alerts=("a", "b")), incident(alerts=("b", "a"))])
        self.assertEqual(len(result.latest), 1)
        self.assertFalse(result.issues)

    def test_same_incident_number_in_different_tenants_is_not_merged(self):
        result = reconcile([incident(), {**incident(), "TenantId": "tenant-b"}])
        self.assertEqual(len(result.latest), 2)
        alerts = reconcile([alert()], "SecurityAlert")
        case = next(c for c in build_cases("snapshot", result, alerts) if c.incident_id == 34)
        self.assertEqual(case.status, "blocked")

    def test_conflicting_incident_guid_is_explicit(self):
        result = reconcile([incident(), {**incident(time="2024-06-27T12:00:00Z"), "IncidentName": "other-guid"}])
        self.assertFalse(result.latest)
        self.assertEqual(result.issues[0].code, "incident_identity_conflict")

    def test_null_membership_is_not_empty(self):
        result = reconcile([incident(), {**incident(time="2024-06-27T12:00:00Z"), "AlertIds": None}])
        self.assertFalse(result.latest)
        self.assertEqual(result.issues[0].code, "invalid_membership")
        self.assertEqual(derive_memberships("snapshot", result), ((), ()))

    def test_known_empty_membership_records_removal(self):
        result = reconcile([incident(), incident(alerts=(), time="2024-06-27T12:00:00Z")])
        historical, transitions = derive_memberships("snapshot", result)
        self.assertEqual(len(historical), 1)
        self.assertEqual(len(transitions), 1)
        self.assertEqual(historical[0].membership.current_relevance, "not_established")
        self.assertEqual(historical[0].membership.other_current_incidents, ())

    def test_removed_alert_can_have_another_current_parent(self):
        result = reconcile([incident(), incident(alerts=(), time="2024-06-27T12:00:00Z"), incident(38)])
        historical, _ = derive_memberships("snapshot", result)
        self.assertEqual(historical[0].membership.other_current_incidents, (38,))

    def test_readded_alert_is_current_not_historical_only(self):
        result = reconcile([
            incident(), incident(alerts=(), time="2024-06-27T12:00:00Z"),
            incident(time="2024-06-28T12:00:00Z"),
        ])
        historical, transitions = derive_memberships("snapshot", result)
        self.assertEqual(historical, ())
        self.assertTrue(transitions[0].current_member_again)
        self.assertEqual(membership(result.latest[("tenant-a", "34")]), ("a",))

    def test_repeated_removal_uses_last_removal_bounds(self):
        result = reconcile([
            incident(), incident(alerts=(), time="2024-06-27T12:00:00Z"),
            incident(time="2024-06-28T12:00:00Z"),
            incident(alerts=(), time="2024-06-29T12:00:00Z"),
        ])
        historical, transitions = derive_memberships("snapshot", result)
        self.assertEqual(len(transitions), 2)
        self.assertEqual(historical[0].membership.last_present_at.day, 28)

    def test_ambiguous_old_membership_does_not_fabricate_removed_edges(self):
        result = reconcile([
            incident(), incident(alerts=("b",)),
            incident(alerts=(), time="2024-06-27T12:00:00Z"),
        ])
        self.assertEqual(len(result.latest), 1)
        self.assertEqual(result.issues[0].severity, "warning")
        self.assertEqual(derive_memberships("snapshot", result), ((), ()))

    def test_invalid_old_membership_suppresses_inferences_not_current_row(self):
        result = reconcile([
            {**incident(), "AlertIds": None}, incident(alerts=(), time="2024-06-27T12:00:00Z"),
        ])
        self.assertEqual(len(result.latest), 1)
        self.assertEqual(derive_memberships("snapshot", result), ((), ()))
        self.assertEqual(result.issues[0].severity, "warning")

    def test_case_manifests_preserve_project_label_and_missing_alert_exclusion(self):
        incidents = reconcile([incident(5, ("missing",), classification=None), incident(322)])
        alerts = reconcile([alert()], "SecurityAlert")
        cases = {c.incident_id: c for c in build_cases("snapshot", incidents, alerts)}
        case = cases[5]
        self.assertEqual(case.status, "ready_with_exclusions")
        assert case.manifest is not None
        self.assertIsNone(case.manifest.source_classification)
        self.assertIn("missing-alert:missing", case.manifest.exclusions)
        self.assertIn("missing-alert:46f3d4b8-060c-4022-c190-4d88954a6a2e", case.manifest.exclusions)
        assert cases[322].manifest is not None
        self.assertIn("missing-source:SquidProxy", cases[322].manifest.exclusions)

    def test_latest_alert_conflict_excludes_alert_not_other_case_members(self):
        incidents = reconcile([incident(alerts=("a", "b"))])
        alerts = reconcile([alert(), {**alert(), "AlertName": "Different"}, alert("b")], "SecurityAlert")
        case = next(c for c in build_cases("snapshot", incidents, alerts) if c.incident_id == 34)
        self.assertEqual(case.conflicting_alert_ids, ("a",))
        self.assertEqual(case.missing_alert_ids, ())
        assert case.manifest is not None
        self.assertIn("conflicting-alert:a", case.manifest.exclusions)

    def test_timezone_normalization_and_json_whitespace_are_stable(self):
        a = incident()
        b = {**a, "TimeGenerated": "2024-06-26T14:00:00+02:00", "IncidentNumber": "34.0", "AlertIds": '[ "a" ]'}
        self.assertEqual(observation(a).observation_id, observation(b).observation_id)

    def test_only_approved_identity_placeholder_is_normalized(self):
        row = {**alert(), "CompromisedEntity": "N/A", "AlertName": "N/A"}
        normalized = normalize_row(row, ALERT_META, "SecurityAlert")
        self.assertIsNone(normalized["CompromisedEntity"])
        self.assertEqual(normalized["AlertName"], "N/A")
        self.assertEqual(normalize_row({"CompromisedEntity": "N/A"}, {}, "Other")["CompromisedEntity"], "N/A")
        empty = {**row, "CompromisedEntity": ""}
        self.assertEqual(
            observation(row, table="SecurityAlert").observation_id,
            observation(empty, table="SecurityAlert").observation_id,
        )

    def test_changed_source_tp_designation_blocks_only_selected_case(self):
        incidents = reconcile([incident(36, classification=None), incident(34)])
        alerts = reconcile([alert()], "SecurityAlert")
        cases = {c.incident_id: c for c in build_cases("snapshot", incidents, alerts)}
        self.assertEqual(cases[36].status, "blocked")
        self.assertEqual(cases[34].status, "ready")

    def test_invalid_source_values_are_not_silently_cast_to_null(self):
        for value, kind in (("nan", "real"), ("wrong", "datetime"), ("1.1", "int"), ("yes", "bool"), ("{'x':1}", "dynamic")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_row({"field": value}, {"field": kind}, "Synthetic")

    def test_unidentifiable_incident_number_is_an_explicit_error(self):
        with self.assertRaisesRegex(ValueError, "invalid incident number"):
            observation({**incident(), "IncidentNumber": "broken"})


class SourceCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.db, self.exports = fixture_sources(self.root)

    def test_catalog_hashes_all_inputs_and_ids_are_reproducible(self):
        first = make_catalog(self.db, self.exports)
        second = make_catalog(self.db, self.exports)
        self.assertEqual(first.manifest.snapshot_id, second.manifest.snapshot_id)
        self.assertEqual(len(first.manifest.sources), 5)
        self.assertEqual(first.manifest.normalization_version, "source-normalization-v1.1")
        self.assertIsNotNone(first.manifest.normalizer_sha256)
        self.assertTrue(all(not Path(s.path).is_absolute() for s in first.manifest.sources))
        first.verify_unchanged()

    def test_catalog_detects_input_changes(self):
        catalog = make_catalog(self.db, self.exports)
        path = self.exports / "incident_34/SecurityAlert.csv"
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "input changed"):
            catalog.verify_unchanged()

    def test_missing_metadata_is_explicit_failure(self):
        (self.exports / "incident_34/SecurityIncident.meta").unlink()
        with self.assertRaisesRegex(ValueError, "missing metadata"):
            make_catalog(self.db, self.exports)

    def test_csv_extra_columns_are_not_silently_truncated(self):
        path = self.exports / "incident_34/SecurityAlert.csv"
        with path.open("a") as stream:
            stream.write("too❖few❖columns\n")
        catalog = make_catalog(self.db, self.exports)
        with duckdb.connect(str(self.db), read_only=True) as con:
            with self.assertRaisesRegex(ValueError, "column count mismatch"):
                read_core(con, catalog, "SecurityAlert")

    def test_invalid_identifiable_row_blocks_entity_instead_of_using_old_row(self):
        bad = alert()
        bad["Entities"] = "malformed JSON"
        write_csv(self.exports / "incident_34/SecurityAlert.csv", [bad], ALERT_META)
        catalog = make_catalog(self.db, self.exports)
        with duckdb.connect(str(self.db), read_only=True) as con:
            result = read_core(con, catalog, "SecurityAlert")
        self.assertFalse(result.latest)
        self.assertEqual(result.issues[0].code, "invalid_source_row")

    def test_current_row_restored_from_csv_with_both_sources_preserved(self):
        new = incident(alerts=("b",), time="2024-06-27T12:00:00Z", classification=None)
        write_csv(self.exports / "incident_34/SecurityIncident.csv", [incident(), new], INCIDENT_META)
        catalog = make_catalog(self.db, self.exports)
        with duckdb.connect(str(self.db), read_only=True) as con:
            result = read_core(con, catalog, "SecurityIncident")
        self.assertEqual(result.source_rows, 3)
        self.assertEqual(len(result.references), 2)
        self.assertEqual(membership(result.latest[("tenant-a", "34")]), ("b",))

    def test_no_writes_to_inputs_and_no_old_incident_payloads_in_output(self):
        newer = incident(alerts=("b",), time="2024-06-27T12:00:00Z", classification=None)
        write_csv(self.exports / "incident_34/SecurityIncident.csv", [incident(), newer], INCIDENT_META)
        write_csv(self.exports / "incident_34/SecurityAlert.csv", [alert("b"), alert("unassigned")], ALERT_META)
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        output = self.root / "result"
        report = reconcile_sources(self.db, self.exports, output)
        self.assertEqual(report["summary"]["latest_incidents"], 1)
        self.assertEqual(report["summary"]["latest_alerts"], 3)
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)
        active = read_jsonl(output / "incidents.jsonl")
        self.assertEqual(len(active), 1)
        self.assertIsNone(json.loads(active[0]["fields_json"])["Classification"])
        refs = read_jsonl(output / "observation_references.jsonl")
        self.assertTrue(all("fields_json" not in r for r in refs))
        self.assertEqual(len(read_jsonl(output / "historical_memberships.jsonl")), 1)
        self.assertEqual(len(read_jsonl(output / "cases.jsonl")), 10)
        self.assertTrue((output / "report.json").is_file())
        for name, expected in report["outputs"].items():
            self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), expected["sha256"])

    def test_refuses_output_reuse_or_source_directory(self):
        output = self.root / "occupied"
        output.mkdir()
        marker = output / "untouched"
        marker.write_text("preserve")
        with self.assertRaisesRegex(ValueError, "already exists"):
            reconcile_sources(self.db, self.exports, output)
        self.assertEqual(marker.read_text(), "preserve")
        with self.assertRaisesRegex(ValueError, "outside the source"):
            reconcile_sources(self.db, self.exports, self.exports / "output")

    def test_core_corruption_cannot_leave_completion_marker(self):
        path = self.exports / "incident_34/SecurityIncident.csv"
        path.write_text("broken\nrow\n")
        output = self.root / "failed"
        with self.assertRaises(ValueError):
            reconcile_sources(self.db, self.exports, output)
        self.assertFalse((output / "report.json").exists())

    def test_cli_exit_status_distinguishes_blocked_cases(self):
        result = subprocess.run([
            sys.executable, "-m", "secgym.qagen.agentic", "reconcile-sources",
            "--tenant-db", str(self.db), "--incident-root", str(self.exports),
            "--output", str(self.root / "cli-result"),
        ], cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "complete_with_blocks")


class CompleteFixtureTests(unittest.TestCase):
    def test_all_cases_with_coverage_and_baseline_empty_table(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db, exports = fixture_sources(root, all_cases=True)
            output = root / "result"
            report = reconcile_sources(db, exports, output)
            self.assertEqual(report["status"], "complete")
            self.assertEqual(report["summary"]["latest_incidents"], 10)
            self.assertEqual(report["summary"]["baseline_source_tables"], 4)
            self.assertTrue(all(c["operational_rows"] == 1 for c in report["case_coverage"]))
            tables = read_jsonl(output / "tables.jsonl")
            empty = next(t for t in tables if t["table"] == "EmptyOperational")
            self.assertTrue(empty["present_in_baseline"])
            self.assertEqual(empty["baseline_rows"], 0)


if __name__ == "__main__":
    unittest.main()

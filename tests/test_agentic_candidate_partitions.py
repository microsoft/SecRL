# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentic_runtime_fixture import runtime_fixture
from secgym.qagen.agentic.contracts import AnswerProgram, fingerprint
from secgym.qagen.agentic.difficulty import (
    AmbiguityProbe, ExhaustiveRetrieval, PartitionedAmbiguityProbe, PartitionedProbeMeasurement,
    _partitioned_results, _probe,
)
from secgym.qagen.agentic.evidence import EvidenceVerifier
from secgym.qagen.agentic.mysql_serving import open_duckdb_engine
from secgym.qagen.agentic.query import QueryLimits, QueryResult, checked_select
from test_agentic_difficulty import plan_for, question


class ExhaustiveCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        _, _, cls.serving, _ = runtime_fixture(Path(cls.temp.name), extra_rows=1597)
        cls.engine = open_duckdb_engine(cls.serving, QueryLimits(max_rows=50, max_bytes=65536, timeout_ms=3000))
        cls.verifier = EvidenceVerifier(cls.serving, cls.engine, frozenset())

    @classmethod
    def tearDownClass(cls):
        cls.verifier.close()
        cls.engine.connection.close()
        cls.temp.cleanup()

    def setUp(self):
        self.engine.limits = QueryLimits(max_rows=50, max_bytes=65536, timeout_ms=3000)

    def probe(self, query="SELECT _record_id,ProcessId FROM DeviceProcessEvents", **changes):
        data = {
            "probe_id": "all-candidates", "decision_step": "lookup", "table": "DeviceProcessEvents",
            "program": AnswerProgram(program_id="population", engine="duckdb", query=query),
            "identity_kind": "source_observation", "scope_and_relaxation": "Synthetic full-source population.",
            "retrieval_policy": "exhaustive-record-ranges-v1",
        }
        data.update(changes)
        return PartitionedAmbiguityProbe(**data)

    def test_exact_1599_sources_without_raising_per_query_limits(self):
        original_limits = self.engine.limits
        measurement = _probe(self.probe(), self.verifier)
        self.assertIsInstance(measurement, PartitionedProbeMeasurement)
        self.assertEqual(measurement.candidate_count, 1599)
        self.assertEqual(measurement.retrieved_rows, 1599)
        self.assertEqual(len(measurement.observed_citations), 1599)
        self.assertEqual(measurement.retrieval.full_scope_rows, 1599)
        self.assertGreater(len(measurement.retrieval.partitions), 1)
        self.assertTrue(all(part.retrieved_rows <= original_limits.max_rows for part in measurement.retrieval.partitions))
        self.assertEqual(self.engine.limits, original_limits)
        self.assertEqual(PartitionedProbeMeasurement.model_validate_json(measurement.model_dump_json()), measurement)

    def test_qualified_identity_deduplication_across_partitions(self):
        measurement = _probe(self.probe(identity_kind="qualified_fields",
                                        identity_columns=("DeviceName", "ProcessId", "Timestamp")), self.verifier)
        self.assertEqual(measurement.status, "complete")
        self.assertEqual(measurement.retrieved_rows, 1599)
        self.assertEqual(measurement.candidate_count, 3)

    def test_legacy_probe_shape_and_limit_error_are_unchanged(self):
        data = self.probe().model_dump(mode="json")
        data.pop("retrieval_policy")
        legacy = AmbiguityProbe.model_validate_json(json.dumps(data))
        plan = plan_for(question("legacy-partition-shape"), probes=(legacy,))
        self.assertEqual(fingerprint(plan), fingerprint(type(plan).model_validate_json(plan.model_dump_json())))
        self.assertNotIn("retrieval_policy", plan.model_dump(mode="json")["routes"][0]["ambiguity_probes"][0])
        failed = _probe(legacy, self.verifier)
        self.assertEqual(failed.error_code, "row_limit")
        self.assertIsNone(failed.candidate_count)

    def test_byte_bounded_retrieval_uses_complete_disjoint_partitions(self):
        self.engine.limits = QueryLimits(max_rows=5000, max_bytes=1500, timeout_ms=3000)
        measurement = _probe(self.probe(
            "SELECT _record_id,FileName FROM DeviceProcessEvents WHERE Sequence BETWEEN 0 AND 24",
        ), self.verifier)
        self.assertEqual(measurement.status, "complete")
        self.assertEqual(measurement.candidate_count, 26)
        self.assertGreater(len(measurement.retrieval.partitions), 1)
        self.assertEqual(sum(part.retrieved_rows for part in measurement.retrieval.partitions), 26)

    def test_full_scope_window_and_union_are_inside_partition_filters(self):
        self.engine.limits = QueryLimits(max_rows=1, max_bytes=65536, timeout_ms=3000)
        query = (
            "WITH candidates AS (SELECT _record_id,ProcessId FROM DeviceProcessEvents WHERE DeviceName='host.test' "
            "UNION ALL SELECT _record_id,ProcessId FROM DeviceProcessEvents WHERE DeviceName='other.test') "
            "SELECT _record_id,ProcessId,ROW_NUMBER() OVER (ORDER BY ProcessId) AS ordinal FROM candidates"
        )
        probe = self.probe(query)
        tree = checked_select(query, "duckdb", set(self.verifier.tables))
        pages, audit = _partitioned_results(probe, self.verifier, tree)
        self.assertEqual(audit.full_scope_rows, 2)
        self.assertEqual(sorted(row[-1] for _, result in pages for row in result.rows), [1, 2])
        self.assertEqual(_probe(probe, self.verifier).candidate_count, 2)

    def test_exhaustive_paging_does_not_permit_sampling(self):
        for suffix in (" LIMIT 5", " LIMIT 5 OFFSET 1", " USING SAMPLE 10 PERCENT"):
            result = _probe(self.probe("SELECT _record_id,ProcessId FROM DeviceProcessEvents" + suffix), self.verifier)
            self.assertEqual(result.status, "error")
            self.assertEqual(result.error_code, "truncated_candidate_scope")
            self.assertIsNone(result.candidate_count)

    def test_actual_source_attribution_still_required_for_every_page(self):
        record = self.engine.execute("SELECT _record_id FROM DeviceProcessEvents WHERE DeviceName='host.test'").rows[0][0]
        queries = (
            "SELECT _record_id FROM DeviceProcessEvents WHERE DeviceName='host.test'",
            f"SELECT '{record}' AS _record_id,ProcessId FROM DeviceProcessEvents WHERE DeviceName='host.test'",
        )
        for query in queries:
            with self.subTest(query=query):
                result = _probe(self.probe(query), self.verifier)
                self.assertEqual(result.error_code, "unattributed_candidate")
                self.assertEqual(result.observed_citations, ())
                self.assertIsNone(result.candidate_count)

    def test_null_malformed_duplicate_and_missing_locators_fail_closed(self):
        queries = (
            ("SELECT NULL AS _record_id,ProcessId FROM DeviceProcessEvents", "invalid_candidate_locator"),
            ("SELECT 'bad-locator' AS _record_id,ProcessId FROM DeviceProcessEvents", "invalid_candidate_locator"),
            ("SELECT ProcessId FROM DeviceProcessEvents", "candidate_columns"),
            ("SELECT _record_id,_record_id,ProcessId FROM DeviceProcessEvents", "candidate_columns"),
            ("SELECT _record_id,ProcessId FROM DeviceProcessEvents WHERE FALSE", "empty_candidate_scope"),
        )
        for query, code in queries:
            with self.subTest(query=query):
                result = _probe(self.probe(query), self.verifier)
                self.assertEqual(result.status, "error")
                self.assertEqual(result.error_code, code)
                self.assertIsNone(result.retrieved_rows)
        query = "SELECT _record_id,ProcessId FROM DeviceProcessEvents WHERE DeviceName='host.test'"
        self.engine.limits = QueryLimits(max_rows=1, max_bytes=65536, timeout_ms=3000)
        result = _probe(self.probe(query + " UNION ALL " + query), self.verifier)
        self.assertEqual(result.error_code, "candidate_partition_unsplittable")
        self.assertIsNone(result.candidate_count)

    def test_query_errors_and_resource_exhaustion_are_not_counts(self):
        result = _probe(self.probe("SELECT _record_id,unknown_column FROM DeviceProcessEvents"), self.verifier)
        self.assertEqual(result.error_code, "query_execution")
        for name, value, code in (
            ("MAX_PARTITION_QUERIES", 1, "candidate_partition_limit"),
            ("MAX_PARTITION_RESULT_BYTES", 1, "candidate_partition_byte_budget"),
        ):
            with patch(f"secgym.qagen.agentic.difficulty.{name}", value):
                result = _probe(self.probe(), self.verifier)
                self.assertEqual(result.error_code, code)
                self.assertEqual(result.observed_citations, ())
                self.assertIsNone(result.candidate_count)

    def test_changed_census_cannot_certify_incomplete_retrieval(self):
        execute = self.engine.execute

        def incorrect_census(query, **kwargs):
            result = execute(query, **kwargs)
            if result.columns == ("scope_rows", "located_rows", "first_locator", "last_locator"):
                count, located, first, last = result.rows[0]
                return QueryResult(result.columns, ((count + 1, located + 1, first, last),))
            return result

        with patch.object(self.engine, "execute", side_effect=incorrect_census):
            result = _probe(self.probe("SELECT _record_id,ProcessId FROM DeviceProcessEvents WHERE DeviceName='host.test'"),
                            self.verifier)
        self.assertEqual(result.error_code, "candidate_census_mismatch")
        self.assertIsNone(result.candidate_count)

    def test_partition_audit_rejects_gaps_overlap_and_wrong_counts(self):
        self.engine.limits = QueryLimits(max_rows=1, max_bytes=65536, timeout_ms=3000)
        probe = self.probe("SELECT _record_id,ProcessId FROM DeviceProcessEvents WHERE DeviceName<>'bulk.test'")
        measurement = _probe(probe, self.verifier)
        self.assertEqual(measurement.status, "complete")
        original = measurement.retrieval.model_dump(mode="json")
        for mutation in ("count", "gap", "unbounded"):
            data = json.loads(json.dumps(original))
            if mutation == "count":
                data["full_scope_rows"] += 1
            elif mutation == "gap":
                data["partitions"][1]["lower_exclusive"] = "r:" + "0" * 64
            else:
                data["partitions"][0]["upper_inclusive"] = None
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                ExhaustiveRetrieval.model_validate_json(json.dumps(data))


if __name__ == "__main__":
    unittest.main()

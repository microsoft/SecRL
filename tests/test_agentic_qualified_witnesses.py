# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentic_runtime_fixture import qualified_runtime_draft, runtime_fixture, runtime_task
from secgym.qagen.agentic.contracts import PublicCitation, QualifiedWitnessProgram, TaskRecord, fingerprint
from secgym.qagen.agentic.evidence import EvidenceFailure, EvidenceVerifier, Finding
from secgym.qagen.agentic.generation import compile_draft
from secgym.qagen.agentic.mysql_serving import open_duckdb_engine
from secgym.qagen.agentic.qualified_witnesses import (
    CANDIDATE_COLUMNS, CATALOG_COLUMNS, parse_proofs, validate_qualified_program,
)
from secgym.qagen.agentic.query import QueryFailure, QueryLimits, QueryResult
from secgym.qagen.agentic.secrl_adapter import SecRLV1Env, Submission
from test_agentic_adapters import reviewed_fixture


def citation(record):
    return PublicCitation(table="DeviceProcessEvents", record_id=record)


class QualifiedProofLogicTests(unittest.TestCase):
    def proofs(self, rows, obligations=(("group", "a"), ("group", "b"))):
        return parse_proofs(QueryResult(CATALOG_COLUMNS, obligations), QueryResult(CANDIDATE_COLUMNS, tuple(rows)))

    def test_each_obligation_needs_a_whole_candidate_bundle(self):
        proofs = self.proofs([
            ("group", "a", "first", None, "DeviceProcessEvents", "a1"),
            ("group", "a", "first", None, "DeviceProcessEvents", "a2"),
            ("group", "a", "second", None, "DeviceProcessEvents", "a3"),
            ("group", "a", "second", None, "DeviceProcessEvents", "a4"),
            ("group", "b", "only", None, "DeviceProcessEvents", "b1"),
        ])
        for records, passes in ((("a1", "a2", "b1"), True), (("a3", "a4", "b1"), True),
                                (("a1", "a4", "b1"), False), (("a1", "a2"), False)):
            available = frozenset(citation(record) for record in records)
            with self.subTest(records=records):
                self.assertEqual(proofs.match(available, behavior=available, requires_behavior=True) is not None, passes)

    def test_shared_source_bindings_prevent_cross_instance_splicing(self):
        proofs = self.proofs([
            ("group", "a", "x", "process", "DeviceProcessEvents", "process-x"),
            ("group", "a", "x", None, "DeviceProcessEvents", "event-x"),
            ("group", "a", "y", "process", "DeviceProcessEvents", "process-y"),
            ("group", "a", "y", None, "DeviceProcessEvents", "event-y"),
            ("group", "b", "y", "process", "DeviceProcessEvents", "process-y"),
        ])
        available = frozenset(citation(record) for record in ("process-x", "event-x", "process-y"))
        self.assertIsNone(proofs.match(available, behavior=available, requires_behavior=True))
        complete = available | {citation("event-y")}
        self.assertEqual(proofs.match(complete, behavior=complete, requires_behavior=True),
                         frozenset({citation("process-y"), citation("event-y")}))

    def test_groups_are_alternatives_not_mixable_partial_routes(self):
        proofs = self.proofs([
            ("one", "a", "choice", None, "DeviceProcessEvents", "a"),
            ("two", "b", "choice", None, "DeviceProcessEvents", "b"),
        ], (("one", "a"), ("one", "b"), ("two", "a"), ("two", "b")))
        available = frozenset({citation("a"), citation("b")})
        self.assertIsNone(proofs.match(available, behavior=available, requires_behavior=True))

    def test_behavior_must_belong_to_the_selected_complete_proof(self):
        proofs = self.proofs([("group", "a", "choice", None, "DeviceProcessEvents", "context")],
                             (("group", "a"),))
        available = frozenset({citation("context"), citation("unrelated-behavior")})
        self.assertIsNone(proofs.match(available, behavior=frozenset({citation("unrelated-behavior")}), requires_behavior=True))
        self.assertIsNotNone(proofs.match(available, behavior=frozenset(), requires_behavior=False))

    def test_factorized_choices_do_not_enumerate_the_cartesian_product(self):
        obligations = tuple(("group", str(i)) for i in range(40))
        rows = [
            ("group", obligation, choice, None, "DeviceProcessEvents", f"record-{obligation}-{choice}")
            for _, obligation in obligations for choice in ("a", "b")
        ]
        proofs = self.proofs(rows, obligations)
        result = proofs.match(proofs.relevant, behavior=proofs.relevant, requires_behavior=True)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 40)
        with patch("secgym.qagen.agentic.qualified_witnesses.MAX_PROOF_SEARCH_STATES", 1):
            with self.assertRaisesRegex(QueryFailure, "state limit"):
                proofs.match(proofs.relevant, behavior=proofs.relevant, requires_behavior=True)

    def test_malformed_or_conflicting_proof_rows_are_errors(self):
        valid = ("group", "a", "choice", "process", "DeviceProcessEvents", "x")
        cases = (
            ([valid], ()), ([valid], (("group", "a"), ("group", "a"))),
            ([("wrong", *valid[1:])], (("group", "a"),)),
            ([valid, (*valid[:-1], "y")], (("group", "a"),)),
            ([(*valid[:3], "", *valid[4:])], (("group", "a"),)),
        )
        for rows, obligations in cases:
            with self.subTest(rows=rows), self.assertRaises(QueryFailure):
                self.proofs(rows, obligations)


class QualifiedWitnessRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        _, _, cls.serving, report = runtime_fixture(Path(cls.temp.name), extra_rows=2)
        cls.engine = open_duckdb_engine(cls.serving, QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000))
        cls.verifier = EvidenceVerifier(cls.serving, cls.engine, frozenset({"43"}))
        cls.draft = qualified_runtime_draft(cls.serving, report)
        cls.task = compile_draft(cls.draft, cls.verifier, mode="tenant", incident_id=None,
                                 task_id="qualified-fixture", revision_id="r1", checkpoint_cap=0.5)
        cls.report = report
        rows = cls.engine.execute("SELECT _record_id,DeviceName FROM DeviceProcessEvents").rows
        cls.bulk = sorted((citation(record) for record, host in rows if host == "bulk.test"),
                          key=lambda item: item.record_id)
        cls.other = next(citation(record) for record, host in rows if host == "other.test")
        cls.unrelated = next(citation(record) for record, host in rows if host == "host.test")

    @classmethod
    def tearDownClass(cls):
        cls.verifier.close()
        cls.engine.connection.close()
        cls.temp.cleanup()

    def finding(self, citations, claim=None):
        return Finding(answer=(claim or self.task.private_gold.final).expected, citations=tuple(citations), step=1)

    def test_new_program_roundtrip_and_legacy_serialization_identity(self):
        old = runtime_task(self.serving, self.report)
        data = old.model_dump(mode="json")
        self.assertEqual(TaskRecord.model_validate_json(json.dumps(data)).model_dump(mode="json"), data)
        self.assertFalse(any("witness_policy" in program for program in data["private_gold"]["final"]["witness_programs"]))
        reloaded = TaskRecord.model_validate_json(self.task.model_dump_json())
        self.assertEqual(fingerprint(reloaded), fingerprint(self.task))
        self.assertIsInstance(reloaded.private_gold.final.witness_programs[0], QualifiedWitnessProgram)

    def test_alternative_source_records_receive_grounded_final_and_checkpoint_credit(self):
        witnesses = self.verifier.preflight(self.task)
        original = witnesses["final"][0]
        alternate = tuple({self.other, *set(self.bulk)} - original | {self.other})
        self.assertEqual(len(alternate), 2)
        self.assertFalse(self.verifier.evidence_matches(self.finding(alternate), witnesses["final"]))
        self.assertTrue(self.verifier.evidence_matches(self.finding(alternate), witnesses["final"],
                                                       claim=self.task.private_gold.final))
        result = self.verifier.evaluate(
            self.task, self.finding(alternate), (self.finding(alternate, self.task.private_gold.checkpoints[0].claim),),
            run_id="alternative", backend="secrl", trajectory_ref="fixture:alternate",
        )
        self.assertEqual(result.aggregate_reward, 1.0)
        self.assertEqual(result.checkpoint_progress, 1.0)

    def test_missing_cohort_members_cannot_prove_even_the_common_scalar(self):
        proofs = self.verifier.preflight(self.task)
        for key, claim in (("final", self.task.private_gold.final),
                           ("common-executable", self.task.private_gold.checkpoints[0].claim)):
            for subset in ((self.other,), (self.bulk[0],), ()):
                with self.subTest(key=key, subset=subset):
                    self.assertFalse(self.verifier.evidence_matches(self.finding(subset, claim), proofs[key], claim=claim))

    def test_irrelevant_and_duplicate_citations_are_not_grounded_but_extra_observations_are_allowed(self):
        claim = self.task.private_gold.final
        proof = self.verifier.preflight(self.task)["final"]
        complete = (self.other, self.bulk[0])
        truncated = PublicCitation(table=self.bulk[0].table, record_id=self.bulk[0].record_id[:-1])
        for bad in ((*complete, self.unrelated), (*complete, self.other), (self.other, truncated)):
            self.assertFalse(self.verifier.evidence_matches(self.finding(bad), proof, claim=claim))
        self.assertTrue(self.verifier.complete_witness_observed(claim, proof, frozenset((*complete, self.unrelated))))

    def test_catalog_is_unconditional_and_result_limits_are_errors(self):
        program = self.task.private_gold.final.witness_programs[0]
        self.assertIsInstance(program, QualifiedWitnessProgram)
        full = self.verifier.qualified_proofs(self.task.private_gold.final, frozenset((self.other, self.bulk[0])))[0]
        partial = self.verifier.qualified_proofs(self.task.private_gold.final, frozenset((self.other,)))[0]
        self.assertEqual(full.obligations, partial.obligations)
        self.assertEqual(len(full.obligations), 2)
        original = self.engine.limits
        try:
            self.engine.limits = QueryLimits(max_rows=1, max_bytes=65536, timeout_ms=3000)
            with self.assertRaisesRegex(QueryFailure, "row limit"):
                self.verifier.qualified_proofs(self.task.private_gold.final, frozenset((self.other,)))
        finally:
            self.engine.limits = original

    def test_no_caller_relation_shadowing_or_citation_only_gold(self):
        data = self.task.private_gold.final.witness_programs[0].model_dump(mode="json")
        for query in (
            "SELECT * FROM proof_citations",
            "WITH proof_citations AS (SELECT * FROM DeviceProcessEvents) SELECT * FROM proof_citations",
            "SELECT * FROM DeviceProcessEvents",
        ):
            program = QualifiedWitnessProgram.model_validate_json(json.dumps({**data, "candidates_query": query}))
            with self.subTest(query=query), self.assertRaises(QueryFailure):
                validate_qualified_program(program, set(self.engine.tables), frozenset({"43", "DeviceProcessEvents"}))
        program = QualifiedWitnessProgram.model_validate_json(json.dumps({
            **data, "obligations_query": "SELECT record_id AS evidence_group,record_id AS obligation_id FROM proof_citations",
        }))
        with self.assertRaises(QueryFailure):
            validate_qualified_program(program, set(self.engine.tables), frozenset({"43", "DeviceProcessEvents"}))

    def test_incomplete_representative_and_mixed_backend_policies_fail_closed(self):
        data = self.task.model_dump(mode="json")
        for program in data["private_gold"]["final"]["witness_programs"]:
            program["query"] += " HAVING DeviceName='other.test'"
        verifier = EvidenceVerifier(self.serving, self.engine, frozenset({"43", "other.test"}))
        try:
            with self.assertRaisesRegex(EvidenceFailure, "every source-qualified proof obligation"):
                verifier.preflight(TaskRecord.model_validate_json(json.dumps(data)))
        finally:
            verifier.close()
        data = self.task.model_dump(mode="json")
        for field in ("witness_policy", "obligations_query", "candidates_query"):
            data["private_gold"]["final"]["witness_programs"][0].pop(field)
        with self.assertRaisesRegex(ValueError, "cannot mix"):
            TaskRecord.model_validate_json(json.dumps(data))

    def test_adapter_requires_actual_attributed_source_retrieval(self):
        citations = (self.other, self.bulk[-1])
        payload = Submission(answer=self.task.private_gold.final.expected, citations=citations).model_dump_json()
        for query, reward in (
            ("SELECT _record_id FROM DeviceProcessEvents WHERE ProcessId=43", 0.0),
            ("SELECT _record_id,DeviceName FROM DeviceProcessEvents WHERE ProcessId=43", 1.0),
        ):
            with self.subTest(query=query):
                env = SecRLV1Env(self.task, self.verifier, reviewed_fixture(self.task), run_id="qualified-adapter",
                                 trajectory_ref="fixture:qualified", max_steps=3)
                env.step(query)
                env.step(payload, submit=True)
                self.assertEqual(env.evaluation.aggregate_reward, reward)


if __name__ == "__main__":
    unittest.main()

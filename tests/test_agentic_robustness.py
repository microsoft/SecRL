# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import duckdb

from agentic_runtime_fixture import qualified_runtime_draft, runtime_fixture, runtime_task
from secgym.qagen.agentic.__main__ import main
from secgym.qagen.agentic.contracts import ClaimCheck, PublicCitation, TaskRecord, TypedAnswer, fingerprint
from secgym.qagen.agentic.evidence import EvidenceVerifier
from secgym.qagen.agentic.generation import compile_draft
from secgym.qagen.agentic.ledger import JsonNumber, encode_json, file_sha256
from secgym.qagen.agentic.mysql_serving import open_duckdb_engine
from secgym.qagen.agentic.query import PublicQueryEngine, QueryFailure, QueryLimits
from secgym.qagen.agentic.robustness import (
    CellEdit, ClaimExpectation, ProgramAnswers, RobustnessCase, RobustnessPlan, RobustnessReport, WitnessGroup,
    _answer_vectors_equal, _expected_answers, _observe, json_variant, run_robustness, validate_plan_expectations,
)
from secgym.qagen.agentic.serving import parse_json


class JsonVariantTests(unittest.TestCase):
    def test_representation_preserves_precision_arrays_and_encoded_payload_strings(self):
        text = '{"Z":9007199254740993,"A":[1.00000000000000000001,null,true],"Nested":"{\\"value\\":2}"}'
        changed = json_variant(text, "representation")
        self.assertNotEqual(changed, text)
        self.assertEqual(parse_json(changed), parse_json(text))
        self.assertIn("1.00000000000000000001", changed)
        self.assertEqual(parse_json(changed)["Z"], JsonNumber("9007199254740993"))
        self.assertEqual(parse_json(changed)["Nested"], parse_json(text)["Nested"])

    def test_array_transforms_are_explicit_and_support_named_encoded_containers(self):
        text = '{"Roles":"[{\\"Name\\":\\"first\\"},{\\"Name\\":\\"second\\"}]"}'
        reversed_text = json_variant(text, "reverse_array", path=("Roles",))
        self.assertEqual(parse_json(parse_json(reversed_text)["Roles"])[0]["Name"], "second")
        added = json_variant(text, "prepend_array", path=("Roles",), member_json='{"Name":"unrelated"}')
        self.assertEqual(len(parse_json(parse_json(added)["Roles"])), 3)

    def test_invalid_missing_noop_and_ambiguous_interventions_fail_explicitly(self):
        cases = (
            ("[]", "reverse_array", {}),
            ("[1]", "reverse_array", {}),
            ("{}", "reverse_array", {}),
            ('{"a":[]}', "reverse_array", {"path": ("missing",)}),
            ("[1,2]", "reverse_array", {"member_json": "3"}),
            ("[1,2]", "prepend_array", {}),
            ("[1,2]", "representation", {"path": (0,)}),
            ("[1,2]", "representation", {"member_json": "3"}),
            ("null", "representation", {}),
            ('{"a":1,"a":2}', "representation", {}),
        )
        for text, operation, kwargs in cases:
            with self.subTest(text=text, operation=operation):
                with self.assertRaises(ValueError):
                    json_variant(text, operation, **kwargs)

    def test_schemas_are_available_without_native_startup_or_model_calls(self):
        for kind in ("robustness-plan", "robustness-report"):
            with patch("sys.argv", ["agentic", "schema", kind]), contextlib.redirect_stdout(io.StringIO()) as output:
                main()
            self.assertIn("properties", json.loads(output.getvalue()))


class CounterfactualWitnessTests(unittest.TestCase):
    def setUp(self):
        self.connection = duckdb.connect()
        self.addCleanup(self.connection.close)
        self.connection.execute("CREATE TABLE activity(_record_id VARCHAR, kind VARCHAR)")
        self.citation = PublicCitation(table="activity", record_id="r:" + "a" * 64)
        self.connection.execute("INSERT INTO activity VALUES (?, 'detector')", [self.citation.record_id])
        self.engine = PublicQueryEngine(
            self.connection, "duckdb", {"activity"}, QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000),
        )
        self.claim = ClaimCheck.model_validate_json(json.dumps({
            "expected": {"format": {"kind": "number", "semantic_kind": "count", "normalization": "exact",
                                    "tolerance": 0.0, "units": "records"}, "value": 1},
            "programs": [{"program_id": "answer", "engine": "duckdb",
                          "query": "SELECT COUNT(*) FROM activity WHERE kind='behavior'"}],
            "witness_programs": [{"program_id": "witness", "engine": "duckdb",
                                  "query": "SELECT kind AS evidence_group,'activity' AS table_name,_record_id AS record_id FROM activity"}],
            "evidence_sets": [{"evidence_ids": ["anchor"], "rationale": "A source-bound witness is required."}],
            "requires_behavior_evidence": True,
        }))
        self.records = frozenset({self.citation})
        self.probes = (self.records, frozenset())
        self.allowed = frozenset({"activity", "behavior"})

    def test_negative_world_records_raw_context_but_never_supports_behavior(self):
        observed = _observe(self.claim, self.engine, self.allowed, self.records, frozenset(), self.probes,
                            negative_world=True)
        self.assertEqual(observed.answers[0].value, 0)
        self.assertEqual(observed.witnesses, (WitnessGroup(citations=(self.citation,)),))
        self.assertEqual(observed.support, (False, False))

    def test_positive_world_still_rejects_context_only_behavior_proofs(self):
        with self.assertRaisesRegex(QueryFailure, "lost its behavior"):
            _observe(self.claim, self.engine, self.allowed, self.records, frozenset(), self.probes)

    def test_negative_world_still_rejects_unknown_witness_records(self):
        with self.assertRaisesRegex(QueryFailure, "absent from this fixture"):
            _observe(self.claim, self.engine, self.allowed, frozenset(), frozenset(), self.probes,
                     negative_world=True)

    def test_security_control_lineage_still_satisfies_behavior_flag(self):
        observed = _observe(self.claim, self.engine, self.allowed, self.records, self.records, self.probes,
                            negative_world=True)
        self.assertEqual(observed.support, (True, False))


class RobustnessFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        _, _, self.serving, self.source_report = runtime_fixture(self.root / "source", extra_rows=1)
        self.engine = open_duckdb_engine(self.serving, QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000))
        self.addCleanup(self.engine.connection.close)
        self.verifier = EvidenceVerifier(self.serving, self.engine, frozenset({"43"}))
        self.addCleanup(self.verifier.close)
        self.task = compile_draft(
            qualified_runtime_draft(self.serving, self.source_report), self.verifier,
            mode="tenant", incident_id=None, task_id="robustness-fixture", revision_id="r1", checkpoint_cap=0.5,
        )
        self.citation = next(PublicCitation(table=ref.table, record_id=ref.public_record_id)
                             for ref in self.task.evidence if ref.private_locator == "obs:2")
        _, self.row = self.verifier.record_values(self.citation)

    def unchanged(self, task=None):
        task = task or self.task
        return tuple(ClaimExpectation(claim_id=name, answer="baseline", witnesses="baseline", support="baseline")
                     for name in ("final", *(c.checkpoint_id for c in task.private_gold.checkpoints)))

    def representation_case(self, task=None):
        return RobustnessCase(
            case_id="json-format", rationale="Vary formatting only; the cohort predicates do not change.",
            scope="serving_contract",
            edits=(CellEdit(citation=self.citation, column="AdditionalFields",
                            value=json_variant(self.row["AdditionalFields"], "representation")),),
            expected=self.unchanged(task),
        )

    def run_plan(self, plan, *, task=None, verifier=None, output="result"):
        return run_robustness(task or self.task, verifier or self.verifier, plan,
                              mysqld=Path(os.environ["SECRL_MYSQLD"]), workdir=self.root, output=self.root / output)

    def test_missing_claim_unknown_record_and_noop_cannot_start_a_native_fixture(self):
        case = self.representation_case()
        variants = [
            case.model_copy(update={"expected": case.expected[:1]}),
            case.model_copy(update={"edits": (CellEdit(citation=self.citation, column="not_a_source_field", value="x"),)}),
            case.model_copy(update={"edits": (CellEdit(citation=self.citation, column="AdditionalFields",
                                                      value=self.row["AdditionalFields"]),)}),
        ]
        with patch("secgym.qagen.agentic.robustness.owned_fixtures") as native:
            for value in variants:
                plan = RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(value,))
                with self.assertRaises(ValueError):
                    run_robustness(self.task, self.verifier, plan, mysqld=Path("unused"), workdir=self.root,
                                   output=self.root / "invalid")
            native.assert_not_called()
        self.assertFalse((self.root / "invalid").exists())

    def test_source_declared_support_vectors_are_validated_without_observing_counterfactual_output(self):
            data = self.task.model_dump(mode="json")
            for claim in (data["private_gold"]["final"], *(c["claim"] for c in data["private_gold"]["checkpoints"])):
                claim["witness_programs"] = [
                    {key: p[key] for key in ("program_id", "engine", "query")} for p in claim["witness_programs"]
                ]
            task = TaskRecord.model_validate_json(json.dumps(data))
            proofs = self.verifier.preflight(task)
            citations = frozenset(c for groups in proofs.values() for group in groups for c in group)
            records = {c: self.verifier.record_values(c)[1] for c in citations}
            case = self.representation_case(task)
            invalid = case.model_copy(update={"expected": (
                case.expected[0].model_copy(update={"support": False}), *case.expected[1:],
            )})
            plan = RobustnessPlan(task_fingerprint=fingerprint(task), cases=(invalid,))
            with self.assertRaisesRegex(ValueError, "support contradicts.*declared enumerated witnesses"):
                validate_plan_expectations(task, plan, proofs, records, citations)
            legacy = plan.model_copy(update={"policy_version": "isolated-source-robustness-v1"})
            validate_plan_expectations(task, legacy, proofs, records, citations)

    def test_qualified_support_is_not_inferred_from_its_representative_union(self):
            proofs = self.verifier.preflight(self.task)
            citations = frozenset(c for groups in proofs.values() for group in groups for c in group)
            records = {c: self.verifier.record_values(c)[1] for c in citations}
            case = self.representation_case()
            independent = case.model_copy(update={"expected": tuple(
                e.model_copy(update={"support": False}) for e in case.expected
            )})
            validate_plan_expectations(
                self.task, RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(independent,)),
                proofs, records, citations,
            )

    def test_unknown_expected_witness_is_rejected_by_the_shared_author_validator(self):
            proofs = self.verifier.preflight(self.task)
            citations = frozenset(c for groups in proofs.values() for group in groups for c in group)
            records = {c: self.verifier.record_values(c)[1] for c in citations}
            case = self.representation_case()
            invalid = case.model_copy(update={"expected": (
                case.expected[0].model_copy(update={"witnesses": (
                    WitnessGroup(citations=(PublicCitation(table="DeviceProcessEvents", record_id="r:" + "0" * 64),)),
                )}), *case.expected[1:],
            )})
            with self.assertRaisesRegex(ValueError, "unknown source witnesses"):
                validate_plan_expectations(
                    self.task, RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(invalid,)),
                    proofs, records, citations,
                )

    def test_mutation_contract_rejects_locator_edits_and_duplicate_targets(self):
        data = self.representation_case().model_dump(mode="json")
        for edits in ([{**data["edits"][0], "column": "_record_id"}], data["edits"] * 2):
            with self.assertRaises(ValueError):
                RobustnessCase.model_validate_json(json.dumps({**data, "edits": edits}))

    def test_program_answers_require_exact_ids_and_public_formats_before_native_startup(self):
        claim = self.task.private_gold.final
        answers = {p.program_id: claim.expected for p in claim.programs}
        first = claim.programs[0].program_id
        wrong_format = claim.expected.model_copy(update={
            "format": claim.expected.format.model_copy(update={"semantic_kind": "unrelated"}),
        })
        variants = (
            {key: value for key, value in answers.items() if key != first},
            {**answers, "unknown-program": claim.expected},
            {**answers, first: wrong_format},
        )
        case = self.representation_case()
        with patch("secgym.qagen.agentic.robustness.owned_fixtures") as native:
            for by_program in variants:
                changed = case.model_copy(update={"expected": (
                    case.expected[0].model_copy(update={"answer": ProgramAnswers(by_program=by_program)}),
                    *case.expected[1:],
                )})
                with self.assertRaises(ValueError):
                    run_robustness(self.task, self.verifier, RobustnessPlan(
                        task_fingerprint=fingerprint(self.task), cases=(changed,),
                    ), mysqld=Path("unused"), workdir=self.root, output=self.root / "invalid-programs")
            native.assert_not_called()
        self.assertFalse((self.root / "invalid-programs").exists())

    def test_answer_vectors_preserve_null_empty_sets_order_and_cardinality(self):
        answer = self.task.private_gold.final.expected
        empty = TypedAnswer(format=answer.format, value=())
        expected = (answer, None)
        self.assertTrue(_answer_vectors_equal(expected, expected))
        for actual in ((answer,), (None, answer), (answer, answer), (answer, None, None), (answer, empty)):
            self.assertFalse(_answer_vectors_equal(expected, actual))
        by_program = ProgramAnswers(by_program={p.program_id: answer for p in reversed(self.task.private_gold.final.programs)})
        self.assertEqual(_expected_answers(self.task.private_gold.final, by_program, "duckdb"), (answer,))
        claim = self.task.private_gold.final
        original = next(p for p in claim.programs if p.engine == "duckdb")
        alternate = original.model_copy(update={"program_id": original.program_id + "-alternate"})
        claim = claim.model_copy(update={"programs": (*claim.programs, alternate)})
        by_program = ProgramAnswers(by_program={
            p.program_id: None if p.program_id == alternate.program_id else answer for p in reversed(claim.programs)
        })
        self.assertEqual(_expected_answers(claim, by_program, "duckdb"), (answer, None))
        before = {"claim_id": "final", "answer": "baseline", "witnesses": "baseline", "support": "baseline"}
        self.assertEqual(ClaimExpectation.model_validate(before).model_dump(mode="json"), before)

    @unittest.skipUnless(os.environ.get("SECRL_MYSQLD"), "set SECRL_MYSQLD for owned MySQL fixtures")
    def test_actual_backends_can_expect_one_surviving_and_one_empty_answer_program(self):
        task = runtime_task(self.serving, self.source_report)
        data = task.model_dump(mode="json")
        programs = data["private_gold"]["final"]["programs"]
        programs.extend([
            {**program, "program_id": program["program_id"] + "-optional",
             "query": program["query"] + " AND CAST(JSON_EXTRACT(AdditionalFields,'$.Visible') AS CHAR)='9007199254740993'"}
            for program in tuple(programs)
        ])
        task = TaskRecord.model_validate_json(json.dumps(data))
        verifier = EvidenceVerifier(self.serving, self.engine, frozenset({"host.test", "$.Visible", "9007199254740993"}))
        self.addCleanup(verifier.close)
        ref = task.evidence[0]
        citation = PublicCitation(table=ref.table, record_id=ref.public_record_id)
        _, row = verifier.record_values(citation)
        value = parse_json(row["AdditionalFields"])
        value.pop("Visible")
        case = RobustnessCase(
            case_id="optional-property-removed", rationale="The primary answer route survives the optional property removal.",
            scope="serving_contract", edits=(CellEdit(citation=citation, column="AdditionalFields", value=encode_json(value)),),
            expected=self.unchanged(task),
        )
        old = self.run_plan(RobustnessPlan(task_fingerprint=fingerprint(task), cases=(case,)),
                            task=task, verifier=verifier, output="uniform-answer")
        self.assertEqual(old.status, "mismatch")
        failures = [check for check in old.checks if check.status != "pass"]
        self.assertEqual({(c.claim_id, c.engine) for c in failures}, {("final", "duckdb"), ("final", "mysql")})
        answers = ProgramAnswers(by_program={
            p.program_id: None if p.program_id.endswith("-optional") else task.private_gold.final.expected
            for p in task.private_gold.final.programs
        })
        revised = case.model_copy(update={"expected": (
            case.expected[0].model_copy(update={"answer": answers}), *case.expected[1:],
        )})
        result = self.run_plan(RobustnessPlan(task_fingerprint=fingerprint(task), cases=(revised,)),
                               task=task, verifier=verifier, output="program-answers")
        self.assertEqual(result.status, "pass")
        for check in result.checks:
            if check.case_id == case.case_id and check.claim_id == "final":
                self.assertEqual(check.observed.answers, (task.private_gold.final.expected, None))

    @unittest.skipUnless(os.environ.get("SECRL_MYSQLD"), "set SECRL_MYSQLD for owned MySQL fixtures")
    def test_actual_backends_preserve_qualified_proof_and_reject_missing_member_citations(self):
        before = file_sha256(self.serving / self.source_report["public_database"]["path"])
        plan = RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(self.representation_case(),))
        result = self.run_plan(plan)
        self.assertEqual(result.status, "pass")
        self.assertEqual(len(result.checks), 8)
        self.assertEqual(set(result.backend_versions), {"duckdb", "mysql"})
        for check in result.checks:
            self.assertTrue(check.observed.support[0])
            self.assertFalse(check.observed.support[1])
            self.assertIn(False, check.observed.support[2:])
        self.assertFalse(result.source_databases_modified)
        self.assertFalse(result.semantic_plan_review_performed)
        self.assertFalse(result.full_snapshot_mysql_revalidated)
        self.assertEqual(file_sha256(self.serving / self.source_report["public_database"]["path"]), before)
        self.assertEqual(list(self.root.glob(".secrl-robustness-*")), [])
        self.assertEqual(RobustnessReport.model_validate_json((self.root / "result/report.json").read_bytes()), result)
        with self.assertRaisesRegex(ValueError, "new directory"):
            self.run_plan(plan)

    @unittest.skipUnless(os.environ.get("SECRL_MYSQLD"), "set SECRL_MYSQLD for owned MySQL fixtures")
    def test_explicit_record_omission_changes_the_cohort_without_laundering_incomplete_citations(self):
        record = self.citation
        other = next(PublicCitation(table=ref.table, record_id=ref.public_record_id)
                     for ref in self.task.evidence if ref.private_locator.startswith("obs:bulk"))
        citations = frozenset(PublicCitation(table=r.table, record_id=r.public_record_id) for r in self.task.evidence)
        probes = (citations, frozenset(), *(citations - {c} for c in sorted(citations, key=lambda c: (c.table, c.record_id))))
        support = tuple(other in available for available in probes)
        expectations = (
            ClaimExpectation(claim_id="final",
                             answer=TypedAnswer(format=self.task.private_gold.final.expected.format, value=("bulk.test",)),
                             witnesses=(WitnessGroup(citations=(other,)),), support=support),
            ClaimExpectation(claim_id="common-executable", answer="baseline",
                             witnesses=(WitnessGroup(citations=(other,)),), support=support),
        )
        case = RobustnessCase(case_id="remove-one-event", rationale="The fixture now contains one qualifying host.",
                              scope="serving_contract", removed_records=(record,), expected=expectations)
        empty = RobustnessCase(
            case_id="remove-cohort", rationale="An empty requested set is distinct from a missing scalar answer.",
            scope="serving_contract", removed_records=(record, other), expected=(
                ClaimExpectation(claim_id="final", answer=TypedAnswer(format=self.task.private_gold.final.expected.format, value=()),
                                 witnesses=(), support=False),
                ClaimExpectation(claim_id="common-executable", answer=None, witnesses=(), support=False),
            ),
        )
        result = self.run_plan(RobustnessPlan(task_fingerprint=fingerprint(self.task), cases=(case, empty)))
        self.assertEqual(result.status, "pass")

    def scalar_task(self, *, serialized):
        task = runtime_task(self.serving, self.source_report)
        data = task.model_dump(mode="json")
        data["context"] += " The recorded Visible value is 9007199254740993."
        literal = '"Visible":9007199254740993'
        for claim in (data["private_gold"]["final"], data["private_gold"]["checkpoints"][0]["claim"]):
            for program in claim["programs"] + claim["witness_programs"]:
                if serialized:
                    predicate = (
                        f"STRPOS(AdditionalFields,'{literal}')>0" if program["engine"] == "duckdb"
                        else f"LOCATE('{literal}',AdditionalFields)>0"
                    )
                else:
                    predicate = "CAST(JSON_EXTRACT(AdditionalFields,'$.Visible') AS CHAR)='9007199254740993'"
                program["query"] += " AND " + predicate
        compiled = TaskRecord.model_validate_json(json.dumps(data))
        allowed = frozenset({"host.test", literal, "0"}) if serialized else frozenset({"host.test", "$.Visible", "9007199254740993"})
        verifier = EvidenceVerifier(self.serving, self.engine, allowed)
        self.addCleanup(verifier.close)
        ref = compiled.evidence[0]
        self.citation = PublicCitation(table=ref.table, record_id=ref.public_record_id)
        _, self.row = verifier.record_values(self.citation)
        return compiled, verifier

    @unittest.skipUnless(os.environ.get("SECRL_MYSQLD"), "set SECRL_MYSQLD for owned MySQL fixtures")
    def test_representation_dependent_selection_is_detected_in_both_real_backends(self):
        task, verifier = self.scalar_task(serialized=True)
        plan = RobustnessPlan(task_fingerprint=fingerprint(task), cases=(self.representation_case(task),))
        result = self.run_plan(plan, task=task, verifier=verifier)
        self.assertEqual(result.status, "mismatch")
        self.assertTrue(all(c.status == "pass" for c in result.checks if c.case_id == "baseline"))
        failures = [c for c in result.checks if c.case_id != "baseline"]
        self.assertEqual(len(failures), 4)
        self.assertEqual({c.engine for c in failures}, {"duckdb", "mysql"})
        self.assertTrue(all(c.status == "mismatch" for c in failures))

    @unittest.skipUnless(os.environ.get("SECRL_MYSQLD"), "set SECRL_MYSQLD for owned MySQL fixtures")
    def test_structured_selection_survives_formatting_and_detects_a_missing_named_property(self):
        task, verifier = self.scalar_task(serialized=False)
        value = parse_json(self.row["AdditionalFields"])
        value.pop("Visible")
        absent = RobustnessCase(
            case_id="missing-property", rationale="Remove the exact qualifying property, not an array neighbor.",
            scope="serving_contract",
            edits=(CellEdit(citation=self.citation, column="AdditionalFields", value=encode_json(value)),),
            expected=tuple(ClaimExpectation(claim_id=e.claim_id, answer=None, witnesses=(), support=False)
                           for e in self.unchanged(task)),
        )
        plan = RobustnessPlan(task_fingerprint=fingerprint(task), cases=(self.representation_case(task), absent))
        result = self.run_plan(plan, task=task, verifier=verifier)
        self.assertEqual(result.status, "pass")
        self.assertEqual(len(result.checks), 12)

    @unittest.skipUnless(os.environ.get("SECRL_MYSQLD"), "set SECRL_MYSQLD for owned MySQL fixtures")
    def test_full_source_query_error_is_not_a_proof_failure_or_a_successful_empty_result(self):
        task, verifier = self.scalar_task(serialized=False)
        original = self.engine.limits
        self.engine.limits = QueryLimits(max_rows=100, max_bytes=1, timeout_ms=3000)
        try:
            with self.assertRaisesRegex(ValueError, "byte limit"):
                self.run_plan(RobustnessPlan(task_fingerprint=fingerprint(task), cases=(self.representation_case(task),)),
                              task=task, verifier=verifier)
        finally:
            self.engine.limits = original
        self.assertFalse((self.root / "result/report.json").exists())

    @unittest.skipUnless(os.environ.get("SECRL_MYSQLD"), "set SECRL_MYSQLD for owned MySQL fixtures")
    def test_native_baseline_error_is_explicit_and_prevents_counterfactual_execution(self):
        task, verifier = self.scalar_task(serialized=False)
        data = task.model_dump(mode="json")
        for program in data["private_gold"]["final"]["programs"]:
            if program["engine"] == "mysql":
                program["query"] = "SELECT MissingColumn FROM DeviceProcessEvents WHERE DeviceName='host.test'"
        task = TaskRecord.model_validate_json(json.dumps(data))
        plan = RobustnessPlan(task_fingerprint=fingerprint(task), cases=(self.representation_case(task),))
        result = self.run_plan(plan, task=task, verifier=verifier)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.cases_not_run, ("json-format",))
        self.assertEqual({c.case_id for c in result.checks}, {"baseline"})
        self.assertTrue(any(c.engine == "mysql" and c.error_code == "query_execution" for c in result.checks))

    @unittest.skipUnless(os.environ.get("SECRL_MYSQLD"), "set SECRL_MYSQLD for owned MySQL fixtures")
    def test_incomplete_count_fixture_is_not_certified_by_its_exemplar_witness(self):
        task, verifier = self.scalar_task(serialized=False)
        data = task.model_dump(mode="json")
        data["private_gold"]["final"]["expected"] = {
            "format": {"kind": "number", "semantic_kind": "event_count", "units": "events"}, "value": 3,
        }
        for program in data["private_gold"]["final"]["programs"]:
            program["query"] = "SELECT COUNT(*) FROM DeviceProcessEvents"
        task = TaskRecord.model_validate_json(json.dumps(data))
        plan = RobustnessPlan(task_fingerprint=fingerprint(task), cases=(self.representation_case(task),))
        result = self.run_plan(plan, task=task, verifier=verifier)
        self.assertEqual(result.status, "fixture_incomplete")
        self.assertEqual(result.cases_not_run, ("json-format",))
        self.assertTrue(all(c.status == "mismatch" for c in result.checks if c.claim_id == "final"))

    @unittest.skipUnless(os.environ.get("SECRL_MYSQLD"), "set SECRL_MYSQLD for owned MySQL fixtures")
    def test_backend_bookkeeping_labels_are_not_compared_as_semantic_witnesses(self):
        task, verifier = self.scalar_task(serialized=False)
        data = task.model_dump(mode="json")
        for claim in (data["private_gold"]["final"], data["private_gold"]["checkpoints"][0]["claim"]):
            for program in claim["witness_programs"]:
                if program["engine"] == "mysql":
                    program["query"] = program["query"].replace("_record_id AS evidence_group",
                                                               "'DeviceProcessEvents' AS evidence_group")
        task = TaskRecord.model_validate_json(json.dumps(data))
        result = self.run_plan(RobustnessPlan(task_fingerprint=fingerprint(task), cases=(self.representation_case(task),)),
                               task=task, verifier=verifier)
        self.assertEqual(result.status, "pass")


if __name__ == "__main__":
    unittest.main()

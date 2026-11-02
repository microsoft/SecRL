# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import itertools
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agentic_runtime_fixture import runtime_fixture, runtime_task
from test_agentic_adapters import reviewed_fixture
from test_agentic_question_splits import question, write_inputs
from secgym.qagen.agentic.canonical_facts import (
    CanonicalFactReview, SourceFactProposal, SourceFactResolver,
)
from secgym.qagen.agentic.contracts import AnswerProgram, fingerprint
from secgym.qagen.agentic.difficulty import (
    AmbiguityProbe, AxisScores, DifficultyPlan, DifficultyReview, ProofChoice, ProofRoute, ReasoningStep,
    DifficultySidecar, _count_band, measure_difficulty, profile_questions, score_axes,
)
from secgym.qagen.agentic.evidence import EvidenceVerifier
from secgym.qagen.agentic.footprints import build_unit_footprint
from secgym.qagen.agentic.mysql_serving import open_duckdb_engine
from secgym.qagen.agentic.query import QueryLimits
from secgym.qagen.agentic.question_splits import SplitQuestion, binding_for, load_questions


ROOT = Path(__file__).resolve().parents[1]


def plan_for(case, *, steps=None, probes=(), terminal=None):
    evidence = case.task.evidence[0].evidence_id
    steps = steps or (ReasoningStep(step_id="lookup", evidence_ids=(evidence,), justification="Controlled direct lookup."),)
    terminal = terminal or steps[-1].step_id
    claims = (("final", case.task.private_gold.final),
              *((checkpoint.checkpoint_id, checkpoint.claim) for checkpoint in case.task.private_gold.checkpoints))
    route = ProofRoute(
        route_id="reviewed-route", steps=steps,
        claims=tuple(ProofChoice(claim_id=key, evidence_set_fingerprint=fingerprint(claim.evidence_sets[0]),
                                 terminal_step=terminal) for key, claim in claims),
        ambiguity_probes=probes, ambiguity_coverage="Controlled fixture explicitly declares its decision points.",
    )
    return DifficultyPlan(binding=binding_for(case), routes=(route,))


def review_for(plan, **changes):
    data = dict(
        plan_fingerprint=fingerprint(plan), reviewer="synthetic-feature-review",
        recommendation="pass", proof_choices_complete_and_material=True,
        logical_bindings_and_domains_valid=True, operations_necessary=True,
        ambiguity_scopes_and_identities_valid=True, reasons=("Controlled synthetic feature review.",),
    )
    data.update(changes)
    return DifficultyReview(**data)


class DifficultyTests(unittest.TestCase):
    def setUp(self):
        self.case = question("difficulty-fixture")

    def test_exact_four_axis_formula_for_all_ordinal_combinations(self):
        for b, p, r, a in itertools.product(range(4), repeat=4):
            axes = AxisScores(breadth=b, dependency=p, reasoning=r, ambiguity=a)
            score, band = score_axes(axes)
            expected = (20 * b + 30 * p + 30 * r + 20 * a) / 3
            self.assertEqual(score, expected)
            self.assertEqual(band, "easy" if expected < 25 else "medium" if expected < 50 else "hard" if expected < 75 else "very_hard")
        self.assertEqual(score_axes(AxisScores(breadth=0, dependency=2, reasoning=3, ambiguity=0)), (50.0, "hard"))

    def test_missing_axes_are_not_zero_or_renormalized(self):
        for missing in ("breadth", "dependency", "reasoning", "ambiguity"):
            values = dict(breadth=3, dependency=3, reasoning=3, ambiguity=3)
            values[missing] = None
            self.assertEqual(score_axes(AxisScores.model_validate(values)), (None, None))
        with self.assertRaises(ValueError):
            AxisScores(breadth=4, dependency=0, reasoning=0, ambiguity=0)

    def test_exact_breadth_depth_and_ambiguity_bin_boundaries(self):
        for thresholds, expected in (
            ((2, 5, 11), {1: 0, 2: 1, 4: 1, 5: 2, 10: 2, 11: 3}),
            ((2, 3, 4), {0: 0, 1: 0, 2: 1, 3: 2, 4: 3}),
            ((1, 2, 4), {0: 0, 1: 1, 2: 2, 3: 2, 4: 3}),
            ((2, 4, 11), {1: 0, 2: 1, 3: 1, 4: 2, 10: 2, 11: 3}),
        ):
            for count, value in expected.items():
                self.assertEqual(_count_band(count, thresholds), value)

    def test_descriptors_do_not_create_labels_or_change_task_fingerprint(self):
        before = fingerprint(self.case.task)
        sidecar = measure_difficulty(self.case)
        self.assertEqual(sidecar.status, "not_measured")
        self.assertIsNone(sidecar.score)
        self.assertIsNone(sidecar.band)
        self.assertEqual(sidecar.descriptors.checkpoint_count, 1)
        self.assertFalse(sidecar.student_prompt_changed)
        self.assertFalse(sidecar.grading_changed)
        self.assertEqual(fingerprint(self.case.task), before)
        self.assertNotIn("difficulty", self.case.task.public_task().model_dump())

    def test_no_model_outcomes_are_accepted_as_inputs(self):
        data = plan_for(self.case).model_dump(mode="json")
        for field in ("solver_success", "astra_solved", "luna_failed", "one_shot_solved_by", "pass_rate"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                DifficultyPlan.model_validate_json(json.dumps({**data, field: True}))

    def test_review_is_required_and_fingerprint_bound(self):
        plan = plan_for(self.case)
        self.assertEqual(measure_difficulty(self.case, plan=plan).status, "needs_review")
        held = measure_difficulty(self.case, plan=plan, review=review_for(plan, operations_necessary=False))
        self.assertEqual(held.status, "needs_review")
        self.assertIsNone(held.score)
        with self.assertRaisesRegex(ValueError, "exact measurement plan"):
            measure_difficulty(self.case, plan=plan, review=review_for(plan, plan_fingerprint="0" * 64))

    def test_changed_task_and_proof_bindings_fail_closed(self):
        plan = plan_for(self.case)
        with self.assertRaisesRegex(ValueError, "bindings"):
            measure_difficulty(question("another-task"), plan=plan)
        data = plan.model_dump(mode="json")
        data["routes"][0]["claims"][0]["evidence_set_fingerprint"] = "0" * 64
        changed = DifficultyPlan.model_validate_json(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "complete validated alternative"):
            measure_difficulty(self.case, plan=changed, review=review_for(changed))

    def test_every_checkpoint_must_be_covered(self):
        data = plan_for(self.case).model_dump(mode="json")
        data["routes"][0]["claims"] = data["routes"][0]["claims"][:1]
        plan = DifficultyPlan.model_validate_json(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "every checkpoint"):
            measure_difficulty(self.case, plan=plan)

    def test_cycles_and_unused_padding_are_rejected(self):
        data = plan_for(self.case).model_dump(mode="json")
        for steps in (
            [{"step_id": "lookup", "evidence_ids": ["private-evidence"], "depends_on": ["lookup"], "justification": "Bad cycle."}],
            [{"step_id": key, "evidence_ids": ["private-evidence"], "justification": "Fixture."} for key in ("lookup", "unused")],
        ):
            data["routes"][0]["steps"] = steps
            with self.assertRaises(ValueError):
                DifficultyPlan.model_validate_json(json.dumps(data))

    def test_claim_bound_evidence_cannot_escape_or_be_omitted(self):
        plan = plan_for(self.case)
        data = plan.model_dump(mode="json")
        data["routes"][0]["steps"][0]["evidence_ids"] = ["not-in-this-proof"]
        bad = DifficultyPlan.model_validate_json(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "claim-bound"):
            measure_difficulty(self.case, plan=bad)

    def test_logical_depth_and_operation_families_not_sql_or_checkpoint_count(self):
        evidence = ("private-evidence",)
        steps = (
            ReasoningStep(step_id="anchor", evidence_ids=evidence, justification="Public anchor."),
            ReasoningStep(step_id="one", depends_on=("anchor",), evidence_ids=evidence,
                          discovered_binding=True, operations=("temporal_alignment",), justification="First binding."),
            ReasoningStep(step_id="two", depends_on=("one",), evidence_ids=evidence,
                          discovered_binding=True, operations=("temporal_alignment", "ranking_ordering"), justification="Second binding."),
        )
        plan = plan_for(self.case, steps=steps)
        result = measure_difficulty(self.case, plan=plan, review=review_for(plan))
        combined = result.routes[0].combined
        self.assertEqual(combined.logical_binding_depth, 2)
        self.assertEqual(combined.axes.dependency, 2)
        self.assertEqual(combined.axes.reasoning, 2)
        self.assertEqual(combined.observations, 1)
        self.assertEqual(len(result.routes[0].objectives), 2)
        self.assertEqual(result.status, "provisional")

    def test_only_independent_binding_branches_count_as_reconvergence(self):
        evidence = ("private-evidence",)
        for independent in (False, True):
            steps = (
                ReasoningStep(step_id="one", evidence_ids=evidence, discovered_binding=True, justification="First binding."),
                ReasoningStep(step_id="two", depends_on=() if independent else ("one",), evidence_ids=evidence,
                              discovered_binding=True, justification="Other binding."),
                ReasoningStep(step_id="merge", depends_on=("one", "two"), evidence_ids=evidence, justification="Require both."),
            )
            plan = plan_for(self.case, steps=steps)
            result = measure_difficulty(self.case, plan=plan, review=review_for(plan))
            self.assertEqual(result.routes[0].combined.necessary_reconvergence, independent)

    def test_unknown_ambiguity_is_not_an_easy_default(self):
        plan = plan_for(self.case, probes=None)
        result = measure_difficulty(self.case, plan=plan, review=review_for(plan))
        self.assertEqual(result.status, "incomplete")
        self.assertIsNone(result.score)
        self.assertIsNone(result.routes[0].combined.axes.ambiguity)
        self.assertIsNone(result.routes[0].combined.ambiguity_candidates)

    def test_explicit_no_choice_profile_is_distinct_from_unknown(self):
        plan = plan_for(self.case, probes=())
        result = measure_difficulty(self.case, plan=plan, review=review_for(plan))
        self.assertEqual(result.status, "provisional")
        self.assertEqual(result.routes[0].combined.axes.ambiguity, 0)
        self.assertEqual(result.score, 0)

    def test_saved_scalar_and_route_axes_cannot_be_tampered_with(self):
        plan = plan_for(self.case)
        result = measure_difficulty(self.case, plan=plan, review=review_for(plan))
        for change in ("overall", "axis", "raw_feature"):
            data = result.model_dump(mode="json")
            if change == "overall":
                data["score"] = 100.0
            elif change == "axis":
                data["routes"][0]["combined"]["axes"]["dependency"] = 3
            else:
                data["routes"][0]["combined"]["logical_binding_depth"] = 10
            with self.subTest(change=change), self.assertRaises(ValueError):
                DifficultySidecar.model_validate_json(json.dumps(data))

    def test_an_unmeasured_alternative_does_not_get_silently_ignored(self):
        complete = plan_for(self.case)
        data = complete.model_dump(mode="json")
        unknown = dict(data["routes"][0])
        unknown.update(route_id="unknown-route", ambiguity_probes=None)
        data["routes"].append(unknown)
        plan = DifficultyPlan.model_validate_json(json.dumps(data))
        result = measure_difficulty(self.case, plan=plan, review=review_for(plan))
        self.assertEqual(result.status, "incomplete")
        self.assertIsNone(result.score)
        self.assertIsNone(result.selected_route)
        self.assertEqual(len(result.routes), 2)

    def test_overlap_graph_size_is_not_difficulty_breadth(self):
        data = self.case.model_dump(mode="json")
        data["baseline"]["edges"] = [{"feature_id": f"edge:{i}", "weight": 1.0} for i in range(500)]
        changed = SplitQuestion.model_validate_json(json.dumps(data))
        plan = plan_for(changed)
        result = measure_difficulty(changed, plan=plan, review=review_for(plan))
        self.assertEqual(result.descriptors.overlap_footprint_edges, 500)
        self.assertEqual(result.routes[0].combined.axes.breadth, 0)
        self.assertEqual(result.score, 0)

    def test_inventory_writer_is_private_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            loaded = load_questions(write_inputs(root, (self.case,)))
            summary = profile_questions(loaded, root / "difficulty")
            self.assertEqual(summary["statuses"], {"not_measured": 1})
            saved = json.loads((root / "difficulty/difficulty-fixture.json").read_text())
            self.assertIsNone(saved["score"])
            self.assertFalse(saved["empirical_calibration_performed"])
            self.assertNotIn("private-gold", json.dumps(saved))
            with self.assertRaises(ValueError):
                profile_questions(loaded, root / "difficulty")
            with self.assertRaises(ValueError):
                profile_questions(loaded, loaded.annotation_directories[0] / "difficulty")

    def test_cli_profiles_without_invoking_models(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = write_inputs(root, (self.case,))
            result = subprocess.run(
                [sys.executable, "-m", "secgym.qagen.agentic", "difficulty-profile",
                 "--inputs", str(manifest), "--output", str(root / "difficulty")],
                cwd=ROOT, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["requested_measurements"], 0)
            self.assertFalse(summary["model_evaluations_run"])
            self.assertEqual(summary["statuses"], {"not_measured": 1})

    def test_reviewed_cli_plan_is_scored_and_missing_review_stays_explicit(self):
        for supplied in (True, False):
            with self.subTest(review_supplied=supplied), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = write_inputs(root, (self.case,))
                plan = plan_for(self.case)
                (root / "plan.json").write_text(plan.model_dump_json())
                (root / "review.json").write_text(review_for(plan).model_dump_json())
                entry = {"task_id": self.case.task.task_id, "plan": "plan.json",
                         "review": "review.json" if supplied else None}
                (root / "plans.json").write_text(json.dumps({"entries": [entry]}))
                result = subprocess.run(
                    [sys.executable, "-m", "secgym.qagen.agentic", "difficulty-profile",
                     "--inputs", str(manifest), "--plans", str(root / "plans.json"),
                     "--output", str(root / "difficulty")],
                    cwd=ROOT, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0 if supplied else 1, result.stderr)
                summary = json.loads(result.stdout)
                self.assertEqual(summary["statuses"], {"provisional" if supplied else "needs_review": 1})

    def test_cli_difficulty_schemas_are_available(self):
        for name in ("difficulty-plan", "difficulty-review", "difficulty-inputs", "difficulty-sidecar"):
            result = subprocess.run([sys.executable, "-m", "secgym.qagen.agentic", "schema", name],
                                    cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("properties", json.loads(result.stdout))


class SourceDifficultyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        graph, _, self.serving, report = runtime_fixture(root)
        task = runtime_task(self.serving, report)
        validation = reviewed_fixture(task)
        self.engine = open_duckdb_engine(self.serving, QueryLimits(max_rows=20, max_bytes=65536, timeout_ms=3000))
        self.addCleanup(self.engine.connection.close)
        self.verifier = EvidenceVerifier(self.serving, self.engine, frozenset())
        self.addCleanup(self.verifier.close)
        citation = {"table": "DeviceProcessEvents", "record_id": task.evidence[0].public_record_id}
        proposal = SourceFactProposal.model_validate_json(json.dumps({"claims": [
            {"claim_id": "final", "references": [{"citation": citation, "column": "FileName"}], "rationale": "Fixture final."},
            {"claim_id": task.private_gold.checkpoints[0].checkpoint_id,
             "references": [{"citation": citation, "column": "ProcessId"}], "rationale": "Fixture checkpoint."},
        ]}))
        bundle = SourceFactResolver(self.verifier).resolve(task, validation, proposal)
        review = CanonicalFactReview(
            bundle_fingerprint=fingerprint(bundle), recommendation="pass", source_properties_relevant=True,
            subjects_roles_times_preserved=True, claim_coverage_complete=True, no_value_only_merging=True,
            reasons=("Fixture source inspection.",),
        )
        self.case = SplitQuestion(task=task, validation=validation,
                                  baseline=build_unit_footprint(task, validation, graph), facts=bundle, review=review)

    def probe(self, query, **changes):
        values = dict(
            probe_id="candidates", decision_step="lookup", table="DeviceProcessEvents",
            program=AnswerProgram(program_id="candidate-query", engine="duckdb", query=query),
            identity_kind="qualified_fields", identity_columns=("TenantId", "ProcessId", "Timestamp"),
            scope_and_relaxation="Synthetic public fixture candidate scope, before choosing a host.",
        )
        values.update(changes)
        return AmbiguityProbe(**values)

    def measured(self, probe):
        plan = plan_for(self.case, probes=(probe,))
        return measure_difficulty(self.case, plan=plan, review=review_for(plan), verifier=self.verifier)

    def test_actual_source_candidates_are_counted_and_duplicates_do_not_inflate(self):
        query = "SELECT _record_id,ProcessId FROM DeviceProcessEvents"
        result = self.measured(self.probe(query + " UNION ALL " + query))
        measurement = result.routes[0].probes[0]
        self.assertEqual(measurement.retrieved_rows, 4)
        self.assertEqual(measurement.candidate_count, 2)
        self.assertEqual(len(measurement.observed_citations), 2)
        self.assertEqual(result.routes[0].combined.axes.ambiguity, 1)
        self.assertIsNotNone(measurement.result_sha256)

    def test_empty_truncated_or_unattributed_queries_do_not_produce_difficulty(self):
        record_id = self.case.task.evidence[0].public_record_id
        queries = (
            "SELECT _record_id,ProcessId FROM DeviceProcessEvents WHERE ProcessId=-1",
            "SELECT _record_id,ProcessId FROM DeviceProcessEvents LIMIT 1",
            f"SELECT '{record_id}' AS _record_id,ProcessId FROM DeviceProcessEvents",
            "SELECT _record_id FROM DeviceProcessEvents",
            "SELECT COUNT(*) AS candidate_count FROM DeviceProcessEvents",
        )
        for query in queries:
            with self.subTest(query=query):
                result = self.measured(self.probe(query))
                self.assertEqual(result.status, "incomplete")
                self.assertEqual(result.routes[0].probes[0].status, "error")
                self.assertIsNone(result.score)
                self.assertIsNone(result.band)

    def test_query_errors_are_measurement_errors_not_hard_labels(self):
        result = self.measured(self.probe("SELECT _record_id,unknown_column FROM DeviceProcessEvents"))
        self.assertEqual(result.status, "incomplete")
        self.assertIsNotNone(result.routes[0].probes[0].error_code)
        self.assertIsNone(result.routes[0].combined.axes.ambiguity)

    def test_result_limit_failure_is_not_a_candidate_count(self):
        self.engine.limits = QueryLimits(max_rows=1, max_bytes=65536, timeout_ms=3000)
        result = self.measured(self.probe("SELECT _record_id,ProcessId FROM DeviceProcessEvents"))
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.routes[0].probes[0].status, "error")
        self.assertIsNone(result.routes[0].probes[0].candidate_count)
        self.assertIsNone(result.score)

    def test_missing_identity_fields_are_not_a_success_shaped_fallback(self):
        result = self.measured(self.probe("SELECT _record_id,ProcessId FROM DeviceProcessEvents",
                                          identity_columns=("not_a_source_field",)))
        self.assertEqual(result.routes[0].probes[0].error_code, "incomplete_candidate_identity")
        self.assertIsNone(result.score)

    def test_probe_engine_and_snapshot_must_match(self):
        probe = self.probe("SELECT _record_id,ProcessId FROM DeviceProcessEvents")
        plan = plan_for(self.case, probes=(probe,))
        with self.assertRaisesRegex(ValueError, "actual read-only"):
            measure_difficulty(self.case, plan=plan, review=review_for(plan))
        self.verifier.report = {**self.verifier.report, "graph_id": "different-graph"}
        with self.assertRaisesRegex(ValueError, "different source"):
            measure_difficulty(self.case, plan=plan, review=review_for(plan), verifier=self.verifier)


if __name__ == "__main__":
    unittest.main()

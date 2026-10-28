# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import ast
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from secgym.qagen.agentic.contracts import (
    REQUIRED_GATES, CaseManifest, EvaluationRecord, GateResult, HistoricalMembership, PublicTask, RewardPolicy,
    ScoreComponent, SimilarityRecord, SnapshotManifest, TaskRecord, TypedAnswer,
    ValidationReport, fingerprint,
)
from secgym.qagen.agentic.legacy import (
    baseline_changes, baseline_summary, build_legacy_baseline, file_record, load_pinned_baseline,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/agentic_task.json"


def task_data():
    return json.loads(FIXTURE.read_text())


def parse_task(data):
    return TaskRecord.model_validate_json(json.dumps(data))


class TaskContractTests(unittest.TestCase):
    def setUp(self):
        self.data = task_data()
        self.task = parse_task(self.data)

    def test_json_round_trip_and_fingerprint(self):
        self.assertEqual(TaskRecord.model_validate_json(self.task.model_dump_json()), self.task)
        self.assertEqual(fingerprint(self.task), fingerprint(parse_task(self.data)))
        self.assertEqual(len(fingerprint(self.task)), 64)
        changed = copy.deepcopy(self.data)
        changed["question"] += " Changed wording."
        self.assertNotEqual(fingerprint(self.task), fingerprint(parse_task(changed)))

    def test_frozen_task_and_nested_fields(self):
        with self.assertRaises(ValidationError):
            self.task.question = "mutated"
        self.assertIsInstance(self.task.private_gold.checkpoints, tuple)
        with self.assertRaises(ValidationError):
            self.task.evidence[0].private_locator = "mutated"

    def test_public_projection_is_an_allowlist(self):
        public = self.task.public_task().model_dump(mode="json")
        self.assertEqual(set(public), {
            "schema_version", "task_id", "revision_id", "serving_view_id",
            "scope", "context", "question", "answer_format",
        })
        self.assertEqual(public["scope"], {"mode": "incident", "incident_id": 34})
        serialized = json.dumps(public)
        for secret in ("private-", "SELECT", "checkpoint", "rationale", "gold",
                       "lineage_group", "reward_policy", "content_sha256"):
            self.assertNotIn(secret, serialized)

    def test_standalone_public_contract_checks_scope(self):
        data = self.task.public_task().model_dump(mode="json")
        data["scope"]["mode"] = "tenant"
        with self.assertRaises(ValidationError):
            PublicTask.model_validate_json(json.dumps(data))

    def test_unknown_fields_rejected_at_each_boundary(self):
        for where in ("root", "gold", "evidence", "checkpoint", "format"):
            with self.subTest(where=where):
                data = task_data()
                target = {
                    "root": data,
                    "gold": data["private_gold"],
                    "evidence": data["evidence"][0],
                    "checkpoint": data["private_gold"]["checkpoints"][0],
                    "format": data["private_gold"]["final"]["expected"]["format"],
                }[where]
                target["unexpected"] = "must not be ignored"
                with self.assertRaises(ValidationError):
                    parse_task(data)

    def test_required_evidence_and_programs(self):
        for field in ("programs", "evidence_sets"):
            for claim in ("final", "checkpoint"):
                with self.subTest(field=field, claim=claim):
                    data = task_data()
                    target = data["private_gold"]["final"] if claim == "final" else data["private_gold"]["checkpoints"][0]["claim"]
                    target[field] = []
                    with self.assertRaises(ValidationError):
                        parse_task(data)

    def test_missing_and_mismatched_evidence_rejected(self):
        for mutation in ("empty", "unresolved", "wrong_snapshot", "duplicate"):
            with self.subTest(mutation=mutation):
                data = task_data()
                if mutation == "empty":
                    data["evidence"] = []
                elif mutation == "unresolved":
                    data["private_gold"]["final"]["evidence_sets"][0]["evidence_ids"] = ["missing"]
                elif mutation == "wrong_snapshot":
                    data["evidence"][0]["snapshot_id"] = "other"
                else:
                    data["evidence"].append(copy.deepcopy(data["evidence"][0]))
                with self.assertRaises(ValidationError):
                    parse_task(data)

    def test_scope_and_ineligible_tasks(self):
        for field, value in (("incident_id", 175), ("incident_id", True), ("anchor_evidence_ids", [])):
            with self.subTest(field=field, value=value):
                data = task_data()
                data["scope"][field] = value
                with self.assertRaises(ValidationError):
                    parse_task(data)
        data = task_data()
        data["task_family"] = "false_positive"
        with self.assertRaises(ValidationError):
            parse_task(data)
        data = task_data()
        data["scope"]["mode"] = "tenant"
        with self.assertRaises(ValidationError):
            parse_task(data)
        data["scope"]["incident_id"] = None
        data["scope"]["anchor_evidence_ids"] = []
        self.assertEqual(parse_task(data).scope.mode, "tenant")

    def test_checkpoint_dependencies_are_acyclic_and_resolved(self):
        for dependencies in (["missing"], ["private-checkpoint"], ["missing", "missing"]):
            data = task_data()
            data["private_gold"]["checkpoints"][0]["depends_on"] = dependencies
            with self.subTest(dependencies=dependencies), self.assertRaises(ValidationError):
                parse_task(data)
        data = task_data()
        second = copy.deepcopy(data["private_gold"]["checkpoints"][0])
        second["checkpoint_id"] = "second"
        second["depends_on"] = ["private-checkpoint"]
        data["private_gold"]["checkpoints"].insert(0, second)
        self.assertEqual(len(parse_task(data).private_gold.checkpoints), 2)
        data["private_gold"]["checkpoints"][1]["depends_on"] = ["second"]
        with self.assertRaises(ValidationError):
            parse_task(data)

    def test_empty_or_duplicate_checkpoints_rejected(self):
        data = task_data()
        data["private_gold"]["checkpoints"] = []
        with self.assertRaises(ValidationError):
            parse_task(data)
        data = task_data()
        data["private_gold"]["checkpoints"] *= 2
        with self.assertRaises(ValidationError):
            parse_task(data)

    def test_unknown_version_and_blank_text_rejected(self):
        for field, value in (("schema_version", "2"), ("generator_version", "v0"), ("question", "  ")):
            data = task_data()
            data[field] = value
            with self.subTest(field=field), self.assertRaises(ValidationError):
                parse_task(data)

    def test_timezone_and_time_order(self):
        for window in (
            {"start": "2024-06-26T11:00:00", "end": "2024-06-26T12:00:00Z"},
            {"start": "2024-06-27T11:00:00Z", "end": "2024-06-26T12:00:00Z"},
        ):
            data = task_data()
            data["scope"]["answer_window"] = window
            with self.subTest(window=window), self.assertRaises(ValidationError):
                parse_task(data)


class ValueAndManifestTests(unittest.TestCase):
    def test_typed_answers(self):
        valid = [
            ({"kind": "boolean", "semantic_kind": "observed"}, False),
            ({"kind": "number", "semantic_kind": "count", "units": "events"}, 0),
            ({"kind": "timestamp", "semantic_kind": "first_seen", "units": "seconds"}, "2024-01-01T00:00:00Z"),
            ({"kind": "set", "semantic_kind": "hosts"}, []),
            ({"kind": "ordered_list", "semantic_kind": "hosts"}, ["host-a", "host-a"]),
        ]
        for fmt, value in valid:
            with self.subTest(fmt=fmt):
                TypedAnswer.model_validate_json(json.dumps({"format": fmt, "value": value}))
        invalid = [
            ({"kind": "boolean", "semantic_kind": "observed"}, "false"),
            ({"kind": "number", "semantic_kind": "count", "units": "events"}, True),
            ({"kind": "number", "semantic_kind": "count", "units": "events"}, "1"),
            ({"kind": "number", "semantic_kind": "count"}, 1),
            ({"kind": "timestamp", "semantic_kind": "time", "units": "minutes"}, "2024-01-01T00:00:00Z"),
            ({"kind": "timestamp", "semantic_kind": "time", "units": "seconds"}, "2024-01-01"),
            ({"kind": "set", "semantic_kind": "hosts", "normalization": "casefold"}, ["A", "a"]),
            ({"kind": "entity", "semantic_kind": "host", "tolerance": 2}, "host-a"),
            ({"kind": "ordered_list", "semantic_kind": "hosts"}, ["  "]),
        ]
        for fmt, value in invalid:
            with self.subTest(fmt=fmt, value=value), self.assertRaises(ValidationError):
                TypedAnswer.model_validate_json(json.dumps({"format": fmt, "value": value}))

    def test_reward_cap_is_explicit_and_strictly_partial(self):
        with self.assertRaises(ValidationError):
            RewardPolicy(policy_version="fixture")
        for cap in (0, 1, 2, -1, float("nan"), float("inf"), True, "0.5"):
            with self.subTest(cap=cap), self.assertRaises(ValidationError):
                RewardPolicy.model_validate({"policy_version": "fixture", "checkpoint_cap": cap})
        self.assertEqual(RewardPolicy(policy_version="fixture", checkpoint_cap=0.5).checkpoint_cap, 0.5)

    def test_case_exclusions_and_project_labels(self):
        data = {
            "snapshot_id": "snapshot", "incident_id": 5, "latest_incident_evidence_id": "incident-row",
            "source_classification": None, "designation_basis": "project_assumption",
            "current_alert_ids": [], "exclusions": [],
        }
        with self.assertRaises(ValidationError):
            CaseManifest.model_validate_json(json.dumps(data))
        data["exclusions"] = ["missing-alert:46f3d4b8-060c-4022-c190-4d88954a6a2e"]
        model = CaseManifest.model_validate_json(json.dumps(data))
        self.assertIsNone(model.source_classification)
        self.assertEqual(model.project_classification, "TruePositive")
        data["incident_id"] = 322
        with self.assertRaises(ValidationError):
            CaseManifest.model_validate_json(json.dumps(data))
        data["exclusions"] = ["missing-source:SquidProxy"]
        CaseManifest.model_validate_json(json.dumps(data))
        data["designation_basis"] = "source_label"
        with self.assertRaises(ValidationError):
            CaseManifest.model_validate_json(json.dumps(data))

    def test_historical_membership_is_not_current_or_a_verdict(self):
        data = {
            "snapshot_id": "snapshot", "incident_id": 34, "alert_id": "alert-a",
            "last_present_at": "2024-01-01T00:00:00Z", "first_absent_at": "2024-01-02T00:00:00Z",
            "before_evidence_id": "before", "after_evidence_id": "after",
            "other_current_incidents": [35],
        }
        model = HistoricalMembership.model_validate_json(json.dumps(data))
        self.assertEqual(model.current_relevance, "not_established")
        for key, value in (
            ("first_absent_at", data["last_present_at"]), ("other_current_incidents", [34]),
            ("other_current_incidents", [35, 35]), ("status", "current"), ("benign", True),
        ):
            with self.subTest(key=key), self.assertRaises(ValidationError):
                HistoricalMembership.model_validate_json(json.dumps({**data, key: value}))

    def test_snapshot_has_real_shape_not_duplicate_sources(self):
        data = {
            "snapshot_id": "snapshot", "created_at": "2024-01-01T00:00:00Z",
            "sources": [{"source_id": "tenant", "path": "tenant.duckdb", "sha256": "a" * 64,
                         "size_bytes": 100, "source_kind": "tenant_duckdb"}],
            "provenance_limits": ["Synthetic manifest only."],
        }
        SnapshotManifest.model_validate_json(json.dumps(data))
        data["sources"] *= 2
        with self.assertRaises(ValidationError):
            SnapshotManifest.model_validate_json(json.dumps(data))


class ValidationAndResultTests(unittest.TestCase):
    def setUp(self):
        self.task = parse_task(task_data())

    def report(self, gates):
        return ValidationReport(
            task_id=self.task.task_id, task_fingerprint=fingerprint(self.task),
            evaluator_version="fixture-validator", gates=tuple(gates),
        )

    def test_missing_gates_fail_closed_with_reasons(self):
        blockers = self.report([]).release_blockers(self.task)
        self.assertEqual(len(blockers), len(REQUIRED_GATES))
        self.assertTrue(all("missing" in b for b in blockers))

    def test_every_required_gate_must_pass_and_bind_current_content(self):
        results = [GateResult(gate=name, status="pass", reason="Synthetic fixture result.") for name in REQUIRED_GATES]
        self.assertEqual(self.report(results).release_blockers(self.task), ())
        for status in ("fail", "error", "not_applicable"):
            altered = list(results)
            altered[0] = GateResult(gate=REQUIRED_GATES[0], status=status, reason="Not valid.",
                                    error_code="fixture_error" if status == "error" else None)
            with self.subTest(status=status):
                self.assertTrue(self.report(altered).release_blockers(self.task))
        changed = task_data()
        changed["private_gold"]["checkpoints"][0]["objective"] += " Changed."
        self.assertTrue(self.report(results).release_blockers(parse_task(changed)))

    def test_duplicate_gate_and_unexplained_error_rejected(self):
        result = GateResult(gate="schema", status="pass", reason="Fixture.")
        with self.assertRaises(ValidationError):
            self.report([result, result])
        with self.assertRaises(ValidationError):
            GateResult(gate="schema", status="error", reason="Fixture.")
        with self.assertRaises(ValidationError):
            GateResult(gate="schema", status="pass", reason="Fixture.", error_code="failure")

    def score_data(self):
        return {
            "component_id": "checkpoint-a", "kind": "checkpoint", "status": "complete",
            "score": 1.0, "max_score": 1.0, "weight": 1.0,
            "evidence": [{"table": "DeviceEvents", "record_id": "public-1"}],
            "trajectory_steps": [2], "first_completion_step": 2,
            "explanation": "Synthetic observed evidence.", "evaluator_version": "fixture",
        }

    def test_score_errors_cannot_look_like_success_or_zero(self):
        data = self.score_data()
        ScoreComponent.model_validate_json(json.dumps(data))
        for status in ("error", "incomplete"):
            with self.subTest(status=status), self.assertRaises(ValidationError):
                ScoreComponent.model_validate_json(json.dumps({**data, "status": status}))
        data.update(status="error", score=None, first_completion_step=None, error_code="timeout")
        self.assertIsNone(ScoreComponent.model_validate_json(json.dumps(data)).score)
        data["score"] = 0
        with self.assertRaises(ValidationError):
            ScoreComponent.model_validate_json(json.dumps(data))

    def test_positive_checkpoint_credit_requires_evidence_and_observed_step(self):
        for key, value in (("evidence", []), ("trajectory_steps", []),
                           ("first_completion_step", 99), ("score", 2), ("score", float("nan"))):
            with self.subTest(key=key), self.assertRaises(ValidationError):
                ScoreComponent.model_validate_json(json.dumps({**self.score_data(), key: value}))

    def test_similarity_retains_weighted_components(self):
        data = {
            "metric_version": "evidence-v1", "feature_weight_version": "fixture",
            "left_task_fingerprint": "a" * 64, "right_task_fingerprint": "b" * 64,
            "status": "complete", "weights": {"edges": 0.25, "observations": 0.25, "facts": 0.25, "containment": 0.25},
            "components": {"edges": 0.0, "observations": 0.5, "facts": 0.5, "containment": 1.0},
            "score": 0.5, "reason": "Synthetic comparison.",
        }
        SimilarityRecord.model_validate_json(json.dumps(data))
        for key, value in (("score", 0.9), ("components", None), ("status", "incomplete")):
            with self.subTest(key=key), self.assertRaises(ValidationError):
                SimilarityRecord.model_validate_json(json.dumps({**data, key: value}))
        data.update(status="incomplete", components=None, score=None)
        self.assertIsNone(SimilarityRecord.model_validate_json(json.dumps(data)).score)
        data["weights"]["edges"] = 0
        with self.assertRaises(ValidationError):
            SimilarityRecord.model_validate_json(json.dumps(data))

    def test_incomplete_similarity_preserves_known_components_without_zero_fallback(self):
        data = {
            "metric_version": "evidence-v1", "feature_weight_version": "fixture",
            "left_task_fingerprint": "a" * 64, "right_task_fingerprint": "b" * 64,
            "status": "incomplete",
            "weights": {"edges": 0.25, "observations": 0.25, "facts": 0.25, "containment": 0.25},
            "components": {"edges": None, "observations": 0.5, "facts": 0.5, "containment": 1.0},
            "score": None, "reason": "Missing edge footprint.",
        }
        result = SimilarityRecord.model_validate_json(json.dumps(data))
        self.assertIsNone(result.score)
        assert result.components is not None
        self.assertEqual(result.components.observations, 0.5)
        data.update(status="complete", score=0.5)
        with self.assertRaises(ValidationError):
            SimilarityRecord.model_validate_json(json.dumps(data))

    def evaluation_data(self):
        checkpoint = {**self.score_data(), "component_id": "private-checkpoint"}
        answer = {
            **checkpoint, "component_id": "final-answer", "kind": "answer_correctness",
            "score": 0.0, "evidence": [], "trajectory_steps": [], "first_completion_step": None,
        }
        evidence = {
            **answer, "component_id": "final-evidence", "kind": "final_evidence",
        }
        checkpoint["evidence"] = [{"table": "DeviceProcessEvents", "record_id": "public-row-17"}]
        return {
            "run_id": "fixture-run", "task_id": self.task.task_id, "task_fingerprint": fingerprint(self.task),
            "evaluation_profile": self.task.evaluation_profile, "backend": "secrl",
            "reward_policy": self.task.reward_policy.model_dump(mode="json"),
            "trajectory_ref": "synthetic-trace.json", "status": "complete",
            "answer_correctness": answer, "final_evidence": evidence, "checkpoints": [checkpoint],
            "grounded_final": False, "checkpoint_progress": 1.0, "aggregate_reward": 0.5,
        }

    def test_completed_checkpoints_do_not_imply_full_reward(self):
        data = self.evaluation_data()
        result = EvaluationRecord.model_validate_json(json.dumps(data))
        self.assertEqual(result.task_mismatches(self.task), ())
        self.assertEqual(result.aggregate_reward, 0.5)
        data["aggregate_reward"] = 1.0
        with self.assertRaises(ValidationError):
            EvaluationRecord.model_validate_json(json.dumps(data))

    def test_correct_guessed_answer_is_not_grounded_final_success(self):
        data = self.evaluation_data()
        data["answer_correctness"]["score"] = 1.0
        result = EvaluationRecord.model_validate_json(json.dumps(data))
        self.assertFalse(result.grounded_final)
        data["grounded_final"] = True
        data["aggregate_reward"] = 1.0
        with self.assertRaises(ValidationError):
            EvaluationRecord.model_validate_json(json.dumps(data))

    def test_grounded_final_can_succeed_without_prescribed_intermediate_path(self):
        data = self.evaluation_data()
        data["answer_correctness"]["score"] = 1.0
        data["final_evidence"].update(
            score=1.0, evidence=[{"table": "DeviceProcessEvents", "record_id": "public-row-17"}],
        )
        data["checkpoints"][0].update(score=0.0, evidence=[], trajectory_steps=[], first_completion_step=None)
        data.update(grounded_final=True, checkpoint_progress=0.0, aggregate_reward=1.0)
        for backend in ("secrl", "acesevals"):
            with self.subTest(backend=backend):
                data["backend"] = backend
                self.assertEqual(EvaluationRecord.model_validate_json(json.dumps(data)).aggregate_reward, 1.0)

    def test_error_checkpoint_blocks_completed_aggregate(self):
        data = self.evaluation_data()
        data["checkpoints"][0].update(status="error", score=None, error_code="timeout", first_completion_step=None)
        with self.assertRaises(ValidationError):
            EvaluationRecord.model_validate_json(json.dumps(data))
        data.update(status="error", grounded_final=None, checkpoint_progress=None, aggregate_reward=None)
        self.assertIsNone(EvaluationRecord.model_validate_json(json.dumps(data)).aggregate_reward)

    def test_reaggregation_keeps_components_and_requires_consistent_policy(self):
        data = self.evaluation_data()
        data["reward_policy"]["checkpoint_cap"] = 0.7
        with self.assertRaises(ValidationError):
            EvaluationRecord.model_validate_json(json.dumps(data))
        data["aggregate_reward"] = 0.7
        result = EvaluationRecord.model_validate_json(json.dumps(data))
        self.assertEqual(result.checkpoint_progress, 1.0)
        self.assertEqual(result.task_mismatches(self.task), ())

    def test_mismatched_task_and_rubric_cannot_reuse_results(self):
        data = self.evaluation_data()
        data["task_fingerprint"] = "f" * 64
        data["checkpoints"][0]["component_id"] = "unknown-checkpoint"
        mismatches = EvaluationRecord.model_validate_json(json.dumps(data)).task_mismatches(self.task)
        self.assertEqual(len(mismatches), 2)

    def test_alternative_citations_are_not_restricted_to_authors_path(self):
        data = self.evaluation_data()
        data["checkpoints"][0]["evidence"][0]["record_id"] = "alternative-public-record"
        result = EvaluationRecord.model_validate_json(json.dumps(data))
        self.assertEqual(result.task_mismatches(self.task), ())


class LegacyBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.measured = build_legacy_baseline(ROOT)
        cls.pinned = load_pinned_baseline()

    def test_existing_files_unchanged(self):
        self.assertEqual(baseline_changes(self.pinned, self.measured), ())

    def test_release_counts_and_corrected_o1_alias(self):
        summary = baseline_summary(self.measured)
        self.assertEqual(summary["releases"], {
            "v0.1": {"train": 418, "test": 589}, "v0.2": {"train": 418, "test": 599},
        })
        self.assertEqual(len(self.measured.release_files), 32)
        self.assertTrue(all("/o1/v1/" in r.path for r in self.measured.release_files if r.dataset_release == "v0.1"))
        paths = {f.path for f in self.measured.preserved_files}
        self.assertTrue(any("/o1/v0/" in p for p in paths))
        self.assertTrue(any("/o3/" in p for p in paths))

    def test_current_default_routes_still_match_o1(self):
        module = ast.parse((ROOT / "secgym/excytin_env.py").read_text())
        assignment = next(node for node in module.body if isinstance(node, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == "ATTACKS" for t in node.targets))
        attacks = ast.literal_eval(assignment.value)
        paths = {r.path for r in self.measured.release_files if r.dataset_release == "v0.1" and r.split == "test"}
        self.assertEqual({f"secgym/questions/{a['qafile']}" for a in attacks.values()}, paths)

    def test_changed_file_is_reported(self):
        altered = self.measured.model_dump(mode="json")
        altered["preserved_files"][0]["sha256"] = "0" * 64
        changed = type(self.measured).model_validate_json(json.dumps(altered))
        self.assertTrue(baseline_changes(self.pinned, changed))

    def test_file_record_refuses_external_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            outside = Path(directory) / "outside"
            outside.write_text("fixture")
            with self.assertRaises(ValueError):
                file_record(root, "../outside")
            (root / "link").symlink_to(outside)
            with self.assertRaises(ValueError):
                file_record(root, "link")


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "secgym.qagen.agentic", *map(str, args)],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )

    def test_contract_command_does_not_claim_evidence_or_release_approval(self):
        result = self.run_cli("validate-contract", FIXTURE)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertTrue(output["contract_valid"])
        self.assertFalse(output["evidence_validated"])
        self.assertFalse(output["release_approved"])

    def test_public_payload_and_schema(self):
        result = self.run_cli("public-task", FIXTURE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("private-", result.stdout)
        schema = self.run_cli("schema", "task")
        self.assertEqual(schema.returncode, 0, schema.stderr)
        self.assertFalse(json.loads(schema.stdout)["additionalProperties"])

    def test_invalid_input_is_explicit_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.json"
            bad.write_text('{"schema_version":"not-supported"}')
            result = self.run_cli("validate-contract", bad)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("error:", result.stderr)
            self.assertEqual(result.stdout, "")

    def test_import_does_not_initialize_agents_models_or_databases(self):
        result = subprocess.run(
            [sys.executable, "-c",
             "import sys; from secgym.qagen.agentic import contracts; "
             "assert not {'autogen','docker','mysql.connector','secgym.myconfig','secgym.excytin_env'} & sys.modules.keys()"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

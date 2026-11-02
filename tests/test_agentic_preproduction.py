# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import contextlib
import io
import json
from pathlib import Path
import tempfile
from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentic_runtime_fixture import runtime_fixture, runtime_task
from secgym.qagen.agentic.__main__ import main
from secgym.qagen.agentic.azure_generation import AzureGenerationConfig
from secgym.qagen.agentic.contracts import SELECTED_INCIDENTS, TaskRecord, fingerprint
from secgym.qagen.agentic.generation import RoleAbstained
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.preproduction import (
    PreproductionPlan, SourceOutcome, configured_model_binding, locked_run, run_source_wave,
    runtime_hashes, safe_unfinished_roles, source_progress,
)
from secgym.qagen.agentic.query import QueryLimits


class PreproductionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.graph, _, self.serving, report = runtime_fixture(self.root / "source")
        self.seed = runtime_task(self.serving, report)
        endpoint = self.root / "endpoint.env"
        endpoint.write_text("AZUREAI_OPENAI_BASE_URL=https://fixture.invalid/\nAZUREAI_OPENAI_API_VERSION=fixture-version\n")
        self.client = SimpleNamespace(config=AzureGenerationConfig(
            env_file=endpoint, deployment="gpt-6-sol", timeout_seconds=300, max_completion_tokens=16000,
        ))
        self.plan = PreproductionPlan(
            batch_id="preprod-fixture", serving_view_id=self.seed.serving_view_id, graph_id=self.seed.graph_version,
            serving_report_sha256=file_sha256(self.serving / "serving_report.json"),
            graph_report_sha256=file_sha256(self.graph / "graph_report.json"),
            model=configured_model_binding(self.client), query_limits=QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000),
            checkpoint_cap=0.5, seed_questions=(self.seed,), implementation_sha256=runtime_hashes(),
        )
        self.output = self.root / "run"
        self.calls = []

    def runner(self, **kwargs):
        self.calls.append(kwargs)
        self.assertTrue(kwargs["quality_gate"])
        data = self.seed.model_dump(mode="json")
        data.update(task_id=kwargs["task_id"], lineage_group=kwargs["task_id"], revision_id="r3",
                    question="Distinct synthetic objective " + kwargs["task_id"])
        data["scope"].update(mode=kwargs["mode"], incident_id=kwargs["incident_id"])
        task = TaskRecord.model_validate_json(json.dumps(data))
        directory = kwargs["output"]
        directory.mkdir(parents=True, exist_ok=kwargs["resume"])
        (directory / "task.json").write_text(task.model_dump_json())
        report = {"status": "needs_revision", "task_fingerprint": fingerprint(task)}
        (directory / "pilot_report.json").write_text(json.dumps(report))
        return report

    def wave(self, count, **kwargs):
        return run_source_wave(plan=self.plan, client=self.client, serving_bundle=self.serving,
                               graph_bundle=self.graph, output=self.output, wave_size=count,
                               runner=kwargs.pop("runner", self.runner), **kwargs)

    def test_exact_approved_envelope_and_frozen_development_exclusion(self):
        attempts = self.plan.attempts()
        self.assertEqual(len(attempts), 2000)
        self.assertEqual(len({attempt.task_id for attempt in attempts}), 2000)
        self.assertEqual(Counter(a.incident_id for a in attempts if a.mode == "incident"),
                         Counter({incident: 100 for incident in SELECTED_INCIDENTS}))
        self.assertEqual(sum(a.mode == "tenant" for a in attempts), 1000)
        self.assertNotIn(self.seed.task_id, {a.task_id for a in attempts})
        self.assertEqual(10 * self.plan.incident_target + self.plan.tenant_target, 1000)
        self.assertIsNone(self.plan.overlap_admission_cap)
        self.assertIsNone(self.plan.difficulty_admission_quota)
        with self.assertRaises(ValueError):
            PreproductionPlan.model_validate_json(self.plan.model_copy(update={"tenant_attempt_ceiling": 1001}).model_dump_json())

    def test_waves_resume_new_slots_and_preserve_scope_local_novelty_context(self):
        first = self.wave(11)
        self.assertEqual(first["logical_attempts_started"], 11)
        self.assertEqual(first["validated_new_questions"], 0)
        self.assertEqual(self.calls[0]["prior_questions"], ())
        self.assertEqual(self.calls[10]["prior_questions"], (self.seed.question,))
        first_id = self.calls[0]["task_id"]
        original = (self.output / "attempts" / first_id / "source-outcome.json").read_bytes()
        second = self.wave(1, resume=True)
        self.assertEqual(second["logical_attempts_started"], 12)
        self.assertEqual(self.calls[-1]["incident_id"], 5)
        self.assertEqual(self.calls[-1]["prior_questions"], ("Distinct synthetic objective " + first_id,))
        self.assertEqual((self.output / "attempts" / first_id / "source-outcome.json").read_bytes(), original)
        self.assertEqual(len(list((self.output / "waves").glob("*.json"))), 2)

    def test_compile_revisions_and_model_calls_do_not_consume_new_logical_attempts(self):
        def repairs(**kwargs):
            report = self.runner(**kwargs)
            for index in range(3):
                (kwargs["output"] / f"compile-failure-{index}.json").write_text("{}")
                directory = kwargs["output"] / f"repair-{index}"
                directory.mkdir()
                (directory / "0000-request.json").write_text("{}")
                (directory / "0000-response.json").write_text("{}")
            return report

        report = self.wave(1, runner=repairs)
        bucket = report["buckets"]["incident:5"]
        self.assertEqual(bucket["logical_attempts_started"], 1)
        self.assertEqual(bucket["model_requests"], 3)
        self.assertEqual(bucket["model_responses"], 3)
        self.assertEqual(bucket["compile_repair_events"], 3)
        self.assertEqual(bucket["validated_new_questions"], 0)
        self.assertEqual(bucket["validated_shortfall"], 50)

    def test_returned_tuple_report_matches_its_saved_json_array(self):
        def tuple_report(**kwargs):
            report = self.runner(**kwargs)
            report["mechanical_release_blockers"] = ("split_review: missing", "release_review: missing")
            (kwargs["output"] / "pilot_report.json").write_text(json.dumps(report))
            return report

        report = self.wave(1, runner=tuple_report)
        self.assertEqual(report["buckets"]["incident:5"]["quality_holds"], 1)
        self.assertEqual(report["buckets"]["incident:5"]["operational_errors"], 0)
        self.assertEqual(report["logical_attempts_started"], 1)

    def test_json_normalization_does_not_hide_changed_report_content(self):
        def changed_report(**kwargs):
            report = self.runner(**kwargs)
            report["mechanical_release_blockers"] = ("original blocker",)
            (kwargs["output"] / "pilot_report.json").write_text(json.dumps({
                **report, "mechanical_release_blockers": ["different blocker"],
            }))
            return report

        with self.assertRaisesRegex(RuntimeError, "does not match its saved report"):
            self.wave(1, runner=changed_report)

    def test_source_ready_requires_quality_artifacts_and_still_is_not_final_admission(self):
        def candidate(**kwargs):
            report = self.runner(**kwargs)
            report["status"] = "candidate_for_mysql_validation"
            (kwargs["output"] / "pilot_report.json").write_text(json.dumps(report))
            return report

        with patch("secgym.qagen.agentic.quality.validate_quality_gate") as quality:
            result = self.wave(1, runner=candidate)
        quality.assert_called_once()
        self.assertEqual(result["source_ready"], 1)
        self.assertEqual(result["validated_new_questions"], 0)
        self.assertFalse(result["admission_performed"])
        self.assertFalse(result["source_capacity_exhausted"])
        self.assertIn("canonical_facts", result["remaining_required_stages"])

    def test_missing_quality_gate_is_an_explicit_retained_error_and_not_a_candidate(self):
        def candidate(**kwargs):
            report = self.runner(**kwargs)
            report["status"] = "candidate_for_mysql_validation"
            (kwargs["output"] / "pilot_report.json").write_text(json.dumps(report))
            return report

        with self.assertRaisesRegex(RuntimeError, "retained operational error"):
            self.wave(1, runner=candidate)
        outcome = SourceOutcome.model_validate_json(next((self.output / "attempts").glob("*/source-outcome.json")).read_bytes())
        self.assertEqual(outcome.status, "operational_error")
        self.assertFalse(outcome.accepted_question)
        self.assertEqual(source_progress(self.plan, self.output)["source_ready"], 0)

    def test_source_abstention_quality_hold_and_endpoint_error_remain_distinct(self):
        def mixed(**kwargs):
            if kwargs["incident_id"] == 5:
                raise RoleAbstained("Required source unavailable.")
            if kwargs["incident_id"] == 34:
                self.runner(**kwargs)
                raise RoleAbstained("Source reviewer cannot establish the complete proof.")
            raise RuntimeError("Endpoint unavailable.")

        with self.assertRaisesRegex(RuntimeError, "Endpoint unavailable"):
            self.wave(3, runner=mixed)
        result = source_progress(self.plan, self.output)
        self.assertEqual(result["logical_attempts_started"], 3)
        self.assertEqual(result["buckets"]["incident:5"]["source_insufficiency"], 1)
        self.assertEqual(result["buckets"]["incident:34"]["quality_holds"], 1)
        self.assertEqual(result["buckets"]["incident:36"]["operational_errors"], 1)
        self.wave(1, resume=True)
        self.assertEqual(self.calls[-1]["incident_id"], 38)

    def test_source_or_model_or_runtime_drift_prevents_new_calls(self):
        for field, value in (("model", self.plan.model.model_copy(update={"deployment": "other"})),
                             ("implementation_sha256", {}), ("serving_report_sha256", "0" * 64)):
            previous = self.plan
            self.plan = self.plan.model_copy(update={field: value})
            try:
                with self.assertRaises(ValueError):
                    self.wave(1)
            finally:
                self.plan = previous
        self.assertFalse(self.calls)
        self.assertFalse(self.output.exists())

    def test_recorded_artifact_and_allocation_tampering_is_not_silently_accepted(self):
        self.wave(1)
        path = self.output / "attempts" / self.calls[0]["task_id"] / "source/task.json"
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "artifacts changed"):
            self.wave(1, resume=True)
        self.assertEqual(len(self.calls), 1)

    def test_interruption_after_a_safe_tool_boundary_resumes_the_same_logical_attempt(self):
        def interrupted(**kwargs):
            role = kwargs["output"] / "scout"
            role.mkdir(parents=True)
            (role / "0000-request.json").write_text("{}")
            (role / "0000-response.json").write_text(json.dumps({
                "choices": [{"message": {"tool_calls": [{"id": "q", "function": {"name": "sql"}}]}}],
            }))
            (role / "0000-tool-results.json").write_text(json.dumps([{"tool_call_id": "q", "content": "{}"}]))
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self.wave(1, runner=interrupted)
        self.assertEqual(source_progress(self.plan, self.output)["logical_attempts_started"], 1)
        result = self.wave(1, resume=True)
        self.assertTrue(self.calls[-1]["resume"])
        self.assertEqual(result["logical_attempts_started"], 1)
        self.assertEqual(result["source_outcomes_recorded"], 1)

    def test_accepted_finish_and_ambiguous_request_never_reroll_a_student(self):
        role = self.root / "student"
        role.mkdir()
        (role / "0000-request.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            safe_unfinished_roles(self.root)
        (role / "0000-response.json").write_text(json.dumps({
            "choices": [{"message": {"tool_calls": [{"id": "done", "function": {"name": "finish"}}]}}],
        }))
        (role / "0000-tool-results.json").write_text(json.dumps([{"tool_call_id": "done", "content": '{"accepted":true}'}]))
        with self.assertRaisesRegex(ValueError, "accepted finish"):
            safe_unfinished_roles(self.root)

    def test_concurrent_worker_and_unallocated_attempt_are_rejected(self):
        self.output.mkdir()
        (self.output / "plan.json").write_text(self.plan.model_dump_json())
        with locked_run(self.output):
            with self.assertRaisesRegex(ValueError, "owning worker"):
                self.wave(1, resume=True)
        (self.output / "attempts/outside-approved-envelope").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "outside the approved envelope"):
            self.wave(1, resume=True)
        self.assertFalse(self.calls)

    def test_metadata_writers_wait_and_serialize_without_becoming_failed_candidates(self):
        self.output.mkdir()
        started = [Event() for _ in range(4)]
        recorded = self.output / "metadata-writers.json"
        recorded.write_text("[]")

        def append(index):
            started[index].set()
            with locked_run(self.output, wait=True):
                values = json.loads(recorded.read_text())
                values.append(index)
                recorded.write_text(json.dumps(values))
            return index

        with ThreadPoolExecutor(max_workers=4) as workers:
            with locked_run(self.output):
                futures = [workers.submit(append, index) for index in range(4)]
                self.assertTrue(all(event.wait(5) for event in started))
                self.assertTrue(all(not future.done() for future in futures))
            self.assertEqual(sorted(future.result(timeout=5) for future in futures), list(range(4)))
        self.assertEqual(sorted(json.loads(recorded.read_text())), list(range(4)))

    def test_no_fake_source_yield_when_nothing_has_run(self):
        self.output.mkdir()
        progress = source_progress(self.plan, self.output)
        self.assertEqual(progress["logical_attempts_started"], 0)
        self.assertIsNone(progress["buckets"]["tenant"]["source_candidate_yield"])
        self.assertEqual(progress["buckets"]["tenant"]["remaining_logical_attempts"], 1000)

    def test_cli_verifies_saved_accounting_and_exposes_strict_schemas(self):
        self.wave(1)
        with patch("sys.argv", ["agentic", "preproduction-progress", "--run", str(self.output)]):
            with contextlib.redirect_stdout(io.StringIO()) as stream:
                main()
        progress = json.loads(stream.getvalue())
        self.assertEqual(progress["logical_attempts_started"], 1)
        self.assertEqual(progress["validated_new_questions"], 0)
        for kind in ("preproduction-plan", "preproduction-source-outcome"):
            with patch("sys.argv", ["agentic", "schema", kind]), contextlib.redirect_stdout(io.StringIO()) as stream:
                main()
            self.assertIn("properties", json.loads(stream.getvalue()))

    def test_source_generation_skips_scopes_that_reached_the_validated_target(self):
        admitted = tuple(SimpleNamespace(bucket="incident:5", difficulty_score=30.0) for _ in range(50))
        with patch("secgym.qagen.agentic.preproduction_admission.admitted_receipts", return_value=admitted):
            report = self.wave(1)
        self.assertEqual(self.calls[0]["incident_id"], 34)
        self.assertEqual(report["buckets"]["incident:5"]["validated_new_questions"], 50)
        self.assertEqual(report["buckets"]["incident:5"]["logical_attempts_started"], 0)


if __name__ == "__main__":
    unittest.main()

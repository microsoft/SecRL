# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import asyncio
import json
import tempfile
import unittest
from importlib.util import find_spec
from pathlib import Path
from unittest.mock import patch

from agentic_runtime_fixture import runtime_fixture, runtime_task
from secgym.qagen.agentic.acesevals_adapter import aces_task_id, export_aces_task, make_aces_tools, register_aces_strategy
from secgym.qagen.agentic.contracts import REQUIRED_GATES, GateResult, ValidationReport, fingerprint
from secgym.qagen.agentic.evidence import EvidenceVerifier
from secgym.qagen.agentic.mysql_serving import open_duckdb_engine
from secgym.qagen.agentic.query import QueryFailure, QueryLimits
from secgym.qagen.agentic.secrl_adapter import SecRLV1Env, Submission


def reviewed_fixture(task):
    return ValidationReport(
        task_id=task.task_id, task_fingerprint=fingerprint(task), evaluator_version="synthetic-fixture-review",
        gates=tuple(GateResult(gate=g, status="pass", reason="Controlled synthetic test fixture review, not benchmark approval.") for g in REQUIRED_GATES),
    )


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        _, _, serving, report = runtime_fixture(Path(self.temp.name))
        self.task = runtime_task(serving, report)
        engine = open_duckdb_engine(serving, QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000))
        self.addCleanup(engine.connection.close)
        self.verifier = EvidenceVerifier(serving, engine, frozenset({"host.test"}))
        self.addCleanup(self.verifier.close)
        self.review = reviewed_fixture(self.task)
        self.env = SecRLV1Env(self.task, self.verifier, self.review, run_id="fixture-secrl",
                             trajectory_ref="fixture:secrl-trajectory", max_steps=10)

    def payload(self, expected):
        return Submission(answer=expected, citations=(
            {"table": "DeviceProcessEvents", "record_id": self.task.evidence[0].public_record_id},
        )).model_dump_json()

    def retrieve(self, env):
        return env.step("SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'")

    def test_public_projection_and_missing_reviews(self):
        public, _ = self.env.reset()
        self.assertNotIn("Tool.EXE", public)
        self.assertNotIn("checkpoint", public)
        self.assertNotIn("private-evidence", public)
        with self.assertRaisesRegex(ValueError, "not admitted"):
            SecRLV1Env(self.task, self.verifier, self.verifier.mechanical_report(self.task),
                       run_id="blocked", trajectory_ref="fixture:blocked", max_steps=10)

    def test_private_pilot_only_defers_missing_split_and_release_reviews(self):
        from secgym.qagen.agentic.contracts import TaskRecord
        data = self.task.model_dump(mode="json")
        data["dataset_release"] = "v1-private-pilot"
        task = TaskRecord.model_validate_json(json.dumps(data))
        review = ValidationReport(task_id=task.task_id, task_fingerprint=fingerprint(task), evaluator_version="fixture",
                                  gates=tuple(g for g in self.review.gates if g.gate not in ("split_review", "release_review")))
        with self.assertRaises(ValueError):
            SecRLV1Env(task, self.verifier, review, run_id="no-release", trajectory_ref="fixture", max_steps=10)
        env = SecRLV1Env(task, self.verifier, review, run_id="pilot", trajectory_ref="fixture", max_steps=10,
                        admission="private_pilot")
        self.assertFalse(env.get_logging()["release_approved"])
        failed = ValidationReport(task_id=task.task_id, task_fingerprint=fingerprint(task), evaluator_version="fixture",
                                  gates=(*review.gates, GateResult(gate="release_review", status="fail", reason="Rejected.")))
        with self.assertRaises(ValueError):
            SecRLV1Env(task, self.verifier, failed, run_id="rejected", trajectory_ref="fixture", max_steps=10,
                       admission="private_pilot")

    def test_citations_require_observed_source_values_not_just_guessed_ids(self):
        self.env.step("SELECT _record_id FROM DeviceProcessEvents WHERE DeviceName='host.test'")
        _, reward, done, _ = self.env.step(self.payload(self.task.private_gold.final.expected), submit=True)
        self.assertTrue(done)
        self.assertEqual(reward, 0.0)
        self.env.reset()
        self.retrieve(self.env)
        _, reward, _, _ = self.env.step(self.payload(self.task.private_gold.final.expected), submit=True)
        self.assertEqual(reward, 1.0)

    def test_checkpoint_feedback_stays_private_and_missing_final_can_get_partial_credit(self):
        self.retrieve(self.env)
        observation, reward, done, _ = self.env.record_finding(self.payload(self.task.private_gold.checkpoints[0].claim.expected))
        self.assertEqual(observation, {"finding_recorded": True})
        self.assertEqual(reward, 0.0)
        self.assertFalse(done)
        result = self.env.finish_for_scorer("")
        self.assertEqual(result.aggregate_reward, 0.5)
        self.assertEqual(result.checkpoints[0].first_completion_step, 1)
        self.assertEqual(result.checkpoints[0].trajectory_steps, (0, 1))

    def test_public_finding_label_gets_source_checked_credit_without_a_secret_id(self):
        from secgym.qagen.agentic.contracts import TypedAnswer
        self.retrieve(self.env)
        data = self.task.private_gold.checkpoints[0].claim.expected.model_dump(mode="json")
        data["format"]["semantic_kind"] = "observed_process_id"
        finding = TypedAnswer.model_validate_json(json.dumps(data))
        self.env.record_finding(self.payload(finding))
        result = self.env.finish_for_scorer("")
        self.assertEqual(result.checkpoint_progress, 1.0)
        self.assertEqual(result.aggregate_reward, 0.5)
        self.assertEqual(result.checkpoints[0].evaluator_version, "source-witness-v1.3")

    def test_equivalent_aliased_cte_projections_are_observed_evidence(self):
        self.env.step("WITH c AS (SELECT _record_id AS k,FileName AS v FROM DeviceProcessEvents WHERE DeviceName='host.test') SELECT k AS evidence_key,v AS artifact FROM c")
        _, reward, _, _ = self.env.step(self.payload(self.task.private_gold.final.expected), submit=True)
        self.assertEqual(reward, 1.0)

    def test_union_source_projections_are_observed_evidence(self):
        queries = (
            "SELECT 'first' AS src,_record_id,FileName FROM DeviceProcessEvents WHERE DeviceName='host.test' "
            "UNION ALL SELECT 'second',_record_id,FileName FROM DeviceProcessEvents WHERE DeviceName='host.test' "
            "ORDER BY FileName LIMIT 100",
            "WITH u AS (SELECT _record_id AS k,FileName AS v FROM DeviceProcessEvents "
            "UNION ALL SELECT _record_id,DeviceName FROM DeviceProcessEvents) SELECT k AS evidence_key,v AS value FROM u",
            "SELECT _record_id,FileName FROM DeviceProcessEvents UNION "
            "SELECT _record_id,FileName FROM DeviceProcessEvents UNION ALL "
            "SELECT _record_id,FileName FROM DeviceProcessEvents",
        )
        for query in queries:
            with self.subTest(query=query):
                self.env.reset()
                self.env.step(query)
                _, reward, _, _ = self.env.step(self.payload(self.task.private_gold.final.expected), submit=True)
                self.assertEqual(reward, 1.0)

    def test_union_cannot_launder_literal_ids_or_unrelated_source_fields(self):
        record = self.task.evidence[0].public_record_id
        queries = (
            "SELECT _record_id,FileName FROM DeviceProcessEvents UNION ALL "
            f"SELECT '{record}' AS _record_id,FileName FROM DeviceProcessEvents",
            "SELECT a._record_id,b.FileName FROM DeviceProcessEvents a CROSS JOIN DeviceProcessEvents b UNION ALL "
            "SELECT c._record_id,d.FileName FROM DeviceProcessEvents c CROSS JOIN DeviceProcessEvents d",
            "SELECT _record_id FROM DeviceProcessEvents UNION ALL SELECT _record_id FROM DeviceProcessEvents",
        )
        for query in queries:
            with self.subTest(query=query):
                self.env.reset()
                self.env.step(query)
                _, reward, _, _ = self.env.step(self.payload(self.task.private_gold.final.expected), submit=True)
                self.assertEqual(reward, 0.0)

    def test_literal_record_ids_with_copied_fields_are_not_observed_rows(self):
        record = self.task.evidence[0].public_record_id
        self.env.step(f"SELECT '{record}' AS _record_id,'Tool.EXE' AS FileName")
        _, reward, _, _ = self.env.step(self.payload(self.task.private_gold.final.expected), submit=True)
        self.assertEqual(reward, 0.0)

    def test_scorer_errors_remain_errors_and_do_not_leak_private_queries(self):
        self.retrieve(self.env)
        with patch.object(self.verifier, "preflight", side_effect=QueryFailure("timeout", "private gold SQL must remain private")):
            observation, reward, done, info = self.env.step(self.payload(self.task.private_gold.final.expected), submit=True)
        self.assertIsNone(reward)
        self.assertTrue(done)
        self.assertEqual(info["evaluation_status"], "error")
        self.assertNotIn("private gold", observation)
        self.assertEqual(self.env.evaluation.answer_correctness.error_code, "timeout")

    def test_logs_persist_and_reset_keeps_completed_episodes(self):
        path = Path(self.temp.name) / "episode.json"
        self.env.log_path = path
        self.retrieve(self.env)
        self.env.step(self.payload(self.task.private_gold.final.expected), submit=True)
        persisted = json.loads(path.read_text())
        self.assertEqual(persisted["current_episode"]["evaluation"]["aggregate_reward"], 1.0)
        old_run = self.env.run_id
        self.env.reset()
        self.assertEqual(self.env.all_logs[0]["evaluation"]["aggregate_reward"], 1.0)
        self.assertNotEqual(old_run, self.env.run_id)

    @unittest.skipUnless(find_spec("saber") and find_spec("inspect_ai"), "optional pinned ACE SDK environment required")
    def test_real_ace_task_strategy_and_tools_match_secrl_components(self):
        from saber.config.models import TaskConfig
        from saber.scoring.context import ScoringContext
        from saber.scoring.registry import ScoringStrategyRegistry
        from saber.scoring.aggregation import aggregate_scorer_results
        from saber.scoring.factory import ScorerFactory
        from inspect_ai.solver import TaskState
        from inspect_ai.model import ModelName, ModelOutput
        from inspect_ai.scorer import Target

        self.retrieve(self.env)
        discovery = self.payload(self.task.private_gold.checkpoints[0].claim.expected)
        self.env.record_finding(discovery)
        expected = self.env.finish_for_scorer("")
        ace = SecRLV1Env(self.task, self.verifier, self.review, run_id="fixture-ace",
                         trajectory_ref="fixture:ace-trajectory", max_steps=10, backend="acesevals")
        exported = export_aces_task(self.task, instruction_template="fixture-instruction.j2", max_steps=10)
        config = TaskConfig.model_validate(exported["tasks"][0])
        self.assertEqual(config.task_id, aces_task_id(self.task))
        self.assertNotIn("Tool.EXE", json.dumps(exported))
        tools = make_aces_tools(ace)
        asyncio.run(tools[0](query="SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'"))
        asyncio.run(tools[1](finding=discovery))
        self.assertNotIn("record_map", asyncio.run(tools[2]()))
        registry = ScoringStrategyRegistry()
        register_aces_strategy(registry, {"fixture-ace": ace})
        actual = []
        for scorer in config.scorers:
            context = ScoringContext(
                submission="", tool_steps=(), messages=(), target="", task_id=config.task_id,
                domain="excytin", metadata={"secrl_run_id": "fixture-ace"}, scorer=scorer,
            )
            score = asyncio.run(registry.get(scorer.strategy).score(context, None))
            actual.append((scorer.scorer_name, score.value))
        self.assertIn(("reward", expected.aggregate_reward), actual)
        self.assertEqual(ace.evaluation.checkpoints, expected.checkpoints)
        self.assertEqual(ace.evaluation.answer_correctness, expected.answer_correctness)
        aggregate, _ = aggregate_scorer_results(
            scorer_configs=config.scorers, raw_scores=dict(actual), agg_config=config.scoring_aggregation)
        self.assertEqual(aggregate, 0.5)
        state = TaskState(model=ModelName("mockllm/model"), sample_id="fixture", epoch=1,
                          input=self.task.question, messages=[], metadata={"secrl_run_id": "fixture-ace"},
                          output=ModelOutput.from_content(model="fixture", content=""), store={})
        factory = ScorerFactory(Path(self.temp.name), registry)
        factory_score = asyncio.run(factory.compute_task_aggregate(config, state, Target("")))
        self.assertEqual(factory_score.value, 0.5)


if __name__ == "__main__":
    unittest.main()

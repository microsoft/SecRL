# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentic_runtime_fixture import runtime_fixture, runtime_task
from secgym.qagen.agentic.contracts import TaskRecord, fingerprint
from secgym.qagen.agentic.evidence import EvidenceFailure, EvidenceVerifier
from secgym.qagen.agentic.generation import (
    BlindSolution, DiscoveryTools, RoleAbstained, TaskDraft, compile_draft, observed_role_citations, run_role,
)
from secgym.qagen.agentic.mysql_serving import open_duckdb_engine
from secgym.qagen.agentic.query import PublicQueryEngine, QueryFailure, QueryLimits
from secgym.qagen.agentic.discovery_context import GraphDiscovery
from secgym.qagen.agentic.azure_generation import replay_output
from secgym.qagen.agentic.pilot import run_discovery_pilot


class FakeClient:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.contexts = []

    def complete(self, messages, tools):
        self.contexts.append(json.loads(json.dumps(messages)))
        return {"choices": [{"finish_reason": "tool_calls", "message": {
            "role": "assistant", "tool_calls": [next(self.responses)],
        }}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}}


def call(name, arguments):
    return {"id": name, "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}


class GenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.graph, _, serving, report = runtime_fixture(self.root / "fixture")
        self.serving = serving
        self.task = runtime_task(serving, report)
        self.engine = open_duckdb_engine(serving, QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000))
        self.addCleanup(self.engine.connection.close)
        self.verifier = EvidenceVerifier(serving, self.engine, frozenset({"host.test"}))
        self.addCleanup(self.verifier.close)
        self.tools = DiscoveryTools(self.engine, self.verifier.tables)

    def test_sql_tool_explicitly_identifies_its_actual_dialect(self):
        for dialect in ("duckdb", "mysql"):
            engine = PublicQueryEngine(None, dialect, set(self.engine.tables), self.engine.limits)
            tools = DiscoveryTools(engine, self.verifier.tables)
            sql_tool = next(tool["function"] for tool in tools.schemas() if tool["function"]["name"] == "sql")
            with self.subTest(dialect=dialect):
                self.assertIn(dialect, sql_tool["description"])
                self.assertEqual(tools.dispatch("tables", {})["engine"], dialect)

    def test_graph_tool_is_bound_and_samples_are_explicit(self):
        from secgym.qagen.agentic.contracts import PublicCitation
        graph = GraphDiscovery(self.graph, self.verifier)
        try:
            result = graph.neighbors(PublicCitation(table="DeviceProcessEvents", record_id=self.task.evidence[0].public_record_id))
            self.assertTrue(result["participants"])
            self.assertTrue(result["neighbors_sampled"])
            self.assertEqual(result["neighbor_sample"], [])
        finally:
            graph.close()

    def test_model_failure_is_persisted_and_not_a_successful_role(self):
        class FailedClient:
            def complete(self, messages, tools):
                raise RuntimeError("fixture endpoint unavailable")
        with self.assertRaises(RuntimeError):
            run_role(FailedClient(), self.tools, "blind", "", {}, BlindSolution, self.root / "failed")
        self.assertTrue((self.root / "failed/0000-error.json").is_file())
        self.assertFalse((self.root / "failed/complete.json").exists())
        final = {"answer": self.task.private_gold.final.expected.model_dump(mode="json"), "citations": [],
                 "confidence": "uncertain", "explanation": "Resumed fixture."}
        result = run_role(FakeClient([call("finish", final)]), self.tools, "blind", "", {}, BlindSolution,
                          self.root / "failed", resume=True)
        self.assertEqual(result.explanation, "Resumed fixture.")
        self.assertTrue((self.root / "failed/0000-error.json").exists())
        self.assertTrue((self.root / "failed/0001-response.json").exists())

    def test_explicit_resume_does_not_accept_or_execute_token_truncated_output(self):
        class TruncatedClient:
            def complete(self, messages, tools):
                return {"choices": [{"finish_reason": "incomplete", "message": {
                    "role": "assistant", "tool_calls": [call("sql", {"query": "DELETE FROM DeviceProcessEvents"})],
                }}], "azure_responses": {"status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}}}
        directory = self.root / "truncated"
        with self.assertRaisesRegex(ValueError, "model response incomplete"):
            run_role(TruncatedClient(), self.tools, "blind", "", {}, BlindSolution, directory)
        self.assertFalse((directory / "0000-tool-results.json").exists())
        self.assertFalse((directory / "complete.json").exists())
        final = {"answer": self.task.private_gold.final.expected.model_dump(mode="json"), "citations": [],
                 "confidence": "uncertain", "explanation": "Retried completion."}
        client = FakeClient([call("finish", final)])
        run_role(client, self.tools, "blind", "", {}, BlindSolution, directory, resume=True)
        self.assertNotIn("DELETE", json.dumps(client.contexts))
        self.assertTrue((directory / "0001-recovery.json").exists())
        self.assertTrue((directory / "0000-response.json").exists())

    def test_azure_replay_retains_reasoning_state_without_response_only_fields(self):
        result = replay_output([
            {"type": "reasoning", "id": "r", "summary": [], "encrypted_content": "opaque", "status": None, "content": []},
            {"type": "function_call", "id": "fc", "call_id": "call", "name": "tables", "arguments": "{}",
             "status": "completed", "namespace": None},
        ])
        self.assertEqual(result[0]["encrypted_content"], "opaque")
        self.assertEqual(result[1]["call_id"], "call")
        self.assertTrue(all("status" not in item and "namespace" not in item for item in result))

    def test_invalid_result_citation_is_repaired_before_role_completion(self):
        final = {"answer": self.task.private_gold.final.expected.model_dump(mode="json"),
                 "citations": [{"table": "DeviceProcessEvents", "record_id": "unknown"}],
                 "confidence": "supported", "explanation": "Fixture."}
        corrected = {**final, "citations": [{"table": "DeviceProcessEvents", "record_id": self.task.evidence[0].public_record_id}]}
        client = FakeClient([call("finish", final), call("finish", corrected)])
        def validate(result):
            for citation in result.citations:
                self.verifier.citation_lineage(citation)
        result = run_role(client, self.tools, "blind", "", {}, BlindSolution, self.root / "validated",
                          validate_result=validate)
        self.assertEqual(result.citations[0].record_id, self.task.evidence[0].public_record_id)
        self.assertEqual(len(client.contexts), 2)
        self.assertIn("does not resolve", json.dumps(client.contexts[1]))

    def test_observed_complete_proof_does_not_imply_a_grounded_submission(self):
        from secgym.qagen.agentic.evidence import Finding
        final = {"answer": self.task.private_gold.final.expected.model_dump(mode="json"), "citations": [],
                 "confidence": "supported", "explanation": "Correct answer without final citations."}
        client = FakeClient([
            call("sql", {"query": "SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'"}),
            call("finish", final),
        ])
        directory = self.root / "observation"
        run_role(client, self.tools, "blind", "", self.task.public_task().model_dump(mode="json"),
                 BlindSolution, directory)
        observed = observed_role_citations(self.verifier, directory, self.task)
        proofs = self.verifier.preflight(self.task)["final"]
        self.assertTrue(any(group <= observed for group in proofs))
        self.assertFalse(self.verifier.evidence_matches(Finding(answer=self.task.private_gold.final.expected,
                                                               citations=(), step=0), proofs))

    def test_scout_must_correct_invalid_citations_before_the_author_receives_a_lead(self):
        draft = self.draft_payload()
        lead = {"title": "Fixture", "question_direction": "Inspect the source event.",
                "evidence": [{"table": "DeviceProcessEvents", "record_id": "invalid-row"}], "uncertainty": "Synthetic only."}
        bad = {"leads": [lead], "coverage_limits": []}
        good = {"leads": [{**lead, "evidence": draft["anchors"]}], "coverage_limits": []}
        review = dict(recommendation="pass", scope_supported=True, evidence_independent=True, causal_claims_supported=True,
                      wording_leakage_free=True, literal_justifications_supported=True, answer_unambiguous=True,
                      checkpoints_distinct_and_supported=True, reasons=["Controlled fixture."], counterevidence=[])
        client = FakeClient([
            call("finish", bad), call("finish", good), call("finish", draft),
            call("sql", {"query": "SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'"}),
            call("finish", {"answer": self.task.private_gold.final.expected.model_dump(mode="json"),
                            "citations": draft["anchors"], "confidence": "supported", "explanation": "Fixture."}),
            call("finish", review),
        ])
        with patch("secgym.qagen.agentic.pilot.scope_context", return_value={"mode": "tenant", "incident_id": None}):
            report = run_discovery_pilot(client=client, serving_bundle=self.serving, graph_bundle=self.graph,
                                        mode="tenant", incident_id=None, output=self.root / "validated-scout",
                                        limits=self.engine.limits, checkpoint_cap=0.5)
        self.assertEqual(report["status"], "candidate_for_mysql_validation")
        self.assertIn("does not resolve", json.dumps(client.contexts[1]))
        self.assertNotIn("invalid-row", client.contexts[2][1]["content"])

    def test_role_errors_are_explicit_and_blind_context_is_isolated(self):
        final = {"answer": self.task.private_gold.final.expected.model_dump(mode="json"), "citations": [],
                 "confidence": "uncertain", "explanation": "Fixture result."}
        client = FakeClient([call("sql", {"query": "DELETE FROM DeviceProcessEvents"}), call("finish", final)])
        result = run_role(client, self.tools, "blind", "Read only.", {"question": "Public question only"},
                          BlindSolution, self.root / "blind")
        self.assertEqual(result.confidence, "uncertain")
        self.assertNotIn("Tool.EXE", json.dumps(client.contexts[0]))
        self.assertIn("sql_not_select", json.dumps(client.contexts[1]))
        self.assertTrue((self.root / "blind/complete.json").is_file())
        with self.assertRaises(ValueError):
            run_role(client, self.tools, "blind", "", {}, BlindSolution, self.root / "blind")

    def test_unsupported_evidence_can_abstain_without_fabricating_a_result(self):
        client = FakeClient([call("abstain", {"reason": "Required event source is unavailable."})])
        with self.assertRaises(RoleAbstained):
            run_role(client, self.tools, "scout", "", {}, BlindSolution, self.root / "abstained")
        self.assertTrue((self.root / "abstained/abstention.json").is_file())
        self.assertFalse((self.root / "abstained/result.json").exists())
        self.assertFalse((self.root / "abstained/complete.json").exists())

    def draft_payload(self):
        def draft_claim(claim):
            data = claim.model_dump(mode="json")
            data.pop("evidence_sets")
            return {**data, "explanation": "Synthetic source-backed witness."}
        return {
            "context": self.task.context, "question": self.task.question, "task_family": self.task.task_family,
            "answer_window": self.task.scope.answer_window.model_dump(mode="json"),
            "anchors": [{"table": e.table, "record_id": e.public_record_id} for e in self.task.evidence],
            "relevance_rationale": "Synthetic tenant event.", "final": draft_claim(self.task.private_gold.final),
            "checkpoints": [{"checkpoint_id": c.checkpoint_id, "objective": c.objective, "claim": draft_claim(c.claim)}
                            for c in self.task.private_gold.checkpoints],
            "allowed_literals": [{"value": "host.test", "basis": "public_anchor", "rationale": "Public question host."}],
            "required_tables": ["DeviceProcessEvents"], "coverage_limits": [], "counterevidence": [], "solution": ["Fixture."],
        }

    def test_draft_compiles_only_executable_witnesses_with_source_provenance(self):
        data = self.draft_payload()
        draft = TaskDraft.model_validate_json(json.dumps(data))
        task = compile_draft(draft, self.verifier, mode="tenant", incident_id=None, task_id="draft", revision_id="r1", checkpoint_cap=0.5)
        self.assertEqual(task.evidence[0].private_locator, "obs:1")
        self.assertEqual(task.evidence[0].source_id, "source:fixture")
        self.assertEqual(task.private_gold.final.expected.value, "Tool.EXE")
        self.assertNotIn("Tool.EXE", task.public_task().model_dump_json())
        self.assertEqual(task.reward_policy.checkpoint_cap, 0.5)
        data["checkpoints"] = []
        with self.assertRaises(ValueError):
            TaskDraft.model_validate_json(json.dumps(data))

    def test_compile_checks_literals_in_both_backend_answer_and_witness_programs(self):
        queries = {
            "programs": "SELECT CAST(FileName AS CHAR(128)) FROM DeviceProcessEvents WHERE DeviceName='host.test'",
            "witness_programs": (
                "SELECT 'DeviceProcessEvents' AS evidence_group, 'DeviceProcessEvents' AS table_name, "
                "CAST(_record_id AS CHAR(128)) AS record_id FROM DeviceProcessEvents WHERE DeviceName='host.test'"
            ),
        }
        for location in ("final", "checkpoint"):
            for kind, query in queries.items():
                with self.subTest(location=location, kind=kind):
                    data = self.draft_payload()
                    claim = data["final"] if location == "final" else data["checkpoints"][0]["claim"]
                    next(p for p in claim[kind] if p["engine"] == "mysql")["query"] = query
                    draft = TaskDraft.model_validate_json(json.dumps(data))
                    with patch.object(self.verifier, "claim_witnesses", wraps=self.verifier.claim_witnesses) as execute:
                        with self.assertRaisesRegex(QueryFailure, "unreviewed literal: '128'"):
                            compile_draft(draft, self.verifier, mode="tenant", incident_id=None,
                                          task_id="invalid", revision_id="r1", checkpoint_cap=0.5)
                        execute.assert_not_called()

    def test_compile_rejects_unsafe_mysql_programs_while_using_duckdb(self):
        queries = (
            "SELECT FileName FROM private_mapping",
            "SELECT FileName FROM DeviceProcessEvents LIMIT 1",
            "SELECT LOAD_FILE(FileName) FROM DeviceProcessEvents",
        )
        for query in queries:
            with self.subTest(query=query):
                data = self.draft_payload()
                next(p for p in data["final"]["programs"] if p["engine"] == "mysql")["query"] = query
                with self.assertRaises(QueryFailure):
                    compile_draft(TaskDraft.model_validate_json(json.dumps(data)), self.verifier, mode="tenant", incident_id=None,
                                  task_id="invalid", revision_id="r1", checkpoint_cap=0.5)

    def test_compile_checks_source_derivation_and_order_in_inactive_backend(self):
        data = self.draft_payload()
        next(p for p in data["final"]["programs"] if p["engine"] == "mysql")["query"] = (
            "SELECT 'DeviceProcessEvents' FROM DeviceProcessEvents WHERE DeviceName='host.test'"
        )
        with self.assertRaisesRegex(EvidenceFailure, "derived from source"):
            compile_draft(TaskDraft.model_validate_json(json.dumps(data)), self.verifier, mode="tenant", incident_id=None,
                          task_id="constant", revision_id="r1", checkpoint_cap=0.5)
        data = self.draft_payload()
        data["final"]["expected"]["format"]["kind"] = "ordered_list"
        data["final"]["expected"]["value"] = ["Tool.EXE"]
        next(p for p in data["final"]["programs"] if p["engine"] == "duckdb")["query"] = (
            "SELECT FileName FROM DeviceProcessEvents WHERE DeviceName='host.test' ORDER BY FileName"
        )
        with self.assertRaisesRegex(EvidenceFailure, "explicit outer ORDER BY"):
            compile_draft(TaskDraft.model_validate_json(json.dumps(data)), self.verifier, mode="tenant", incident_id=None,
                          task_id="unordered", revision_id="r1", checkpoint_cap=0.5)

    def test_related_task_has_new_identity_shared_lineage_and_isolated_blind_context(self):
        seed = self.root / "seed"
        (seed / "scout").mkdir(parents=True)
        context = {"mode": "tenant", "incident_id": None, "fixture": True}
        draft = self.draft_payload()
        for name, value in {
            "scope.json": context,
            "execution-policy.json": {"serving_view_id": self.task.serving_view_id},
            "task.json": self.task.model_dump(mode="json"),
            "draft.json": draft,
            "pilot_report.json": {"status": "candidate_for_mysql_validation", "task_fingerprint": fingerprint(self.task)},
            "scout/result.json": {"leads": [{"title": "Fixture", "question_direction": "Inspect the source event.",
                                           "evidence": draft["anchors"], "uncertainty": "Synthetic only."}],
                                  "coverage_limits": []},
        }.items():
            (seed / name).write_text(json.dumps(value))
        review = dict(recommendation="pass", scope_supported=True, evidence_independent=True, causal_claims_supported=True,
                      wording_leakage_free=True, literal_justifications_supported=True, answer_unambiguous=True,
                      checkpoints_distinct_and_supported=True, reasons=["Controlled fixture."], counterevidence=[])
        client = FakeClient([
            call("finish", draft),
            call("sql", {"query": "SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'"}),
            call("finish", {"answer": self.task.private_gold.final.expected.model_dump(mode="json"),
                            "citations": draft["anchors"], "confidence": "supported", "explanation": "Fixture."}),
            call("finish", review),
        ])
        output = self.root / "related"
        with patch("secgym.qagen.agentic.pilot.scope_context", return_value=context):
            report = run_discovery_pilot(client=client, serving_bundle=self.serving, graph_bundle=self.graph,
                                        mode="tenant", incident_id=None, output=output, limits=self.engine.limits,
                                        checkpoint_cap=0.5, related_from=seed, relation="paraphrase", task_id="new-task")
            with self.assertRaisesRegex(ValueError, "new ID"):
                run_discovery_pilot(client=FakeClient([]), serving_bundle=self.serving, graph_bundle=self.graph,
                                    mode="tenant", incident_id=None, output=self.root / "same-id",
                                    limits=self.engine.limits, checkpoint_cap=0.5, related_from=seed,
                                    relation="paraphrase", task_id=self.task.task_id)
        task = TaskRecord.model_validate_json((output / "task.json").read_text())
        self.assertEqual(task.task_id, "new-task")
        self.assertEqual(task.revision_id, "r1")
        self.assertEqual(task.lineage_group, self.task.lineage_group)
        self.assertEqual(report["status"], "candidate_for_mysql_validation")
        self.assertIn("comparison_draft", client.contexts[0][1]["content"])
        self.assertNotIn("comparison_draft", client.contexts[1][1]["content"])
        self.assertNotIn("Tool.EXE", client.contexts[1][1]["content"])
        self.assertEqual(json.loads((output / "related-source.json").read_text())["relation"], "paraphrase")
        saved = (output / "related-source.json").read_text()
        task_bytes = (output / "task.json").read_bytes()
        altered = self.task.model_dump(mode="json")
        altered["lineage_group"] = "different-lineage"
        changed = TaskRecord.model_validate_json(json.dumps(altered))
        (seed / "task.json").write_text(changed.model_dump_json())
        (seed / "pilot_report.json").write_text(json.dumps({
            "status": "candidate_for_mysql_validation", "task_fingerprint": fingerprint(changed),
        }))
        with patch("secgym.qagen.agentic.pilot.scope_context", return_value=context):
            with self.assertRaisesRegex(ValueError, "seed binding changed"):
                run_discovery_pilot(client=FakeClient([]), serving_bundle=self.serving, graph_bundle=self.graph,
                                    mode="tenant", incident_id=None, output=output, limits=self.engine.limits,
                                    checkpoint_cap=0.5, related_from=seed, relation="paraphrase",
                                    task_id="new-task", resume=True)
        self.assertEqual((output / "related-source.json").read_text(), saved)
        self.assertEqual((output / "task.json").read_bytes(), task_bytes)


if __name__ == "__main__":
    unittest.main()

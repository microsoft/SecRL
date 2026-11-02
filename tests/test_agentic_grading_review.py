# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentic_runtime_fixture import qualified_runtime_draft, runtime_fixture, runtime_task
from test_agentic_adapters import reviewed_fixture
from test_agentic_generation import FakeClient, call
from secgym.qagen.agentic.__main__ import main
from secgym.qagen.agentic.canonical_facts import SourceFactReference
from secgym.qagen.agentic.contracts import AnswerProgram, PublicCitation, TaskRecord, TypedAnswer, fingerprint
from secgym.qagen.agentic.evidence import EvidenceVerifier, Finding
from secgym.qagen.agentic.generation import compile_draft
from secgym.qagen.agentic.grading_review import (
    CheckpointIdentityRule, GradingAmendment, GradingReview, ReviewedEvidenceVerifier, ReviewedGradingAmendment,
    SupportingEvidenceRule, identity_values, load_reviewed_grading, review_grading_amendment, runtime_hashes, supporting_citations,
)
from secgym.qagen.agentic.mysql_serving import open_duckdb_engine
from secgym.qagen.agentic.query import QueryLimits
from secgym.qagen.agentic.secrl_adapter import SecRLV1Env, Submission


def passing_review(policy):
    return GradingReview(task_fingerprint=policy.task_fingerprint, policy_fingerprint=fingerprint(policy),
                         recommendation="pass",
                         reviewed_rule_ids=tuple(rule.rule_id for rule in (*policy.supporting_evidence, *policy.checkpoint_identities)),
                         required_proofs_preserved=True, supplemental_scope_relevant=True,
                         identity_roles_verified=True, checkpoints_preserved=True,
                         reasons=("Controlled fixture-only review; not a production semantic approval.",))


class ReviewedGradingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        _, _, self.serving, self.report = runtime_fixture(self.root / "source", extra_rows=1)
        self.task = runtime_task(self.serving, self.report)
        self.engine = open_duckdb_engine(self.serving, QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000))
        self.addCleanup(self.engine.connection.close)
        self.base = EvidenceVerifier(self.serving, self.engine, frozenset({"host.test", "43"}))
        self.addCleanup(self.base.close)
        self.citations = {host: PublicCitation(table="DeviceProcessEvents", record_id=record)
                          for record, host in self.engine.execute("SELECT _record_id,DeviceName FROM DeviceProcessEvents").rows}
        self.core = self.citations["host.test"]
        self.extra = self.citations["other.test"]
        self.bulk = self.citations["bulk.test"]

    def policy(self, task=None, claim_id="final"):
        task = task or self.task
        return GradingAmendment(
            task_fingerprint=fingerprint(task), revision_id="source-review-r1",
            supporting_evidence=(SupportingEvidenceRule(
                rule_id="same-host-context", claim_id=claim_id, table="DeviceProcessEvents",
                rationale="Fixture-only explicit comparison scope.",
                programs=tuple(AnswerProgram(program_id=f"context-{engine}", engine=engine,
                                              query="SELECT _record_id,DeviceName FROM DeviceProcessEvents WHERE DeviceName='host.test'")
                               for engine in ("duckdb", "mysql")),
                review_examples=(self.core,),
            ),), rationale="Source-qualified comparison records may accompany but not replace core evidence.",
        )

    def approved(self, policy):
        return ReviewedGradingAmendment(policy=policy, reviewer=passing_review(policy), reflection=passing_review(policy),
                                        implementation_sha256=runtime_hashes())

    def verifier(self, task, policy):
        verifier = ReviewedEvidenceVerifier(self.serving, self.engine, self.base.allowed_literals,
                                             task=task, amendment=self.approved(policy))
        self.addCleanup(verifier.close)
        return verifier

    def qualified_task(self):
        draft = qualified_runtime_draft(self.serving, self.report)
        verifier = EvidenceVerifier(self.serving, self.engine, frozenset({"43"}))
        try:
            return compile_draft(draft, verifier, mode="tenant", incident_id=None,
                                 task_id="policy-fixture", revision_id="r1", checkpoint_cap=0.5)
        finally:
            verifier.close()

    def test_scoped_context_does_not_replace_complete_qualified_proof(self):
        task = self.qualified_task()
        verifier = self.verifier(task, self.policy(task))
        proof = verifier.preflight(task)["final"]
        finding = Finding(answer=task.private_gold.final.expected, citations=(self.extra, self.bulk, self.core), step=1)
        self.assertFalse(self.base.evidence_matches(finding, proof, claim=task.private_gold.final))
        self.assertTrue(verifier.evidence_matches(finding, proof, claim=task.private_gold.final))
        for citations in ((self.core,), (self.extra, self.core), (self.bulk, self.core)):
            self.assertFalse(verifier.evidence_matches(finding.model_copy(update={"citations": citations}),
                                                        proof, claim=task.private_gold.final))
        self.assertFalse(verifier.evidence_matches(finding.model_copy(update={"citations": (*finding.citations, self.core)}),
                                                    proof, claim=task.private_gold.final))

    def test_enumerated_core_and_source_scoped_extras_are_separate(self):
        policy = self.policy()
        program = "SELECT _record_id,DeviceName FROM DeviceProcessEvents WHERE ProcessId=43 AND DeviceName<> 'host.test'"
        policy = policy.model_copy(update={"supporting_evidence": (
            policy.supporting_evidence[0].model_copy(update={
                "programs": tuple(AnswerProgram(program_id=f"context-{engine}", engine=engine, query=program) for engine in ("duckdb", "mysql")),
                "review_examples": (self.extra,),
            }),)})
        verifier = self.verifier(self.task, policy)
        proof = verifier.preflight(self.task)["final"]
        finding = Finding(answer=self.task.private_gold.final.expected, citations=(self.core, self.extra), step=1)
        self.assertTrue(verifier.evidence_matches(finding, proof, claim=self.task.private_gold.final))
        self.assertFalse(verifier.evidence_matches(finding.model_copy(update={"citations": (self.extra,)}),
                                                    proof, claim=self.task.private_gold.final))
        forged = PublicCitation(table="DeviceProcessEvents", record_id="r:" + "0" * 64)
        self.assertFalse(verifier.evidence_matches(finding.model_copy(update={"citations": (self.core, forged)}),
                                                    proof, claim=self.task.private_gold.final))

    def test_claim_local_allowance_never_leaks_into_other_checkpoint(self):
        task = self.qualified_task()
        verifier = self.verifier(task, self.policy(task))
        claim = task.private_gold.checkpoints[0].claim
        witnesses = verifier.preflight(task)[task.private_gold.checkpoints[0].checkpoint_id]
        self.assertFalse(verifier.evidence_matches(Finding(answer=claim.expected,
                                                          citations=(self.extra, self.bulk, self.core), step=1),
                                                    witnesses, claim=claim))

    def test_unobserved_extra_citation_still_fails_adapter_observation_gate(self):
        task = self.qualified_task()
        verifier = self.verifier(task, self.policy(task))
        env = SecRLV1Env(task, verifier, reviewed_fixture(task), run_id="reviewed", trajectory_ref="fixture",
                         max_steps=5, admission="private_pilot")
        env.step("SELECT * FROM DeviceProcessEvents WHERE ProcessId=43")
        result = env.finish_for_scorer(Submission(answer=task.private_gold.final.expected,
                                                 citations=(self.extra, self.bulk, self.core)).model_dump_json())
        self.assertFalse(result.grounded_final)
        self.assertTrue(result.final_evidence.evaluator_version.startswith("source-reviewed-grading-v1:"))

    def test_support_query_requires_source_fields_not_just_fabricated_ids(self):
        rule = self.policy().supporting_evidence[0]
        for query in ("SELECT _record_id FROM DeviceProcessEvents WHERE DeviceName='host.test'",
                      "SELECT _record_id,'host.test' AS DeviceName FROM DeviceProcessEvents WHERE DeviceName='host.test'"):
            altered = rule.model_copy(update={"programs": tuple(AnswerProgram(program_id=f"p-{engine}", engine=engine, query=query)
                                                               for engine in ("duckdb", "mysql"))})
            with self.assertRaises(ValueError):
                supporting_citations(self.base, altered, frozenset({self.core}))

    def test_same_object_identity_rules_reject_cross_role_and_missing_source_bindings(self):
        canonical = SourceFactReference(citation=self.core, column="Identity", json_path=("user", "upn"))
        alternative = SourceFactReference(citation=self.core, column="Identity", json_path=("user", "id"))
        rule = CheckpointIdentityRule(rule_id="editor", checkpoint_id=self.task.private_gold.checkpoints[0].checkpoint_id,
                                      canonical=canonical, alternative=alternative, rationale="Same source user object.")
        data = self.task.model_dump(mode="json")
        data["private_gold"]["checkpoints"][0]["claim"]["expected"] = {
            "format": {"kind": "entity", "semantic_kind": "user_principal_name"}, "value": "editor@example.test",
        }
        task = TaskRecord.model_validate_json(json.dumps(data))
        with patch.object(self.base, "record_values", return_value=("behavior", {
            "Identity": '{"user":{"upn":"editor@example.test","id":"object-123"},"other":{"id":"object-456"}}',
        })):
            self.assertEqual(identity_values(self.base, rule, task), ("editor@example.test", "object-123"))
        for other in (alternative.model_copy(update={"json_path": ("other", "id")}),
                      alternative.model_copy(update={"citation": self.extra})):
            with self.assertRaises(ValueError):
                CheckpointIdentityRule.model_validate_json(rule.model_copy(update={"alternative": other}).model_dump_json())

    def test_identity_credit_requires_exact_source_entity_citation_and_normalization(self):
        _, _, serving, report = runtime_fixture(self.root / "identities", identity_aliases=True)
        task = runtime_task(serving, report)
        data = task.model_dump(mode="json")
        data["dataset_release"] = "v1-private-pilot"
        checkpoint = data["private_gold"]["checkpoints"][0]
        checkpoint["objective"] = "Resolve the source editor."
        checkpoint["claim"]["expected"] = {
            "format": {"kind": "entity", "semantic_kind": "user_principal_name"}, "value": "editor@example.test",
        }
        for program in checkpoint["claim"]["programs"]:
            program["query"] = ("SELECT json_extract_string(Note,'$.user.userPrincipalName')" if program["engine"] == "duckdb"
                                else "SELECT JSON_UNQUOTE(JSON_EXTRACT(Note,'$.user.userPrincipalName'))") + (
                " FROM DeviceProcessEvents WHERE DeviceName='host.test'"
            )
        task = TaskRecord.model_validate_json(json.dumps(data))
        engine = open_duckdb_engine(serving, self.engine.limits)
        self.addCleanup(engine.connection.close)
        citation = PublicCitation(table=task.evidence[0].table, record_id=task.evidence[0].public_record_id)
        rule = CheckpointIdentityRule(
            rule_id="source-editor", checkpoint_id=task.private_gold.checkpoints[0].checkpoint_id,
            canonical=SourceFactReference(citation=citation, column="Note", json_path=("user", "userPrincipalName")),
            alternative=SourceFactReference(citation=citation, column="Note", json_path=("user", "id")),
            rationale="Same editor object in the controlled source fixture.",
        )
        policy = GradingAmendment(task_fingerprint=fingerprint(task), revision_id="r1",
                                 checkpoint_identities=(rule,), rationale="Accept either source editor identifier.")
        verifier = ReviewedEvidenceVerifier(serving, engine, frozenset({"host.test", "$.user.userPrincipalName"}),
                                             task=task, amendment=self.approved(policy))
        self.addCleanup(verifier.close)
        for value, cite, expected in (("object-123", True, 1.0), ("object-456", True, 0.0),
                                      ("OBJECT-123", True, 0.0), ("object-123", False, 0.0)):
            with self.subTest(value=value, cited=cite):
                env = SecRLV1Env(task, verifier, reviewed_fixture(task), run_id="identity", trajectory_ref="fixture",
                                 max_steps=5, admission="private_pilot")
                env.step("SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'")
                env.record_finding(Submission(
                    answer=TypedAnswer(format=task.private_gold.checkpoints[0].claim.expected.format, value=value),
                    citations=(citation,) if cite else (),
                ).model_dump_json())
                result = env.finish_for_scorer("")
                self.assertEqual(result.checkpoint_progress, expected)
                self.assertFalse(result.grounded_final)

    def test_review_and_reflection_each_require_their_own_source_inspection(self):
        policy = self.policy()
        review = passing_review(policy)
        sql = call("sql", {"query": "SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'"})
        client = FakeClient([sql, call("finish", review.model_dump(mode="json")),
                             call("finish", review.model_dump(mode="json")), sql,
                             call("finish", review.model_dump(mode="json"))])
        result = review_grading_amendment(task=self.task, policy=policy, verifier=self.base, client=client,
                                          output=self.root / "review")
        self.assertIsNotNone(result)
        self.assertEqual(len(client.contexts), 5)
        self.assertNotIn("prior_review", client.contexts[0][1]["content"])
        self.assertIn("prior_review", client.contexts[2][1]["content"])
        self.assertIn("independently inspect", json.dumps(client.contexts[3]))
        resumed = review_grading_amendment(task=self.task, policy=policy, verifier=self.base, client=FakeClient([]),
                                           output=self.root / "review", resume=True)
        self.assertEqual(resumed, result)
        self.assertEqual(load_reviewed_grading(self.root / "review"), result)
        path = self.root / "review/reflection/0000-request.json"
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "trace changed"):
            load_reviewed_grading(self.root / "review")

    def test_reflection_can_block_but_not_silently_replace_a_policy_or_score(self):
        policy = self.policy()
        passing = passing_review(policy)
        failed = passing.model_copy(update={"recommendation": "revise", "supplemental_scope_relevant": False})
        client = FakeClient([
            call("sql", {"query": "SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'"}),
            call("finish", passing.model_dump(mode="json")), call("finish", failed.model_dump(mode="json")),
        ])
        result = review_grading_amendment(task=self.task, policy=policy, verifier=self.base, client=client,
                                          output=self.root / "review")
        self.assertIsNone(result)
        self.assertFalse((self.root / "review/reviewed-policy.json").exists())
        report = json.loads((self.root / "review/review-report.json").read_bytes())
        self.assertEqual(report["status"], "needs_revision")
        self.assertFalse(report["scores_changed"])
        with self.assertRaises(ValueError):
            ReviewedGradingAmendment(policy=policy, reviewer=passing, reflection=failed, implementation_sha256=runtime_hashes())

    def test_versioned_grading_schemas_do_not_change_frozen_task_serialization(self):
        original = self.task.model_dump_json()
        for kind in ("grading-amendment", "reviewed-grading-amendment"):
            with patch("sys.argv", ["agentic", "schema", kind]), contextlib.redirect_stdout(io.StringIO()) as output:
                main()
            self.assertIn("properties", json.loads(output.getvalue()))
        self.assertEqual(self.task.model_dump_json(), original)


if __name__ == "__main__":
    unittest.main()

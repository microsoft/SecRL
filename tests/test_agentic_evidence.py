# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path

from agentic_runtime_fixture import runtime_fixture, runtime_task
from secgym.qagen.agentic.contracts import PublicCitation, TaskRecord, TypedAnswer
from secgym.qagen.agentic.evidence import EvidenceFailure, EvidenceVerifier, Finding
from secgym.qagen.agentic.mysql_serving import open_duckdb_engine
from secgym.qagen.agentic.query import QueryFailure, QueryLimits


class ExecutableEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        _, _, self.serving, report = runtime_fixture(Path(self.temp.name))
        self.task = runtime_task(self.serving, report)
        self.engine = open_duckdb_engine(self.serving, QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=3000))
        self.addCleanup(self.engine.connection.close)
        self.verifier = EvidenceVerifier(self.serving, self.engine, frozenset({"host.test"}))
        self.addCleanup(self.verifier.close)
        self.citation = PublicCitation(table="DeviceProcessEvents", record_id=self.task.evidence[0].public_record_id)

    def finding(self, expected, step=0, citations=None):
        return Finding(answer=expected, step=step, citations=tuple(citations) if citations is not None else (self.citation,))

    def test_executable_preflight_is_not_a_release_or_semantic_review(self):
        proofs = self.verifier.preflight(self.task)
        self.assertEqual(len(proofs["final"]), 1)
        report = self.verifier.mechanical_report(self.task)
        self.assertTrue(all(g.status == "pass" for g in report.gates))
        self.assertTrue(report.release_blockers(self.task))
        self.assertFalse(any(g.gate in ("identity_evidence", "blind_verification", "release_review") for g in report.gates))

    def test_preflight_cli_persists_checks_without_admitting_a_task(self):
        root = Path(self.temp.name)
        task_path, limits_path, literals_path = root / "task.json", root / "limits.json", root / "literals.json"
        task_path.write_text(self.task.model_dump_json())
        limits_path.write_text(self.engine.limits.model_dump_json())
        literals_path.write_text('["host.test"]')
        output = root / "preflight.json"
        result = subprocess.run([
            sys.executable, "-m", "secgym.qagen.agentic", "preflight-task",
            "--task", str(task_path), "--serving-bundle", str(self.serving), "--limits", str(limits_path),
            "--allowed-literals", str(literals_path), "--output", str(output),
        ], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        saved = json.loads(output.read_text())
        self.assertFalse(saved["release_approved"])
        self.assertTrue(saved["release_blockers"])

    def test_missing_witness_or_source_hash_does_not_pass(self):
        for mutation in ("witness", "hash"):
            data = self.task.model_dump(mode="json")
            if mutation == "witness":
                data["private_gold"]["final"]["witness_programs"] = []
            else:
                data["evidence"][0]["content_sha256"] = "0" * 64
            with self.subTest(mutation=mutation), self.assertRaises(EvidenceFailure):
                self.verifier.preflight(TaskRecord.model_validate_json(json.dumps(data)))

    def test_first_row_and_literal_answer_shortcuts_fail(self):
        for query in ("SELECT FileName FROM DeviceProcessEvents", "SELECT FileName FROM DeviceProcessEvents LIMIT 1",
                      "SELECT 'Tool.EXE' FROM DeviceProcessEvents"):
            data = self.task.model_dump(mode="json")
            data["private_gold"]["final"]["programs"][0]["query"] = query
            with self.subTest(query=query), self.assertRaises((EvidenceFailure, QueryFailure)):
                self.verifier.preflight(TaskRecord.model_validate_json(json.dumps(data)))

    def test_wrong_record_duplicate_and_irrelevant_citations_do_not_ground_answer(self):
        proofs = self.verifier.preflight(self.task)["final"]
        other = self.engine.execute("SELECT _record_id FROM DeviceProcessEvents WHERE DeviceName='other.test'").rows[0][0]
        other_citation = PublicCitation(table="DeviceProcessEvents", record_id=other)
        for citations in ((), (other_citation,), (self.citation, other_citation), (self.citation, self.citation)):
            self.assertFalse(self.verifier.evidence_matches(self.finding(self.task.private_gold.final.expected, citations=citations), proofs))

    def test_explicit_findings_receive_capped_credit_once(self):
        finding = self.finding(self.task.private_gold.checkpoints[0].claim.expected, step=2)
        later = self.finding(finding.answer, step=4)
        wrong = TypedAnswer(format=self.task.private_gold.final.expected.format, value="wrong.exe")
        result = self.verifier.evaluate(self.task, self.finding(wrong, step=5), (later, finding),
                                        run_id="fixture", backend="secrl", trajectory_ref="fixture:trajectory")
        self.assertEqual(result.aggregate_reward, 0.5)
        self.assertEqual(result.checkpoints[0].first_completion_step, 2)
        full = self.verifier.evaluate(self.task, self.finding(self.task.private_gold.final.expected, step=5), (),
                                      run_id="fixture", backend="secrl", trajectory_ref="fixture:trajectory")
        self.assertEqual(full.aggregate_reward, 1.0)
        self.assertEqual(full.checkpoint_progress, 0.0)


if __name__ == "__main__":
    unittest.main()

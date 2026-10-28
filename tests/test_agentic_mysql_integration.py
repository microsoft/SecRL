# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
import asyncio
import json
import secrets
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from importlib.util import find_spec

import mysql.connector

from agentic_runtime_fixture import runtime_fixture, runtime_task
from test_agentic_adapters import reviewed_fixture
from secgym.qagen.agentic.acesevals_adapter import export_aces_task, make_aces_tools, register_aces_strategy
from secgym.qagen.agentic.evidence import EvidenceVerifier, serving_parity
from secgym.qagen.agentic.secrl_adapter import SecRLV1Env, Submission
from secgym.qagen.agentic.mysql_serving import install_mysql_indexes, load_mysql_view, open_mysql_engine, open_duckdb_engine, verify_mysql_view
from secgym.qagen.agentic.query import QueryFailure, QueryLimits
from secgym.qagen.agentic.contracts import TaskRecord
from secgym.qagen.agentic.pilot_evaluation import evaluate_candidate


@unittest.skipUnless(os.environ.get("SECRL_MYSQLD"), "set SECRL_MYSQLD for the isolated real-MySQL integration test")
class MySQLServingIntegrationTests(unittest.TestCase):
    def test_isolated_mysql_projection_permissions_and_limits(self):
        with tempfile.TemporaryDirectory(prefix="secrl-v1-mysql-") as temporary:
            root = Path(temporary)
            data, socket = root / "data", root / "mysql.sock"
            binary = os.environ["SECRL_MYSQLD"]
            init = subprocess.run([binary, "--no-defaults", "--initialize-insecure", f"--datadir={data}",
                                   f"--log-error={root / 'initialize.log'}"],
                                  capture_output=True, text=True, timeout=120, check=False)
            if init.returncode:
                self.fail(init.stderr + (root / "initialize.log").read_text())
            server = subprocess.Popen([binary, "--no-defaults", f"--datadir={data}", f"--socket={socket}",
                                       "--skip-networking", "--mysqlx=OFF", f"--pid-file={root / 'mysql.pid'}",
                                       f"--log-error={root / 'server.log'}"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            admin = engine = None
            try:
                for _ in range(120):
                    if server.poll() is not None:
                        self.fail((root / "server.log").read_text())
                    try:
                        admin = mysql.connector.connect(unix_socket=str(socket), user="root", password="")
                        break
                    except mysql.connector.Error:
                        time.sleep(0.25)
                if admin is None:
                    self.fail("isolated MySQL did not become ready")
                _, _, serving, report = runtime_fixture(root / "fixture")
                loaded = load_mysql_view(serving, admin, "secrl_v1_fixture")
                self.assertEqual(loaded["verified_rows"], 2)
                self.assertEqual(len(loaded["column_aliases"]), 1)
                alias = loaded["column_aliases"][0]["mysql_column"]
                self.assertLessEqual(len(alias), 64)
                indexes = install_mysql_indexes(serving, admin, "secrl_v1_fixture")
                self.assertEqual(len(indexes["indexes"]), 3)
                self.assertEqual({i["index"] for i in indexes["indexes"]},
                                 {"secrl_access_v1", "secrl_process_time_v1", "secrl_host_time_v1"})
                self.assertEqual(install_mysql_indexes(serving, admin, "secrl_v1_fixture"), indexes)
                cursor = admin.cursor()
                cursor.execute("DELETE FROM DeviceProcessEvents WHERE DeviceName='other.test'")
                admin.commit()
                self.assertEqual(verify_mysql_view(serving, admin, "secrl_v1_fixture", allow_partial=True), 1)
                resumed = load_mysql_view(serving, admin, "secrl_v1_fixture", resume=True)
                self.assertEqual(resumed["verified_rows"], 2)
                cursor.execute("UPDATE DeviceProcessEvents SET FileName='tampered' WHERE DeviceName='host.test'")
                admin.commit()
                with self.assertRaisesRegex(ValueError, "content differs"):
                    load_mysql_view(serving, admin, "secrl_v1_fixture", resume=True)
                cursor.execute("UPDATE DeviceProcessEvents SET FileName='Tool.EXE' WHERE DeviceName='host.test'")
                admin.commit()
                cursor.close()
                cursor = admin.cursor()
                password = secrets.token_urlsafe(24)
                cursor.execute("CREATE USER 'fixture_reader'@'localhost' IDENTIFIED BY %s", (password,))
                cursor.execute("GRANT SELECT ON secrl_v1_fixture.* TO 'fixture_reader'@'localhost'")
                cursor.close()
                limits = QueryLimits(max_rows=1, max_bytes=4096, timeout_ms=1000)
                with self.assertRaisesRegex(ValueError, "SELECT-only"):
                    open_mysql_engine(serving, database="secrl_v1_fixture", limits=limits,
                                      unix_socket=str(socket), user="root", password="")
                engine = open_mysql_engine(serving, database="secrl_v1_fixture", limits=limits,
                                           unix_socket=str(socket), user="fixture_reader", password=password)
                self.assertEqual(engine.execute("SELECT FileName FROM DeviceProcessEvents WHERE DeviceName='host.test'").rows, (("Tool.EXE",),))
                with self.assertRaisesRegex(QueryFailure, "row limit"):
                    engine.execute("SELECT * FROM DeviceProcessEvents")
                self.assertEqual(engine.execute("SELECT COUNT(*) FROM DeviceProcessEvents").rows, ((2,),))
                self.assertEqual(engine.execute("SELECT COUNT(*) FROM DeviceProcessEvents WHERE FileName='tool.exe'").rows, ((0,),))
                self.assertEqual(engine.execute("SELECT JSON_LENGTH('[1,2,3]')").rows, ((3,),))
                start = "CAST('2024-03-01 00:01:00.123456' AS DATETIME(6))"
                end = "CAST('2024-03-01 00:01:01.123457' AS DATETIME(6))"
                date_result = engine.execute(
                    f"SELECT DATE_SUB({start}, INTERVAL 2 MINUTE), "
                    f"DATE_ADD(DATE_SUB({start}, INTERVAL 2 MINUTE), INTERVAL 2 MINUTE), "
                    f"TIMESTAMPDIFF(MICROSECOND, {start}, {end}), "
                    f"TIMESTAMPDIFF(MICROSECOND, {end}, {start}), "
                    f"TIMESTAMPDIFF(MICROSECOND, {start}, {start})"
                )
                self.assertEqual(date_result.rows, (("2024-02-29T23:59:00.123456+00:00",
                                                    "2024-03-01T00:01:00.123456+00:00", 1000001, -1000001, 0),))
                self.assertEqual(engine.execute(
                    "SELECT TRIM(CHAR(92) FROM FileName) FROM DeviceProcessEvents WHERE DeviceName='host.test'"
                ).rows, (("Tool.EXE",),))
                with self.assertRaisesRegex(QueryFailure, "unsupported result type: bytes"):
                    engine.execute("SELECT CHAR(92)")
                for payload in ('[{"Name":"Other","Value":"x"},{"Name":"ForwardTo","Value":"user@example.test"}]',
                                '[{"Name":"ForwardTo","Value":"user@example.test"},{"Name":"Other","Value":"x"}]'):
                    sql = ("SELECT j.value FROM JSON_TABLE('" + payload + "', '$[*]' "
                           "COLUMNS (name VARCHAR(128) PATH '$.Name', value VARCHAR(512) PATH '$.Value')) AS j "
                           "WHERE j.name='ForwardTo'")
                    self.assertEqual(engine.execute(sql).rows, (("user@example.test",),))
                self.assertEqual(engine.execute("SELECT COUNT(*) FROM DeviceProcessEvents WHERE Note='space \u00e9'").rows, ((0,),))
                self.assertEqual(engine.execute("SELECT BigCount FROM DeviceProcessEvents WHERE DeviceName='host.test'").rows, ((9007199254740993,),))
                self.assertEqual(engine.execute("SELECT LOCATE('printf',ScriptContent) FROM DeviceProcessEvents WHERE DeviceName='host.test'").rows[0][0] > 0, True)
                raw = engine.connection.cursor()
                with self.assertRaises(mysql.connector.Error):
                    raw.execute("DELETE FROM DeviceProcessEvents")
                with self.assertRaises(mysql.connector.Error):
                    raw.execute("SELECT * FROM record_map")
                raw.close()
                self.assertEqual(verify_mysql_view(serving, engine.connection, "secrl_v1_fixture"), 2)
                task = runtime_task(serving, report)
                verifier = EvidenceVerifier(serving, engine, frozenset({"host.test"}))
                try:
                    union_query = (
                        "SELECT _record_id AS k,FileName AS v FROM DeviceProcessEvents WHERE DeviceName='host.test' "
                        "UNION ALL SELECT _record_id,DeviceName FROM DeviceProcessEvents WHERE DeviceName='missing.test'"
                    )
                    observed = verifier.observed_citations(engine.execute(union_query), union_query)
                    self.assertEqual({(item.table, item.record_id) for item in observed},
                                     {("DeviceProcessEvents", task.evidence[0].public_record_id)})
                    forged_union = (
                        "SELECT _record_id,FileName FROM DeviceProcessEvents WHERE DeviceName='missing.test' UNION ALL "
                        f"SELECT '{task.evidence[0].public_record_id}',FileName FROM DeviceProcessEvents WHERE DeviceName='host.test'"
                    )
                    self.assertEqual(verifier.observed_citations(engine.execute(forged_union), forged_union), set())
                    source_engine = open_duckdb_engine(serving, limits)
                    source_verifier = EvidenceVerifier(serving, source_engine, frozenset({"host.test"}))
                    try:
                        self.assertEqual(serving_parity(task, source_verifier, verifier).status, "pass")
                    finally:
                        source_verifier.close()
                        source_engine.connection.close()
                    review = reviewed_fixture(task)
                    citations = ({"table": "DeviceProcessEvents", "record_id": task.evidence[0].public_record_id},)
                    discovery = Submission(answer=task.private_gold.checkpoints[0].claim.expected, citations=citations).model_dump_json()
                    env = SecRLV1Env(task, verifier, review, run_id="mysql-secrl",
                                     trajectory_ref="fixture:mysql-secrl", max_steps=10, log_path=root / "secrl-episode.json")
                    env.step("SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'")
                    env.record_finding(discovery)
                    expected = env.finish_for_scorer("")
                    self.assertEqual(expected.aggregate_reward, 0.5)
                    self.assertEqual(expected.backend_adapter_version, "secrl-env-v1")
                    if find_spec("saber") and find_spec("inspect_ai"):
                        from saber.config.models import TaskConfig
                        from saber.scoring.context import ScoringContext
                        from saber.scoring.registry import ScoringStrategyRegistry
                        from saber.scoring.aggregation import aggregate_scorer_results

                        ace = SecRLV1Env(task, verifier, review, run_id="mysql-ace", trajectory_ref="fixture:mysql-ace",
                                         max_steps=10, backend="acesevals", log_path=root / "ace-episode.json")
                        tools = make_aces_tools(ace)
                        asyncio.run(tools[0](query="SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'"))
                        asyncio.run(tools[1](finding=discovery))
                        config = TaskConfig.model_validate(export_aces_task(task, instruction_template="fixture.j2", max_steps=10)["tasks"][0])
                        registry = ScoringStrategyRegistry()
                        register_aces_strategy(registry, {"mysql-ace": ace})
                        scores = {}
                        for scorer in config.scorers:
                            ctx = ScoringContext(submission="", tool_steps=(), messages=(), target="", task_id=config.task_id,
                                                 domain="excytin", metadata={"secrl_run_id": "mysql-ace"}, scorer=scorer)
                            scores[scorer.scorer_name] = asyncio.run(registry.get(scorer.strategy).score(ctx, None)).value
                        aggregate, _ = aggregate_scorer_results(scorer_configs=config.scorers, raw_scores=scores,
                                                                agg_config=config.scoring_aggregation)
                        self.assertEqual(aggregate, expected.aggregate_reward)
                        self.assertEqual(ace.evaluation.checkpoints, expected.checkpoints)
                        self.assertEqual(ace.evaluation.backend_adapter_version, "aces-native-v1")
                        self.assertEqual(json.loads((root / "ace-episode.json").read_text())["current_episode"]["evaluation"]["aggregate_reward"], 0.5)
                        candidate = root / "candidate"
                        candidate.mkdir()
                        (candidate / "refuter").mkdir()
                        task_data = task.model_dump(mode="json")
                        task_data["dataset_release"] = "v1-private-pilot"
                        pilot_task = TaskRecord.model_validate_json(json.dumps(task_data))
                        (candidate / "task.json").write_text(pilot_task.model_dump_json())
                        from secgym.qagen.agentic.contracts import fingerprint
                        (candidate / "pilot_report.json").write_text(json.dumps({
                            "status": "candidate_for_mysql_validation", "task_fingerprint": fingerprint(pilot_task),
                            "blind_answer_correct": True, "blind_evidence_grounded": True,
                        }))
                        (candidate / "refuter/result.json").write_text(json.dumps({
                            "recommendation": "pass", "scope_supported": True, "evidence_independent": True,
                            "causal_claims_supported": True, "wording_leakage_free": True,
                            "literal_justifications_supported": True, "answer_unambiguous": True,
                            "checkpoints_distinct_and_supported": True, "reasons": ["Controlled synthetic review fixture."],
                            "counterevidence": [],
                        }))
                        def claim_draft(claim):
                            values = claim.model_dump(mode="json")
                            values.pop("evidence_sets")
                            return {**values, "explanation": "Synthetic source witness."}
                        (candidate / "draft.json").write_text(json.dumps({
                            "context": pilot_task.context, "question": pilot_task.question, "task_family": pilot_task.task_family,
                            "answer_window": pilot_task.scope.answer_window.model_dump(mode="json"), "anchors": citations,
                            "relevance_rationale": "Synthetic tenant task.", "final": claim_draft(pilot_task.private_gold.final),
                            "checkpoints": [{"checkpoint_id": cp.checkpoint_id, "objective": cp.objective, "claim": claim_draft(cp.claim)}
                                            for cp in pilot_task.private_gold.checkpoints],
                            "allowed_literals": [{"value": "host.test", "basis": "public_anchor", "rationale": "Public host."}],
                            "required_tables": ["DeviceProcessEvents"], "coverage_limits": [], "counterevidence": [],
                            "solution": ["Synthetic source."],
                        }))
                        from test_agentic_generation import FakeClient, call
                        fake = FakeClient([
                            call("sql", {"query": "SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'"}),
                            call("record_finding", {"answer": pilot_task.private_gold.checkpoints[0].claim.expected.model_dump(mode="json"),
                                                     "citations": citations}),
                            call("finish", {"answer": pilot_task.private_gold.final.expected.model_dump(mode="json"),
                                            "citations": citations, "confidence": "supported", "explanation": "Fixture observation."}),
                        ])
                        source_engine = open_duckdb_engine(serving, limits)
                        source_verifier = EvidenceVerifier(serving, source_engine, frozenset({"host.test"}))
                        try:
                            finished = evaluate_candidate(candidate, root / "pilot-evaluation", source_verifier, verifier, fake)
                            self.assertEqual(finished["status"], "private_pilot_completed")
                            self.assertEqual(finished["aces_aggregate_reward"], 1.0)
                            self.assertTrue(finished["explicit_checkpoint_findings_in_blind_trace"])
                            self.assertEqual(finished["checkpoint_progress"], 1.0)
                            self.assertFalse(finished["release_approved"])
                            fake_under_citation = FakeClient([
                                call("sql", {"query": "SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'"}),
                                call("finish", {"answer": pilot_task.private_gold.final.expected.model_dump(mode="json"),
                                                "citations": [], "confidence": "supported", "explanation": "Correct fact; forgot citations."}),
                            ])
                            measured = evaluate_candidate(candidate, root / "pilot-under-citation", source_verifier, verifier, fake_under_citation)
                            self.assertEqual(measured["status"], "private_pilot_completed")
                            self.assertTrue(measured["candidate_checks_passed"])
                            self.assertTrue(measured["complete_witness_observed"])
                            self.assertEqual(measured["secrl_reward"], 0.0)
                            self.assertFalse(measured["student_grounded_success"])
                            replayed = evaluate_candidate(candidate, root / "pilot-replayed", source_verifier, verifier, None,
                                                           blind_from=root / "pilot-under-citation/mysql-blind")
                            self.assertEqual(replayed["secrl_reward"], 0.0)
                            wrong_answer = pilot_task.private_gold.final.expected.model_dump(mode="json")
                            wrong_answer["value"] = "incorrect.exe"
                            for saw_evidence in (False, True):
                                responses = []
                                if saw_evidence:
                                    responses.extend([
                                        call("sql", {"query": "SELECT * FROM DeviceProcessEvents WHERE DeviceName='host.test'"}),
                                        call("record_finding", {
                                            "answer": pilot_task.private_gold.checkpoints[0].claim.expected.model_dump(mode="json"),
                                            "citations": citations,
                                        }),
                                    ])
                                responses.append(call("finish", {
                                    "answer": wrong_answer, "citations": [], "confidence": "uncertain",
                                    "explanation": "Measured incorrect student answer, not a reason to rewrite the task.",
                                }))
                                failure = evaluate_candidate(candidate, root / f"pilot-wrong-{saw_evidence}",
                                                             source_verifier, verifier, FakeClient(responses))
                                self.assertEqual(failure["status"], "private_pilot_completed")
                                self.assertFalse(failure["mysql_blind_answer_correct"])
                                self.assertEqual(failure["complete_witness_observed"], saw_evidence)
                                self.assertEqual(failure["secrl_reward"], 0.5 if saw_evidence else 0.0)
                                self.assertEqual(failure["aces_aggregate_reward"], failure["secrl_reward"])
                        finally:
                            source_verifier.close()
                            source_engine.connection.close()
                finally:
                    verifier.close()
                cursor = admin.cursor()
                cursor.execute("SET SESSION lock_wait_timeout=2")
                cursor.execute("ALTER TABLE DeviceProcessEvents ADD COLUMN UnexpectedPrivateColumn LONGTEXT")
                cursor.close()
                with self.assertRaisesRegex(ValueError, "column/type/collation"):
                    open_mysql_engine(serving, database="secrl_v1_fixture", limits=limits,
                                      unix_socket=str(socket), user="fixture_reader", password=password)
                engine.connection.close()
                with self.assertRaises(QueryFailure):
                    engine.execute("SELECT COUNT(*) FROM DeviceProcessEvents")
                self.assertFalse(report["release_approved"])
            finally:
                if engine is not None:
                    engine.connection.close()
                if admin is not None:
                    admin.close()
                server.terminate()
                try:
                    server.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=30)


if __name__ == "__main__":
    unittest.main()

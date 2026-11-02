# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
from threading import Barrier, Event, Thread
import time
import unittest

import mysql.connector

from agentic_runtime_fixture import runtime_fixture, runtime_task
from secgym.qagen.agentic.evidence import EvidenceVerifier
from secgym.qagen.agentic.ledger import file_sha256
from secgym.qagen.agentic.model_panel import immutable_json
from secgym.qagen.agentic.mysql_serving import install_mysql_indexes, load_mysql_view, open_duckdb_engine
from secgym.qagen.agentic.preproduction import ModelBinding, PreproductionPlan, runtime_hashes
from secgym.qagen.agentic.query import QueryFailure, QueryLimits
from secgym.qagen.agentic.snapshot_service import SnapshotServicePool, serve_snapshot, service_binding


@unittest.skipUnless(os.environ.get("SECRL_MYSQLD"), "set SECRL_MYSQLD for real shared-snapshot service tests")
class SnapshotServiceTests(unittest.TestCase):
    def test_persistent_readonly_sessions_concurrency_isolation_identity_and_graceful_drain(self):
        with tempfile.TemporaryDirectory(prefix="secrl-shared-test-", dir="/tmp") as temporary:
            root = Path(temporary)
            graph, _, serving, report = runtime_fixture(root / "source")
            task = runtime_task(serving, report)
            mysql_bundle = root / "mysql"
            mysql_bundle.mkdir()
            binary = Path(os.environ["SECRL_MYSQLD"])
            data, setup_socket = mysql_bundle / "data", root / "setup.sock"
            initialized = subprocess.run(
                [str(binary), "--no-defaults", "--initialize-insecure", "--innodb-page-size=32768",
                 f"--datadir={data}", f"--log-error={root / 'initialize.log'}"],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            setup = subprocess.Popen(
                [str(binary), "--no-defaults", f"--datadir={data}", f"--socket={setup_socket}", "--skip-networking",
                 "--mysqlx=OFF", "--innodb-page-size=32768", f"--pid-file={root / 'setup.pid'}",
                 f"--log-error={root / 'setup.log'}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            admin = None
            try:
                for _ in range(160):
                    if setup.poll() is not None:
                        self.fail((root / "setup.log").read_text())
                    try:
                        admin = mysql.connector.connect(unix_socket=str(setup_socket), user="root", password="")
                        break
                    except mysql.connector.Error:
                        time.sleep(0.1)
                self.assertIsNotNone(admin)
                loaded = load_mysql_view(serving, admin, "secrl_v1_shared")
                indexes = install_mysql_indexes(serving, admin, "secrl_v1_shared")
                password = secrets.token_urlsafe(24)
                cursor = admin.cursor()
                try:
                    cursor.execute("CREATE USER 'shared_reader'@'localhost' IDENTIFIED BY %s", (password,))
                    cursor.execute("GRANT SELECT ON secrl_v1_shared.* TO 'shared_reader'@'localhost'")
                finally:
                    cursor.close()
                immutable_json(mysql_bundle / "reader.json", {
                    "user": "shared_reader", "password": password, "database": "secrl_v1_shared",
                })
                immutable_json(mysql_bundle / "index_report.json", indexes)
                immutable_json(mysql_bundle / "mysql_report.json", {
                    "status": "complete", "serving_view_id": task.serving_view_id, "verified_rows": loaded["verified_rows"],
                    "reader_credentials_file": "reader.json", "data_directory": str(data),
                    "mysqld_binary": str(binary), "innodb_page_size": 32768,
                })
            finally:
                if admin is not None:
                    admin.close()
                setup.terminate()
                setup.wait(timeout=30)
            index_digest = hashlib.sha256(json.dumps({
                "index_report.json": file_sha256(mysql_bundle / "index_report.json"),
            }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            plan = PreproductionPlan(
                batch_id="shared-fixture", serving_view_id=task.serving_view_id, graph_id=task.graph_version,
                serving_report_sha256=file_sha256(serving / "serving_report.json"),
                graph_report_sha256=file_sha256(graph / "graph_report.json"),
                native_snapshot_sha256=file_sha256(mysql_bundle / "mysql_report.json"), native_indexes_sha256=index_digest,
                model=ModelBinding(deployment="gpt-6-sol", endpoint_sha256="a" * 64, api_version="fixture",
                                   request_timeout_seconds=300, max_completion_tokens=16000, reasoning_effort="medium"),
                query_limits=QueryLimits(max_rows=100, max_bytes=65536, timeout_ms=1000),
                grader_timeout_ms=5000, checkpoint_cap=0.5, seed_questions=(task,), implementation_sha256=runtime_hashes(),
            )
            binding = service_binding(plan, serving, mysql_bundle, slots=2)
            directory = root / "service"
            stop, errors = Event(), []

            def serve():
                try:
                    serve_snapshot(binding=binding, directory=directory, workdir=root, stop=stop)
                except (ValueError, RuntimeError, OSError, mysql.connector.Error) as error:
                    errors.append(error)

            thread = Thread(target=serve)
            thread.start()
            engine = verifier = None
            try:
                for _ in range(240):
                    if errors:
                        raise errors[0]
                    if (directory / "current.json").exists():
                        break
                    time.sleep(0.1)
                self.assertTrue((directory / "current.json").exists())
                pool = SnapshotServicePool(directory, plan)
                status = pool.status()
                self.assertEqual(status["status"], "ready")
                server_pid = status["server_pid"]
                engine = open_duckdb_engine(serving, plan.query_limits.model_copy(update={"timeout_ms": 5000}))
                verifier = EvidenceVerifier(serving, engine, frozenset({"host.test"}))
                expected_proofs = verifier.preflight(task)
                barrier = Barrier(2)

                def candidate(index):
                    with pool.lease(verifier, root / f"native-{index}") as (native, student):
                        barrier.wait(timeout=10)
                        self.assertEqual(native.engine.limits.timeout_ms, 5000)
                        self.assertEqual(student.limits.timeout_ms, 1000)
                        cursor = native.engine.connection.cursor()
                        try:
                            cursor.execute("SET @candidate_only=%s", (index,))
                            cursor.execute("SELECT CONNECTION_ID()")
                            native_id, = cursor.fetchone()
                            with self.assertRaises(mysql.connector.Error):
                                cursor.execute("DELETE FROM DeviceProcessEvents")
                        finally:
                            cursor.close()
                        cursor = student.connection.cursor()
                        try:
                            cursor.execute("SELECT @candidate_only,CONNECTION_ID()")
                            state, student_id = cursor.fetchone()
                        finally:
                            cursor.close()
                        self.assertIsNone(state)
                        self.assertNotEqual(native_id, student_id)
                        with self.assertRaises(QueryFailure):
                            student.execute("DELETE FROM DeviceProcessEvents")
                        self.assertEqual(student.execute("SELECT COUNT(*) FROM DeviceProcessEvents").rows, ((2,),))
                        self.assertEqual(native.preflight(task), expected_proofs)
                        return native_id, student_id

                with ThreadPoolExecutor(max_workers=2) as workers:
                    pairs = list(workers.map(candidate, (1, 2)))
                self.assertEqual(len({value for pair in pairs for value in pair}), 4)
                self.assertEqual(pool.status()["server_pid"], server_pid)
                self.assertTrue(verifier.preflight(task))
                _, ready = pool.ready_instance()
                with self.assertRaisesRegex(ValueError, "bound read-only snapshot instance"):
                    pool._engine(ready.model_copy(update={"instance_id": "mysql-wrong-instance"}), plan.query_limits)
                with pool.lease(verifier, root / "native-3") as (_, student):
                    cursor = student.connection.cursor()
                    try:
                        cursor.execute("SELECT @candidate_only")
                        self.assertIsNone(cursor.fetchone()[0])
                    finally:
                        cursor.close()
                self.assertEqual(pool.status()["server_pid"], server_pid)
                with self.assertRaisesRegex(ValueError, "already has an owner"):
                    serve_snapshot(binding=binding, directory=directory, workdir=root, stop=Event())
                with self.assertRaisesRegex(ValueError, "second SQL server"):
                    serve_snapshot(binding=binding, directory=root / "second-owner", workdir=root, stop=Event())
                with self.assertRaisesRegex(ValueError, "different|match"):
                    SnapshotServicePool(directory, plan.model_copy(update={"serving_view_id": "view:other"}))
                entered = Event()

                def queued():
                    with pool.lease(verifier, root / "native-queued"):
                        entered.set()

                with ExitStack() as saturated:
                    first = pool.lease(verifier, root / "native-slot-one")
                    second = pool.lease(verifier, root / "native-slot-two")
                    saturated.enter_context(first)
                    saturated.enter_context(second)
                    waiting = Thread(target=queued)
                    waiting.start()
                    time.sleep(0.15)
                    self.assertFalse(entered.is_set(), "configured native-slot bound was exceeded")
                waiting.join(timeout=10)
                self.assertTrue(entered.is_set())
                self.assertFalse(waiting.is_alive())
                with ExitStack() as active:
                    _, student = active.enter_context(pool.lease(verifier, root / "native-drain"))
                    stop.set()
                    instance, _ = directory / "instances" / status["instance_id"], status
                    for _ in range(100):
                        if (instance / "draining.json").exists():
                            break
                        time.sleep(0.05)
                    self.assertTrue(thread.is_alive(), "service stopped while a candidate still owned its lease")
                    self.assertEqual(student.execute("SELECT COUNT(*) FROM DeviceProcessEvents").rows, ((2,),))
                    with self.assertRaisesRegex(RuntimeError, "draining"):
                        pool.status()
                thread.join(timeout=40)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertTrue(data.exists(), "service cleanup deleted the persistent snapshot")
                with self.assertRaisesRegex(RuntimeError, "not running"):
                    pool.status()
            finally:
                stop.set()
                thread.join(timeout=45)
                if verifier is not None:
                    verifier.close()
                if engine is not None:
                    engine.connection.close()
                self.assertFalse(thread.is_alive(), "owned test service failed to terminate")


if __name__ == "__main__":
    unittest.main()

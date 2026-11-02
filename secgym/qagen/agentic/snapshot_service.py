# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""One managed read-only MySQL process per verified snapshot, with isolated candidate sessions."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
from threading import Event
import time
from typing import Literal
from uuid import uuid4

import mysql.connector
from pydantic import Field

from .contracts import Contract, Digest, Identifier, Text, fingerprint
from .evidence import EvidenceVerifier
from .ledger import file_sha256
from .model_panel import immutable_json
from .mysql_serving import check_mysql_schema, load_serving_report, mysql_identifier
from .preproduction import PreproductionPlan
from .query import PublicQueryEngine, QueryLimits


class SnapshotServiceBinding(Contract):
    policy_version: Literal["readonly-snapshot-service-v1"] = "readonly-snapshot-service-v1"
    serving_view_id: Identifier
    serving_bundle: Text
    mysql_bundle: Text
    serving_report_sha256: Digest
    mysql_report_sha256: Digest
    native_indexes_sha256: Digest
    native_candidate_slots: int = Field(default=4, ge=1, le=8)
    implementation_sha256: Digest
    shared_database_writable: Literal[False] = False


class SnapshotServiceInstance(Contract):
    instance_id: Identifier
    binding_fingerprint: Digest
    owner_pid: int = Field(gt=0)
    server_pid: int = Field(gt=0)
    socket: Text
    server_uuid: Text
    server_version: Text
    started_at: Text


def _indexes(bundle: Path) -> str:
    values = {path.name: file_sha256(path) for path in sorted(bundle.glob("index_report*.json"))}
    if not values:
        raise ValueError("the shared snapshot must have verified native indexes")
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def service_binding(plan: PreproductionPlan, serving: Path, mysql: Path, slots: int = 4) -> SnapshotServiceBinding:
    if plan.native_snapshot_sha256 is None or plan.native_indexes_sha256 is None:
        raise ValueError("the shared service requires a bound native snapshot and index manifest")
    if (file_sha256(serving / "serving_report.json"), file_sha256(mysql / "mysql_report.json"), _indexes(mysql)) != (
        plan.serving_report_sha256, plan.native_snapshot_sha256, plan.native_indexes_sha256,
    ):
        raise ValueError("shared service snapshot/index manifests differ from the approved run")
    return SnapshotServiceBinding(
        serving_view_id=plan.serving_view_id, serving_bundle=str(serving.resolve()), mysql_bundle=str(mysql.resolve()),
        serving_report_sha256=plan.serving_report_sha256, mysql_report_sha256=plan.native_snapshot_sha256,
        native_indexes_sha256=plan.native_indexes_sha256, native_candidate_slots=slots,
        implementation_sha256=file_sha256(Path(__file__)),
    )


def _write_pointer(directory: Path, instance_id: str) -> None:
    temporary = directory / (".current-" + uuid4().hex)
    try:
        with temporary.open("x") as stream:
            json.dump({"instance_id": instance_id}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / "current.json")
    finally:
        temporary.unlink(missing_ok=True)


def _instance_directory(directory: Path, instance_id: str) -> Path:
    path = (directory / "instances" / instance_id).resolve()
    if path.parent != (directory / "instances").resolve():
        raise ValueError("service instance escapes its owned directory")
    return path


def _reader_credentials(binding: SnapshotServiceBinding) -> dict:
    bundle = Path(binding.mysql_bundle)
    metadata = json.loads((bundle / "mysql_report.json").read_bytes())
    path = (bundle / metadata["reader_credentials_file"]).resolve()
    if not path.is_relative_to(bundle.resolve()):
        raise ValueError("snapshot reader credentials escape the native bundle")
    return json.loads(path.read_bytes())


def _identity(connection, *, nonce: str, data_directory: Path, page_size: int) -> tuple[str, str, int]:
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT @@server_uuid,@@version,@@datadir,@@innodb_page_size,"
                       "@@global.read_only,@@global.super_read_only,@secrl_snapshot_instance,CONNECTION_ID()")
        server_uuid, version, data, page, readonly, super_readonly, actual_nonce, connection_id = cursor.fetchone()
        if Path(data).resolve() != data_directory.resolve() or page != page_size or (
            not readonly or not super_readonly or actual_nonce != nonce
        ):
            raise ValueError("connected SQL service is not the bound read-only snapshot instance")
        return str(server_uuid), str(version), int(connection_id)
    finally:
        cursor.close()


def _configure_reader(connection, database: str, report: dict, *, validate_schema: bool) -> None:
    connection.autocommit = True
    cursor = connection.cursor()
    try:
        cursor.execute("SHOW GRANTS FOR CURRENT_USER")
        grants = [row[0] for row in cursor.fetchall()]
        permitted = re.compile(r"^GRANT (USAGE ON \*\.\*|SELECT ON " + re.escape(mysql_identifier(database)) + r"\.\*) TO ")
        if not grants or any(not permitted.match(grant) or "WITH GRANT OPTION" in grant for grant in grants):
            raise ValueError("shared sessions require a dedicated database-scoped SELECT-only account")
        if validate_schema:
            check_mysql_schema(cursor, report)
        cursor.execute("SET SESSION time_zone='+00:00'")
        cursor.execute("SET SESSION TRANSACTION READ ONLY")
    finally:
        cursor.close()


def _slots_idle(instance: Path, count: int) -> bool:
    held = []
    try:
        for index in range(count):
            stream = (instance / "leases" / f"{index:02d}.lock").open("a+")
            held.append(stream)
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
        return True
    finally:
        for stream in held:
            stream.close()


def serve_snapshot(*, binding: SnapshotServiceBinding, directory: Path, workdir: Path,
                   stop: Event | None = None, wait_for_workflow: Path | None = None) -> None:
    binding = SnapshotServiceBinding.model_validate_json(binding.model_dump_json())
    if binding.implementation_sha256 != file_sha256(Path(__file__)):
        raise ValueError("shared service binding does not identify this implementation")
    directory = directory.resolve()
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    stop = stop or Event()
    with (directory / "owner.lock").open("a+") as owner:
        try:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("this snapshot service already has an owner") from error
        immutable_json(directory / "binding.json", binding)
        transition = None
        try:
            if wait_for_workflow is not None:
                transition = (wait_for_workflow / "checkpoint-workflow.lock").open("a+")
                while True:
                    try:
                        fcntl.flock(transition, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if stop.wait(0.25):
                            raise RuntimeError("shared service stopped before the existing workflow drained")
            bundle = Path(binding.mysql_bundle)
            if (file_sha256(Path(binding.serving_bundle) / "serving_report.json"),
                file_sha256(bundle / "mysql_report.json"), _indexes(bundle)) != (
                binding.serving_report_sha256, binding.mysql_report_sha256, binding.native_indexes_sha256,
            ):
                raise ValueError("shared service startup manifests changed")
            metadata = json.loads((bundle / "mysql_report.json").read_bytes())
            serving = load_serving_report(Path(binding.serving_bundle))
            if (metadata["status"], metadata["serving_view_id"], metadata["verified_rows"]) != (
                "complete", binding.serving_view_id, sum(table["rows"] for table in serving["tables"] if table["status"] == "public"),
            ):
                raise ValueError("shared service requires the complete verified public snapshot")
            credentials = _reader_credentials(binding)
            with (bundle / "pipeline-mysql.lock").open("a+") as database_owner:
                try:
                    fcntl.flock(database_owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise ValueError("the native datadir is already owned; a second SQL server must not start") from error
                instance_id = "mysql-" + uuid4().hex
                instance = _instance_directory(directory, instance_id)
                (instance / "leases").mkdir(parents=True, mode=0o700)
                for index in range(binding.native_candidate_slots):
                    (instance / "leases" / f"{index:02d}.lock").touch(mode=0o600)
                with tempfile.TemporaryDirectory(prefix=".secrl-shared-mysql-", dir=workdir.resolve()) as temporary:
                    socket = Path(temporary) / "mysql.sock"
                    if len(str(socket).encode()) > 100:
                        raise ValueError("shared MySQL socket path is too long")
                    server = subprocess.Popen([
                        metadata["mysqld_binary"], "--no-defaults", f"--datadir={metadata['data_directory']}",
                        f"--socket={socket}", "--skip-networking", "--mysqlx=OFF",
                        f"--innodb-page-size={metadata['innodb_page_size']}", "--innodb-buffer-pool-size=512M",
                        "--read-only=ON", "--super-read-only=ON",
                        f"--init-connect=SET @secrl_snapshot_instance='{instance_id}'",
                        f"--pid-file={instance / 'mysql.pid'}", f"--log-error={instance / 'mysql.log'}",
                    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       pass_fds=(database_owner.fileno(),))
                    try:
                        connection = None
                        last_error = None
                        for _ in range(240):
                            if server.poll() is not None:
                                raise RuntimeError("shared MySQL exited before readiness; inspect its owned server log")
                            try:
                                connection = mysql.connector.connect(unix_socket=str(socket), connection_timeout=5, **credentials)
                                break
                            except mysql.connector.Error as error:
                                last_error = str(error)
                                if stop.wait(0.25):
                                    raise RuntimeError("shared service startup was cancelled")
                        if connection is None:
                            raise RuntimeError("shared MySQL readiness timeout: " + str(last_error))
                        try:
                            _configure_reader(connection, credentials["database"], serving, validate_schema=True)
                            server_uuid, version, _ = _identity(
                                connection, nonce=instance_id, data_directory=Path(metadata["data_directory"]),
                                page_size=metadata["innodb_page_size"],
                            )
                        finally:
                            connection.close()
                        ready = SnapshotServiceInstance(
                            instance_id=instance_id, binding_fingerprint=fingerprint(binding),
                            owner_pid=os.getpid(), server_pid=server.pid, socket=str(socket),
                            server_uuid=server_uuid, server_version=version, started_at=datetime.now(timezone.utc).isoformat(),
                        )
                        immutable_json(instance / "ready.json", ready)
                        immutable_json(instance / "producer.json", {
                            "sha256": binding.implementation_sha256, "source": Path(__file__).read_text(),
                        })
                        _write_pointer(directory, instance_id)
                        if transition is not None:
                            transition.close()
                            transition = None
                        print(json.dumps({"status": "ready", "instance_id": instance_id,
                                          "native_candidate_slots": binding.native_candidate_slots}), flush=True)
                        while True:
                            if server.poll() is not None:
                                raise RuntimeError("the owned shared MySQL process exited unexpectedly")
                            if stop.is_set() or (instance / "stop-request.json").exists():
                                immutable_json(instance / "draining.json", {"instance_id": instance_id, "new_leases_allowed": False})
                                if _slots_idle(instance, binding.native_candidate_slots):
                                    break
                            time.sleep(0.25)
                    except (ValueError, RuntimeError, OSError, mysql.connector.Error) as error:
                        immutable_json(instance / "failure.json", {"type": type(error).__name__, "detail": str(error)})
                        raise
                    finally:
                        server.terminate()
                        try:
                            server.wait(timeout=30)
                        except subprocess.TimeoutExpired:
                            server.kill()
                            server.wait(timeout=30)
                        immutable_json(instance / "stopped.json", {"instance_id": instance_id, "server_returncode": server.returncode})
        finally:
            if transition is not None:
                transition.close()


class SessionEvidenceVerifier(EvidenceVerifier):
    """Reuse the already verified source snapshot with an independent private metadata connection."""

    def __init__(self, source: EvidenceVerifier, engine: PublicQueryEngine):
        if engine.engine != "mysql" or engine.serving_view_id != source.report["serving_view_id"]:
            raise ValueError("shared native verifier must use the source's exact snapshot")
        self.report, self.tables = source.report, source.tables
        self.engine, self.allowed_literals = engine, source.allowed_literals
        self.private = source.private.cursor()


class SnapshotServicePool:
    def __init__(self, directory: Path, plan: PreproductionPlan):
        self.directory = directory.resolve()
        self.binding = SnapshotServiceBinding.model_validate_json((self.directory / "binding.json").read_bytes())
        if (self.binding.serving_view_id, self.binding.serving_report_sha256,
            self.binding.mysql_report_sha256, self.binding.native_indexes_sha256) != (
            plan.serving_view_id, plan.serving_report_sha256, plan.native_snapshot_sha256, plan.native_indexes_sha256,
        ) or self.binding.implementation_sha256 != file_sha256(Path(__file__)):
            raise ValueError("shared service does not match the candidate snapshot or implementation")
        self.plan = plan
        self.report = json.loads((Path(self.binding.serving_bundle) / "serving_report.json").read_bytes())
        self.metadata = json.loads((Path(self.binding.mysql_bundle) / "mysql_report.json").read_bytes())
        self.credentials = _reader_credentials(self.binding)

    def ready_instance(self) -> tuple[Path, SnapshotServiceInstance]:
        if self.binding.implementation_sha256 != file_sha256(Path(__file__)):
            raise ValueError("the shared service implementation changed; use an explicitly versioned service deployment")
        owner_path = self.directory / "owner.lock"
        if not owner_path.exists():
            raise RuntimeError("shared snapshot service has no owner")
        with owner_path.open("r") as owner:
            try:
                fcntl.flock(owner, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise RuntimeError("shared snapshot service is not running")
        current = json.loads((self.directory / "current.json").read_bytes())
        instance = _instance_directory(self.directory, current["instance_id"])
        if any((instance / name).exists() for name in ("draining.json", "stopped.json", "failure.json", "stop-request.json")):
            raise RuntimeError("shared snapshot service is draining, stopped or failed")
        ready = SnapshotServiceInstance.model_validate_json((instance / "ready.json").read_bytes())
        if ready.instance_id != current["instance_id"] or ready.binding_fingerprint != fingerprint(self.binding):
            raise ValueError("shared service instance binding changed")
        if (file_sha256(Path(self.binding.serving_bundle) / "serving_report.json"),
            file_sha256(Path(self.binding.mysql_bundle) / "mysql_report.json"), _indexes(Path(self.binding.mysql_bundle))) != (
            self.binding.serving_report_sha256, self.binding.mysql_report_sha256, self.binding.native_indexes_sha256,
        ):
            raise ValueError("shared service snapshot/index manifests changed")
        return instance, ready

    def _engine(self, ready: SnapshotServiceInstance, limits: QueryLimits) -> tuple[PublicQueryEngine, int]:
        connection = mysql.connector.connect(unix_socket=ready.socket, connection_timeout=5, **self.credentials)
        try:
            _configure_reader(connection, self.credentials["database"], self.report, validate_schema=False)
            uuid, version, connection_id = _identity(
                connection, nonce=ready.instance_id, data_directory=Path(self.metadata["data_directory"]),
                page_size=self.metadata["innodb_page_size"],
            )
            if (uuid, version) != (ready.server_uuid, ready.server_version):
                raise ValueError("the SQL server restarted or changed behind its service descriptor")
            tables = {table["table"] for table in self.report["tables"] if table["status"] == "public"}
            return PublicQueryEngine(connection, "mysql", tables, limits, self.binding.serving_view_id), connection_id
        except (ValueError, mysql.connector.Error):
            connection.close()
            raise

    def status(self) -> dict:
        _, ready = self.ready_instance()
        engine, _ = self._engine(ready, self.plan.query_limits)
        try:
            engine.execute("SELECT 1")
        finally:
            engine.connection.close()
        return {"status": "ready", "instance_id": ready.instance_id, "server_pid": ready.server_pid,
                "native_candidate_slots": self.binding.native_candidate_slots, "snapshot_read_only": True}

    @contextmanager
    def lease(self, source: EvidenceVerifier, output: Path):
        if source.report["serving_view_id"] != self.binding.serving_view_id:
            raise ValueError("native lease requested for a different source snapshot")
        instance, ready = self.ready_instance()
        slot = None
        while slot is None:
            for index in range(self.binding.native_candidate_slots):
                stream = (instance / "leases" / f"{index:02d}.lock").open("a+")
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    stream.close()
                    continue
                slot = stream
                break
            if slot is None:
                if self.ready_instance()[1] != ready:
                    raise RuntimeError("shared SQL instance changed while a candidate waited")
                time.sleep(0.05)
        grader = student = verifier = None
        try:
            if self.ready_instance()[1] != ready:
                raise RuntimeError("shared SQL instance changed before the candidate lease")
            limits = self.plan.query_limits.model_copy(update={"timeout_ms": self.plan.grader_timeout_ms or self.plan.query_limits.timeout_ms})
            grader, grader_id = self._engine(ready, limits)
            student, student_id = self._engine(ready, self.plan.query_limits)
            if grader_id == student_id:
                raise ValueError("student and grader must have independent SQL sessions")
            verifier = SessionEvidenceVerifier(source, grader)
            output.mkdir(parents=True, mode=0o700, exist_ok=True)
            immutable_json(output / "shared-service.json", {
                "service_binding": self.binding.model_dump(mode="json"), "instance": ready.model_dump(mode="json"),
                "lease_slot": index, "grader_connection_id": grader_id, "student_connection_id": student_id,
                "grader_query_limits": limits.model_dump(mode="json"),
                "student_query_limits": self.plan.query_limits.model_dump(mode="json"),
                "source_verifier_snapshot_reused": True, "mutations_allowed": False,
            })
            yield verifier, student
        finally:
            if verifier is not None:
                verifier.close()
            for engine in (grader, student):
                if engine is not None:
                    engine.connection.close()
            slot.close()


def main():
    from .preproduction_revisions import effective_native_plan

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("serve", "status", "stop"))
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--service-directory", type=Path, required=True)
    parser.add_argument("--serving-bundle", type=Path)
    parser.add_argument("--mysql-bundle", type=Path)
    parser.add_argument("--workdir", type=Path, default=Path("/tmp"))
    parser.add_argument("--native-slots", type=int, default=4)
    parser.add_argument("--wait-for-workflow", action="store_true")
    args = parser.parse_args()
    plan = PreproductionPlan.model_validate_json((args.run / "plan.json").read_bytes())
    plan = effective_native_plan(plan, args.run)
    if args.command == "serve":
        if args.serving_bundle is None or args.mysql_bundle is None:
            raise ValueError("serve requires the explicit serving and native bundles")
        stop = Event()
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, lambda _signal, _frame: stop.set())
        serve_snapshot(
            binding=service_binding(plan, args.serving_bundle, args.mysql_bundle, args.native_slots),
            directory=args.service_directory, workdir=args.workdir, stop=stop,
            wait_for_workflow=args.run if args.wait_for_workflow else None,
        )
    else:
        pool = SnapshotServicePool(args.service_directory, plan)
        if args.command == "status":
            print(json.dumps(pool.status()))
        else:
            instance, ready = pool.ready_instance()
            immutable_json(instance / "stop-request.json", {"instance_id": ready.instance_id, "drain_active_candidates": True})
            print(json.dumps({"status": "draining_requested", "instance_id": ready.instance_id}))


if __name__ == "__main__":
    main()

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Load a public-only view into a new MySQL database and verify its exact rows."""

import json
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from functools import lru_cache

import duckdb
import mysql.connector

from .ledger import file_sha256
from .query import PublicQueryEngine, QueryLimits, scalar_value
from .serving import row_digest
from .sources import quote_identifier


MYSQL_TYPES = {
    "VARCHAR": "LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin",
    "BIGINT": "BIGINT", "INTEGER": "INTEGER", "DOUBLE": "DOUBLE", "BOOLEAN": "BOOLEAN",
    "TIMESTAMP WITH TIME ZONE": "DATETIME(6)",
}
MYSQL_SCHEMA_TYPES = {
    "VARCHAR": "longtext", "BIGINT": "bigint", "INTEGER": "int", "DOUBLE": "double",
    "BOOLEAN": "tinyint(1)", "TIMESTAMP WITH TIME ZONE": "datetime(6)",
}
PUBLIC_ACCESS_INDEXES = {
    "SecurityIncident": (("IncidentNumber", None),),
    "SecurityAlert": (("AlertName", 191), ("StartTime", None)),
    "DeviceProcessEvents": (("FileName", 128), ("DeviceName", 191), ("Timestamp", None)),
    "DeviceFileEvents": (("DeviceId", 128), ("ActionType", 64), ("InitiatingProcessId", None), ("Timestamp", None)),
    "DeviceEvents": (("DeviceId", 128), ("ActionType", 128), ("Timestamp", None)),
    "AuditLogs": (("ActivityDisplayName", 191), ("Result", 64), ("ActivityDateTime", None)),
    "MicrosoftGraphActivityLogs": (("AppId", 128), ("RequestMethod", 16), ("TimeGenerated", None)),
    "CloudAppEvents": (("ActionType", 191), ("Timestamp", None)),
}
PROCESS_LOOKUP_INDEXES = {
    "secrl_process_identity_v1": (("DeviceId", 128), ("ProcessId", None), ("ProcessCreationTime", None)),
    "secrl_process_parent_v1": (("DeviceId", 128), ("InitiatingProcessId", None), ("InitiatingProcessCreationTime", None)),
    "secrl_process_time_v1": (("Timestamp", None),),
}
TELEMETRY_LOOKUP_INDEXES = (
    *((table, "secrl_initiator_v1", (
        ("DeviceId", 128), ("InitiatingProcessId", None), ("InitiatingProcessCreationTime", None), ("Timestamp", None),
    )) for table in ("DeviceNetworkEvents", "DeviceFileEvents", "DeviceRegistryEvents", "DeviceEvents")),
    *((table, "secrl_host_time_v1", (("DeviceName", 191), ("Timestamp", None)))
      for table in ("DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceRegistryEvents", "DeviceEvents")),
    *((table, "secrl_action_time_v1", (("ActionType", 128), ("Timestamp", None)))
      for table in ("DeviceNetworkEvents", "DeviceFileEvents", "DeviceRegistryEvents", "DeviceEvents")),
    *((table, "secrl_host_action_time_v1", (("DeviceName", 191), ("ActionType", 128), ("Timestamp", None)))
      for table in ("DeviceFileEvents", "DeviceEvents")),
    ("DeviceFileEvents", "secrl_content_time_v1", (("SHA256", 64), ("Timestamp", None))),
    ("DeviceFileEvents", "secrl_file_name_device_time_v1",
     (("FileName", 191), ("DeviceId", 128), ("Timestamp", None))),
    ("DeviceProcessEvents", "secrl_process_device_name_time_v1",
     (("DeviceId", 128), ("FileName", 128), ("Timestamp", None))),
    ("DeviceRegistryEvents", "secrl_registry_key_v1", (("DeviceId", 128), ("RegistryKey", 384), ("Timestamp", None))),
    ("DeviceRegistryEvents", "secrl_previous_registry_key_v1",
     (("DeviceId", 128), ("PreviousRegistryKey", 384), ("Timestamp", None))),
    ("DeviceRegistryEvents", "secrl_registry_value_time_v1",
     (("RegistryValueName", 191), ("ActionType", 128), ("Timestamp", None))),
    *((table, name, fields)
      for table in ("SigninLogs", "AADNonInteractiveUserSignInLogs", "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs")
      for name, fields in (
          ("secrl_signin_request_v1", (("Id", 128), ("TimeGenerated", None))),
          ("secrl_signin_user_v1", (("UserId", 128), ("TimeGenerated", None))),
          ("secrl_signin_upn_v1", (("UserPrincipalName", 191), ("TimeGenerated", None))),
          ("secrl_signin_correlation_v1", (("CorrelationId", 128), ("TimeGenerated", None))),
      )),
    ("OfficeActivity", "secrl_office_operation_v1", (("Operation", 191), ("TimeGenerated", None))),
    ("OfficeActivity", "secrl_office_mailbox_v1", (("MailboxOwnerUPN", 191), ("TimeGenerated", None))),
    ("CloudAppEvents", "secrl_cloud_time_v1", (("Timestamp", None),)),
)


def mysql_identifier(value: str) -> str:
    return "`" + value.replace("`", "``") + "`"


def mysql_column_name(value: str) -> str:
    if len(value) <= 64:
        return value
    return value[:47] + "_" + hashlib.sha256(value.encode()).hexdigest()[:16]


@lru_cache(maxsize=128)
def prepared_insert_statement(table: str, columns: int, rows: int, resume: bool) -> str:
    if columns <= 0 or rows <= 0 or columns * rows > 60000:
        raise ValueError("prepared batch parameter count is outside the supported bounds")
    group = "(" + ",".join("?" for _ in range(columns)) + ")"
    statement = f"INSERT INTO {mysql_identifier(table)} VALUES " + ",".join(group for _ in range(rows))
    return statement + (" ON DUPLICATE KEY UPDATE _record_id=_record_id" if resume else "")


def load_serving_report(bundle: Path) -> dict:
    report = json.loads((bundle / "serving_report.json").read_text())
    if report.get("status") != "complete":
        raise ValueError("serving projection is incomplete")
    for key in ("public_database", "private_mapping"):
        name = report[key]["path"]
        path = bundle / name
        if Path(name).name != name or path.is_symlink() or file_sha256(path) != report[key]["sha256"]:
            raise ValueError(f"invalid serving artifact: {key}")
    return report


def install_mysql_indexes(bundle: Path, admin_connection, database: str) -> dict:
    """Non-unique access indexes do not change the public schema or filter rows."""
    report = load_serving_report(bundle)
    cursor = admin_connection.cursor()
    applied = []
    try:
        cursor.execute(f"USE {mysql_identifier(database)}")
        check_mysql_schema(cursor, report)
        inventory = {table["table"]: table for table in report["tables"] if table["status"] == "public"}
        indexes = [(table, "secrl_access_v1", fields) for table, fields in PUBLIC_ACCESS_INDEXES.items()]
        indexes.extend(("DeviceProcessEvents", name, fields) for name, fields in PROCESS_LOOKUP_INDEXES.items())
        indexes.extend(TELEMETRY_LOOKUP_INDEXES)
        for table, name, fields in indexes:
            if table not in inventory or not {name for name, _ in fields} <= {c["name"] for c in inventory[table]["columns"]}:
                continue
            cursor.execute(f"SHOW INDEX FROM {mysql_identifier(table)} WHERE Key_name=%s", (name,))
            existing = cursor.fetchall()
            desired = [(column, prefix) for column, prefix in fields]
            if existing:
                found = [(r[4], r[7]) for r in sorted(existing, key=lambda r: r[3])]
                if found != desired or any(r[1] != 1 for r in existing):
                    raise ValueError("existing named MySQL access index differs from its declared policy")
            else:
                columns = ",".join(mysql_identifier(column) + (f"({prefix})" if prefix else "") for column, prefix in fields)
                cursor.execute(f"CREATE INDEX {mysql_identifier(name)} ON {mysql_identifier(table)} ({columns})")
                cursor.execute(f"ANALYZE TABLE {mysql_identifier(table)}")
                analysis = cursor.fetchall()
                if any(row[2] == "error" for row in analysis):
                    raise ValueError("MySQL access-index analysis failed")
            applied.append({"table": table, "index": name, "fields": desired})
            print(f"[mysql-index] {table}: verified", flush=True)
        return {"status": "complete", "policy_version": "mysql-access-indexes-v6",
                "serving_view_id": report["serving_view_id"], "indexes": applied, "source_rows_modified": False}
    finally:
        cursor.close()


def mysql_value(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    if isinstance(value, float):
        # Some prepared-parameter connectors bind Python floats as FLOAT32.
        return repr(value)
    return value


def canonical_mysql_row(row, columns):
    values = []
    for value, column in zip(row, columns):
        if value is not None and column["type"] == "BOOLEAN":
            if value not in (0, 1):
                raise ValueError("invalid MySQL boolean")
            value = bool(value)
        values.append(value)
    return tuple(values)


def check_mysql_schema(cursor, report):
    cursor.execute("SHOW FULL TABLES")
    expected = {t["table"]: t for t in report["tables"] if t["status"] == "public"}
    if set(cursor.fetchall()) != {(name, "BASE TABLE") for name in expected}:
        raise ValueError("MySQL public table inventory/type differs from the serving manifest")
    for name, table in expected.items():
        cursor.execute(f"SHOW FULL COLUMNS FROM {mysql_identifier(name)}")
        actual = cursor.fetchall()
        required = []
        for column in table["columns"]:
            field = column["name"]
            kind = "varchar(66)" if field == "_record_id" else MYSQL_SCHEMA_TYPES[column["type"]]
            collation = "ascii_bin" if field == "_record_id" else "utf8mb4_0900_bin" if column["type"] == "VARCHAR" else None
            required.append((mysql_column_name(field), kind, collation))
        if [(row[0], row[1].lower(), row[2]) for row in actual] != required:
            raise ValueError("MySQL public column/type/collation inventory differs from the serving manifest")


def load_mysql_view(bundle: Path, admin_connection, database: str, *, resume: bool = False) -> dict:
    if not re.fullmatch(r"secrl_v1_[a-z0-9_]+", database):
        raise ValueError("a new secrl_v1_ database name is required; existing/legacy databases are never replaced")
    report = load_serving_report(bundle)
    cursor = admin_connection.cursor()
    try:
        if not resume:
            cursor.execute(f"CREATE DATABASE {mysql_identifier(database)} CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin")
        cursor.execute(f"USE {mysql_identifier(database)}")
        cursor.execute("SET SESSION time_zone='+00:00'")
        if resume:
            existing = verify_mysql_view(bundle, admin_connection, database, allow_partial=True)
            print(f"[mysql-resume] {existing} existing rows independently verified before continuing", flush=True)
        for table in report["tables"]:
            if table["status"] != "public":
                continue
            if resume:
                continue
            print(f"[mysql-schema] {table['table']}: {len(table['columns'])} columns", flush=True)
            fields = []
            aliases = [mysql_column_name(c["name"]) for c in table["columns"]]
            if len(set(name.casefold() for name in aliases)) != len(aliases):
                raise ValueError("MySQL storage-column alias collision")
            for column in table["columns"]:
                name = column["name"]
                sql_type = "VARCHAR(66) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY" if name == "_record_id" else MYSQL_TYPES[column["type"]]
                fields.append(f"{mysql_identifier(mysql_column_name(name))} {sql_type}")
            cursor.execute(f"CREATE TABLE {mysql_identifier(table['table'])}({','.join(fields)})")
        with duckdb.connect(str(bundle / report["public_database"]["path"]), read_only=True,
                            config={"threads": 1, "memory_limit": "512MB"}) as source:
            for table in report["tables"]:
                if table["status"] != "public":
                    continue
                if resume:
                    cursor.execute(f"SELECT count(*) FROM {mysql_identifier(table['table'])}")
                    if cursor.fetchone()[0] == table["rows"]:
                        print(f"[mysql-resume] {table['table']}: already complete and verified", flush=True)
                        continue
                stream = source.execute(f"SELECT * FROM {quote_identifier(table['table'])}")
                count, next_progress = 0, 100000
                batch_size = min(512, 60000 // len(table["columns"]))
                prepared = admin_connection.cursor(prepared=True)
                try:
                    while rows := stream.fetchmany(batch_size):
                        statement = prepared_insert_statement(table["table"], len(table["columns"]), len(rows), resume)
                        prepared.execute(statement, tuple(mysql_value(value) for row in rows for value in row))
                        admin_connection.commit()
                        count += len(rows)
                        if count >= next_progress:
                            print(f"[mysql-load] {table['table']}: {count} source rows processed", flush=True)
                            next_progress += 100000
                finally:
                    prepared.close()
                if count != table["rows"]:
                    raise ValueError("public source row count differs from its serving manifest")
                print(f"[mysql-load] {table['table']}: complete ({count} rows)", flush=True)
        access_indexes = install_mysql_indexes(bundle, admin_connection, database)
        verified = verify_mysql_view(bundle, admin_connection, database)
        cursor.execute("SELECT @@innodb_page_size")
        page_size = cursor.fetchone()[0]
        return {"status": "complete", "serving_view_id": report["serving_view_id"],
                "database": database, "verified_rows": verified, "release_approved": False,
                "innodb_page_size": page_size,
                "access_indexes": access_indexes,
                "storage_mapping_version": "mysql-column-aliases-v1",
                "column_aliases": [
                    {"table": t["table"], "source_column": c["name"], "mysql_column": mysql_column_name(c["name"])}
                    for t in report["tables"] if t["status"] == "public" for c in t["columns"]
                    if mysql_column_name(c["name"]) != c["name"]
                ]}
    finally:
        cursor.close()


def verify_mysql_view(bundle: Path, connection, database: str, *, allow_partial: bool = False) -> int:
    report = load_serving_report(bundle)
    cursor = connection.cursor()
    verified = 0
    try:
        cursor.execute(f"USE {mysql_identifier(database)}")
        cursor.execute("SET SESSION time_zone='+00:00'")
        check_mysql_schema(cursor, report)
        with duckdb.connect(str(bundle / report["private_mapping"]["path"]), read_only=True,
                            config={"threads": 1, "memory_limit": "1GB", "max_temp_directory_size": "32GB"}) as private:
            for table in report["tables"]:
                if table["status"] != "public":
                    continue
                if allow_partial:
                    cursor.execute(f"SELECT count(*) FROM {mysql_identifier(table['table'])}")
                    if cursor.fetchone()[0] == 0:
                        print(f"[mysql-verify] {table['table']}: empty partial table", flush=True)
                        continue
                expected = private.execute("SELECT record_id,public_sha256 FROM record_map WHERE table_name=? ORDER BY record_id", [table["table"]])
                def expected_rows():
                    while batch := expected.fetchmany(512):
                        yield from batch
                expected_iterator = iter(expected_rows())
                reference = next(expected_iterator, None)
                names = tuple(c["name"] for c in table["columns"])
                cursor.execute(f"SELECT {','.join(mysql_identifier(mysql_column_name(n)) for n in names)} FROM {mysql_identifier(table['table'])} ORDER BY _record_id")
                count = 0
                while rows := cursor.fetchmany(512):
                    for row in rows:
                        if allow_partial:
                            while reference is not None and reference[0] < row[0]:
                                reference = next(expected_iterator, None)
                        if reference is None or row[0] != reference[0]:
                            raise ValueError("MySQL contains unexpected or missing rows")
                        if row_digest(names, canonical_mysql_row(row, table["columns"])) != reference[1]:
                            with duckdb.connect(str(bundle / report["public_database"]["path"]), read_only=True) as original:
                                expected_row = original.execute(
                                    f"SELECT * FROM {quote_identifier(table['table'])} WHERE _record_id=?", [row[0]],
                                ).fetchone()
                            actual_row = canonical_mysql_row(row, table["columns"])
                            different = [name for name, a, b in zip(names, actual_row, expected_row or ())
                                         if scalar_value(a) != scalar_value(b)]
                            raise ValueError(f"MySQL public row content differs from the serving projection: {table['table']} {row[0]} fields={different}")
                        reference = next(expected_iterator, None)
                    count += len(rows)
                if count > table["rows"] or (not allow_partial and (count != table["rows"] or reference is not None)):
                    raise ValueError("MySQL public row inventory differs from the serving projection")
                verified += count
                print(f"[mysql-verify] {table['table']}: {count}/{table['rows']} exact rows verified", flush=True)
        return verified
    finally:
        cursor.close()


def open_mysql_engine(bundle: Path, *, database: str, limits: QueryLimits, **connection_options) -> PublicQueryEngine:
    report = load_serving_report(bundle)
    connection = mysql.connector.connect(database=database, **connection_options)
    connection.autocommit = True
    cursor = connection.cursor()
    try:
        cursor.execute("SHOW GRANTS FOR CURRENT_USER")
        grants = [row[0] for row in cursor.fetchall()]
        permitted = re.compile(r"^GRANT (USAGE ON \*\.\*|SELECT ON " + re.escape(mysql_identifier(database)) + r"\.\*) TO ")
        if not grants or any(not permitted.match(grant) or "WITH GRANT OPTION" in grant for grant in grants):
            raise ValueError("evaluation requires a dedicated SELECT-only account scoped to the public database")
        check_mysql_schema(cursor, report)
        cursor.execute("SET SESSION time_zone='+00:00'")
        cursor.execute("SET SESSION TRANSACTION READ ONLY")
    except (ValueError, mysql.connector.Error):
        connection.close()
        raise
    finally:
        cursor.close()
    tables = {t["table"] for t in report["tables"] if t["status"] == "public"}
    return PublicQueryEngine(connection, "mysql", tables, limits, report["serving_view_id"])


def open_duckdb_engine(bundle: Path, limits: QueryLimits) -> PublicQueryEngine:
    report = load_serving_report(bundle)
    connection = duckdb.connect(str(bundle / report["public_database"]["path"]), read_only=True,
                                config={"threads": 1, "memory_limit": "512MB", "enable_external_access": False})
    tables = {t["table"] for t in report["tables"] if t["status"] == "public"}
    return PublicQueryEngine(connection, "duckdb", tables, limits, report["serving_view_id"])

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Exact typed observations with every source origin retained."""

from __future__ import annotations

import hashlib
import json
import math
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from functools import lru_cache
from pathlib import Path

import duckdb

from .columns import ColumnBinding, checked_projection, column_bindings
from .contracts import Contract, Identifier, Text
from .dynamic import DYNAMIC_POLICY_VERSION
from .sources import CORE_TABLES, TECHNICAL_COLUMNS, Catalog, Observation, digest, parse_time, quote_identifier
from .telemetry import SQL_TYPES, attach_baseline, load_source_bundle, reserve_output, stage_csv


ROW_POLICY_VERSION = "exact-typed-observations-v1"
SUPPORTED_TYPES = {"VARCHAR", "INTEGER", "BIGINT", "DOUBLE", "BOOLEAN", "TIMESTAMPTZ"}
RESERVED_COLUMNS = {"_observation_id", "_source_schema_id", "_field_quality", "_source_record", "_source_id"}


@dataclass(frozen=True)
class JsonNumber:
    text: str


def json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key in observation identity")
        result[key] = value
    return result


def invalid_constant(value: str) -> object:
    raise ValueError(f"invalid JSON constant: {value}")


def encode_json(value: object) -> str:
    if isinstance(value, JsonNumber):
        return value.text
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=True) + ":" + encode_json(value[k]) for k in sorted(value)) + "}"
    if isinstance(value, list):
        return "[" + ",".join(encode_json(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=True, allow_nan=False)


@lru_cache(maxsize=128)
def canonical_dynamic(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    # Preserve numeric tokens exactly: float parsing must not round source JSON.
    parsed = json.loads(
        value, parse_int=JsonNumber, parse_float=JsonNumber,
        object_pairs_hook=json_pairs, parse_constant=invalid_constant,
    )
    return encode_json(parsed)


def exact_integer(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        number = Decimal(value)
    except ArithmeticError as error:
        raise ValueError("invalid integer source value") from error
    if not number.is_finite() or number != number.to_integral_value():
        raise ValueError("integer source value would be rounded or is nonfinite")
    return int(number)


class ColumnSpec(Contract):
    name: Text
    sql_type: Text
    dynamic: bool


class TableSpec(Contract):
    table: Identifier
    columns: tuple[ColumnSpec, ...]
    schema_id: Identifier


def file_sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def attach_readonly(con: duckdb.DuckDBPyConnection, path: Path, alias: str) -> None:
    literal = str(path).replace("'", "''")
    con.execute(f"ATTACH '{literal}' AS {quote_identifier(alias)} (READ_ONLY)")


def load_repairs(directory: Path, snapshot_id: str) -> tuple[Path, dict[str, object]]:
    report = json.loads((directory / "dynamic_report.json").read_text())
    if report.get("status") not in ("complete", "complete_with_quarantines"):
        raise ValueError("dynamic normalization is not complete")
    if report.get("source_snapshot_id") != snapshot_id or report.get("dynamic_policy_version") != DYNAMIC_POLICY_VERSION:
        raise ValueError("dynamic normalization source/policy mismatch")
    name = report["database"]["path"]
    if Path(name).name != name or (directory / name).is_symlink():
        raise ValueError("invalid dynamic-normalization database path")
    database = directory / name
    if database.stat().st_size != report["database"]["size_bytes"] or file_sha256(database) != report["database"]["sha256"]:
        raise ValueError("dynamic-normalization checksum mismatch")
    return database, report


def table_specs(con: duckdb.DuckDBPyConnection, catalog: Catalog) -> tuple[TableSpec, ...]:
    native: dict[str, dict[str, tuple[str, bool]]] = defaultdict(dict)
    declared_types: dict[tuple[str, str], str] = {}
    for (table,) in con.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_catalog='baseline' AND NOT starts_with(table_name,'_')"
    ).fetchall():
        columns = {r[0]: r[1] for r in con.execute(f"DESCRIBE baseline.{quote_identifier(table)}").fetchall()}
        for binding in column_bindings(list(columns), table, baseline=True):
            if binding.original_name in TECHNICAL_COLUMNS:
                continue
            kind = columns[binding.storage_name].replace("TIMESTAMP WITH TIME ZONE", "TIMESTAMPTZ")
            if kind not in SUPPORTED_TYPES:
                raise ValueError(f"unsupported baseline type: {table}.{binding.storage_name}: {kind}")
            previous = native[table].get(binding.canonical_name)
            if previous and previous[0] != kind:
                raise ValueError(f"conflicting alias types: {table}.{binding.canonical_name}")
            native[table][binding.canonical_name] = (kind, False)
    for source in catalog.csv_sources:
        metadata = catalog.metadata[source.meta]
        for binding in column_bindings(list(metadata), source.table):
            if binding.original_name in TECHNICAL_COLUMNS:
                continue
            declared = metadata[binding.original_name]
            key = (source.table, binding.canonical_name)
            if key in declared_types and declared_types[key] != declared:
                raise ValueError(f"conflicting declared field semantics: {source.table}.{binding.canonical_name}")
            declared_types[key] = declared
            if declared not in SQL_TYPES:
                raise ValueError(f"unsupported declared type: {declared}")
            kind = SQL_TYPES[declared]
            prior = native[source.table].get(binding.canonical_name)
            if prior and prior[0] != kind:
                raise ValueError(f"baseline/CSV type conflict: {source.table}.{binding.canonical_name}")
            native[source.table][binding.canonical_name] = (kind, declared == "dynamic" or (prior is not None and prior[1]))
    specs = []
    for table, columns in sorted(native.items()):
        if any(name.casefold() in RESERVED_COLUMNS for name in columns):
            raise ValueError(f"reserved source column in {table}")
        if len(columns) != len({name.casefold() for name in columns}):
            raise ValueError(f"unapproved schema case collision in {table}")
        ordered = tuple(ColumnSpec(name=name, sql_type=kind, dynamic=dynamic)
                        for name, (kind, dynamic) in sorted(columns.items()))
        specs.append(TableSpec(
            table=table, columns=ordered,
            schema_id="schema:" + digest([c.model_dump(mode="json") for c in ordered]),
        ))
    return tuple(specs)


def initialize_ledger(con: duckdb.DuckDBPyConnection) -> None:
    con.create_function("v1_json_identity", canonical_dynamic, ["VARCHAR"], "VARCHAR", null_handling="special")
    con.create_function("v1_exact_integer", exact_integer, ["VARCHAR"], "BIGINT", null_handling="special")
    con.execute("""
        CREATE TABLE _origins(
            table_name VARCHAR,observation_id VARCHAR,source_id VARCHAR,locator_kind VARCHAR,source_record BIGINT
        )
    """)
    con.execute("""
        CREATE TABLE _stream_schemas(
            table_name VARCHAR,source_id VARCHAR,source_schema_id VARCHAR,present_columns VARCHAR
        )
    """)
    con.execute("""
        CREATE TABLE _column_aliases(
            table_name VARCHAR,source_id VARCHAR,original_name VARCHAR,storage_name VARCHAR,canonical_name VARCHAR
        )
    """)


def create_observation_table(con: duckdb.DuckDBPyConnection, spec: TableSpec) -> None:
    definitions = ",".join(f"{quote_identifier(c.name)} {c.sql_type}" for c in spec.columns)
    con.execute(
        f"CREATE TABLE {quote_identifier(spec.table)}(_observation_id VARCHAR,_source_schema_id VARCHAR,_field_quality VARCHAR,{definitions})"
    )


def typed_expression(column: ColumnSpec, source_type: str) -> str:
    name = quote_identifier(column.name)
    if source_type == "VARCHAR":
        source = f"nullif({name},'')"
        if column.dynamic:
            return f"v1_json_identity({name})"
        if column.sql_type in ("INTEGER", "BIGINT"):
            return f"CAST(v1_exact_integer({name}) AS {column.sql_type})"
        return f"CAST({source} AS {column.sql_type})"
    if column.sql_type != source_type.replace("TIMESTAMP WITH TIME ZONE", "TIMESTAMPTZ"):
        raise ValueError(f"unsupported implicit type change: {column.name} {source_type} -> {column.sql_type}")
    return name


def prepare_stream(
    con: duckdb.DuckDBPyConnection, spec: TableSpec, relation: str, bindings: tuple[ColumnBinding, ...],
    locator: str, source_id: str,
) -> tuple[int, str]:
    bindings = tuple(b for b in bindings if b.original_name not in TECHNICAL_COLUMNS)
    projection = checked_projection(con, relation, bindings, locator, table=spec.table)
    con.execute(f"CREATE OR REPLACE TEMP VIEW projected AS SELECT {projection},{quote_identifier(locator)} AS _source_record FROM {relation}")
    present = {b.canonical_name for b in bindings}
    if present - {c.name for c in spec.columns}:
        raise ValueError(f"source columns are absent from the full table schema: {spec.table}")
    source_schema = "schema:" + digest([c.model_dump(mode="json") for c in spec.columns if c.name in present])
    con.execute("INSERT INTO _stream_schemas VALUES (?,?,?,?)",
                [spec.table, source_id, source_schema, json.dumps(sorted(present))])
    con.executemany("INSERT INTO _column_aliases VALUES (?,?,?,?,?)", [
        (spec.table, source_id, b.original_name, b.storage_name, b.canonical_name) for b in bindings
    ])
    source_types = {r[0]: r[1] for r in con.execute("DESCRIBE projected").fetchall()}
    selections = ["_source_record"]
    for column in spec.columns:
        if column.name not in present:
            expression = f"NULL::{column.sql_type}"
        else:
            expression = typed_expression(column, source_types[column.name])
            if column.sql_type == "BOOLEAN" and source_types[column.name] == "VARCHAR":
                invalid = con.execute(
                    f"SELECT count(*) FROM projected WHERE nullif({quote_identifier(column.name)},'') IS NOT NULL "
                    f"AND lower({quote_identifier(column.name)}) NOT IN ('true','false')"
                ).fetchone()[0]
                if invalid:
                    raise ValueError(f"invalid declared boolean: {spec.table}.{column.name}")
        selections.append(f"{expression} AS {quote_identifier(column.name)}")
    con.execute("CREATE OR REPLACE TEMP TABLE typed_rows AS SELECT " + ",".join(selections) + " FROM projected")
    count, unique, nonnull = con.execute(
        "SELECT count(*),count(DISTINCT _source_record),count(_source_record) FROM typed_rows"
    ).fetchone()
    if count != unique or count != nonnull:
        raise ValueError("source record locators must be nonnull and unique within each stream")
    for column in spec.columns:
        if column.sql_type == "DOUBLE":
            if con.execute(
                f"SELECT count(*) FROM typed_rows WHERE {quote_identifier(column.name)} IS NOT NULL "
                f"AND NOT isfinite({quote_identifier(column.name)})"
            ).fetchone()[0]:
                raise ValueError(f"nonfinite numeric value: {spec.table}.{column.name}")
    con.execute("""
        CREATE OR REPLACE TEMP TABLE quality AS
        SELECT source_record,to_json(list(struct_pack(column_name:=column_name,raw_hash:=raw_value_sha256)
          ORDER BY column_name,raw_value_sha256))::VARCHAR AS field_quality
        FROM _field_changes WHERE source_id=? AND table_name=? AND status='quarantined'
        GROUP BY source_record
    """, [source_id, spec.table])
    payload = "to_json(struct_pack(" + ",".join(
        f"{quote_identifier(c.name)}:={quote_identifier(c.name)}" for c in spec.columns
    ) + "))::VARCHAR"
    con.execute(
        "CREATE OR REPLACE TEMP TABLE keyed_rows AS SELECT "
        "'obs:'||sha256(?||?||" + payload + "||coalesce(q.field_quality,'[]')) AS _observation_id,"
        "?::VARCHAR AS _source_schema_id,coalesce(q.field_quality,'[]') AS _field_quality,t.* "
        "FROM typed_rows t LEFT JOIN quality q ON t._source_record=q.source_record",
        [ROW_POLICY_VERSION + "|" + spec.table + "|", source_schema, source_schema],
    )
    return count, source_schema


def append_stream(
    con: duckdb.DuckDBPyConnection, spec: TableSpec, source_id: str, locator_kind: str,
) -> dict[str, int]:
    table = quote_identifier(spec.table)
    keys = ["_source_schema_id", "_field_quality", *(c.name for c in spec.columns)]
    con.execute("""
        CREATE OR REPLACE TEMP TABLE unique_rows AS SELECT * FROM keyed_rows
        QUALIFY row_number() OVER(PARTITION BY _observation_id ORDER BY _source_record)=1
    """)
    input_rows = con.execute("SELECT count(*) FROM keyed_rows").fetchone()[0]
    unique_rows = con.execute("SELECT count(*) FROM unique_rows").fetchone()[0]
    if input_rows != unique_rows:
        con.execute("""
            CREATE OR REPLACE TEMP TABLE duplicate_rows AS
            SELECT n.* FROM keyed_rows n JOIN unique_rows o USING(_observation_id)
            WHERE n._source_record<>o._source_record
        """)
        con.execute("""
            CREATE OR REPLACE TEMP TABLE duplicate_representatives AS
            SELECT u.* FROM unique_rows u SEMI JOIN duplicate_rows d USING(_observation_id)
        """)
        assert_matching_payloads(
            con, "duplicate_rows", "duplicate_representatives", keys,
        )
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE existing_matches AS SELECT old.* FROM {table} old "
        "SEMI JOIN unique_rows new USING(_observation_id)"
    )
    if con.execute("SELECT count(*) FROM existing_matches").fetchone()[0]:
        assert_matching_payloads(con, "unique_rows", "existing_matches", keys)
    new_rows = con.execute(
        f"SELECT count(*) FROM unique_rows u WHERE NOT EXISTS(SELECT 1 FROM {table} old WHERE old._observation_id=u._observation_id)"
    ).fetchone()[0]
    con.execute(
        f"INSERT INTO {table} SELECT u.* EXCLUDE(_source_record) FROM unique_rows u WHERE NOT EXISTS "
        f"(SELECT 1 FROM {table} old WHERE old._observation_id=u._observation_id)"
    )
    con.execute(
        "INSERT INTO _origins SELECT ?,_observation_id,?,?,_source_record FROM keyed_rows",
        [spec.table, source_id, locator_kind],
    )
    return {"source_rows": input_rows, "new_observations": new_rows, "existing_observation_origins": input_rows - new_rows}


def assert_matching_payloads(
    con: duckdb.DuckDBPyConnection, left: str, right: str, columns: list[str], condition: str = "true",
) -> None:
    # Wide diagnostic tables can exceed the engine memory budget in one full-row join.
    for offset in range(0, len(columns), 16):
        differences = " OR ".join(
            f"n.{quote_identifier(name)} IS DISTINCT FROM o.{quote_identifier(name)}"
            for name in columns[offset:offset + 16]
        )
        conflict = con.execute(
            f"SELECT n._observation_id FROM {left} n JOIN {right} o USING(_observation_id) "
            f"WHERE ({condition}) AND ({differences}) LIMIT 1"
        ).fetchone()
        if conflict is not None:
            raise ValueError("observation-ID collision or non-equivalent typed payload")


def import_core(con: duckdb.DuckDBPyConnection, source_bundle: Path, spec: TableSpec) -> int:
    filename = "incidents.jsonl" if spec.table == "SecurityIncident" else "alerts.jsonl"
    path = source_bundle / filename
    source_rows = 0
    placeholders = ",".join("?" for _ in range(len(spec.columns) + 3))
    insert = f"INSERT INTO {quote_identifier(spec.table)} VALUES ({placeholders})"
    batch = []
    origins = []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            observation = Observation.model_validate_json(line)
            fields = observation.fields()
            values = [core_value(fields.get(c.name), c) for c in spec.columns]
            batch.append((observation.observation_id, spec.schema_id, "[]", *values))
            for origin in observation.origins:
                ordinal = int(origin.locator.rsplit(":", 1)[-1])
                kind = "csv_record_ordinal" if origin.locator.startswith("csv-record:") else "duckdb_rid"
                origins.append((spec.table, observation.observation_id, origin.source_id, kind, ordinal))
                source_rows += 1
            if len(batch) >= 64:
                con.executemany(insert, batch)
                con.executemany("INSERT INTO _origins VALUES (?,?,?,?,?)", origins)
                batch.clear()
                origins.clear()
        if batch:
            con.executemany(insert, batch)
            con.executemany("INSERT INTO _origins VALUES (?,?,?,?,?)", origins)
    return source_rows


def core_value(value: object, column: ColumnSpec) -> object:
    if value is None:
        return None
    if column.dynamic or column.name in ("Entities", "ExtendedProperties", "ExtendedLinks"):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if column.sql_type == "VARCHAR" and isinstance(value, str):
        return value
    if column.sql_type == "TIMESTAMPTZ":
        return parse_time(value)
    if column.sql_type in ("INTEGER", "BIGINT") and type(value) is int:
        return value
    if column.sql_type == "BOOLEAN" and type(value) is bool:
        return value
    if column.sql_type == "DOUBLE" and type(value) in (int, float) and math.isfinite(value):
        return value
    raise ValueError(f"core observation value has the wrong type for {column.name}")


def build_ledger(source_bundle: Path, dynamic_bundle: Path, output: Path) -> dict[str, object]:
    source_bundle = source_bundle.resolve()
    catalog, source_report = load_source_bundle(source_bundle)
    repair_database, repair_report = load_repairs(dynamic_bundle.resolve(), catalog.manifest.snapshot_id)
    output = reserve_output(output, catalog)
    implementation = {
        name: file_sha256(Path(__file__).with_name(name))
        for name in ("ledger.py", "telemetry.py", "columns.py")
    }
    database = output / "observations.duckdb"
    streams = []
    summaries = []
    repairs = {(s["source_id"], s["table"]): s for s in repair_report["streams"]}
    canonical_dynamic.cache_clear()
    with tempfile.TemporaryDirectory(prefix="spill-", dir=output) as spill:
        with duckdb.connect(str(database), config={"memory_limit": "1GB", "threads": 1}) as con:
            con.execute("SET TimeZone='UTC'")
            con.execute("SET preserve_insertion_order=true")
            con.execute("SET temp_directory=?", [spill])
            con.execute("SET max_temp_directory_size='32GB'")
            attach_baseline(con, catalog.tenant_db)
            attach_readonly(con, repair_database, "repairs")
            initialize_ledger(con)
            con.execute("CREATE TABLE _field_changes AS SELECT * FROM repairs.field_changes")
            con.execute("CREATE TABLE _dynamic_decisions AS SELECT * FROM repairs.dynamic_decisions")
            con.execute("""CREATE TABLE _historical_memberships AS SELECT * FROM read_json(
                ?,format='newline_delimited',columns={tenant_id:'VARCHAR',membership:'JSON'})""",
                        [str(source_bundle / "historical_memberships.jsonl")])
            con.execute("""CREATE TABLE _core_source_references AS SELECT * FROM read_json(
                ?,format='newline_delimited',columns={observation_id:'VARCHAR','table':'VARCHAR',content_sha256:'VARCHAR',origins:'JSON'})""",
                        [str(source_bundle / "observation_references.jsonl")])
            con.execute("""CREATE TABLE _cases AS SELECT * FROM read_json(
                ?,format='newline_delimited',columns={incident_id:'INTEGER',status:'VARCHAR',manifest:'JSON',
                  blocking_reasons:'JSON',missing_alert_ids:'JSON',conflicting_alert_ids:'JSON',
                  coverage_start:'TIMESTAMPTZ',coverage_end:'TIMESTAMPTZ'})""", [str(source_bundle / "cases.jsonl")])
            specs = sorted(table_specs(con, catalog), key=lambda s: (s.table not in CORE_TABLES, s.table))
            base_tables = {r[0] for r in con.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_catalog='baseline'"
            ).fetchall()}
            for spec in specs:
                create_observation_table(con, spec)
                table_streams = []
                if spec.table in CORE_TABLES:
                    source_rows = import_core(con, source_bundle, spec)
                else:
                    candidates = [(None, catalog.tenant_source_id)] if spec.table in base_tables else []
                    candidates += [(s, s.source_id) for s in catalog.csv_sources if s.table == spec.table]
                    for source, source_id in candidates:
                        is_baseline = source is None
                        prepared = repairs.get((source_id, spec.table))
                        if any(c.dynamic for c in spec.columns) and prepared is None:
                            raise ValueError(f"missing dynamic-field verification for stream {source_id}/{spec.table}")
                        if prepared and prepared["normalized_table"] is not None:
                            expected = (
                                "imported." + quote_identifier(spec.table) if is_baseline else
                                "csv_exports." + quote_identifier(spec.table + "_" + source_id.removeprefix("src:"))
                            )
                            if prepared["normalized_table"] != expected:
                                raise ValueError("unexpected normalized stream identifier")
                            relation, locator = "repairs." + expected, "_source_record"
                            bindings = tuple(ColumnBinding.model_validate(b) for b in prepared["column_mapping"])
                        elif is_baseline:
                            relation, locator = "baseline." + quote_identifier(spec.table), "_rid"
                            names = [r[0] for r in con.execute(f"DESCRIBE {relation}").fetchall()]
                            bindings = column_bindings(names, spec.table, baseline=True)
                        else:
                            assert source is not None
                            bindings = stage_csv(con, source.path, source.table)
                            relation, locator = "input_rows", "source_record"
                        count, variant = prepare_stream(con, spec, relation, bindings, locator, source_id)
                        result = append_stream(con, spec, source_id, "duckdb_rid" if is_baseline else "csv_record_ordinal")
                        if result["source_rows"] != count:
                            raise ValueError("typed stream row count mismatch")
                        table_streams.append({
                            "table": spec.table, "source_id": source_id, "source_schema_id": variant,
                            "origin": "baseline" if is_baseline else "csv", **result,
                        })
                    source_rows = sum(s["source_rows"] for s in table_streams)
                actual = con.execute(f"SELECT count(*) FROM {quote_identifier(spec.table)}").fetchone()[0]
                origins = con.execute("SELECT count(*) FROM _origins WHERE table_name=?", [spec.table]).fetchone()[0]
                if origins != source_rows:
                    raise ValueError("lost source provenance")
                dangling = con.execute(
                    f"SELECT count(*) FROM _origins o LEFT JOIN {quote_identifier(spec.table)} t "
                    "ON t._observation_id=o.observation_id WHERE o.table_name=? AND t._observation_id IS NULL", [spec.table],
                ).fetchone()[0]
                if dangling:
                    raise ValueError("source origin refers to a missing observation")
                summaries.append({
                    "table": spec.table, "observations": actual, "source_origins": origins,
                    "csv_added_observations": sum(s["new_observations"] for s in table_streams if s["origin"] == "csv"),
                    "schema": spec.model_dump(mode="json"),
                })
                streams.extend(table_streams)
                print(f"[ledger] {spec.table}: {origins} origins -> {actual} observations", flush=True)
                con.execute("CHECKPOINT")
            con.execute("DETACH baseline")
            con.execute("DETACH repairs")
            con.execute("CHECKPOINT")
    canonical_dynamic.cache_clear()
    catalog.verify_unchanged()
    for name, sha in implementation.items():
        if file_sha256(Path(__file__).with_name(name)) != sha:
            raise ValueError("ledger implementation changed during build")
    report = {
        "schema_version": "1", "visibility": "private_build",
        "status": "complete_with_blocks" if source_report["status"] != "complete" or repair_report["status"] != "complete" else "complete",
        "source_snapshot_id": catalog.manifest.snapshot_id, "dynamic_normalization_id": repair_report["normalization_id"],
        "row_policy_version": ROW_POLICY_VERSION, "implementation_sha256": implementation,
        "duckdb_version": duckdb.__version__,
        "ledger_id": "ledger:" + digest([catalog.manifest.snapshot_id, repair_report["normalization_id"], implementation, duckdb.__version__]),
        "summary": {
            "tables": len(summaries), "observations": sum(t["observations"] for t in summaries),
            "source_origins": sum(t["source_origins"] for t in summaries),
            "csv_added_observations": sum(t["csv_added_observations"] for t in summaries),
            "inputs_unchanged": True,
        },
        "tables": summaries, "streams": streams,
        "database": {"path": database.name, "sha256": file_sha256(database), "size_bytes": database.stat().st_size},
        "limitations": [
            "Distinct canonical observations are not certified independent events or attacks.",
            "Rows merge only on full typed content, source-field availability and quarantine state; similar or partially populated rows are retained separately.",
            "Dynamic JSON key order/whitespace is canonicalized for identity; numeric tokens and array order remain exact.",
            "Empty fields normalize to unavailable values. Timestamps use UTC microsecond precision of the baseline schema.",
            "No global command/path quote replacement, filename equality, or time-window heuristic is used to deduplicate rows.",
            "Original locators, column maps and field repairs/quarantines remain available. Evidence consumers must enforce field-quality exclusions.",
            "Only latest resolved incident/alert payloads are active; historical incident memberships retain metadata references, not old incident payloads.",
            "This is a private observation layer, not a student-visible serving view, graph or QA release.",
        ],
    }
    (output / "ledger_report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report

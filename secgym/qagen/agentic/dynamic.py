# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Lossless dynamic-field normalization with explicit repair/quarantine provenance."""

from __future__ import annotations

import ast
import hashlib
import json
import math
import tempfile
from collections import Counter
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Literal

import duckdb
from pydantic import JsonValue

from .columns import ColumnBinding, column_bindings
from .contracts import Contract, Text
from .sources import CORE_TABLES, digest, quote_identifier
from .telemetry import attach_baseline, load_source_bundle, reserve_output, stage_csv


DYNAMIC_POLICY_VERSION = "dynamic-json-v1"
MAX_VALUE_CHARACTERS = 1_000_000
MAX_TREE_DEPTH = 64
MAX_TREE_NODES = 100_000
MAX_CHANGE_BYTES_PER_COLUMN = 64 * 1024 * 1024


class DynamicDecision(Contract):
    status: Literal["unchanged", "repaired", "quarantined"]
    normalized_value: str | None
    reason: Text


def unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object keys would lose information")
        result[key] = value
    return result


def reject_constant(value: str) -> JsonValue:
    raise ValueError(f"nonfinite JSON constant: {value}")


def strict_json(value: str) -> JsonValue:
    return json.loads(value, object_pairs_hook=unique_object, parse_constant=reject_constant)


def check_json_value(value: JsonValue, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [MAX_TREE_NODES]
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_TREE_DEPTH:
        raise ValueError("dynamic value exceeds structural limits")
    if isinstance(value, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise ValueError("unpaired Unicode surrogate")
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("nonfinite numeric value")
    elif isinstance(value, list):
        for item in value:
            check_json_value(item, depth + 1, budget)
    elif isinstance(value, dict):
        for key, item in value.items():
            check_json_value(key, depth + 1, budget)
            check_json_value(item, depth + 1, budget)


def literal_data(node: ast.AST, source: str, depth: int, budget: list[int]) -> JsonValue:
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_TREE_DEPTH:
        raise ValueError("literal data exceeds structural limits")
    if isinstance(node, ast.Constant):
        value = node.value
        if value is None or isinstance(value, (str, bool, int)):
            return value
        if isinstance(value, float):
            segment = ast.get_source_segment(source, node)
            if not math.isfinite(value) or segment is None:
                raise ValueError("nonfinite or unverifiable numeric literal")
            # Parsing a float must not silently round a higher-precision literal.
            if Decimal(segment.replace("_", "")) != Decimal(json.dumps(value)):
                raise ValueError("numeric literal loses decimal precision")
            return value
        raise ValueError("literal type has no lossless JSON representation")
    if isinstance(node, ast.List):
        return [literal_data(item, source, depth + 1, budget) for item in node.elts]
    if isinstance(node, ast.Dict):
        result = {}
        for key, value in zip(node.keys, node.values):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                raise ValueError("JSON object keys must be literal strings")
            if key.value in result:
                raise ValueError("duplicate object keys would lose information")
            result[key.value] = literal_data(value, source, depth + 1, budget)
        return result
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        if not isinstance(node.operand, ast.Constant):
            raise ValueError("only signed numeric constants are allowed")
        value = literal_data(node.operand, source, depth + 1, budget)
        if type(value) not in (int, float):
            raise ValueError("sign operator requires a numeric constant")
        return -value if isinstance(node.op, ast.USub) else value
    raise ValueError(f"non-data syntax is not permitted: {type(node).__name__}")


def same_json_types(left: JsonValue, right: JsonValue) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(same_json_types(a, b) for a, b in zip(left, right))
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(same_json_types(v, right[k]) for k, v in left.items())
    if isinstance(left, float) and isinstance(right, float) and left == right == 0:
        return math.copysign(1, left) == math.copysign(1, right)
    return left == right


def normalize_dynamic_value(raw: str | None, declared_type: str) -> DynamicDecision:
    if declared_type != "dynamic":
        return DynamicDecision(status="unchanged", normalized_value=raw, reason="outside_dynamic_schema")
    if raw is None or raw == "":
        return DynamicDecision(status="unchanged", normalized_value=raw, reason="absent")
    if len(raw) > MAX_VALUE_CHARACTERS:
        return DynamicDecision(status="quarantined", normalized_value=None, reason="value_exceeds_size_limit")
    try:
        try:
            value = strict_json(raw)
        except json.JSONDecodeError:
            tree = ast.parse(raw.strip(), mode="eval")
            value = literal_data(tree.body, raw.strip(), 0, [MAX_TREE_NODES])
            check_json_value(value)
            normalized = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
            round_trip = strict_json(normalized)
            if not same_json_types(value, round_trip):
                raise ValueError("JSON round-trip changed value or type")
            return DynamicDecision(status="repaired", normalized_value=normalized, reason="literal_data_to_json")
        check_json_value(value)
        return DynamicDecision(status="unchanged", normalized_value=raw, reason="valid_json_preserved")
    except (ValueError, SyntaxError, RecursionError, ArithmeticError) as error:
        return DynamicDecision(status="quarantined", normalized_value=None, reason=str(error))


@dataclass(frozen=True)
class ValueChange:
    original: str
    decision: DynamicDecision
    occurrences: int


def initialize_decision_tables(con: duckdb.DuckDBPyConnection) -> None:
    con.execute("""
        CREATE TABLE dynamic_decisions(
            source_id VARCHAR,table_name VARCHAR,column_name VARCHAR,raw_value_sha256 VARCHAR,
            original_value VARCHAR,normalized_value VARCHAR,status VARCHAR,reason VARCHAR,affected_rows BIGINT
        )
    """)
    con.execute("""
        CREATE TABLE field_changes(
            source_id VARCHAR,table_name VARCHAR,source_record BIGINT,column_name VARCHAR,
            raw_value_sha256 VARCHAR,status VARCHAR
        )
    """)


def inspect_dynamic_column(
    con: duckdb.DuckDBPyConnection, relation: str, column: str,
) -> tuple[dict[str, int], list[ValueChange]]:
    quoted = quote_identifier(column)
    cursor = con.execute(
        f"SELECT {quoted},count(*) FROM {relation} WHERE {quoted} IS NOT NULL AND {quoted}<>'' GROUP BY 1"
    )
    counts: Counter[str] = Counter()
    changes = []
    change_bytes = 0
    while rows := cursor.fetchmany(128):
        for raw, occurrences in rows:
            decision = normalize_dynamic_value(raw, "dynamic")
            counts[decision.status] += occurrences
            counts["distinct_values"] += 1
            if decision.status != "unchanged":
                change_bytes += len(raw.encode("utf-8")) + len((decision.normalized_value or "").encode("utf-8"))
                if change_bytes > MAX_CHANGE_BYTES_PER_COLUMN:
                    raise ValueError(f"dynamic change map exceeds the per-column memory budget: {column}")
                changes.append(ValueChange(raw, decision, occurrences))
    return dict(counts), changes


def normalize_dynamic_stream(
    con: duckdb.DuckDBPyConnection, *, relation: str, table: str, source_id: str,
    locator: str, bindings: tuple[ColumnBinding, ...], metadata: dict[str, str], target: str,
) -> dict[str, object]:
    dynamic = [b for b in bindings if metadata.get(b.original_name) == "dynamic"]
    types = {row[0]: row[1] for row in con.execute(f"DESCRIBE SELECT * FROM {relation}").fetchall()}
    if any(b.storage_name.casefold() in ("_source_id", "_source_record") for b in bindings):
        raise ValueError("source uses reserved provenance column names")
    count, unique, nonnull = con.execute(
        f"SELECT count(*),count(DISTINCT {quote_identifier(locator)}),count({quote_identifier(locator)}) FROM {relation}"
    ).fetchone()
    if count != unique or count != nonnull:
        raise ValueError("missing or duplicate source record locator")
    findings = []
    changed_columns = []
    totals: Counter[str] = Counter()
    for binding in dynamic:
        if types[binding.storage_name] != "VARCHAR":
            raise ValueError(f"dynamic field has unexpected storage type: {table}.{binding.original_name}")
        stats, changes = inspect_dynamic_column(con, relation, binding.storage_name)
        totals.update(stats)
        findings.append({"column": binding.original_name, "storage_column": binding.storage_name, **stats})
        if not changes:
            continue
        changed_columns.append(binding)
        con.executemany("INSERT INTO dynamic_decisions VALUES (?,?,?,?,?,?,?,?,?)", [
            (source_id, table, binding.storage_name, hashlib.sha256(c.original.encode("utf-8")).hexdigest(),
             c.original, c.decision.normalized_value, c.decision.status, c.decision.reason, c.occurrences)
            for c in changes
        ])
        con.execute(
            f"INSERT INTO field_changes SELECT ?,?,s.{quote_identifier(locator)},?,d.raw_value_sha256,d.status "
            f"FROM {relation} s JOIN dynamic_decisions d ON d.original_value=s.{quote_identifier(binding.storage_name)} "
            "WHERE d.source_id=? AND d.table_name=? AND d.column_name=?",
            [source_id, table, binding.storage_name, source_id, table, binding.storage_name],
        )
    materialized = bool(changed_columns)
    if materialized:
        projection = ",".join(quote_identifier(b.storage_name) for b in bindings)
        con.execute(
            f"CREATE TABLE {target} AS SELECT {projection},?::VARCHAR AS _source_id,"
            f"{quote_identifier(locator)} AS _source_record FROM {relation}", [source_id],
        )
        for binding in changed_columns:
            column = quote_identifier(binding.storage_name)
            con.execute(
                f"UPDATE {target} n SET {column}=d.normalized_value FROM dynamic_decisions d "
                f"WHERE d.source_id=? AND d.table_name=? AND d.column_name=? AND n.{column}=d.original_value",
                [source_id, table, binding.storage_name],
            )
        if con.execute(f"SELECT count(*) FROM {target}").fetchone()[0] != count:
            raise ValueError("dynamic normalization changed the source row count")
        changed_names = {b.storage_name for b in changed_columns}
        checks = [
            f"count(*) FILTER(WHERE s.{quote_identifier(b.storage_name)} IS DISTINCT FROM n.{quote_identifier(b.storage_name)})"
            for b in bindings if b.storage_name not in changed_names
        ]
        if checks:
            differences = con.execute(
                "SELECT " + ",".join(checks) + f" FROM {relation} s JOIN {target} n "
                f"ON s.{quote_identifier(locator)}=n._source_record"
            ).fetchone()
            if any(differences):
                raise ValueError("normalization modified an unrelated source field")
        for binding in changed_columns:
            column = quote_identifier(binding.storage_name)
            differences = con.execute(
                f"SELECT count(*) FROM {relation} s JOIN {target} n ON s.{quote_identifier(locator)}=n._source_record "
                f"LEFT JOIN dynamic_decisions d ON d.original_value=s.{column} AND d.source_id=? "
                "AND d.table_name=? AND d.column_name=? "
                f"WHERE n.{column} IS DISTINCT FROM CASE WHEN d.source_id IS NULL THEN s.{column} ELSE d.normalized_value END",
                [source_id, table, binding.storage_name],
            ).fetchone()[0]
            if differences:
                raise ValueError("normalized values do not match recorded decisions")
        for binding in dynamic:
            column = quote_identifier(binding.storage_name)
            invalid = con.execute(
                f"SELECT count(*) FROM {target} WHERE {column} IS NOT NULL AND {column}<>'' AND NOT json_valid({column})"
            ).fetchone()[0]
            if invalid:
                raise ValueError(f"normalized dynamic field is not consumable as JSON: {binding.original_name}")
    changed_rows = con.execute(
        "SELECT count(*) FROM field_changes WHERE source_id=? AND table_name=?", [source_id, table],
    ).fetchone()[0]
    if changed_rows != totals["repaired"] + totals["quarantined"]:
        raise ValueError("field provenance count differs from normalization outcomes")
    return {
        "source_id": source_id, "table": table, "source_rows": count, "dynamic_columns": len(dynamic),
        "outcomes": dict(totals), "columns": findings, "normalized_table": target if materialized else None,
        "source_locator_kind": "csv_record_ordinal" if locator == "source_record" else "duckdb_rid",
        "column_mapping": [b.model_dump(mode="json") for b in bindings],
        "other_source_fields_preserved": True,
    }


def normalize_dynamic_fields(source_bundle: Path, output: Path) -> dict[str, object]:
    catalog, source_report = load_source_bundle(source_bundle.resolve())
    output = reserve_output(output, catalog)
    implementation = {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in ("dynamic.py", "telemetry.py", "columns.py")
    }
    metadata: dict[str, dict[str, str]] = {}
    for source in catalog.csv_sources:
        if source.table in CORE_TABLES:
            continue
        schema = metadata.setdefault(source.table, {})
        for name, kind in catalog.metadata[source.meta].items():
            if name in schema and schema[name] != kind:
                raise ValueError(f"metadata type conflict: {source.table}.{name}")
            schema[name] = kind
    database = output / "dynamic_fields.duckdb"
    streams = []
    with tempfile.TemporaryDirectory(prefix="spill-", dir=output) as spill:
        with duckdb.connect(str(database), config={"threads": "1", "memory_limit": "1GB"}) as con:
            con.execute("SET TimeZone='UTC'")
            con.execute("SET temp_directory=?", [spill])
            con.execute("CREATE SCHEMA imported")
            con.execute("CREATE SCHEMA csv_exports")
            initialize_decision_tables(con)
            attach_baseline(con, catalog.tenant_db)
            baseline_tables = {r[0] for r in con.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_catalog='baseline'"
            ).fetchall()}
            for table, schema in sorted(metadata.items()):
                if table not in baseline_tables or "dynamic" not in schema.values():
                    continue
                relation = "baseline." + quote_identifier(table)
                names = [r[0] for r in con.execute(f"DESCRIBE {relation}").fetchall()]
                bindings = column_bindings(names, table, baseline=True)
                streams.append(normalize_dynamic_stream(
                    con, relation=relation, table=table, source_id=catalog.tenant_source_id,
                    locator="_rid", bindings=bindings, metadata=schema,
                    target="imported." + quote_identifier(table),
                ))
                print(f"[dynamic] baseline {table}: {streams[-1]['outcomes']}", flush=True)
            for source in catalog.csv_sources:
                if source.table in CORE_TABLES or "dynamic" not in catalog.metadata[source.meta].values():
                    continue
                bindings = stage_csv(con, source.path, source.table)
                streams.append(normalize_dynamic_stream(
                    con, relation="input_rows", table=source.table, source_id=source.source_id,
                    locator="source_record", bindings=bindings, metadata=catalog.metadata[source.meta],
                    target="csv_exports." + quote_identifier(source.table + "_" + source.source_id.removeprefix("src:")),
                ))
            con.execute("CHECKPOINT")
    catalog.verify_unchanged()
    for name, sha in implementation.items():
        if hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() != sha:
            raise ValueError("dynamic normalizer changed during build")
    totals: Counter[str] = Counter()
    for stream in streams:
        totals.update(stream["outcomes"])
    database_hash = hashlib.sha256()
    with database.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            database_hash.update(chunk)
    report = {
        "schema_version": "1", "visibility": "private_build",
        "status": "complete_with_quarantines" if totals["quarantined"] else "complete",
        "source_snapshot_id": catalog.manifest.snapshot_id, "source_reconciliation_status": source_report["status"],
        "dynamic_policy_version": DYNAMIC_POLICY_VERSION, "implementation_sha256": implementation,
        "normalization_id": "dynamic:" + digest([catalog.manifest.snapshot_id, DYNAMIC_POLICY_VERSION, implementation]),
        "summary": {
            "source_streams_checked": len(streams), "dynamic_field_outcomes": dict(totals),
            "materialized_streams": sum(s["normalized_table"] is not None for s in streams),
            "inputs_unchanged": True,
        },
        "streams": streams,
        "database": {"path": database.name, "sha256": database_hash.hexdigest(), "size_bytes": database.stat().st_size},
        "limits": {
            "max_value_characters": MAX_VALUE_CHARACTERS, "max_tree_depth": MAX_TREE_DEPTH,
            "max_tree_nodes": MAX_TREE_NODES, "max_change_bytes_per_column": MAX_CHANGE_BYTES_PER_COLUMN,
        },
        "limitations": [
            "Only schema-declared non-core dynamic fields are eligible. Other text is not repaired.",
            "Counts are field occurrences across overlapping source streams, not unique events.",
            "Only changed streams are materialized; unchanged streams remain at their pinned original source.",
            "Quarantined fields have a null normalized value plus mandatory field_changes metadata; dependent claims/extractions are blocked, not treated as evidence of absence.",
            "This does not merge or deduplicate telemetry, construct a graph, or approve QA.",
        ],
    }
    (output / "dynamic_report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report

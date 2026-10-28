# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Explicitly reviewed public projections; private provenance is a separate database."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from functools import lru_cache
from typing import Literal

import duckdb
from pydantic import model_validator

from .contracts import Contract, Digest, Identifier, Text, fingerprint, require_unique
from .graph import load_ledger
from .ledger import JsonNumber, attach_readonly, encode_json, file_sha256, invalid_constant, json_pairs
from .query import scalar_value
from .sources import quote_identifier


PUBLIC_TYPES = {"VARCHAR", "BIGINT", "INTEGER", "DOUBLE", "BOOLEAN", "TIMESTAMP WITH TIME ZONE"}
INTERNAL_COLUMNS = {"_observation_id", "_source_schema_id", "_field_quality"}


class ConditionalJsonRemoval(Contract):
    field: Text
    values: tuple[Text, ...]
    paths: tuple[tuple[Text, ...], ...]

    @model_validator(mode="after")
    def bounded_condition(self):
        if not self.values or not self.paths or any(not path or path[-1] == "*" for path in self.paths):
            raise ValueError("conditional redaction requires values and named field paths")
        require_unique(self.values, "conditional match values")
        return self


class ColumnProjection(Contract):
    name: Text
    action: Literal["keep", "drop", "json", "redact_json"]
    reason: Text
    json_paths: tuple[tuple[Text, ...], ...] = ()
    json_remove_paths: tuple[tuple[Text, ...], ...] = ()
    json_remove_if: tuple[ConditionalJsonRemoval, ...] = ()

    @model_validator(mode="after")
    def explicit_json_policy(self):
        if (self.action == "json") != bool(self.json_paths):
            raise ValueError("JSON projection requires explicit allowed scalar paths; other actions must not supply them")
        if (self.action == "redact_json") != bool(self.json_remove_paths or self.json_remove_if):
            raise ValueError("data-pinned JSON redaction requires explicit removed field paths")
        if any(not path or path[-1] == "*" for path in self.json_remove_paths):
            raise ValueError("redaction must remove named fields, not whole arrays/elements")
        if len(set(self.json_paths)) != len(self.json_paths):
            raise ValueError("duplicate JSON paths")
        if len(set(self.json_remove_paths)) != len(self.json_remove_paths):
            raise ValueError("duplicate JSON redaction paths")
        if any(not path for path in self.json_paths):
            raise ValueError("whole JSON containers cannot be allowlisted")
        return self


class TableProjection(Contract):
    table: Identifier
    columns: tuple[ColumnProjection, ...]
    exclude_reason: Text | None = None

    @model_validator(mode="after")
    def explicit_table_policy(self):
        require_unique(tuple(c.name for c in self.columns), "column policies")
        if bool(self.columns) == (self.exclude_reason is not None):
            raise ValueError("declare column dispositions or an explicit table exclusion, not both")
        return self


class ServingPolicy(Contract):
    policy_version: Identifier
    review_ref: Text
    source_snapshot_id: Identifier
    source_ledger_sha256: Digest
    tables: tuple[TableProjection, ...]

    @model_validator(mode="after")
    def unique_tables(self):
        require_unique(tuple(t.table for t in self.tables), "table policies")
        if not self.tables:
            raise ValueError("serving policy must cover the source inventory")
        return self


def parse_json(text: str):
    return json.loads(text, parse_int=JsonNumber, parse_float=JsonNumber,
                      object_pairs_hook=json_pairs, parse_constant=invalid_constant)


def project_json(text: str | None, paths: tuple[tuple[str, ...], ...]) -> str | None:
    if text is None or text == "":
        return text

    def prefix(path):
        return any(allowed[:len(path)] == path for allowed in paths)

    def project(value, path):
        if value is None:
            return None
        if isinstance(value, str) and path not in paths:
            decoded = parse_json(value)
            if not isinstance(decoded, (dict, list)):
                raise ValueError("encoded JSON policy expected a container")
            return encode_json(project(decoded, path))
        if isinstance(value, dict):
            if path in paths:
                raise ValueError("an allowlisted scalar path contains an unreviewed object")
            return {key: project(child, path + (key,)) for key, child in value.items() if prefix(path + (key,))}
        if isinstance(value, list):
            if not prefix(path + ("*",)):
                raise ValueError("JSON array shape differs from its reviewed projection")
            return [project(child, path + ("*",)) for child in value]
        if path not in paths:
            raise ValueError("JSON scalar shape differs from its reviewed projection")
        if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
            if isinstance(parse_json(value), (dict, list)):
                raise ValueError("encoded JSON at a scalar path needs an explicit nested projection")
        return value

    return encode_json(project(parse_json(text), ()))


def redact_json(text: str | None, removed: tuple[tuple[str, ...], ...],
                conditions: tuple[ConditionalJsonRemoval, ...] = ()) -> str | None:
    """Remove reviewed metadata paths, preserving unrelated literal/encoded payloads."""
    if text is None or text == "":
        return text
    parsed = parse_json(text)
    if isinstance(parsed, dict):
        removed = tuple(set(removed).union(
            path for condition in conditions if parsed.get(condition.field) in condition.values for path in condition.paths
        ))

    def relevant(path):
        return any(target[:len(path)] == path for target in removed)

    def walk(value, path, depth=0):
        if depth > 64:
            raise ValueError("JSON redaction exceeds depth limit")
        if isinstance(value, dict):
            result, changed = {}, False
            for key, child in value.items():
                child_path = path + (key,)
                if child_path in removed:
                    changed = True
                elif relevant(child_path):
                    result[key], altered = walk(child, child_path, depth + 1)
                    changed |= altered
                else:
                    result[key] = child
            return result, changed
        if isinstance(value, list):
            child_path = path + ("*",)
            if not relevant(child_path):
                return value, False
            values = [walk(child, child_path, depth + 1) for child in value]
            return [item for item, _ in values], any(changed for _, changed in values)
        if isinstance(value, str) and relevant(path):
            decoded, layers = value, 0
            while isinstance(decoded, str) and decoded.lstrip().startswith(("{", "[", '"')):
                if depth + layers > 64:
                    raise ValueError("encoded JSON redaction exceeds depth limit")
                try:
                    next_value = parse_json(decoded)
                except json.JSONDecodeError:
                    break
                if next_value == decoded:
                    break
                decoded, layers = next_value, layers + 1
            if isinstance(decoded, (dict, list)):
                result, changed = walk(decoded, path, depth + layers)
                if changed:
                    for _ in range(layers):
                        result = encode_json(result)
                    return result, True
        return value, False

    result, changed = walk(parsed, ())
    return encode_json(result) if changed else text


@lru_cache(maxsize=256)
def row_hash_prefix(columns: tuple[str, ...]):
    encoded = b"[" + json.dumps(columns, separators=(",", ":"), ensure_ascii=True).encode() + b","
    return hashlib.sha256(encoded)


def row_digest(columns: tuple[str, ...], row: tuple) -> str:
    values = [scalar_value(value) for value in row]
    digest = row_hash_prefix(columns).copy()
    digest.update(json.dumps(values, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode())
    digest.update(b"]")
    return digest.hexdigest()


def export_public_view(graph_bundle: Path, policy: ServingPolicy, output: Path) -> dict:
    policy = ServingPolicy.model_validate(policy)
    graph_bundle, output = graph_bundle.resolve(), output.resolve()
    graph_report = json.loads((graph_bundle / "graph_report.json").read_text())
    if graph_report.get("status") != "complete":
        raise ValueError("a completed source graph is required")
    ledger_bundle = Path(graph_report["ledger_bundle"]).resolve()
    if output.exists() or any(output.is_relative_to(p) or p.is_relative_to(output) for p in (graph_bundle, ledger_bundle)):
        raise ValueError("public view output must be new and outside input bundles")
    graph_db = graph_bundle / graph_report["database"]["path"]
    if graph_db.name != graph_report["database"]["path"] or graph_db.is_symlink():
        raise ValueError("invalid graph database path")
    if file_sha256(graph_db) != graph_report["database"]["sha256"]:
        raise ValueError("graph checksum mismatch")
    ledger_db, ledger = load_ledger(ledger_bundle)
    if ledger["database"]["sha256"] != graph_report["ledger_database_sha256"]:
        raise ValueError("graph does not belong to the exact ledger")
    if policy.source_snapshot_id != ledger["source_snapshot_id"] or policy.source_ledger_sha256 != ledger["database"]["sha256"]:
        raise ValueError("projection policy was not reviewed for this exact source snapshot/ledger")
    expected_tables = {t["table"] for t in ledger["tables"]}
    if {t.table for t in policy.tables} != expected_tables:
        raise ValueError("policy must explicitly cover every source table, including exclusions")
    snapshot_id = ledger["source_snapshot_id"]
    implementation = {name: file_sha256(Path(__file__).with_name(name))
                      for name in ("serving.py", "query.py", "ledger.py", "contracts.py")}
    view_id = "view:" + hashlib.sha256(json.dumps(
        [snapshot_id, ledger["database"]["sha256"], graph_report["database"]["sha256"], fingerprint(policy), implementation],
    ).encode()).hexdigest()
    inputs = {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in (graph_db, ledger_db)}
    output.mkdir(parents=True, mode=0o700)
    public_path, mapping_path = output / "public.duckdb", output / "private_mapping.duckdb"
    inventory = []
    with duckdb.connect(str(public_path), config={"threads": 1, "memory_limit": "512MB"}) as public:
        with duckdb.connect(str(mapping_path), config={"threads": 1, "memory_limit": "512MB"}) as private:
            private.execute("""CREATE TABLE record_map(
                table_name VARCHAR,record_id VARCHAR,observation_id VARCHAR,private_sha256 VARCHAR,
                public_sha256 VARCHAR,lineage VARCHAR)""")
            attach_readonly(private, ledger_db, "ledger")
            attach_readonly(private, graph_db, "graph")
            for table in policy.tables:
                schema = private.execute(f"DESCRIBE ledger.{quote_identifier(table.table)}").fetchall()
                source_columns = tuple(row[0] for row in schema if row[0] not in INTERNAL_COLUMNS)
                types = {row[0]: row[1] for row in schema}
                if table.exclude_reason:
                    inventory.append({"table": table.table, "status": "excluded", "reason": table.exclude_reason})
                    print(f"[serving] {table.table}: excluded ({table.exclude_reason})", flush=True)
                    continue
                if {c.name for c in table.columns} != set(source_columns):
                    raise ValueError(f"policy/schema mismatch in {table.table}; no implicit column defaults")
                kept = tuple(c for c in table.columns if c.action != "drop")
                if not kept:
                    raise ValueError(f"{table.table}: use an explicit table exclusion instead of dropping every column")
                if any(types[c.name] not in PUBLIC_TYPES for c in kept):
                    raise ValueError(f"{table.table}: unreviewed source type")
                if any(c.action in ("json", "redact_json") and types[c.name] != "VARCHAR" for c in kept):
                    raise ValueError("JSON projection is only supported on declared text-encoded JSON columns")
                columns = ("_record_id", *(c.name for c in kept))
                definitions = ['"_record_id" VARCHAR PRIMARY KEY', *(f"{quote_identifier(c.name)} {types[c.name]}" for c in kept)]
                public.execute(f"CREATE TABLE {quote_identifier(table.table)}({','.join(definitions)})")
                cursor = private.execute(f"""
                    SELECT l.*,o.lineage FROM ledger.{quote_identifier(table.table)} l
                    LEFT JOIN graph.observations o ON l._observation_id=o.observation_id AND o.table_name=?
                """, [table.table])
                names = tuple(item[0] for item in cursor.description)
                count, quarantined = 0, 0
                next_progress = 100000
                while batch := cursor.fetchmany(512):
                    output_rows, mappings = [], []
                    for raw in batch:
                        row = dict(zip(names, raw))
                        if row["lineage"] is None:
                            raise ValueError("source observation lacks graph lineage")
                        if row["_field_quality"] != "[]":
                            quarantined += 1
                            continue
                        oid = row["_observation_id"]
                        record_id = "r:" + hashlib.sha256(f"{view_id}|{table.table}|{oid}".encode()).hexdigest()
                        values = tuple(
                            project_json(row[c.name], c.json_paths) if c.action == "json"
                            else redact_json(row[c.name], c.json_remove_paths, c.json_remove_if) if c.action == "redact_json"
                            else row[c.name] for c in kept
                        )
                        published = (record_id, *values)
                        output_rows.append(published)
                        mappings.append((table.table, record_id, oid,
                                         row_digest(source_columns, tuple(row[c] for c in source_columns)),
                                         row_digest(columns, published), row["lineage"]))
                    if output_rows:
                        public.execute("BEGIN")
                        casts = ["VARCHAR", *(types[c.name].replace("TIMESTAMP WITH TIME ZONE", "TIMESTAMPTZ") for c in kept)]
                        public.execute(
                            f"INSERT INTO {quote_identifier(table.table)} SELECT " + ",".join(f"unnest(?::{kind}[])" for kind in casts),
                            [[row[index] for row in output_rows] for index in range(len(columns))],
                        )
                        public.execute("COMMIT")
                        # Use a separate cursor so the source stream is not replaced by writes.
                        writer = private.cursor()
                        try:
                            writer.execute("BEGIN")
                            writer.execute(
                                "INSERT INTO record_map SELECT " + ",".join("unnest(?::VARCHAR[])" for _ in range(6)),
                                [[row[index] for row in mappings] for index in range(6)],
                            )
                            writer.execute("COMMIT")
                        finally:
                            writer.close()
                    count += len(output_rows)
                    if count >= next_progress:
                        print(f"[serving] {table.table}: {count} rows", flush=True)
                        next_progress += 100000
                inventory.append({
                    "table": table.table, "status": "public", "rows": count, "quarantined_rows_excluded": quarantined,
                    "columns": [{"name": name, "type": "VARCHAR" if name == "_record_id" else types[name]} for name in columns],
                })
                print(f"[serving] {table.table}: complete ({count} rows, {quarantined} quarantined excluded)", flush=True)
            private.execute("DETACH ledger")
            private.execute("DETACH graph")
    for path, state in inputs.items():
        if (path.stat().st_size, path.stat().st_mtime_ns) != state:
            raise ValueError("source changed during public projection")
    if any(file_sha256(Path(__file__).with_name(name)) != digest for name, digest in implementation.items()):
        raise ValueError("projection implementation changed during the build")
    result = {
        "status": "complete", "visibility": "private_build", "serving_view_id": view_id,
        "snapshot_id": snapshot_id, "ledger_bundle": str(ledger_bundle),
        "ledger_sha256": ledger["database"]["sha256"], "graph_id": graph_report["graph_id"],
        "implementation_sha256": implementation, "policy": policy.model_dump(mode="json"),
        "tables": inventory,
        "public_database": {"path": public_path.name, "sha256": file_sha256(public_path)},
        "private_mapping": {"path": mapping_path.name, "sha256": file_sha256(mapping_path)},
        "release_approved": False,
    }
    (output / "serving_report.json").write_text(json.dumps(result, indent=2) + "\n")
    return result

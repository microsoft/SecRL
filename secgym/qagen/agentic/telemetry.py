# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Inspect immutable telemetry sources before selecting reconciliation rules."""

from __future__ import annotations

import csv
import hashlib
import json
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import duckdb

from .contracts import Contract, Identifier, NonnegativeInt, PositiveInt, SnapshotManifest, Text
from .columns import (
    BASELINE_ORIGINAL_NAMES, COLUMN_POLICY_VERSION, DIAGNOSTIC_ALIASES,
    ColumnBinding, canonical_groups, checked_projection, column_bindings,
)
from .sources import CORE_TABLES, Catalog, digest, make_catalog, quote_identifier


SQL_TYPES = {
    "string": "VARCHAR", "guid": "VARCHAR", "dynamic": "VARCHAR", "timespan": "VARCHAR",
    "datetime": "TIMESTAMPTZ", "int": "INTEGER", "long": "BIGINT",
    "real": "DOUBLE", "decimal": "DOUBLE", "bool": "BOOLEAN",
}
class TelemetryFinding(Contract):
    column: Text
    kind: Literal["invalid_json", "invalid_cast", "extra_column_nonempty"]
    rows: PositiveInt
    sample_record_ordinals: tuple[PositiveInt, ...]


class CsvInspection(Contract):
    rows: NonnegativeInt
    columns: NonnegativeInt
    extra_columns: tuple[Text, ...]
    columns_missing_metadata: tuple[Text, ...]
    metadata_columns_absent_from_file: tuple[Text, ...]
    findings: tuple[TelemetryFinding, ...]
    column_mapping: tuple[ColumnBinding, ...]
    canonical_columns: tuple[Text, ...]


class FileInspection(Contract):
    source_id: Identifier
    table: Identifier
    path: Text
    status: Literal["scanned", "error"]
    inspection: CsvInspection | None
    error: Text | None = None


@dataclass
class TableInspection:
    baseline_columns: set[str]
    csv_rows: int = 0
    csv_files: int = 0


def attach_baseline(con: duckdb.DuckDBPyConnection, path: Path) -> None:
    # DuckDB does not accept a bound filename parameter in ATTACH.
    literal = str(path).replace("'", "''")
    con.execute(f"ATTACH '{literal}' AS baseline (READ_ONLY)")


def load_source_bundle(directory: Path) -> tuple[Catalog, dict[str, object]]:
    report = json.loads((directory / "report.json").read_text())
    if report.get("status") not in ("complete", "complete_with_blocks"):
        raise ValueError("source bundle is not a completed reconciliation")
    for name, expected in report["outputs"].items():
        if Path(name).name != name or (directory / name).is_symlink():
            raise ValueError(f"invalid bundle member: {name}")
        content = (directory / name).read_bytes()
        if len(content) != expected["size_bytes"] or hashlib.sha256(content).hexdigest() != expected["sha256"]:
            raise ValueError(f"source bundle checksum mismatch: {name}")
    pinned = SnapshotManifest.model_validate_json((directory / "snapshot.json").read_bytes())
    roots = report["input_roots"]
    catalog = make_catalog(Path(roots["tenant_db"]), Path(roots["incident_root"]))
    if pinned.snapshot_id != catalog.manifest.snapshot_id:
        raise ValueError("input hashes or normalizer differ from the pinned source bundle")
    if report["summary"]["snapshot_id"] != pinned.snapshot_id:
        raise ValueError("report and snapshot identities differ")
    return catalog, report


def reserve_output(output: Path, catalog: Catalog) -> Path:
    output = output.resolve()
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    for root in (catalog.tenant_db.parent, catalog.incident_root):
        if output.is_relative_to(root) or root.is_relative_to(output):
            raise ValueError("output must be outside and must not contain source directories")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    return output


def stage_csv(
    con: duckdb.DuckDBPyConnection, path: Path, table: str,
) -> tuple[ColumnBinding, ...]:
    """Parse source CSV with Python; JSON-lines transfer avoids CSV reinterpretation."""
    csv.field_size_limit(100_000_000)
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream, delimiter="❖", strict=True)
        try:
            header = next(reader, None)
            if not header:
                raise ValueError(f"missing CSV header: {path}")
            names = [name.lstrip("\ufeff").strip() for name in header]
            if any(name.casefold() == "source_record" for name in names):
                raise ValueError("source_record is reserved for source provenance")
            bindings = column_bindings(names, table)
            with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", suffix=".jsonl") as transfer:
                count = 0
                for count, values in enumerate(reader, 1):
                    if len(values) != len(names):
                        raise ValueError(f"CSV column count mismatch at {path}:record{count}")
                    transfer.write(json.dumps({"source_record": count, "values": values}, ensure_ascii=True) + "\n")
                transfer.flush()
                con.execute("DROP TABLE IF EXISTS input_rows")
                if count:
                    select = ", ".join(
                        f"\"values\"[{b.position + 1}] AS {quote_identifier(b.storage_name)}" for b in bindings
                    )
                    con.execute(
                        "CREATE TEMP TABLE input_rows AS SELECT source_record," + select
                        + " FROM read_json(?,format='newline_delimited',"
                          "columns={source_record:'BIGINT',values:'VARCHAR[]'},maximum_object_size=100000000)",
                        [transfer.name],
                    )
                else:
                    definitions = ", ".join(f"{quote_identifier(b.storage_name)} VARCHAR" for b in bindings)
                    con.execute(f"CREATE TEMP TABLE input_rows(source_record BIGINT,{definitions})")
        except csv.Error as error:
            raise ValueError(f"invalid CSV at {path}: {error}") from error
    return bindings


def scan_csv(
    con: duckdb.DuckDBPyConnection, path: Path, metadata: dict[str, str],
    baseline_columns: set[str], *, table: str = "Synthetic",
) -> CsvInspection:
    bindings = stage_csv(con, path, table)
    columns = [b.original_name for b in bindings]
    storage = {b.original_name: b.storage_name for b in bindings}
    baseline_originals = {
        BASELINE_ORIGINAL_NAMES.get(name, name) if table == "AzureDiagnostics" else name for name in baseline_columns
    }
    unexplained = sorted(set(columns) - set(metadata) - {"rn", "_rid"})
    missing = sorted(set(metadata) - set(columns))
    # Validate approved aliases, but keep original fields intact for source auditing.
    checked_projection(con, "input_rows", bindings, "source_record", table=table)
    checks: list[tuple[str, Literal["invalid_json", "invalid_cast", "extra_column_nonempty"], str]] = []
    for column in columns:
        if column in ("_rid", "rn"):
            continue
        kind = metadata.get(column)
        if kind is None:
            continue
        if kind not in SQL_TYPES:
            raise ValueError(f"unsupported declared source type: {column}: {kind}")
        expr = quote_identifier(storage[column])
        present = f"{expr} IS NOT NULL AND {expr}<>''"
        if kind == "dynamic":
            checks.append((column, "invalid_json", f"({present}) AND NOT json_valid({expr})"))
        elif kind == "bool":
            checks.append((column, "invalid_cast", f"({present}) AND lower({expr}) NOT IN ('true','false')"))
        elif SQL_TYPES[kind] != "VARCHAR":
            cast = f"try_cast({expr} AS {SQL_TYPES[kind]})"
            predicate = f"({present}) AND {cast} IS NULL"
            if kind in ("real", "decimal"):
                predicate = f"({present}) AND ({cast} IS NULL OR NOT isfinite({cast}))"
            elif kind in ("int", "long"):
                predicate = f"({present}) AND ({cast} IS NULL OR try_cast({expr} AS DOUBLE)<>{cast})"
            checks.append((column, "invalid_cast", predicate))
        if column not in baseline_originals:
            checks.append((column, "extra_column_nonempty", present))
    selections = ["count(*)"] + [f"count(*) FILTER(WHERE {predicate})" for _, _, predicate in checks]
    values = con.execute("SELECT " + ",".join(selections) + " FROM input_rows").fetchone()
    findings = []
    for (column, issue, predicate), count in zip(checks, values[1:]):
        if count:
            sample = [r[0] for r in con.execute(
                f"SELECT source_record FROM input_rows WHERE {predicate} ORDER BY source_record LIMIT 3"
            ).fetchall()]
            findings.append(TelemetryFinding(
                column=column, kind=issue, rows=count, sample_record_ordinals=tuple(sample),
            ))
    return CsvInspection(
        rows=values[0], columns=len(columns),
        extra_columns=tuple(sorted(set(columns) - baseline_originals - {"rn", "_rid"})),
        columns_missing_metadata=tuple(unexplained), metadata_columns_absent_from_file=tuple(missing),
        findings=tuple(findings), column_mapping=bindings, canonical_columns=tuple(canonical_groups(bindings)),
    )


def audit_telemetry(source_bundle: Path, output: Path) -> dict[str, object]:
    catalog, source_report = load_source_bundle(source_bundle.resolve())
    output = reserve_output(output, catalog)
    files: list[FileInspection] = []
    tables: dict[str, TableInspection] = {}
    fatal = False
    with tempfile.TemporaryDirectory(prefix="spill-", dir=output) as spill:
        with duckdb.connect(config={"memory_limit": "1GB", "threads": 1}) as con:
            con.execute("SET TimeZone='UTC'")
            con.execute("SET preserve_insertion_order=true")
            con.execute("SET temp_directory=?", [spill])
            attach_baseline(con, catalog.tenant_db)
            baseline_tables = {r[0] for r in con.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_catalog='baseline'"
            ).fetchall()}
            for source in catalog.csv_sources:
                if source.table in CORE_TABLES:
                    continue
                if source.table not in tables:
                    columns = {r[0] for r in con.execute(
                        f"DESCRIBE baseline.{quote_identifier(source.table)}"
                    ).fetchall()} if source.table in baseline_tables else set()
                    tables[source.table] = TableInspection(columns)
                table = tables[source.table]
                try:
                    scanned = scan_csv(con, source.path, catalog.metadata[source.meta], table.baseline_columns, table=source.table)
                except (duckdb.Error, ValueError) as error:
                    fatal = True
                    files.append(FileInspection(
                        source_id=source.source_id, table=source.table, status="error",
                        error=str(error), path=source.path.relative_to(catalog.incident_root).as_posix(),
                        inspection=None,
                    ))
                    print(f"[telemetry-audit] ERROR {source.path.name}: {error}", flush=True)
                    continue
                table.csv_rows += scanned.rows
                table.csv_files += 1
                files.append(FileInspection(
                    source_id=source.source_id, table=source.table, status="scanned",
                    path=source.path.relative_to(catalog.incident_root).as_posix(), inspection=scanned,
                ))
            for table, data in tables.items():
                print(f"[telemetry-audit] {table}: {data.csv_files} files / {data.csv_rows} rows", flush=True)
    catalog.verify_unchanged()
    counters = Counter()
    for row in files:
        if row.inspection is not None:
            for finding in row.inspection.findings:
                counters[finding.kind] += finding.rows
            counters["columns_missing_metadata"] += len(row.inspection.columns_missing_metadata)
    summary = {
        "source_snapshot_id": catalog.manifest.snapshot_id,
        "csv_files_scanned": sum(r.status == "scanned" for r in files),
        "csv_files_failed": sum(r.status == "error" for r in files),
        "csv_telemetry_rows": sum(r.inspection.rows for r in files if r.inspection is not None),
        "csv_telemetry_tables": len(tables),
        "finding_cells": {k: v for k, v in counters.items() if v}, "inputs_unchanged": True,
    }
    report = {
        "schema_version": "1", "visibility": "private_build",
        "status": "error" if fatal else "needs_policy_review" if any(counters.values()) else "scanned",
        "summary": summary, "files": [f.model_dump(mode="json") for f in files],
        "source_reconciliation_status": source_report["status"],
        "limitations": [
            "This scans source types, JSON and schemas; it does not yet merge or deduplicate telemetry.",
            "Finding counts are cells, not distinct affected rows.",
            "No raw input, existing graph or source record was modified.",
        ],
    }
    with (output / "telemetry_audit.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    return report


def normalize_diagnostics(source_bundle: Path, output: Path) -> dict[str, object]:
    """Materialize column-normalized streams; do not claim cross-export row deduplication."""
    catalog, source_report = load_source_bundle(source_bundle.resolve())
    output = reserve_output(output, catalog)
    implementation = {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in ("columns.py", "telemetry.py")
    }
    database = output / "diagnostics.duckdb"
    mappings = []
    results = []
    with tempfile.TemporaryDirectory(prefix="spill-", dir=output) as spill:
        with duckdb.connect(str(database), config={"memory_limit": "1GB", "threads": 1}) as con:
            con.execute("SET TimeZone='UTC'")
            con.execute("SET preserve_insertion_order=true")
            con.execute("SET temp_directory=?", [spill])
            attach_baseline(con, catalog.tenant_db)
            con.execute("CREATE SCHEMA imported")
            con.execute("CREATE SCHEMA csv_exports")
            con.execute("""
                CREATE TABLE alias_origins(
                    source_id VARCHAR,source_record BIGINT,canonical_column VARCHAR,original_column VARCHAR
                )
            """)
            baseline_columns = [r[0] for r in con.execute("DESCRIBE baseline.AzureDiagnostics").fetchall()]
            bindings = column_bindings(baseline_columns, "AzureDiagnostics", baseline=True)
            # CSV streams are staged and consumed one at a time to bound memory.
            csv_sources = [s for s in catalog.csv_sources if s.table == "AzureDiagnostics"]
            for index in range(len(csv_sources) + 1):
                if index == 0:
                    source_id, relation, locator, target = (
                        catalog.tenant_source_id, "baseline.AzureDiagnostics", "_rid", "imported.AzureDiagnostics",
                    )
                    locator_kind = "duckdb_rid"
                else:
                    source = csv_sources[index - 1]
                    bindings = stage_csv(con, source.path, source.table)
                    source_id, relation, locator, target = (
                        source.source_id, "input_rows", "source_record", "csv_exports.AzureDiagnostics",
                    )
                    locator_kind = "csv_record_ordinal"
                    for binding in bindings:
                        if binding.canonical_name in DIAGNOSTIC_ALIASES:
                            if catalog.metadata[source.meta].get(binding.original_name) != "string":
                                raise ValueError(f"alias field requires declared string type: {binding.original_name}")
                if any(b.storage_name.casefold() in ("_source_id", "_source_record") for b in bindings):
                    raise ValueError("source contains reserved provenance column names")
                rows, keys, nonnull = con.execute(
                    f"SELECT count(*),count(DISTINCT {quote_identifier(locator)}),count({quote_identifier(locator)}) FROM {relation}"
                ).fetchone()
                if rows != keys or rows != nonnull:
                    raise ValueError(f"nonunique or missing source record locators: {source_id}")
                projection = checked_projection(con, relation, bindings, locator, table="AzureDiagnostics")
                con.execute(
                    f"CREATE OR REPLACE TEMP TABLE canonical_rows AS SELECT {projection},"
                    f"?::VARCHAR AS _source_id,{quote_identifier(locator)} AS _source_record FROM {relation}",
                    [source_id],
                )
                if index <= 1:
                    con.execute(f"CREATE TABLE {target} AS SELECT * FROM canonical_rows")
                else:
                    existing = {r[0].casefold(): r[1] for r in con.execute(f"DESCRIBE {target}").fetchall()}
                    incoming = {r[0]: r[1] for r in con.execute("DESCRIBE canonical_rows").fetchall()}
                    for name, kind in incoming.items():
                        if name.casefold() not in existing:
                            con.execute(f"ALTER TABLE {target} ADD COLUMN {quote_identifier(name)} {kind}")
                        elif existing[name.casefold()] != kind:
                            raise ValueError(f"CSV storage types conflict for {name}")
                    con.execute(f"INSERT INTO {target} BY NAME SELECT * FROM canonical_rows")
                checks = []
                for binding in bindings:
                    original = quote_identifier(binding.storage_name)
                    canonical = quote_identifier(binding.canonical_name)
                    if binding.canonical_name in DIAGNOSTIC_ALIASES:
                        expected = f"nullif(s.{original},'')"
                        predicate = f"({expected} IS NOT NULL AND {expected} IS DISTINCT FROM n.{canonical})"
                    else:
                        predicate = f"s.{original} IS DISTINCT FROM n.{canonical}"
                    checks.append(f"count(*) FILTER(WHERE {predicate})")
                differences = con.execute(
                    "SELECT " + ",".join(checks) + f" FROM {relation} s JOIN canonical_rows n"
                    f" ON s.{quote_identifier(locator)}=n._source_record"
                ).fetchone()
                if any(differences):
                    raise ValueError(f"normalized output changed a populated source value: {source_id}")
                if con.execute("SELECT count(*) FROM canonical_rows").fetchone()[0] != rows:
                    raise ValueError("normalization changed the source row count")
                field_counts = {}
                for canonical, group in canonical_groups(bindings).items():
                    if canonical not in DIAGNOSTIC_ALIASES:
                        continue
                    populated = con.execute(
                        f"SELECT count({quote_identifier(canonical)}) FROM canonical_rows"
                    ).fetchone()[0]
                    field_counts[canonical] = populated
                    for binding in group:
                        con.execute(
                            f"INSERT INTO alias_origins SELECT ?,{quote_identifier(locator)},?,?"
                            f" FROM {relation} WHERE nullif({quote_identifier(binding.storage_name)},'') IS NOT NULL",
                            [source_id, canonical, binding.original_name],
                        )
                mappings.append({
                    "source_id": source_id, "locator_kind": locator_kind,
                    "columns": [b.model_dump(mode="json") for b in bindings],
                })
                results.append({
                    "source_id": source_id, "target": target, "rows": rows,
                    "source_columns": len(bindings), "canonical_columns": len(canonical_groups(bindings)),
                    "populated_canonical_fields": field_counts, "populated_value_mismatches": 0,
                })
            con.execute("CHECKPOINT")
    catalog.verify_unchanged()
    for name, sha in implementation.items():
        if hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() != sha:
            raise ValueError("column normalizer implementation changed during build")
    db_sha = hashlib.sha256()
    with database.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            db_sha.update(chunk)
    (output / "column_maps.json").write_text(json.dumps(mappings, indent=2) + "\n")
    report = {
        "schema_version": "1", "status": "complete", "visibility": "private_build",
        "source_snapshot_id": catalog.manifest.snapshot_id,
        "column_policy_version": COLUMN_POLICY_VERSION, "implementation_sha256": implementation,
        "normalization_id": "columns:" + digest([catalog.manifest.snapshot_id, COLUMN_POLICY_VERSION, implementation]),
        "source_reconciliation_status": source_report["status"],
        "canonical_aliases": DIAGNOSTIC_ALIASES,
        "streams": results, "source_stream_count": len(results),
        "imported_rows": sum(r["rows"] for r in results if r["target"].startswith("imported.")),
        "csv_rows": sum(r["rows"] for r in results if r["target"].startswith("csv_exports.")),
        "inputs_unchanged": True, "populated_value_mismatches": 0,
        "database": {"path": database.name, "sha256": db_sha.hexdigest(), "size_bytes": database.stat().st_size},
        "column_map_sha256": hashlib.sha256((output / "column_maps.json").read_bytes()).hexdigest(),
        "limitations": [
            "Imported and CSV streams remain separate: these row counts overlap and are not additive unique events.",
            "Only the seven approved column alias groups are consolidated. Other fields are unchanged.",
            "No dynamic JSON repair, graph construction, or release approval is implied.",
        ],
    }
    (output / "column_report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Read-only source catalog and latest-state reconciliation for v1."""

from __future__ import annotations

import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Iterator, Literal

import duckdb
from pydantic import AwareDatetime, JsonValue

from .contracts import (
    SELECTED_INCIDENTS, CaseManifest, Contract, Digest, HistoricalMembership, Identifier,
    NonnegativeInt, PositiveInt, SnapshotManifest, SourceFile, Text,
)


NORMALIZATION_VERSION = "source-normalization-v1.1"
CORE_TABLES = ("SecurityIncident", "SecurityAlert")
TECHNICAL_COLUMNS = {"_rid", "rn"}
JSON_COLUMNS = {
    "SecurityAlert": {"Entities", "ExtendedProperties", "ExtendedLinks"},
}
NON_OPERATIONAL = {
    "SecurityIncident", "SecurityAlert", "Alert", "AlertInfo", "AlertEvidence", "Anomalies",
    "AADUserRiskEvents", "DeviceInfo", "DeviceNetworkInfo", "DeviceFileCertificateInfo",
    "IntuneDevices", "IntuneDeviceComplianceOrg", "AADRiskyUsers", "ThreatIntelligenceIndicator",
    "Watchlist", "HuntingBookmark", "AzureMetrics", "Heartbeat", "Usage", "Operation",
    "SentinelAudit", "SentinelHealth", "LAQueryLogs", "LASummaryLogs",
}
TIME_COLUMNS = ("Timestamp", "CreatedDateTime", "ActivityDateTime", "StartTime", "TimeGenerated")


def json_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value: object) -> str:
    return hashlib.sha256(json_text(value).encode("utf-8")).hexdigest()


def parse_time(value: object) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("expected an ISO timestamp")
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("timestamp must have a timezone")
    return result.astimezone(timezone.utc)


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


class Origin(Contract):
    source_id: Identifier
    locator: Text


class Observation(Contract):
    observation_id: Identifier
    table: Identifier
    tenant_id: Identifier
    entity_key: Text
    updated_at: AwareDatetime
    content_sha256: Digest
    fields_json: Text
    origins: tuple[Origin, ...]

    def fields(self) -> dict[str, JsonValue]:
        return json.loads(self.fields_json)


class SourceIssue(Contract):
    code: Identifier
    severity: Literal["blocked", "warning"]
    table: Identifier
    tenant_id: str | None
    entity_key: str | None
    message: Text
    origins: tuple[Origin, ...]
    fields: tuple[str, ...] = ()


class ObservationReference(Contract):
    observation_id: Identifier
    table: Identifier
    content_sha256: Digest
    origins: tuple[Origin, ...]


class MembershipTransition(Contract):
    tenant_id: Identifier
    incident_id: PositiveInt
    alert_id: Identifier
    last_present_at: AwareDatetime
    first_absent_at: AwareDatetime
    before_evidence_id: Identifier
    after_evidence_id: Identifier
    current_member_again: bool


class RemovedMembership(Contract):
    tenant_id: Identifier
    membership: HistoricalMembership


class CaseResult(Contract):
    incident_id: PositiveInt
    status: Literal["ready", "ready_with_exclusions", "blocked"]
    manifest: CaseManifest | None
    blocking_reasons: tuple[Text, ...]
    missing_alert_ids: tuple[Identifier, ...]
    conflicting_alert_ids: tuple[Identifier, ...]
    coverage_start: AwareDatetime | None
    coverage_end: AwareDatetime | None


class TableCoverage(Contract):
    table: Identifier
    present_in_baseline: bool
    baseline_rows: NonnegativeInt
    baseline_time_column: str | None
    baseline_min_time: AwareDatetime | None
    baseline_max_time: AwareDatetime | None
    baseline_null_times: NonnegativeInt | None
    baseline_hour_bins: NonnegativeInt
    operational: bool
    csv_source_ids: tuple[Identifier, ...]
    csv_rows_reconciled: bool = False


@dataclass(frozen=True)
class CsvSource:
    path: Path
    table: str
    meta: Path
    source_id: str


@dataclass
class Catalog:
    manifest: SnapshotManifest
    tenant_db: Path
    tenant_source_id: str
    incident_root: Path
    csv_sources: tuple[CsvSource, ...]
    stats: dict[Path, tuple[int, int]]
    metadata: dict[Path, dict[str, str]]

    def verify_unchanged(self) -> None:
        if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != self.manifest.normalizer_sha256:
            raise ValueError("source normalizer changed during reconciliation")
        for path, before in self.stats.items():
            current = path.stat()
            if (current.st_size, current.st_mtime_ns) != before:
                raise ValueError(f"input changed during reconciliation: {path}")
        now = discover_files(self.tenant_db, self.incident_root)
        if set(now.values()) != set(self.stats):
            raise ValueError("source file inventory changed during reconciliation")


def discover_files(tenant_db: Path, incident_root: Path) -> dict[str, Path]:
    if not tenant_db.is_file() or not incident_root.is_dir():
        raise ValueError("tenant database and incident-export directory must exist")
    result = {"tenant/tenant.duckdb": tenant_db}
    folders = [p for p in incident_root.iterdir() if p.is_dir() and p.name.startswith("incident_")]
    if not folders:
        raise ValueError("no incident export folders found")
    for folder in sorted(folders):
        for path in sorted(folder.rglob("*")):
            if path.suffix not in (".csv", ".meta"):
                continue
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(incident_root):
                raise ValueError(f"source must be a regular file inside the input root: {path}")
            result["incidents/" + path.relative_to(incident_root).as_posix()] = path
    if not any(name.endswith(".csv") for name in result):
        raise ValueError("no incident CSV files found")
    return result


def read_metadata(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in data.items()):
        raise ValueError(f"invalid table metadata: {path}")
    return {k.lstrip("\ufeff").strip(): v for k, v in data.items()}


def make_catalog(tenant_db: Path, incident_root: Path) -> Catalog:
    tenant_db, incident_root = tenant_db.resolve(), incident_root.resolve()
    paths = discover_files(tenant_db, incident_root)
    stats = {}
    sources = []
    by_path = {}
    for logical, path in sorted(paths.items()):
        before = path.stat()
        sha = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                sha.update(chunk)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError(f"input changed while hashing: {path}")
        stats[path] = (before.st_size, before.st_mtime_ns)
        source = SourceFile(
            source_id="src:" + digest([logical, sha.hexdigest()]), path=logical,
            sha256=sha.hexdigest(), size_bytes=before.st_size,
            source_kind="tenant_duckdb" if path == tenant_db else "metadata" if path.suffix == ".meta" else "incident_csv",
        )
        sources.append(source)
        by_path[path] = source
    metadata = {p: read_metadata(p) for p in stats if p.suffix == ".meta"}
    csv_sources = []
    for path in sorted(p for p in stats if p.suffix == ".csv"):
        if path.parent.name.startswith("incident_"):
            table, meta = path.stem, path.with_suffix(".meta")
        else:
            table = path.parent.name
            candidates = sorted(path.parent.glob("*.meta"))
            meta = candidates[0] if candidates else path.parent.parent / f"{table}.meta"
            if len(candidates) > 1 and any(metadata[p] != metadata[candidates[0]] for p in candidates):
                raise ValueError(f"conflicting metadata in chunked table: {path.parent}")
        if meta not in metadata:
            raise ValueError(f"missing metadata for {path}")
        csv_sources.append(CsvSource(path, table, meta, by_path[path].source_id))
    normalizer_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    snapshot_id = "snapshot:" + digest({
        "normalization": NORMALIZATION_VERSION,
        "normalizer_sha256": normalizer_sha256,
        "sources": [s.model_dump(mode="json") for s in sources],
    })
    manifest = SnapshotManifest(
        snapshot_id=snapshot_id, created_at=datetime.now(timezone.utc), sources=tuple(sources),
        normalization_version=NORMALIZATION_VERSION, normalizer_sha256=normalizer_sha256,
        provenance_limits=(
            "The full original tenant CSV is unavailable; the DuckDB baseline includes earlier merge/repair operations.",
            "I1 reconciles incident/alert state. Other CSV tables are inventoried and readable but not declared deduplicated against the baseline.",
            "Coverage describes observed baseline rows, not an acquisition-completeness certificate.",
        ),
    )
    return Catalog(manifest, tenant_db, by_path[tenant_db].source_id, incident_root, tuple(csv_sources), stats, metadata)


def normalize_value(value: object, kind: str, *, parse_json: bool) -> JsonValue:
    if value is None or value == "":
        return None
    if kind == "datetime" or isinstance(value, datetime):
        return parse_time(value).isoformat(timespec="microseconds")
    if parse_json or kind == "dynamic":
        if isinstance(value, str):
            return json.loads(value, parse_constant=lambda v: invalid_json_constant(v))
        return json.loads(json_text(value))
    if kind in ("int", "long"):
        number = Decimal(str(value))
        if not number.is_finite() or number != number.to_integral_value():
            raise ValueError("integer column contains a noninteger or nonfinite value")
        return int(number)
    if kind in ("real", "decimal") or isinstance(value, Decimal):
        number = float(str(value))
        if not math.isfinite(number):
            raise ValueError("nonfinite numeric source value")
        return number
    if kind == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.casefold() in ("true", "false"):
            return value.casefold() == "true"
        raise ValueError("invalid boolean source value")
    if isinstance(value, (str, int, float, bool)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("nonfinite numeric source value")
        return value
    raise ValueError(f"unsupported source value type: {type(value).__name__}")


def invalid_json_constant(value: str) -> JsonValue:
    raise ValueError(f"invalid JSON numeric constant: {value}")


def normalize_row(row: dict[str, object], metadata: dict[str, str], table: str) -> dict[str, JsonValue]:
    result = {}
    for name, value in row.items():
        if name in TECHNICAL_COLUMNS:
            continue
        if table == "SecurityAlert" and name == "CompromisedEntity" and value == "N/A":
            value = None
        try:
            result[name] = normalize_value(value, metadata.get(name, "string"), parse_json=name in JSON_COLUMNS.get(table, set()))
        except (ValueError, TypeError, ArithmeticError) as error:
            raise ValueError(f"{table}.{name}: {error}") from error
    return result


def row_identity(row: dict[str, object], table: str) -> tuple[str, str]:
    tenant = row.get("TenantId")
    if not isinstance(tenant, str) or not tenant.strip():
        raise ValueError(f"{table} row is missing TenantId")
    if table == "SecurityIncident":
        value = row.get("IncidentNumber")
        try:
            number = Decimal(str(value))
        except ArithmeticError as error:
            raise ValueError("invalid incident number") from error
        if not number.is_finite() or number != number.to_integral_value() or number <= 0:
            raise ValueError("invalid incident number")
        return tenant.lower(), str(int(number))
    alert = row.get("SystemAlertId")
    if not isinstance(alert, str) or not alert.strip():
        raise ValueError("alert row is missing SystemAlertId")
    return tenant.lower(), alert.lower()


def make_observation(row: dict[str, object], meta: dict[str, str], table: str, origin: Origin) -> Observation:
    tenant, key = row_identity(row, table)
    fields = normalize_row(row, meta, table)
    updated_at = parse_time(fields.get("TimeGenerated"))
    if table == "SecurityIncident":
        guid = fields.get("IncidentName")
        if not isinstance(guid, str) or not guid:
            raise ValueError("incident row is missing IncidentName")
    canonical = json_text(fields)
    sha = digest({"table": table, "fields": fields})
    return Observation(
        observation_id="obs:" + sha, table=table, tenant_id=tenant, entity_key=key,
        updated_at=updated_at, content_sha256=sha, fields_json=canonical, origins=(origin,),
    )


def iter_csv(source: CsvSource) -> Iterator[tuple[dict[str, object], Origin]]:
    csv.field_size_limit(100_000_000)
    with source.path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream, delimiter="❖", strict=True)
        header = next(reader, None)
        if not header:
            raise ValueError(f"missing CSV header: {source.path}")
        names = [name.lstrip("\ufeff").strip() for name in header]
        if len(set(names)) != len(names) or any(not name for name in names):
            raise ValueError(f"duplicate or blank CSV header: {source.path}")
        for ordinal, values in enumerate(reader, 1):
            if len(names) != len(values):
                raise ValueError(f"CSV column count mismatch at {source.path}:record{ordinal}")
            yield dict(zip(names, values)), Origin(source_id=source.source_id, locator=f"csv-record:{ordinal}")


def iter_table_rows(con: duckdb.DuckDBPyConnection, catalog: Catalog, table: str) -> Iterator[tuple[dict[str, object], dict[str, str], Origin]]:
    schemas = [catalog.metadata[s.meta] for s in catalog.csv_sources if s.table == table]
    common_meta = {}
    for schema in schemas:
        for name, kind in schema.items():
            if name in common_meta and common_meta[name] != kind:
                raise ValueError(f"inconsistent source column types: {table}.{name}")
            common_meta[name] = kind
    tables = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
    if table in tables:
        cursor = con.execute(f"SELECT * FROM {quote_identifier(table)} ORDER BY _rid")
        columns = [c[0] for c in cursor.description]
        while batch := cursor.fetchmany(4096):
            for values in batch:
                row = dict(zip(columns, values))
                yield row, common_meta, Origin(source_id=catalog.tenant_source_id, locator=f"{table}#rid:{row['_rid']}")
    for source in catalog.csv_sources:
        if source.table == table:
            for row, origin in iter_csv(source):
                yield row, catalog.metadata[source.meta], origin


def membership(observation: Observation) -> tuple[str, ...]:
    values = observation.fields().get("AlertIds")
    if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values):
        raise ValueError("AlertIds is missing or invalid; it is not a known empty list")
    return tuple(sorted({str(v).lower() for v in values}))


def comparable_fields(observation: Observation) -> dict[str, JsonValue]:
    result = observation.fields()
    if observation.table == "SecurityIncident":
        result["AlertIds"] = list(membership(observation))
    return result


@dataclass
class Reconciled:
    latest: dict[tuple[str, str], Observation]
    history: dict[tuple[str, str], tuple[Observation, ...]]
    references: tuple[ObservationReference, ...]
    issues: list[SourceIssue]
    source_rows: int


def reconcile_observations(observations: list[Observation], issues: list[SourceIssue], source_rows: int) -> Reconciled:
    grouped = defaultdict(list)
    by_id: dict[str, Observation] = {}
    for row in observations:
        old = by_id.get(row.observation_id)
        if old is not None:
            origins = tuple(sorted(set(old.origins + row.origins), key=lambda o: (o.source_id, o.locator)))
            row = old.model_copy(update={"origins": origins})
        by_id[row.observation_id] = row
    for row in by_id.values():
        grouped[(row.tenant_id, row.entity_key)].append(row)
    blocked = {(r.tenant_id, r.entity_key) for r in issues if r.severity == "blocked"}
    latest = {}
    history = {}
    for key, rows in sorted(grouped.items()):
        ordered = sorted(rows, key=lambda r: (r.updated_at, r.observation_id))
        times = defaultdict(list)
        for row in ordered:
            times[row.updated_at].append(row)
        if ordered[0].table == "SecurityIncident":
            guids = {row.fields().get("IncidentName") for row in ordered}
            if len(guids) != 1:
                issues.append(SourceIssue(
                    code="incident_identity_conflict", severity="blocked", table="SecurityIncident",
                    tenant_id=key[0], entity_key=key[1], message="Incident number maps to conflicting incident GUIDs.",
                    origins=tuple(o for r in ordered for o in r.origins),
                ))
                blocked.add(key)
        snapshots = []
        for stamp, versions in sorted(times.items()):
            try:
                variants = [comparable_fields(row) for row in versions]
            except ValueError as error:
                issues.append(SourceIssue(
                    code="invalid_membership", severity="blocked" if stamp == ordered[-1].updated_at else "warning",
                    table=ordered[0].table, tenant_id=key[0], entity_key=key[1],
                    message=str(error), origins=tuple(o for r in versions for o in r.origins),
                ))
                if stamp == ordered[-1].updated_at:
                    blocked.add(key)
                continue
            different = sorted(name for name in set().union(*(v.keys() for v in variants))
                               if len({json_text(v.get(name)) for v in variants}) > 1)
            if different:
                is_latest = stamp == ordered[-1].updated_at
                issues.append(SourceIssue(
                    code="latest_row_conflict" if is_latest else "historical_row_conflict",
                    severity="blocked" if is_latest else "warning", table=ordered[0].table,
                    tenant_id=key[0], entity_key=key[1],
                    message="Same-time source rows disagree; no source or row-ID preference applied.",
                    origins=tuple(o for r in versions for o in r.origins), fields=tuple(different),
                ))
                if is_latest:
                    blocked.add(key)
                continue
            snapshots.append(versions[0])
        if key not in blocked and snapshots and snapshots[-1].updated_at == ordered[-1].updated_at:
            latest[key] = snapshots[-1]
            history[key] = tuple(snapshots)
    references = tuple(ObservationReference(
        observation_id=r.observation_id, table=r.table, content_sha256=r.content_sha256, origins=r.origins,
    ) for r in sorted(by_id.values(), key=lambda r: r.observation_id))
    return Reconciled(latest, history, references, issues, source_rows)


def read_core(con: duckdb.DuckDBPyConnection, catalog: Catalog, table: str) -> Reconciled:
    observations, issues = [], []
    count = 0
    for row, meta, origin in iter_table_rows(con, catalog, table):
        count += 1
        tenant, key = row_identity(row, table)
        try:
            observations.append(make_observation(row, meta, table, origin))
            if table == "SecurityAlert" and row.get("CompromisedEntity") == "N/A":
                issues.append(SourceIssue(
                    code="missing_identity_placeholder_normalized", severity="warning", table=table,
                    tenant_id=tenant, entity_key=key,
                    message="CompromisedEntity 'N/A' treated as unavailable, like an empty value; original value remains at its source locator.",
                    origins=(origin,), fields=("CompromisedEntity",),
                ))
        except (ValueError, TypeError, ArithmeticError) as error:
            issues.append(SourceIssue(
                code="invalid_source_row", severity="blocked", table=table,
                tenant_id=tenant, entity_key=key, message=str(error), origins=(origin,),
            ))
    return reconcile_observations(observations, issues, count)


def derive_memberships(snapshot_id: str, incidents: Reconciled) -> tuple[tuple[RemovedMembership, ...], tuple[MembershipTransition, ...]]:
    parents = defaultdict(set)
    for (tenant, number), row in incidents.latest.items():
        for alert in membership(row):
            parents[(tenant, alert)].add(int(number))
    historical = []
    transitions = []
    ambiguous_histories = {(r.tenant_id, r.entity_key) for r in incidents.issues
                           if r.code in {"historical_row_conflict", "invalid_membership"}}
    for key, rows in sorted(incidents.history.items()):
        if key in ambiguous_histories:
            continue
        current = set(membership(rows[-1]))
        last_removal = {}
        for before, after in zip(rows, rows[1:]):
            for alert in sorted(set(membership(before)) - set(membership(after))):
                transition = MembershipTransition(
                    tenant_id=key[0], incident_id=int(key[1]), alert_id=alert,
                    last_present_at=before.updated_at, first_absent_at=after.updated_at,
                    before_evidence_id=before.observation_id, after_evidence_id=after.observation_id,
                    current_member_again=alert in current,
                )
                transitions.append(transition)
                last_removal[alert] = transition
        for alert, event in sorted(last_removal.items()):
            if alert in current:
                continue
            historical.append(RemovedMembership(
                tenant_id=key[0],
                membership=HistoricalMembership(
                    snapshot_id=snapshot_id, incident_id=int(key[1]), alert_id=alert,
                    last_present_at=event.last_present_at, first_absent_at=event.first_absent_at,
                    before_evidence_id=event.before_evidence_id, after_evidence_id=event.after_evidence_id,
                    other_current_incidents=tuple(sorted(parents[(key[0], alert)])),
                ),
            ))
    return tuple(historical), tuple(transitions)


def build_cases(snapshot_id: str, incidents: Reconciled, alerts: Reconciled) -> tuple[CaseResult, ...]:
    results = []
    for number in SELECTED_INCIDENTS:
        matches = [(key, row) for key, row in incidents.latest.items() if key[1] == str(number)]
        if len(matches) != 1:
            results.append(CaseResult(
                incident_id=number, status="blocked", manifest=None,
                blocking_reasons=("Latest incident state is missing, conflicting, or ambiguous across tenants.",),
                missing_alert_ids=(), conflicting_alert_ids=(), coverage_start=None, coverage_end=None,
            ))
            continue
        key, row = matches[0]
        fields = row.fields()
        ids = membership(row)
        alert_blocked = {issue.entity_key for issue in alerts.issues
                         if issue.tenant_id == key[0] and issue.severity == "blocked"}
        conflicting = tuple(a for a in ids if a in alert_blocked)
        missing = tuple(a for a in ids if (key[0], a) not in alerts.latest and a not in alert_blocked)
        exclusions = [f"missing-alert:{a}" for a in missing] + [f"conflicting-alert:{a}" for a in conflicting]
        if number == 5:
            exclusions.append("missing-alert:46f3d4b8-060c-4022-c190-4d88954a6a2e")
        if number == 322:
            exclusions.append("missing-source:SquidProxy")
        first, last = fields.get("FirstActivityTime"), fields.get("LastActivityTime")
        start = parse_time(first).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1) if first else None
        end = parse_time(last).replace(minute=0, second=0, microsecond=0) + timedelta(hours=1) if last else None
        label = fields.get("Classification")
        if label is not None and not isinstance(label, str):
            raise ValueError(f"invalid classification type for incident {number}")
        if number == 36 and label != "TruePositive":
            results.append(CaseResult(
                incident_id=number, status="blocked", manifest=None,
                blocking_reasons=("The latest row no longer supports incident 36's source-TP designation; review is required.",),
                missing_alert_ids=missing, conflicting_alert_ids=conflicting,
                coverage_start=start, coverage_end=end,
            ))
            continue
        if start is None or end is None or end <= start:
            exclusions.append("coverage:invalid-incident-window")
            start = end = None
        manifest = CaseManifest(
            snapshot_id=snapshot_id, incident_id=number, latest_incident_evidence_id=row.observation_id,
            source_classification=label, designation_basis="source_label" if number == 36 else "project_assumption",
            current_alert_ids=ids, exclusions=tuple(sorted(set(exclusions))),
        )
        results.append(CaseResult(
            incident_id=number, status="ready_with_exclusions" if exclusions else "ready",
            manifest=manifest, blocking_reasons=(), missing_alert_ids=missing,
            conflicting_alert_ids=conflicting, coverage_start=start, coverage_end=end,
        ))
    return tuple(results)


def measure_coverage(
    con: duckdb.DuckDBPyConnection, catalog: Catalog, cases: tuple[CaseResult, ...],
) -> tuple[tuple[TableCoverage, ...], list[dict[str, object]]]:
    tables = sorted(r[0] for r in con.execute("SHOW TABLES").fetchall() if not r[0].startswith("_"))
    csv_tables = {s.table for s in catalog.csv_sources}
    hourly = defaultdict(dict)
    records = []
    for table in sorted(set(tables) | csv_tables):
        source_ids = tuple(s.source_id for s in catalog.csv_sources if s.table == table)
        count, nulls, low, high, time_col, bins = 0, None, None, None, None, 0
        if table in tables:
            columns = {r[0]: r[1] for r in con.execute(f"DESCRIBE {quote_identifier(table)}").fetchall()}
            count = con.execute(f"SELECT count(*) FROM {quote_identifier(table)}").fetchone()[0]
            time_col = next((name for name in TIME_COLUMNS if name in columns and columns[name].startswith("TIMESTAMP")), None)
            if time_col:
                qcol, qtable = quote_identifier(time_col), quote_identifier(table)
                low, high, nulls = con.execute(
                    f"SELECT min({qcol}),max({qcol}),count(*) FILTER(WHERE {qcol} IS NULL) FROM {qtable}"
                ).fetchone()
                hours = con.execute(
                    f"SELECT date_trunc('hour',{qcol}),count(*) FROM {qtable} "
                    f"WHERE {qcol} IS NOT NULL GROUP BY 1 ORDER BY 1"
                ).fetchall()
                bins = len(hours)
                if table not in NON_OPERATIONAL:
                    hourly[table] = dict(hours)
        records.append(TableCoverage(
            table=table, present_in_baseline=table in tables, baseline_rows=count, baseline_time_column=time_col,
            baseline_min_time=low, baseline_max_time=high, baseline_null_times=nulls,
            baseline_hour_bins=bins, operational=table not in NON_OPERATIONAL,
            csv_source_ids=source_ids, csv_rows_reconciled=table in CORE_TABLES,
        ))
    case_coverage = []
    for case in cases:
        per_table = {}
        occupied = set()
        if case.coverage_start is not None and case.coverage_end is not None:
            for table, hours in hourly.items():
                matching = {time: count for time, count in hours.items()
                            if case.coverage_start <= time < case.coverage_end}
                if matching:
                    per_table[table] = sum(matching.values())
                    occupied.update(matching)
        case_coverage.append({
            "incident_id": case.incident_id, "basis": "imported_duckdb_operational_hour_bins",
            "start": case.coverage_start.isoformat() if case.coverage_start else None,
            "end": case.coverage_end.isoformat() if case.coverage_end else None,
            "operational_rows": sum(per_table.values()) if case.coverage_start else None,
            "occupied_hours": len(occupied) if case.coverage_start else None,
            "rows_by_table": per_table,
            "capture_completeness_certified": False,
            "claim_specific_evidence_certified": False,
        })
    return tuple(records), case_coverage


def write_models(path: Path, rows: object) -> None:
    if not isinstance(rows, (list, tuple)):
        raise TypeError("expected a materialized sequence of contracts")
    with path.open("x", encoding="utf-8") as stream:
        for row in rows:
            if not isinstance(row, Contract):
                raise TypeError("expected contract record")
            stream.write(row.model_dump_json() + "\n")


def reconcile_sources(tenant_db: Path, incident_root: Path, output: Path) -> dict[str, object]:
    tenant_db, incident_root, output = tenant_db.resolve(), incident_root.resolve(), output.resolve()
    if output.exists():
        raise ValueError(f"output already exists; choose a new directory: {output}")
    if output.is_relative_to(tenant_db.parent) or output.is_relative_to(incident_root):
        raise ValueError("output must be outside the source directories")
    if tenant_db.is_relative_to(output) or incident_root.is_relative_to(output):
        raise ValueError("output must not contain source inputs")
    catalog = make_catalog(tenant_db, incident_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    with duckdb.connect(str(tenant_db), read_only=True, config={"memory_limit": "512MB", "threads": 1}) as con:
        con.execute("SET TimeZone='UTC'")
        incidents = read_core(con, catalog, "SecurityIncident")
        alerts = read_core(con, catalog, "SecurityAlert")
        historical, transitions = derive_memberships(catalog.manifest.snapshot_id, incidents)
        cases = build_cases(catalog.manifest.snapshot_id, incidents, alerts)
        tables, coverage = measure_coverage(con, catalog, cases)
    issues = incidents.issues + alerts.issues
    write_models(output / "incidents.jsonl", list(incidents.latest.values()))
    write_models(output / "alerts.jsonl", list(alerts.latest.values()))
    write_models(output / "observation_references.jsonl", incidents.references + alerts.references)
    write_models(output / "historical_memberships.jsonl", historical)
    write_models(output / "membership_transitions.jsonl", transitions)
    write_models(output / "cases.jsonl", cases)
    write_models(output / "issues.jsonl", issues)
    write_models(output / "tables.jsonl", tables)
    current_alert_ids = {(tenant, aid) for (tenant, _), row in incidents.latest.items() for aid in membership(row)}
    blocked_alerts = {(r.tenant_id, r.entity_key) for r in alerts.issues if r.severity == "blocked"}
    observed_alert_ids = set(alerts.latest) | blocked_alerts
    blocked_incidents = {(r.tenant_id, r.entity_key) for r in incidents.issues if r.severity == "blocked"}
    catalog.verify_unchanged()
    summary = {
        "snapshot_id": catalog.manifest.snapshot_id,
        "source_files": len(catalog.manifest.sources),
        "incident_source_rows": incidents.source_rows,
        "alert_source_rows": alerts.source_rows,
        "latest_incidents": len(incidents.latest), "latest_alerts": len(alerts.latest),
        "incident_ids_seen": len(set(incidents.latest) | blocked_incidents),
        "alert_ids_seen": len(observed_alert_ids),
        "source_classifications": dict(Counter(str(r.fields().get("Classification") or "Unclassified")
                                              for r in incidents.latest.values())),
        "historical_removed_links": len(historical),
        "membership_removal_transitions": len(transitions),
        "current_incident_alert_links": sum(len(membership(r)) for r in incidents.latest.values()),
        "current_alert_ids": len(current_alert_ids),
        "current_alert_ids_without_resolved_alert": len(current_alert_ids - alerts.latest.keys()),
        "current_alert_ids_absent_from_sources": len(current_alert_ids - observed_alert_ids),
        "current_alert_ids_blocked": len(current_alert_ids & blocked_alerts),
        "baseline_source_tables": sum(r.present_in_baseline for r in tables),
        "baseline_source_rows": sum(r.baseline_rows for r in tables),
        "case_statuses": {str(c.incident_id): c.status for c in cases},
        "blocked_source_entities": len({(r.table, r.tenant_id, r.entity_key) for r in issues if r.severity == "blocked"}),
        "issue_counts": dict(Counter(r.code for r in issues)),
        "inputs_unchanged": True,
    }
    report = {
        "schema_version": "1", "visibility": "private_build",
        "normalization_version": NORMALIZATION_VERSION,
        "status": "complete_with_blocks" if summary["blocked_source_entities"] or any(c.status == "blocked" for c in cases) else "complete",
        "summary": summary, "case_coverage": coverage,
        "input_roots": {"tenant_db": str(tenant_db), "incident_root": str(incident_root)},
        "limitations": catalog.manifest.provenance_limits,
        "release_approved": False,
    }
    with (output / "snapshot.json").open("x", encoding="utf-8") as stream:
        stream.write(catalog.manifest.model_dump_json(indent=2) + "\n")
    report["outputs"] = {
        path.name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size_bytes": path.stat().st_size}
        for path in sorted(output.iterdir()) if path.is_file()
    }
    # The report is the completion marker; a failed build must not look consumable.
    with (output / "report.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    return report

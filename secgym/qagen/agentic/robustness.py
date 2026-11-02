# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Source-bound counterfactual checks in owned, disposable DuckDB/MySQL fixtures."""

from __future__ import annotations

from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
from typing import Literal

import duckdb
import mysql.connector
from pydantic import Field, model_validator

from .contracts import (
    ClaimCheck, Contract, Digest, Identifier, PublicCitation, QualifiedWitnessProgram,
    TaskRecord, Text, TypedAnswer, fingerprint, require_unique,
)
from .evidence import EvidenceVerifier, answer_from_rows
from .ledger import encode_json, file_sha256
from .mysql_serving import MYSQL_TYPES, mysql_column_name, mysql_identifier, mysql_value
from .qualified_witnesses import CANDIDATE_COLUMNS, CATALOG_COLUMNS, parse_proofs, supplied_query
from .query import Engine, PublicQueryEngine, QueryFailure, QueryLimits, Scalar
from .scoring import compare_typed_answers
from .serving import PUBLIC_TYPES, parse_json
from .sources import quote_identifier


ROBUSTNESS_VERSION = "isolated-source-robustness-v2"
RUNTIME_FILES = (
    "robustness.py", "contracts.py", "evidence.py", "qualified_witnesses.py",
    "query.py", "scoring.py", "serving.py", "mysql_serving.py", "ledger.py", "sources.py",
)


class CellEdit(Contract):
    citation: PublicCitation
    column: Text
    value: Scalar


class WitnessGroup(Contract):
    citations: tuple[PublicCitation, ...]

    @model_validator(mode="after")
    def nonempty_unique(self):
        if not self.citations or len(set(self.citations)) != len(self.citations):
            raise ValueError("witness groups require distinct nonempty citations")
        return self


class ProgramAnswers(Contract):
    by_program: dict[Identifier, TypedAnswer | None] = Field(min_length=1)


ExpectedAnswer = TypedAnswer | ProgramAnswers | Literal["baseline"] | None


class ClaimExpectation(Contract):
    claim_id: Identifier
    answer: ExpectedAnswer
    witnesses: tuple[WitnessGroup, ...] | Literal["baseline"]
    support: tuple[bool, ...] | Literal["baseline", False]


class RobustnessCase(Contract):
    case_id: Identifier
    rationale: Text
    scope: Literal["serving_contract", "portability_diagnostic"]
    edits: tuple[CellEdit, ...] = ()
    removed_records: tuple[PublicCitation, ...] = ()
    expected: tuple[ClaimExpectation, ...]

    @model_validator(mode="after")
    def explicit_case(self):
        if self.case_id == "baseline" or not (self.edits or self.removed_records):
            raise ValueError("a counterfactual requires a non-baseline ID and an actual intervention")
        require_unique(tuple(e.claim_id for e in self.expected), "expected claims")
        targets = [(edit.citation, edit.column) for edit in self.edits]
        if len(set(targets)) != len(targets) or len(set(self.removed_records)) != len(self.removed_records):
            raise ValueError("duplicate counterfactual targets")
        if any(edit.citation in self.removed_records or edit.column == "_record_id" for edit in self.edits):
            raise ValueError("cannot edit record locators or edit an omitted record")
        return self


class RobustnessPlan(Contract):
    policy_version: Literal["isolated-source-robustness-v1", "isolated-source-robustness-v2"] = ROBUSTNESS_VERSION
    task_fingerprint: Digest
    extra_source_records: tuple[PublicCitation, ...] = ()
    cases: tuple[RobustnessCase, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_cases(self):
        require_unique(tuple(case.case_id for case in self.cases), "robustness case IDs")
        if len(set(self.extra_source_records)) != len(self.extra_source_records):
            raise ValueError("duplicate extra source records")
        return self


class ObservedClaim(Contract):
    answers: tuple[TypedAnswer | None, ...]
    witnesses: tuple[WitnessGroup, ...]
    support: tuple[bool, ...]


class RobustnessCheck(Contract):
    case_id: Identifier
    claim_id: Identifier
    engine: Engine
    status: Literal["pass", "mismatch", "error"]
    observed: ObservedClaim | None
    reasons: tuple[Text, ...]
    error_code: Text | None = None


class RobustnessReport(Contract):
    policy_version: Literal["isolated-source-robustness-v1", "isolated-source-robustness-v2"] = ROBUSTNESS_VERSION
    task_fingerprint: Digest
    plan_fingerprint: Digest
    serving_view_id: Identifier
    status: Literal["pass", "mismatch", "error", "fixture_incomplete"]
    query_limits: QueryLimits
    implementation_sha256: dict[str, Digest]
    source_records_sha256: Digest
    backend_versions: dict[str, Text]
    probes: tuple[tuple[PublicCitation, ...], ...]
    checks: tuple[RobustnessCheck, ...]
    cases_not_run: tuple[Identifier, ...]
    full_snapshot_mysql_revalidated: Literal[False] = False
    semantic_plan_review_performed: Literal[False] = False
    source_databases_modified: Literal[False] = False
    admission_changed: Literal[False] = False
    release_approved: Literal[False] = False
    model_calls: Literal[0] = 0
    limitations: Text = (
        "Checks cover only the declared finite fixtures, expectations and citation subsets. "
        "They do not prove complete comparison cohorts, acquisition completeness, all candidate "
        "combinations or general sufficiency for absence/count/ranking claims. A portability "
        "diagnostic is not automatically a serving-contract defect. Independent semantic plan "
        "review and full-snapshot native validation remain required."
    )


def represented_json(value: object) -> str:
    """Vary whitespace/object-key order without rounding numeric tokens or changing array order."""
    if isinstance(value, dict):
        return "{" + ", ".join(json.dumps(key, ensure_ascii=True) + ": " + represented_json(value[key])
                               for key in reversed(value)) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(represented_json(item) for item in value) + "]"
    return encode_json(value)


def json_variant(text: str, operation: Literal["representation", "reverse_array", "prepend_array"],
                 *, path: tuple[str | int, ...] = (), member_json: str | None = None) -> str:
    """Paths locate bound fixture leaves, not semantic selectors in a gold query."""
    value = parse_json(text)

    def change(node, remaining):
        if isinstance(node, str):
            return encode_json(change(parse_json(node), remaining))
        if remaining:
            key, *tail = remaining
            if isinstance(node, dict) and isinstance(key, str) and key in node:
                return {name: change(child, tail) if name == key else child for name, child in node.items()}
            if isinstance(node, list) and type(key) is int and 0 <= key < len(node):
                return [change(child, tail) if index == key else child for index, child in enumerate(node)]
            raise ValueError("fixture JSON path does not resolve")
        if operation == "representation":
            raise ValueError("representation transforms the entire JSON text; do not supply a path")
        if not isinstance(node, list):
            raise ValueError("fixture array operation requires an actual array")
        if operation == "reverse_array":
            if len(node) < 2:
                raise ValueError("cannot test array order with fewer than two members")
            return list(reversed(node))
        if operation == "prepend_array" and member_json is not None:
            return [parse_json(member_json), *node]
        raise ValueError("unknown or incomplete JSON intervention")

    if operation == "representation":
        if path or member_json is not None:
            raise ValueError("representation accepts only the original JSON text")
        result = represented_json(value)
    else:
        if operation == "reverse_array" and member_json is not None:
            raise ValueError("array reversal does not accept a new member")
        result = encode_json(change(value, path))
    if result == text:
        raise ValueError("JSON intervention did not change the stored value")
    return result


def _citation_key(citation: PublicCitation):
    return citation.table, citation.record_id


def _groups(values) -> tuple[WitnessGroup, ...]:
    unique = {tuple(sorted(group, key=_citation_key)) for group in values}
    return tuple(WitnessGroup(citations=group) for group in sorted(
        unique, key=lambda group: tuple(_citation_key(c) for c in group),
    ))


def _answers_equal(expected: TypedAnswer | None, actual: TypedAnswer | None) -> bool:
    if expected is None or actual is None:
        return expected is actual
    return expected.format == actual.format and compare_typed_answers(expected, actual)


def _expected_answers(claim: ClaimCheck, expected: ExpectedAnswer, backend: Engine) -> tuple[TypedAnswer | None, ...]:
    programs = tuple(program for program in claim.programs if program.engine == backend)
    if not programs:
        raise ValueError("robustness claim has no answer program for the required backend")
    if isinstance(expected, ProgramAnswers):
        if set(expected.by_program) != {program.program_id for program in claim.programs}:
            raise ValueError("robustness program answers must cover exactly every claim answer-program ID")
        values = tuple(expected.by_program.values())
        answers = tuple(expected.by_program[program.program_id] for program in programs)
    else:
        answer = claim.expected if expected == "baseline" else expected
        values = (answer,)
        answers = (answer,) * len(programs)
    if any(value is not None and value.format != claim.expected.format for value in values):
        raise ValueError("counterfactual must retain the public typed answer format")
    return answers


def _answer_vectors_equal(expected: tuple[TypedAnswer | None, ...], actual: tuple[TypedAnswer | None, ...]) -> bool:
    return len(expected) == len(actual) and all(_answers_equal(a, b) for a, b in zip(expected, actual))


def _enumerated_support(witnesses: tuple[WitnessGroup, ...], probes: tuple[frozenset[PublicCitation], ...],
                        behavior: frozenset[PublicCitation], requires_behavior: bool) -> tuple[bool, ...]:
    groups = tuple(frozenset(group.citations) for group in witnesses)
    return tuple(any(group <= available and (not requires_behavior or bool(group & behavior))
                     for group in groups) for available in probes)


def validate_plan_expectations(task: TaskRecord, plan: RobustnessPlan,
                               proofs: dict[str, tuple[frozenset[PublicCitation], ...]],
                               records: dict[PublicCitation, dict[str, Scalar]],
                               behavior: frozenset[PublicCitation]) -> None:
    if plan.task_fingerprint != fingerprint(task):
        raise ValueError("robustness proposal belongs to another task")
    claims = {"final": task.private_gold.final, **{c.checkpoint_id: c.claim for c in task.private_gold.checkpoints}}
    citations = frozenset(records)
    probes = (citations, frozenset(), *(citations - {c} for c in sorted(citations, key=_citation_key)))
    for case in plan.cases:
        if {expected.claim_id for expected in case.expected} != claims.keys():
            raise ValueError("each counterfactual must explicitly cover every final/checkpoint claim")
        if not set(case.removed_records) <= citations:
            raise ValueError("counterfactual omits an unknown source record")
        for edit in case.edits:
            if edit.citation not in records or edit.column not in records[edit.citation]:
                raise ValueError("counterfactual edits an unknown source cell")
            original = records[edit.citation][edit.column]
            if type(original) is type(edit.value) and original == edit.value:
                raise ValueError("counterfactual edit is a no-op")
        for expected in case.expected:
            claim = claims[expected.claim_id]
            for backend in ("duckdb", "mysql"):
                _expected_answers(claim, expected.answer, backend)
            if isinstance(expected.support, tuple) and len(expected.support) != len(probes):
                raise ValueError("explicit support expectations must cover every citation probe")
            groups = _groups(proofs[expected.claim_id]) if expected.witnesses == "baseline" else expected.witnesses
            if any(not set(group.citations) <= citations for group in groups):
                raise ValueError("counterfactual expects unknown source witnesses")
            if plan.policy_version != ROBUSTNESS_VERSION:
                continue
            if any(set(group.citations) & set(case.removed_records) for group in groups):
                raise ValueError(f"{case.case_id}/{expected.claim_id}: expected witness names a physically removed record")
            if any(isinstance(p, QualifiedWitnessProgram) for p in claim.witness_programs):
                continue
            implied = _enumerated_support(groups, probes, behavior, claim.requires_behavior_evidence)
            declared = (_enumerated_support(_groups(proofs[expected.claim_id]), probes, behavior,
                                             claim.requires_behavior_evidence) if expected.support == "baseline" else
                        (False,) * len(probes) if expected.support is False else expected.support)
            if declared != implied:
                raise ValueError(
                    f"{case.case_id}/{expected.claim_id}: support contradicts the declared enumerated witnesses; "
                    f"their source lineages and ordered citation probes imply {json.dumps(implied)}. "
                    "This is derived from the declared witnesses, not the counterfactual query output."
                )


def _observe(claim: ClaimCheck, engine: PublicQueryEngine, allowed: frozenset[str],
             records: frozenset[PublicCitation], behavior: frozenset[PublicCitation],
             probes: tuple[frozenset[PublicCitation], ...], *, negative_world: bool = False) -> ObservedClaim:
    answers = []
    for program in claim.programs:
        if program.engine != engine.engine:
            continue
        result = engine.execute(program.query, gold=True, allowed_literals=allowed)
        if len(result.columns) != 1:
            raise QueryFailure("fixture_answer_shape", "answer program must return exactly one column")
        try:
            missing = result.rows == ((None,),) or (
                not result.rows and claim.expected.format.kind not in ("set", "ordered_list")
            )
            answer = None if missing else answer_from_rows(claim, result.rows)
        except ValueError as error:
            raise QueryFailure("fixture_answer_shape", str(error)) from error
        if answer is not None and answer.format.kind == "set" and isinstance(answer.value, tuple):
            answer = answer.model_copy(update={"value": tuple(sorted(answer.value))})
        answers.append(answer)
    if not answers:
        raise QueryFailure("fixture_answer_missing", "missing backend answer program")
    groups = []
    programs = [p for p in claim.witness_programs if p.engine == engine.engine]
    if not programs:
        raise QueryFailure("fixture_witness_missing", "missing backend witness program")
    for program in programs:
        result = engine.execute(program.query, gold=True, allowed_literals=allowed)
        if result.columns != ("evidence_group", "table_name", "record_id"):
            raise QueryFailure("fixture_witness_shape", "unexpected witness columns")
        selected: dict[str, set[PublicCitation]] = defaultdict(set)
        for group, table, record in result.rows:
            if not isinstance(group, str) or not group:
                raise QueryFailure("fixture_witness_shape", "witness labels must be nonempty strings")
            citation = PublicCitation(table=table, record_id=record)
            if citation not in records:
                raise QueryFailure("fixture_unknown_witness", "witness names a record absent from this fixture")
            selected[group].add(citation)
        if not negative_world and claim.requires_behavior_evidence and any(not group & behavior for group in selected.values()):
            raise QueryFailure("fixture_nonbehavior_witness", "behavior claim lost its behavior/security-control evidence")
        groups.extend(selected.values())
    witnesses = _groups(groups)
    qualified = [p for p in programs if isinstance(p, QualifiedWitnessProgram)]
    if qualified and len(qualified) != len(programs):
        raise QueryFailure("fixture_mixed_proof_policy", "cannot mix qualified and enumerated witnesses")
    if not qualified:
        return ObservedClaim(answers=tuple(answers), witnesses=witnesses, support=_enumerated_support(
            witnesses, probes, behavior, claim.requires_behavior_evidence,
        ))
    support = []
    for available in probes:
        matches = []
        for program in qualified:
            catalog = engine.execute(program.obligations_query, gold=True, allowed_literals=allowed)
            candidates = engine.execute(supplied_query(program, available, set(engine.tables), allowed))
            if catalog.columns == CATALOG_COLUMNS and not catalog.rows and candidates.columns == CANDIDATE_COLUMNS and not candidates.rows:
                matches.append(False)
            else:
                proof = parse_proofs(catalog, candidates)
                if not proof.relevant <= records:
                    raise QueryFailure("fixture_unknown_candidate", "candidate names a record absent from this fixture")
                matches.append(proof.match(available, behavior=behavior,
                                           requires_behavior=claim.requires_behavior_evidence) is not None)
        support.append(any(matches))
    return ObservedClaim(answers=tuple(answers), witnesses=witnesses, support=tuple(support))


def _physical_value(value: Scalar, kind: str):
    if value is None:
        return None
    expected = {
        "VARCHAR": (str,), "BIGINT": (int,), "INTEGER": (int,),
        "DOUBLE": (int, float), "BOOLEAN": (bool,), "TIMESTAMP WITH TIME ZONE": (str,),
    }
    if type(value) not in expected[kind]:
        raise ValueError("fixture cell value does not match its public source type")
    if kind == "TIMESTAMP WITH TIME ZONE":
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("fixture timestamps must retain their timezone")
        return parsed
    return value


@contextmanager
def owned_fixtures(schemas: dict, limits: QueryLimits, *, mysqld: Path, workdir: Path):
    """Never accepts an existing database/socket or connection for destructive fixture loading."""
    if not mysqld.is_file() or not workdir.is_dir():
        raise ValueError("an existing mysqld executable and owned scratch parent are required")
    with tempfile.TemporaryDirectory(prefix=".secrl-robustness-", dir=workdir.resolve()) as temporary:
        folder = Path(temporary)
        socket = folder / "mysql.sock"
        if len(str(socket).encode()) > 100:
            raise ValueError("owned MySQL fixture socket path is too long; use a shorter project scratch parent")
        init_log, server_log = folder / "initialize.log", folder / "mysql.log"
        initialized = subprocess.run(
            [str(mysqld.resolve()), "--no-defaults", "--initialize-insecure", "--innodb-page-size=32768",
             f"--datadir={folder / 'data'}", f"--log-error={init_log}"],
            capture_output=True, text=True, timeout=120, check=False,
        )
        if initialized.returncode:
            raise RuntimeError("owned MySQL initialization failed: " + initialized.stderr +
                               (init_log.read_text() if init_log.exists() else " (no initialization log)"))
        server = subprocess.Popen(
            [str(mysqld.resolve()), "--no-defaults", f"--datadir={folder / 'data'}", f"--socket={socket}",
             "--skip-networking", "--mysqlx=OFF", "--innodb-page-size=32768", "--innodb-buffer-pool-size=128M",
             f"--pid-file={folder / 'mysql.pid'}", f"--log-error={server_log}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        connection = cursor = source = None
        try:
            last_error = None
            for _ in range(120):
                if server.poll() is not None:
                    raise RuntimeError("owned MySQL exited: " + (server_log.read_text() if server_log.exists() else "no server log"))
                try:
                    connection = mysql.connector.connect(unix_socket=str(socket), user="root", password="")
                    break
                except mysql.connector.Error as error:
                    last_error = str(error)
                    time.sleep(0.25)
            if connection is None:
                raise RuntimeError(f"owned MySQL did not become ready: {last_error}")
            cursor = connection.cursor()
            cursor.execute("CREATE DATABASE secrl_robustness CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin")
            cursor.execute("USE secrl_robustness")
            cursor.execute("SET SESSION time_zone='+00:00'")
            source = duckdb.connect(config={"threads": 1, "memory_limit": "512MB"})
            source.execute("SET TimeZone='UTC'")
            source_statements = {}
            for table, columns in schemas.items():
                if any(c["type"] not in PUBLIC_TYPES for c in columns):
                    raise ValueError("unsupported public fixture column type")
                source_statements[table] = f"CREATE TABLE {quote_identifier(table)}(" + ",".join(
                    f"{quote_identifier(c['name'])} {c['type']}" for c in columns
                ) + ")"
                source.execute(source_statements[table])
                fields = [
                    f"{mysql_identifier(mysql_column_name(c['name']))} " +
                    ("VARCHAR(66) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY"
                     if c["name"] == "_record_id" else MYSQL_TYPES[c["type"]]) for c in columns
                ]
                cursor.execute(f"CREATE TABLE {mysql_identifier(table)}({','.join(fields)})")
            engines = {
                "duckdb": PublicQueryEngine(source, "duckdb", set(schemas), limits),
                "mysql": PublicQueryEngine(connection, "mysql", set(schemas), limits),
            }
            cursor.execute("SELECT VERSION()")
            versions = {"duckdb": duckdb.__version__, "mysql": str(cursor.fetchone()[0])}

            def reload(records):
                for table, columns in schemas.items():
                    values = []
                    for citation, row in records.items():
                        if citation.table != table:
                            continue
                        if set(row) != {c["name"] for c in columns} or row["_record_id"] != citation.record_id:
                            raise ValueError("fixture rows must retain exact schema and record identity")
                        values.append(tuple(_physical_value(row[c["name"]], c["type"]) for c in columns))
                    # Reusing deleted tables can leak optimizer statistics between counterfactual worlds.
                    source.execute(f"DROP TABLE {quote_identifier(table)}")
                    source.execute(source_statements[table])
                    cursor.execute(f"DELETE FROM {mysql_identifier(table)}")
                    if values:
                        source.executemany(f"INSERT INTO {quote_identifier(table)} VALUES ({','.join('?' for _ in columns)})", values)
                        cursor.executemany(f"INSERT INTO {mysql_identifier(table)} VALUES ({','.join('%s' for _ in columns)})",
                                           [tuple(mysql_value(value) for value in row) for row in values])
                connection.commit()

            yield engines, reload, versions
        finally:
            try:
                try:
                    if cursor is not None:
                        cursor.close()
                finally:
                    try:
                        if connection is not None:
                            connection.close()
                    finally:
                        if source is not None:
                            source.close()
            finally:
                server.terminate()
                try:
                    server.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=30)


def run_robustness(task: TaskRecord, verifier: EvidenceVerifier, plan: RobustnessPlan, *,
                   mysqld: Path, workdir: Path, output: Path) -> RobustnessReport:
    task = TaskRecord.model_validate(task)
    plan = RobustnessPlan.model_validate(plan)
    if output.exists():
        raise ValueError("robustness output must be a new directory")
    if plan.task_fingerprint != fingerprint(task) or verifier.engine.engine != "duckdb":
        raise ValueError("robustness requires the exact task and its DuckDB source verifier")
    implementation = {name: file_sha256(Path(__file__).with_name(name)) for name in RUNTIME_FILES}
    claims = {"final": task.private_gold.final, **{c.checkpoint_id: c.claim for c in task.private_gold.checkpoints}}
    if len(claims) != len(task.private_gold.checkpoints) + 1:
        raise ValueError("checkpoint ID conflicts with final")
    proofs = verifier.preflight(task)
    citations = frozenset(
        [PublicCitation(table=ref.table, record_id=ref.public_record_id) for ref in task.evidence]
        + list(plan.extra_source_records)
        + [citation for groups in proofs.values() for group in groups for citation in group]
    )
    records, behavior = {}, set()
    for citation in sorted(citations, key=_citation_key):
        lineage, fields = verifier.record_values(citation)
        records[citation] = fields
        if lineage in ("behavior", "security_control"):
            behavior.add(citation)
    probes = (citations, frozenset(), *(citations - {citation} for citation in sorted(citations, key=_citation_key)))
    allowed = verifier.allowed_literals | frozenset(verifier.tables)
    source_hash = hashlib.sha256(json.dumps(
        [(citation.model_dump(mode="json"), fields) for citation, fields in records.items()],
        sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()
    validate_plan_expectations(task, plan, proofs, records, frozenset(behavior))
    output.mkdir(parents=True, mode=0o700)
    (output / "plan.json").write_text(plan.model_dump_json(indent=2) + "\n")
    checks = []
    baseline = {}
    source_support = {
        name: tuple(verifier.complete_witness_observed(claim, proofs[name], available) for available in probes)
        for name, claim in claims.items()
    }

    def measure(case_id, current, expected_by_claim, engines):
        batch = []
        for claim_id, claim in claims.items():
            for backend, engine in engines.items():
                try:
                    observed = _observe(
                        claim, engine, allowed, frozenset(current), frozenset(behavior), probes,
                        negative_world=case_id != "baseline" and plan.policy_version == ROBUSTNESS_VERSION,
                    )
                    expected = expected_by_claim[claim_id]
                    expected_answers = _expected_answers(claim, expected.answer, backend)
                    reference = baseline.get((claim_id, backend))
                    groups = _groups(proofs[claim_id]) if reference is None else reference.witnesses
                    support = reference.support if reference is not None else source_support[claim_id]
                    expected_groups = groups if expected.witnesses == "baseline" else _groups(g.citations for g in expected.witnesses)
                    expected_support = support if expected.support == "baseline" else (
                        (False,) * len(probes) if expected.support is False else expected.support
                    )
                    reasons = []
                    if not _answer_vectors_equal(expected_answers, observed.answers):
                        reasons.append("typed answer differs from the declared counterfactual expectation")
                    if observed.witnesses != expected_groups:
                        reasons.append("complete witness alternatives differ (bookkeeping labels ignored)")
                    if observed.support != expected_support:
                        reasons.append("available-citation proof support differs")
                    check = RobustnessCheck(case_id=case_id, claim_id=claim_id, engine=backend,
                                            status="mismatch" if reasons else "pass", observed=observed,
                                            reasons=tuple(reasons))
                    if case_id == "baseline":
                        baseline[claim_id, backend] = observed
                except QueryFailure as error:
                    check = RobustnessCheck(case_id=case_id, claim_id=claim_id, engine=backend, status="error",
                                            observed=None, reasons=(str(error),), error_code=error.code)
                batch.append(check)
        return batch

    schemas = {name: table["columns"] for name, table in verifier.tables.items()}
    not_run = ()
    with owned_fixtures(schemas, verifier.engine.limits, mysqld=mysqld, workdir=workdir) as (engines, reload, versions):
        reload(records)
        expected = {name: ClaimExpectation(claim_id=name, answer="baseline", witnesses="baseline", support="baseline")
                    for name in claims}
        checks.extend(measure("baseline", records, expected, engines))
        if any(check.status != "pass" for check in checks):
            status = "error" if any(check.status == "error" for check in checks) else "fixture_incomplete"
            not_run = tuple(case.case_id for case in plan.cases)
        else:
            for case in plan.cases:
                current = {citation: dict(fields) for citation, fields in records.items() if citation not in case.removed_records}
                for edit in case.edits:
                    current[edit.citation][edit.column] = edit.value
                reload(current)
                checks.extend(measure(case.case_id, current, {e.claim_id: e for e in case.expected}, engines))
            status = "error" if any(c.status == "error" for c in checks) else (
                "mismatch" if any(c.status == "mismatch" for c in checks) else "pass"
            )
    if implementation != {name: file_sha256(Path(__file__).with_name(name)) for name in RUNTIME_FILES}:
        raise ValueError("robustness implementation changed during the run")
    result = RobustnessReport(
        policy_version=plan.policy_version,
        task_fingerprint=fingerprint(task), plan_fingerprint=fingerprint(plan),
        serving_view_id=task.serving_view_id, status=status, query_limits=verifier.engine.limits,
        implementation_sha256=implementation, source_records_sha256=source_hash, backend_versions=versions,
        probes=tuple(tuple(sorted(available, key=_citation_key)) for available in probes),
        checks=tuple(checks), cases_not_run=not_run,
    )
    (output / "report.json").write_text(result.model_dump_json(indent=2) + "\n")
    return result

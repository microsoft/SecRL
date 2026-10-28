# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Executable answer/witness checks; semantic and release reviews remain separate gates."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Literal

import duckdb
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.lineage import Node, lineage

from .contracts import (
    AnswerProgram, ClaimCheck, Contract, EvidenceReference, GateResult, NonnegativeInt, PublicCitation,
    ScoreComponent, TaskRecord, TypedAnswer, ValidationReport, fingerprint,
)
from .graph import load_ledger
from .ledger import attach_readonly
from .mysql_serving import canonical_mysql_row, load_serving_report, mysql_column_name, mysql_identifier
from .query import PublicQueryEngine, QueryFailure, Scalar, checked_select
from .scoring import aggregate_evaluation, compare_checkpoint_finding, compare_typed_answers
from .serving import row_digest
from .sources import quote_identifier


VERIFIER_VERSION = "source-witness-v1.2"
CitationOrigin = tuple[str, tuple[str, ...], str, tuple[int, ...]]


class EvidenceFailure(ValueError):
    pass


class Finding(Contract):
    answer: TypedAnswer
    citations: tuple[PublicCitation, ...]
    step: NonnegativeInt
    support_steps: tuple[NonnegativeInt, ...] = ()


def answer_from_rows(claim: ClaimCheck, rows: tuple[tuple, ...]) -> TypedAnswer:
    if any(len(row) != 1 for row in rows):
        raise EvidenceFailure("answer query must return exactly one column")
    kind = claim.expected.format.kind
    if kind in ("set", "ordered_list"):
        value = tuple(row[0] for row in rows)
    else:
        if len(rows) != 1:
            raise EvidenceFailure("scalar answer requires exactly one row, not the first of multiple rows")
        value = rows[0][0]
        if kind == "boolean" and type(value) is int and value in (0, 1):
            value = bool(value)
    return TypedAnswer(format=claim.expected.format, value=value)


class EvidenceVerifier:
    def __init__(self, bundle: Path, engine: PublicQueryEngine, allowed_literals: frozenset[str]):
        self.report = load_serving_report(bundle)
        if engine.serving_view_id != self.report["serving_view_id"]:
            raise EvidenceFailure("query engine is not bound to this serving snapshot")
        ledger, ledger_report = load_ledger(Path(self.report["ledger_bundle"]))
        if ledger_report["database"]["sha256"] != self.report["ledger_sha256"]:
            raise EvidenceFailure("serving provenance does not match the source ledger")
        self.engine, self.allowed_literals = engine, allowed_literals
        self.tables = {t["table"]: t for t in self.report["tables"] if t["status"] == "public"}
        self.private = duckdb.connect(config={"threads": 1, "memory_limit": "512MB"})
        try:
            attach_readonly(self.private, bundle / self.report["private_mapping"]["path"], "mapping")
            attach_readonly(self.private, ledger, "ledger")
        except duckdb.Error:
            self.private.close()
            raise

    def close(self):
        self.private.close()

    def verify_reference(self, reference: EvidenceReference):
        if reference.snapshot_id != self.report["snapshot_id"]:
            raise EvidenceFailure("evidence snapshot does not match the serving source")
        rows = self.private.execute("""
            SELECT observation_id,private_sha256,lineage FROM mapping.record_map WHERE table_name=? AND record_id=?
        """, [reference.table, reference.public_record_id]).fetchall()
        if rows != [(reference.private_locator, reference.content_sha256, reference.lineage)]:
            raise EvidenceFailure("private source locator, content hash or lineage does not match")
        origin = self.private.execute("""
            SELECT count(*) FROM ledger._origins WHERE table_name=? AND observation_id=? AND source_id=?
        """, [reference.table, reference.private_locator, reference.source_id]).fetchone()[0]
        if not origin:
            raise EvidenceFailure("evidence source origin does not resolve")

    def citation_lineage(self, citation: PublicCitation) -> str:
        return self.record_values(citation)[0]

    def record_values(self, citation: PublicCitation) -> tuple[str, dict[str, Scalar]]:
        """Return source-named public fields only after verifying the complete row."""
        table = self.tables.get(citation.table)
        if table is None:
            raise EvidenceFailure("citation does not name a public source table")
        reference = self.private.execute("SELECT public_sha256,lineage FROM mapping.record_map WHERE table_name=? AND record_id=?",
                                         [citation.table, citation.record_id]).fetchall()
        if len(reference) != 1:
            raise EvidenceFailure("citation does not resolve uniquely")
        quote = mysql_identifier if self.engine.engine == "mysql" else quote_identifier
        names = tuple(c["name"] for c in table["columns"])
        storage_names = tuple(mysql_column_name(name) for name in names) if self.engine.engine == "mysql" else names
        literal = "'" + citation.record_id.replace("'", "''") + "'"
        result = self.engine.execute(f"SELECT {','.join(quote(n) for n in storage_names)} FROM {quote(citation.table)} WHERE _record_id={literal}")
        if len(result.rows) != 1:
            raise QueryFailure("serving_integrity", "Known public record is missing or ambiguous.")
        row = canonical_mysql_row(result.rows[0], table["columns"]) if self.engine.engine == "mysql" else result.rows[0]
        if row_digest(names, row) != reference[0][0]:
            raise QueryFailure("serving_integrity", "Known public content differs from the validated projection.")
        return reference[0][1], dict(zip(names, row))

    def validate_program(self, program: AnswerProgram, *, expected: TypedAnswer | None = None) -> None:
        allowed = self.allowed_literals | frozenset(self.tables)
        try:
            tree = checked_select(program.query, program.engine, set(self.tables), gold=True, allowed_literals=allowed)
        except QueryFailure as error:
            raise QueryFailure(error.code, f"{program.engine} program {program.program_id}: {error}") from error
        if expected is not None:
            for selected in tree.selects:
                if not selected.find(exp.Column) and not isinstance(selected, exp.Star) and not any(
                    isinstance(count.this, exp.Star) for count in selected.find_all(exp.Count)
                ):
                    raise EvidenceFailure("answer values must be derived from source columns or source counts, not constants")
            if expected.format.kind == "ordered_list" and not tree.args.get("order"):
                raise EvidenceFailure("ordered answers require an explicit outer ORDER BY")

    def claim_witnesses(self, claim: ClaimCheck) -> tuple[frozenset[PublicCitation], ...]:
        programs = [p for p in claim.programs if p.engine == self.engine.engine]
        witnesses = [p for p in claim.witness_programs if p.engine == self.engine.engine]
        if not programs or not witnesses:
            raise EvidenceFailure("both answer and witness programs are required for this backend")
        allowed = self.allowed_literals | frozenset(self.tables)
        for program in programs:
            self.validate_program(program, expected=claim.expected)
            result = self.engine.execute(program.query, gold=True, allowed_literals=allowed)
            if len(result.columns) != 1 or not compare_typed_answers(claim.expected, answer_from_rows(claim, result.rows)):
                raise EvidenceFailure("executable answer disagrees with the typed gold value")
        alternatives: set[frozenset[PublicCitation]] = set()
        for program in witnesses:
            result = self.engine.execute(program.query, gold=True, allowed_literals=allowed)
            if result.columns != ("evidence_group", "table_name", "record_id") or not result.rows:
                raise EvidenceFailure("witness query must return nonempty evidence_group/table_name/record_id rows")
            groups: dict[str, set[PublicCitation]] = defaultdict(set)
            for group, table, record in result.rows:
                if not isinstance(group, str) or not group:
                    raise EvidenceFailure("witness group must be a nonempty string")
                groups[group].add(PublicCitation(table=table, record_id=record))
            for citations in groups.values():
                lineages = {self.citation_lineage(c) for c in citations}
                if claim.requires_behavior_evidence and not lineages & {"behavior", "security_control"}:
                    raise EvidenceFailure("detector/context-only witnesses cannot independently support a behavior claim")
                alternatives.add(frozenset(citations))
        return tuple(sorted(alternatives, key=lambda group: sorted((c.table, c.record_id) for c in group)))

    def preflight(self, task: TaskRecord) -> dict[str, tuple[frozenset[PublicCitation], ...]]:
        if (task.snapshot_id != self.report["snapshot_id"] or task.serving_view_id != self.report["serving_view_id"]
                or task.graph_version != self.report["graph_id"]):
            raise EvidenceFailure("task snapshot/serving view mismatch")
        for reference in task.evidence:
            self.verify_reference(reference)
        claims = {"final": task.private_gold.final, **{c.checkpoint_id: c.claim for c in task.private_gold.checkpoints}}
        proofs = {key: self.claim_witnesses(claim) for key, claim in claims.items()}
        citations = {e.evidence_id: PublicCitation(table=e.table, record_id=e.public_record_id) for e in task.evidence}
        for key, claim in claims.items():
            for declared in claim.evidence_sets:
                if frozenset(citations[eid] for eid in declared.evidence_ids) not in proofs[key]:
                    raise EvidenceFailure("declared evidence set is not an executable witness for its claim")
        return proofs

    def mechanical_report(self, task: TaskRecord) -> ValidationReport:
        try:
            self.preflight(task)
            gates = tuple(GateResult(gate=name, status="pass",
                                    reason="Executable source/content/witness checks passed; independent semantic/release review is still required.")
                          for name in ("schema", "source_coverage", "executable_answer", "query_integrity", "checkpoint_rubric"))
        except ValueError as error:
            gates = (GateResult(gate="executable_answer", status="error" if isinstance(error, QueryFailure) else "fail",
                                error_code=error.code if isinstance(error, QueryFailure) else None, reason=str(error)),)
        return ValidationReport(task_id=task.task_id, task_fingerprint=fingerprint(task),
                                evaluator_version=VERIFIER_VERSION, gates=gates)

    def evidence_matches(self, finding: Finding, witnesses: tuple[frozenset[PublicCitation], ...]) -> bool:
        citations = frozenset(finding.citations)
        if not citations or len(citations) != len(finding.citations):
            return False
        relevant = frozenset().union(*witnesses)
        if not citations <= relevant or not any(group <= citations for group in witnesses):
            return False
        for citation in citations:
            self.citation_lineage(citation)
        return True

    def observed_citations(self, result, query: str) -> set[PublicCitation]:
        if not any(isinstance(value, str) and value.startswith("r:") and len(value) == 66 for row in result.rows for value in row):
            return set()
        storage = mysql_column_name if self.engine.engine == "mysql" else lambda value: value
        schema = {table: {storage(c["name"]): "UNKNOWN" for c in info["columns"]} for table, info in self.tables.items()}
        table_names = {table.casefold(): table for table in self.tables}

        def source_origins(
            node: Node, chain: tuple[str, ...] = (), field: str | None = None,
            branch: tuple[int, ...] = (),
        ) -> tuple[CitationOrigin, ...]:
            expression = node.expression.unalias()
            if not node.downstream:
                if isinstance(expression, exp.Table) and field is not None:
                    table = table_names.get(expression.name.casefold())
                    if table is not None:
                        names = {storage(c["name"]).casefold(): c["name"] for c in self.tables[table]["columns"]}
                        if field in names:
                            return ((table, chain, names[field], branch),)
                return ()
            if not isinstance(expression, exp.Column):
                return ()
            # A UNION lineage node repeats its first projection, not an additional SELECT scope.
            if not isinstance(node.source, exp.Union):
                chain = (*chain, expression.table.casefold())
                field = expression.name.casefold()
            projected = []
            for position, child in enumerate(node.downstream):
                child_branch = (*branch, position) if len(node.downstream) > 1 else branch
                sources = source_origins(child, chain, field, child_branch)
                if not sources:
                    return ()
                projected.extend(sources)
            return tuple(projected)

        origins: dict[int, tuple[CitationOrigin, ...]] = {}
        for index, column in enumerate(result.columns):
            if sum(name.casefold() == column.casefold() for name in result.columns) != 1:
                continue
            try:
                node = lineage(column, query, schema=schema, dialect=self.engine.engine)
            except SqlglotError as error:
                raise QueryFailure("citation_lineage", "Could not attribute a citation projection; retrieve the source record explicitly.") from error
            origins[index] = source_origins(node)
        observed = set()
        for row in result.rows:
            for index, value in enumerate(row):
                if not isinstance(value, str) or not value.startswith("r:") or len(value) != 66:
                    continue
                candidates = origins.get(index, ())
                if not candidates or any(origin[2] != "_record_id" for origin in candidates):
                    continue
                records = self.private.execute("SELECT table_name FROM mapping.record_map WHERE record_id=?", [value]).fetchall()
                if len(records) != 1:
                    continue
                table = records[0][0]
                candidates = tuple(origin for origin in candidates if origin[0] == table)
                comparisons = [
                    [(i, source[2]) for i, sources in origins.items() for source in sources
                     if (source[0], source[1], source[3]) == (origin[0], origin[1], origin[3])
                     and source[2] != "_record_id"]
                    for origin in candidates
                ]
                if not any(comparisons):
                    continue
                names = tuple(c["name"] for c in self.tables[table]["columns"])
                quote = mysql_identifier if self.engine.engine == "mysql" else quote_identifier
                source = self.engine.execute(f"SELECT {','.join(quote(storage(n)) for n in names)} FROM {quote(table)} WHERE _record_id='{value}'")
                if len(source.rows) != 1:
                    raise QueryFailure("serving_integrity", "Observed record disappeared from the serving view.")
                expected = dict(zip(names, source.rows[0]))
                if any(comparable and all(row[i] == expected[name] for i, name in comparable)
                       for comparable in comparisons):
                    observed.add(PublicCitation(table=table, record_id=value))
        return observed

    def evaluate(self, task: TaskRecord, submission: Finding | None, findings: tuple[Finding, ...], *,
                 run_id: str, backend: Literal["secrl", "acesevals"], trajectory_ref: str,
                 backend_adapter_version: str = "component-record-v1"):
        proofs = self.preflight(task)
        correct = submission is not None and submission.answer.format == task.private_gold.final.expected.format and compare_typed_answers(
            task.private_gold.final.expected, submission.answer)

        def component(cid, kind, score, finding, explanation, maximum=1.0, weight=1.0):
            return ScoreComponent(component_id=cid, kind=kind, status="complete", score=score,
                                  max_score=maximum, weight=weight,
                                  evidence=finding.citations if finding and kind != "answer_correctness" else (),
                                  trajectory_steps=tuple(sorted({finding.step, *finding.support_steps})) if finding else (),
                                  first_completion_step=finding.step if finding and score == maximum else None,
                                  explanation=explanation, evaluator_version=VERIFIER_VERSION)

        answer = component("final-answer", "answer_correctness", float(correct), submission, "Strict typed answer comparison.")
        try:
            grounded = submission is not None and self.evidence_matches(submission, proofs["final"])
        except EvidenceFailure:
            grounded = False
        evidence = component("final-evidence", "final_evidence", float(grounded), submission if grounded else None,
                             "Executable witness binding and public-row content check.")
        checkpoints = {}
        for checkpoint in task.private_gold.checkpoints:
            match = None
            for finding in sorted(findings, key=lambda f: f.step):
                if not compare_checkpoint_finding(checkpoint.claim.expected, finding.answer):
                    continue
                try:
                    valid = self.evidence_matches(finding, proofs[checkpoint.checkpoint_id])
                except EvidenceFailure:
                    valid = False
                if valid:
                    match = finding
                    break
            checkpoints[checkpoint.checkpoint_id] = component(
                checkpoint.checkpoint_id, "checkpoint", checkpoint.max_score if match else 0.0, match,
                "Explicit typed finding checked against source-bound witnesses.", checkpoint.max_score, checkpoint.weight)
        pending = set(checkpoints)
        while pending:
            for rubric in task.private_gold.checkpoints:
                if rubric.checkpoint_id not in pending or set(rubric.depends_on) & pending:
                    continue
                if any(checkpoints[d].score != checkpoints[d].max_score for d in rubric.depends_on):
                    old = checkpoints[rubric.checkpoint_id]
                    checkpoints[rubric.checkpoint_id] = ScoreComponent.model_validate({
                        **old.model_dump(), "score": 0.0, "first_completion_step": None,
                        "explanation": "Finding did not complete its required semantic dependencies.",
                    })
                pending.remove(rubric.checkpoint_id)
        return aggregate_evaluation(task, run_id=run_id, backend=backend, trajectory_ref=trajectory_ref,
                                    answer_correctness=answer, final_evidence=evidence,
                                    backend_adapter_version=backend_adapter_version,
                                    checkpoints=tuple(checkpoints[c.checkpoint_id] for c in task.private_gold.checkpoints))


def serving_parity(task: TaskRecord, source: EvidenceVerifier, mysql: EvidenceVerifier) -> GateResult:
    if source.engine.engine != "duckdb" or mysql.engine.engine != "mysql":
        raise ValueError("serving parity requires both actual backend types")
    try:
        if source.preflight(task) != mysql.preflight(task):
            return GateResult(gate="serving_parity", status="fail", reason="Backend witness sets differ.")
    except QueryFailure as error:
        return GateResult(gate="serving_parity", status="error", error_code=error.code, reason=str(error))
    except EvidenceFailure as error:
        return GateResult(gate="serving_parity", status="fail", reason=str(error))
    return GateResult(gate="serving_parity", status="pass",
                      reason="Both backends reproduce each typed answer and exact source-bound witness set.",
                      artifact_refs=(source.report["serving_view_id"],))

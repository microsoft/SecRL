# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Source-qualified AND/OR proofs with coherent, source-record-bound choices."""

from __future__ import annotations

from dataclasses import dataclass

from sqlglot import exp
from sqlglot.optimizer.scope import traverse_scope

from .contracts import PublicCitation, QualifiedWitnessProgram
from .query import PublicQueryEngine, QueryFailure, QueryResult, checked_select


CITATIONS_TABLE = "proof_citations"
MAX_PROOF_SEARCH_STATES = 10000
CATALOG_COLUMNS = ("evidence_group", "obligation_id")
CANDIDATE_COLUMNS = (
    "evidence_group", "obligation_id", "candidate_id", "binding_key", "table_name", "record_id",
)


@dataclass(frozen=True)
class ProofCandidate:
    group: str
    obligation: str
    candidate: str
    citations: frozenset[PublicCitation]
    bindings: tuple[tuple[str, PublicCitation], ...]


@dataclass(frozen=True)
class QualifiedProofs:
    obligations: tuple[tuple[str, str], ...]
    candidates: tuple[ProofCandidate, ...]

    @property
    def relevant(self) -> frozenset[PublicCitation]:
        return frozenset(c for candidate in self.candidates for c in candidate.citations)

    def match(self, available: frozenset[PublicCitation], *,
              behavior: frozenset[PublicCitation], requires_behavior: bool) -> frozenset[PublicCitation] | None:
        groups: dict[str, list[str]] = {}
        choices: dict[tuple[str, str], list[ProofCandidate]] = {}
        for group, obligation in self.obligations:
            groups.setdefault(group, []).append(obligation)
            choices[group, obligation] = []
        for candidate in self.candidates:
            if candidate.citations <= available:
                choices[candidate.group, candidate.obligation].append(candidate)
        generated = 0
        for group, obligations in groups.items():
            ordered = sorted(obligations, key=lambda key: (len(choices[group, key]), key))
            if any(not choices[group, key] for key in ordered):
                continue
            states: list[tuple[int, dict[str, PublicCitation], frozenset[PublicCitation]]] = [(0, {}, frozenset())]
            while states:
                index, bindings, support = states.pop()
                if index == len(ordered):
                    if not requires_behavior or support & behavior:
                        return support
                    continue
                for candidate in reversed(choices[group, ordered[index]]):
                    if any(key in bindings and bindings[key] != citation for key, citation in candidate.bindings):
                        continue
                    generated += 1
                    if generated > MAX_PROOF_SEARCH_STATES:
                        raise QueryFailure("proof_search_limit", "Coherent proof search exceeded its explicit state limit.")
                    states.append((index + 1, {**bindings, **dict(candidate.bindings)}, support | candidate.citations))
        return None


def candidate_tree(program: QualifiedWitnessProgram, tables: set[str],
                   allowed_literals: frozenset[str]) -> exp.Expression:
    if CITATIONS_TABLE.casefold() in {table.casefold() for table in tables}:
        raise QueryFailure("proof_namespace", "The reserved proof citation relation collides with a source table.")
    tree = checked_select(program.candidates_query, program.engine, tables | {CITATIONS_TABLE},
                          gold=True, allowed_literals=allowed_literals)
    if any(cte.alias.casefold() == CITATIONS_TABLE for cte in tree.find_all(exp.CTE)):
        raise QueryFailure("proof_namespace", "Candidate SQL must not define or shadow the supplied citation relation.")
    physical = {
        source.name for scope in traverse_scope(tree) for _, source in scope.selected_sources.values()
        if isinstance(source, exp.Table) and isinstance(source.this, exp.Identifier)
    }
    if CITATIONS_TABLE not in physical or not physical & tables:
        raise QueryFailure("proof_source", "Candidate SQL must use both supplied citations and actual public source tables.")
    return tree


def validate_qualified_program(program: QualifiedWitnessProgram, tables: set[str],
                               allowed_literals: frozenset[str]) -> None:
    checked_select(program.obligations_query, program.engine, tables, gold=True, allowed_literals=allowed_literals)
    candidate_tree(program, tables, allowed_literals)


def supplied_query(program: QualifiedWitnessProgram, citations: frozenset[PublicCitation],
                   tables: set[str], allowed_literals: frozenset[str]) -> str:
    tree = candidate_tree(program, tables, allowed_literals)
    parameters: exp.Expression | None = None
    for citation in sorted(citations, key=lambda item: (item.table, item.record_id)):
        row = exp.select(
            exp.alias_(exp.Literal.string(citation.table), "table_name"),
            exp.alias_(exp.Literal.string(citation.record_id), "record_id"),
        )
        parameters = row if parameters is None else exp.Union(this=parameters, expression=row, distinct=False)
    if parameters is None:
        parameters = exp.select(
            exp.alias_(exp.Null(), "table_name"), exp.alias_(exp.Null(), "record_id"),
        ).where(exp.false())
    tree = tree.with_(CITATIONS_TABLE, as_=parameters)
    with_clause = tree.find(exp.With)
    if with_clause is None:
        raise QueryFailure("proof_namespace", "Failed to construct the supplied citation relation.")
    # MySQL CTEs cannot refer forward to the supplied relation.
    with_clause.set("expressions", [with_clause.expressions[-1], *with_clause.expressions[:-1]])
    return tree.sql(dialect=program.engine, comments=False)


def _text(value: object, description: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise QueryFailure("proof_shape", f"{description} must be a nonblank source/query label.")
    return value


def parse_proofs(catalog: QueryResult, candidates: QueryResult) -> QualifiedProofs:
    if catalog.columns != CATALOG_COLUMNS or not catalog.rows:
        raise QueryFailure("proof_shape", "Required obligations must be a nonempty evidence_group/obligation_id catalog.")
    obligations = tuple((_text(row[0], "Group"), _text(row[1], "Obligation")) for row in catalog.rows)
    if len(set(obligations)) != len(obligations):
        raise QueryFailure("proof_shape", "Duplicate required obligations must be resolved by source SQL.")
    if candidates.columns != CANDIDATE_COLUMNS:
        raise QueryFailure("proof_shape", "Candidate SQL must return the six declared proof columns.")
    required = set(obligations)
    records: dict[tuple[str, str, str], set[PublicCitation]] = {}
    bindings: dict[tuple[str, str, str], dict[str, PublicCitation]] = {}
    for group, obligation, candidate, binding, table, record in candidates.rows:
        key = (_text(group, "Group"), _text(obligation, "Obligation"), _text(candidate, "Candidate"))
        if key[:2] not in required:
            raise QueryFailure("proof_shape", "Candidate references an undeclared group or obligation.")
        citation = PublicCitation(table=_text(table, "Table"), record_id=_text(record, "Record"))
        records.setdefault(key, set()).add(citation)
        mapping = bindings.setdefault(key, {})
        if binding is not None:
            binding = _text(binding, "Binding key")
            if binding in mapping and mapping[binding] != citation:
                raise QueryFailure("proof_binding", "One candidate assigns conflicting source records to a shared binding.")
            mapping[binding] = citation
    return QualifiedProofs(
        tuple(sorted(obligations)),
        tuple(ProofCandidate(*key, frozenset(records[key]), tuple(sorted(bindings[key].items())))
              for key in sorted(records)),
    )


def resolve_qualified_proofs(program: QualifiedWitnessProgram, engine: PublicQueryEngine,
                            citations: frozenset[PublicCitation], allowed_literals: frozenset[str]) -> QualifiedProofs:
    if program.engine != engine.engine:
        raise QueryFailure("proof_backend", "Qualified proof program does not match the execution backend.")
    validate_qualified_program(program, set(engine.tables), allowed_literals)
    catalog = engine.execute(program.obligations_query, gold=True, allowed_literals=allowed_literals)
    query = supplied_query(program, citations, set(engine.tables), allowed_literals)
    parameters = frozenset(value for citation in citations for value in (citation.table, citation.record_id))
    candidates = engine.execute(query, gold=True, allowed_literals=allowed_literals | parameters)
    return parse_proofs(catalog, candidates)

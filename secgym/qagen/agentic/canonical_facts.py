# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Verified event-bound source facts, separate from answer grading and claim signatures."""

from __future__ import annotations

from json import JSONDecodeError
from typing import Annotated, Literal, TypeAlias

from pydantic import Field, StrictInt, StrictStr, model_validator

from .contracts import (
    Contract, Digest, Identifier, PublicCitation, TaskRecord, Text, ValidationReport, fingerprint, require_unique,
)
from .evidence import EvidenceFailure, EvidenceVerifier
from .ledger import JsonNumber, encode_json
from .query import Scalar
from .serving import parse_json
from .similarity import EvidenceFootprint, WeightedFeature
from .sources import TIME_COLUMNS, digest


FACT_VERSION = "canonical-source-facts-v2"
FEATURE_VERSION = "unit-canonical-source-facts-v2.1"
PathStep: TypeAlias = StrictStr | Annotated[StrictInt, Field(ge=0)]
FactKind: TypeAlias = Literal["property_value", "json_member_presence"]


class SourceFactReference(Contract):
    citation: PublicCitation
    column: Text
    json_path: tuple[PathStep, ...] | None = None
    kind: FactKind = "property_value"

    @model_validator(mode="after")
    def presence_path(self):
        if self.kind == "json_member_presence" and (
            not self.json_path or not isinstance(self.json_path[-1], str)
        ):
            raise ValueError("JSON member presence requires a nonempty path ending in an object key")
        return self


class ClaimFactSelection(Contract):
    claim_id: Identifier
    references: Annotated[tuple[SourceFactReference, ...], Field(min_length=1)]
    rationale: Text

    @model_validator(mode="after")
    def unique_references(self):
        require_unique(tuple(fingerprint(ref) for ref in self.references), "claim fact references")
        return self


class SourceFactProposal(Contract):
    claims: Annotated[tuple[ClaimFactSelection, ...], Field(min_length=1)]
    limitations: tuple[Text, ...] = ()

    @model_validator(mode="after")
    def unique_claims(self):
        require_unique(tuple(claim.claim_id for claim in self.claims), "fact claim IDs")
        return self


class SourceTimeValue(Contract):
    column: Text
    value_json: Text


class CanonicalSourceFact(Contract):
    definition_version: Literal["canonical-source-facts-v2"] = FACT_VERSION
    snapshot_id: Identifier
    subject_kind: Literal["source_observation"] = "source_observation"
    subject_observation_id: Text
    table: Identifier
    column: Text
    json_path: tuple[PathStep, ...] | None
    kind: FactKind = "property_value"
    value_json: Text
    lineage: Literal["behavior", "security_control", "detector_derived", "context", "metadata"]
    source_times: tuple[SourceTimeValue, ...]

    @model_validator(mode="after")
    def atomic_value(self):
        value = parse_json(self.value_json)
        if isinstance(value, (dict, list)) or isinstance(value, str) and _encoded_container(value):
            raise ValueError("canonical facts require an atomic value, not a serialized container")
        if self.kind == "json_member_presence" and type(value) is not bool:
            raise ValueError("JSON member presence must be a boolean source observation")
        return self

    @property
    def fact_id(self) -> str:
        return "source-fact:" + digest({
            "version": self.definition_version, "snapshot": self.snapshot_id,
            "subject_kind": self.subject_kind, "subject": self.subject_observation_id,
            "property": [self.kind, self.table, self.column, self.json_path], "value": self.value_json,
            "source_times": [value.model_dump(mode="json") for value in self.source_times],
        })


class ResolvedClaimFacts(Contract):
    claim_id: Identifier
    fact_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]


class CanonicalFactBundle(Contract):
    definition_version: Literal["canonical-source-facts-v2"] = FACT_VERSION
    task_fingerprint: Digest
    snapshot_id: Identifier
    serving_view_id: Identifier
    graph_version: Identifier
    proposal_fingerprint: Digest
    facts: Annotated[tuple[CanonicalSourceFact, ...], Field(min_length=1)]
    claims: Annotated[tuple[ResolvedClaimFacts, ...], Field(min_length=1)]
    limitations: tuple[Text, ...]

    @model_validator(mode="after")
    def references_resolve(self):
        require_unique(tuple(fact.fact_id for fact in self.facts), "canonical fact IDs")
        require_unique(tuple(claim.claim_id for claim in self.claims), "resolved fact claim IDs")
        facts = {fact.fact_id for fact in self.facts}
        used = set()
        for claim in self.claims:
            require_unique(claim.fact_ids, "resolved claim fact IDs")
            used.update(claim.fact_ids)
        if used != facts or any(fact.snapshot_id != self.snapshot_id for fact in self.facts):
            raise ValueError("canonical fact bundle has unresolved, unused or mismatched facts")
        return self


class CanonicalFactReview(Contract):
    bundle_fingerprint: Digest
    recommendation: Literal["pass", "revise", "reject"]
    source_properties_relevant: bool
    subjects_roles_times_preserved: bool
    claim_coverage_complete: bool
    no_value_only_merging: bool
    reasons: Annotated[tuple[Text, ...], Field(min_length=1)]


def _source_value_at(value: Scalar, path: tuple[PathStep, ...] | None) -> object:
    current: object = value
    if path is not None:
        if not isinstance(current, str):
            raise EvidenceFailure("JSON fact paths require a reported JSON string column")
        current = parse_json(current)
        for step in path:
            if isinstance(current, str):
                current = parse_json(current)
            if isinstance(current, dict) and isinstance(step, str) and step in current:
                current = current[step]
            elif isinstance(current, list) and type(step) is int and 0 <= step < len(current):
                current = current[step]
            else:
                raise EvidenceFailure("fact path is missing or does not match the reported container")
    return current


def _encoded_container(value: str) -> bool:
    decoded: object = value
    while isinstance(decoded, str):
        text = decoded.lstrip()
        if not text or text[0] not in ('[', '{', '"'):
            return False
        try:
            decoded = parse_json(decoded)
        except JSONDecodeError:
            # A literal source string need not be JSON; valid encoded containers are not atomic.
            return False
    return isinstance(decoded, (dict, list))


def source_leaf(
    value: Scalar, path: tuple[PathStep, ...] | None, *, kind: FactKind = "property_value",
) -> str:
    if kind == "json_member_presence":
        if not path or not isinstance(path[-1], str):
            raise EvidenceFailure("JSON member presence requires a nonempty path ending in an object key")
        parent = _source_value_at(value, path[:-1])
        if isinstance(parent, str):
            parent = parse_json(parent)
        if not isinstance(parent, dict):
            raise EvidenceFailure("JSON member presence requires an existing source object parent")
        return encode_json(path[-1] in parent)
    if kind != "property_value":
        raise EvidenceFailure("unsupported canonical source property kind")
    current = _source_value_at(value, path)
    if isinstance(current, (dict, list)) or isinstance(current, str) and _encoded_container(current):
        raise EvidenceFailure("canonical facts require an atomic source value, not an entire container")
    if current is not None and type(current) not in (str, int, float, bool) and not isinstance(current, JsonNumber):
        raise EvidenceFailure("unsupported canonical source value")
    return encode_json(current)


class SourceFactResolver:
    def __init__(self, verifier: EvidenceVerifier):
        self.verifier = verifier
        self._records: dict[PublicCitation, tuple[str, dict[str, Scalar]]] = {}

    def resolve(self, task: TaskRecord, validation: ValidationReport, proposal: SourceFactProposal) -> CanonicalFactBundle:
        blockers = validation.pilot_blockers(task)
        if blockers:
            raise EvidenceFailure("canonical facts require validated private-pilot evidence: " + "; ".join(blockers))
        report = self.verifier.report
        if (task.snapshot_id, task.serving_view_id, task.graph_version) != (
            report["snapshot_id"], report["serving_view_id"], report["graph_id"],
        ):
            raise EvidenceFailure("canonical facts and the source verifier use different snapshots")
        if any(checkpoint.checkpoint_id == "final" for checkpoint in task.private_gold.checkpoints):
            raise EvidenceFailure("checkpoint ID conflicts with the final fact claim")
        claims = {"final": task.private_gold.final, **{c.checkpoint_id: c.claim for c in task.private_gold.checkpoints}}
        if {claim.claim_id for claim in proposal.claims} != claims.keys():
            raise EvidenceFailure("fact proposal must explicitly cover the final and every checkpoint")
        references = {ref.evidence_id: ref for ref in task.evidence}
        facts: dict[str, CanonicalSourceFact] = {}
        resolved = []
        for selection in proposal.claims:
            claim = claims[selection.claim_id]
            permitted = {
                PublicCitation(table=references[eid].table, record_id=references[eid].public_record_id): references[eid]
                for group in claim.evidence_sets for eid in group.evidence_ids
            }
            selected = []
            for binding in selection.references:
                reference = permitted.get(binding.citation)
                if reference is None:
                    raise EvidenceFailure("fact reference is outside this claim's validated evidence")
                if binding.column.casefold() == "_record_id":
                    raise EvidenceFailure("opaque serving record IDs are not canonical source properties")
                self.verifier.verify_reference(reference)
                if binding.citation not in self._records:
                    self._records[binding.citation] = self.verifier.record_values(binding.citation)
                lineage, row = self._records[binding.citation]
                if lineage != reference.lineage or binding.column not in row:
                    raise EvidenceFailure("fact column or lineage does not match the verified public source")
                fact = CanonicalSourceFact(
                    snapshot_id=task.snapshot_id, subject_observation_id=reference.private_locator,
                    table=reference.table, column=binding.column, json_path=binding.json_path,
                    kind=binding.kind,
                    value_json=source_leaf(row[binding.column], binding.json_path, kind=binding.kind),
                    lineage=reference.lineage,
                    source_times=tuple(
                        SourceTimeValue(column=name, value_json=encode_json(row[name]))
                        for name in TIME_COLUMNS if name in row and row[name] is not None
                    ),
                )
                facts[fact.fact_id] = fact
                selected.append(fact.fact_id)
            resolved.append(ResolvedClaimFacts(claim_id=selection.claim_id, fact_ids=tuple(sorted(set(selected)))))
        return CanonicalFactBundle(
            task_fingerprint=fingerprint(task), snapshot_id=task.snapshot_id, serving_view_id=task.serving_view_id,
            graph_version=task.graph_version, proposal_fingerprint=fingerprint(proposal),
            facts=tuple(facts[key] for key in sorted(facts)),
            claims=tuple(sorted(resolved, key=lambda claim: claim.claim_id)), limitations=proposal.limitations,
        )


def canonical_fact_footprint(
    baseline: EvidenceFootprint, bundle: CanonicalFactBundle, review: CanonicalFactReview,
) -> EvidenceFootprint:
    if (baseline.task_fingerprint, baseline.snapshot_id, baseline.graph_version) != (
        bundle.task_fingerprint, bundle.snapshot_id, bundle.graph_version,
    ):
        raise EvidenceFailure("canonical facts do not belong to this task footprint")
    if review.bundle_fingerprint != fingerprint(bundle):
        raise EvidenceFailure("canonical fact review does not bind this resolved bundle")
    if review.recommendation != "pass" or not all((
        review.source_properties_relevant, review.subjects_roles_times_preserved,
        review.claim_coverage_complete, review.no_value_only_merging,
    )):
        raise EvidenceFailure("canonical facts require independent relevance and identity review")
    if baseline.feature_weight_version != "unit-evidence-audit-v1":
        raise EvidenceFailure("canonical unit audit requires the original validated unit baseline")
    observations = {item.feature_id for item in baseline.observations or ()}
    if any(fact.subject_observation_id not in observations for fact in bundle.facts):
        raise EvidenceFailure("canonical fact subject is absent from the validated footprint")
    return EvidenceFootprint(
        task_fingerprint=baseline.task_fingerprint, snapshot_id=baseline.snapshot_id,
        graph_version=baseline.graph_version, feature_weight_version=FEATURE_VERSION,
        edges=baseline.edges, observations=baseline.observations,
        facts=tuple(WeightedFeature(feature_id=fact.fact_id, weight=1.0) for fact in bundle.facts),
    )

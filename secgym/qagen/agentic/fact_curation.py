# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Private source-property curation and independent review for canonical overlap facts."""

import json
from pathlib import Path

from .canonical_facts import (
    CanonicalFactReview, SourceFactProposal, SourceFactResolver, canonical_fact_footprint,
)
from .contracts import PublicCitation, TaskRecord, ValidationReport, fingerprint
from .generation import CompletionClient, DiscoveryTools, run_role
from .ledger import file_sha256
from .query import QueryResult
from .similarity import EvidenceFootprint


CURATION_VERSION = "source-fact-curation-v1.2"

CURATOR_INSTRUCTIONS = """Identify canonical source facts for the already validated task, not new QA or grading rules.
The SQL tool is DuckDB. Inspect actual public source fields and the supplied complete evidence.
Retrieve source _record_id alongside the inspected fields for every record you select; literal-ID
projections or merely repeating IDs from the context do not establish that a record was inspected.
Cover the final claim and EVERY checkpoint using its exact claim_id. Each reference must belong to that
claim's validated evidence sets. Choose the minimal substantive source properties establishing the answer
or a necessary identity/time/role binding, not every available field or a sample of a larger claimed cohort.
For derived counts, ordering or comparisons, include the actual source inputs that establish the derivation.
Include the incident number, alert name, event ActionType and other source properties when they are
actual scope/selection predicates of the validated claim, even when the question supplies their values.
Do not pad with unrelated metadata or select every column merely to create similarity.
Identity resolution may need both the identity field in an anchor and the linked behavioral record's
identity field; do not omit a material shared rule/mailbox field just because the final projection uses
an alert field.
Return ONLY source references, never invented canonical values, subject IDs, predicates or free-form role labels.
The verifier derives values and event-bound subject identity from the immutable source record. A field's
canonical column/JSON path preserves its role: parent and child, actor and target are different properties.
Equal answer text across different observations, roles or times does not establish a shared fact.
Use original public column names. json_path=null selects the column's literal scalar value. A json_path
array selects a scalar JSON leaf using exact object-key strings and zero-based integer array positions;
encoded JSON is decoded when traversing it. These positions locate an immutable source record's field,
not a selection rule for a question or an assumption that unrelated records have the same array order.
Do not select whole JSON containers, opaque _record_id values, private columns, or unused counterevidence.
This also excludes containers stored as JSON strings: selecting an entire AlertIds array with
json_path=null is not an atomic fact. Select each materially relevant member, not the serialized array.
The same rule applies to nested encoded containers; traverse to the actual scalar property.
Source null is only the recorded projection value, not proof of underlying absence or a default zero.
kind=property_value reads a reported scalar. To represent whether a specific JSON object has a named
member, use kind=json_member_presence with the path ending in that exact member name. The verifier
requires every ancestor and the object parent to exist, then derives true/false from its actual keys.
This distinguishes a missing member from an explicit null; it says nothing about real-world absence.
Never use a missing property_value path as an implicit null or false. Select member presence only when
that structural observation materially supports a claim predicate (for example recorded Exec.Arguments).
For a material recorded empty JSON array, use kind=json_array_empty_v1 and the exact JSON path
(an empty path [] for the column's JSON root). This derives the atomic observation true only from an
existing array with no elements. Missing paths, nulls, objects and nonempty arrays are rejected.
It is not a synthetic count, a whole-container fact, or evidence that no real-world activity occurred.
Keep numerical tokens, case, whitespace and timestamp precision unchanged. Missing/ambiguous paths must
be corrected, not guessed. Explain each claim's property choices and any genuine limitations.
The fact extraction is for private overlap diagnostics only. Do not change questions, answers, checkpoints,
reward rules, splits or release status. Finish with SourceFactProposal."""

REVIEWER_INSTRUCTIONS = """Independently review canonical source-fact selection for the supplied validated task.
The SQL tool is DuckDB. Inspect the actual relevant source records rather than trusting selection prose.
Before passing, retrieve source _record_id alongside the inspected fields for EVERY selected record.
Literal-ID projections or repeating supplied IDs do not count as source inspection.
The bundle's values and observation IDs were mechanically source-verified; your job is semantic relevance
and completeness, not re-authoring the QA. Verify that every final/checkpoint has its decisive source
properties and necessary subject/time/role bindings, not a few convenient fields or irrelevant padding.
For derived results, verify the selected source inputs cover the actual count/order/comparison.
Actual incident/alert/action selection predicates are material even when supplied in the question.
Coverage is for the stated answer and checkpoint, not a reconstruction of every historical event or
every SQL-search result. Do not demand outside-window counterexamples solely to illustrate a temporal
boundary already established by the selected event times. Required in-scope alternatives must not be omitted.
json_member_presence is an exact observation about an existing source JSON object's keys, not a value
read at a missing path and not a claim that an activity or real-world attribute is absent.
json_array_empty_v1 is a verified structural observation that the exact source array is empty.
It does not select a whole container or summarize a nonempty one; inspect its materiality and exact path.
Distinguish source-observation facts from claims about the world, successful actions or missing data.
Event-bound subject IDs and exact source property paths must preserve actor/target and parent/child roles
and time/context distinctions. Shared answer strings alone cannot justify merging facts. Different
descriptive labels or surrounding proof routes cannot make the SAME verified event/property/value a
different fact.
Check useful shared identity properties in raw behavioral/control records, not only detector anchors.
Check that incident-membership facts select relevant AlertIds leaves, never a serialized whole array.
Do not omit a source event's ActionType when process-creation status is material, or a recorded
unknown/zero initiating PID when it is necessary to justify a stated attribution limitation.
Do not invent aliases, normalize values, change grading or select production weights/thresholds/splits.
Bind the supplied exact bundle_fingerprint. Pass only if the selected source facts are relevant, complete
for this purpose and preserve subject/property/time-role identity. Otherwise request revision with concrete
reasons; never return a success-shaped fallback."""


class FactInspectionTools(DiscoveryTools):
    def __init__(self, resolver: SourceFactResolver):
        super().__init__(resolver.verifier.engine, resolver.verifier.tables)
        self.verifier = resolver.verifier
        self.observed: set[PublicCitation] = set()

    def dispatch(self, name: str, arguments: dict) -> dict:
        result = super().dispatch(name, arguments)
        if name == "sql":
            query_result = QueryResult(tuple(result["columns"]), tuple(tuple(row) for row in result["rows"]))
            self.observed.update(self.verifier.observed_citations(query_result, arguments["query"]))
        return result


def curate_source_facts(
    *, client: CompletionClient, task: TaskRecord, validation: ValidationReport,
    baseline: EvidenceFootprint, resolver: SourceFactResolver, output: Path,
    revision_from: Path | None = None,
) -> dict:
    blockers = validation.pilot_blockers(task)
    if blockers or baseline.task_fingerprint != fingerprint(task):
        raise ValueError("fact curation requires the matching validated private-pilot task and footprint")
    if baseline.feature_weight_version != "unit-evidence-audit-v1":
        raise ValueError("fact curation requires the retained exact-signature unit baseline")
    if resolver.verifier.engine.engine != "duckdb":
        raise ValueError("source-fact curation requires the DuckDB public source reader")
    if (baseline.snapshot_id, baseline.graph_version) != (task.snapshot_id, task.graph_version):
        raise ValueError("fact curation baseline source identity differs from the task")
    revision_context = {}
    revision_hashes = {}
    if revision_from is not None:
        prior_binding = json.loads((revision_from / "binding.json").read_text())
        if (prior_binding["task_fingerprint"], prior_binding["validation_fingerprint"],
            prior_binding["baseline_fingerprint"]) != (
            fingerprint(task), fingerprint(validation), fingerprint(baseline),
        ):
            raise ValueError("fact revision requires unchanged task, validation and baseline inputs")
        prior_report = json.loads((revision_from / "fact_report.json").read_text())
        prior_review = CanonicalFactReview.model_validate_json((revision_from / "reviewer/result.json").read_text())
        if (prior_report["status"] != "needs_fact_revision"
            or prior_report["bundle_fingerprint"] != prior_review.bundle_fingerprint
            or prior_report["review"] != prior_review.model_dump(mode="json")):
            raise ValueError("fact revision requires a matching recorded revision request")
        prior_proposal = SourceFactProposal.model_validate_json((revision_from / "curator/result.json").read_text())
        revision_context = {
            "previous_annotation": prior_proposal.model_dump(mode="json"),
            "revision_feedback": prior_review.model_dump(mode="json"),
            "revision_instructions": (
                "Correct the source-property annotation, not the validated task. Reinspect the sources. "
                "Review feedback is a fallible diagnostic: check it against the actual claim scope and "
                "evidence bindings. Do not add out-of-claim citations or change gold to satisfy a reviewer."
            ),
        }
        if "mechanical_issues" in prior_report:
            issues = prior_report["mechanical_issues"]
            if not isinstance(issues, list) or not issues or any(not isinstance(issue, str) or not issue for issue in issues):
                raise ValueError("mechanical fact-revision feedback must contain explicit issues")
            revision_context["mechanical_feedback"] = issues
        revision_hashes = {
            name: file_sha256(revision_from / name)
            for name in ("binding.json", "fact_report.json", "curator/result.json",
                         "reviewer/result.json", "canonical-facts.json")
        }
    output.mkdir(parents=True, mode=0o700)
    claims = [{
        "claim_id": "final", "objective": task.question,
        "expected": task.private_gold.final.expected.model_dump(mode="json"),
        "evidence_sets": [group.model_dump(mode="json") for group in task.private_gold.final.evidence_sets],
        "source_programs": [p.model_dump(mode="json") for p in task.private_gold.final.programs if p.engine == "duckdb"],
    }]
    claims.extend({
        "claim_id": checkpoint.checkpoint_id, "objective": checkpoint.objective,
        "expected": checkpoint.claim.expected.model_dump(mode="json"),
        "evidence_sets": [group.model_dump(mode="json") for group in checkpoint.claim.evidence_sets],
        "source_programs": [p.model_dump(mode="json") for p in checkpoint.claim.programs if p.engine == "duckdb"],
    } for checkpoint in task.private_gold.checkpoints)
    context = {
        "public_task": task.public_task().model_dump(mode="json"), "claims": claims,
        "evidence": [ref.model_dump(mode="json") for ref in task.evidence],
    }
    (output / "binding.json").write_text(json.dumps({
        "task_fingerprint": fingerprint(task), "validation_fingerprint": fingerprint(validation),
        "baseline_fingerprint": fingerprint(baseline),
        "curation_version": CURATION_VERSION,
        "revision_from": str(revision_from) if revision_from is not None else None,
        "revision_artifacts_sha256": revision_hashes,
        "implementation_sha256": {
            name: file_sha256(Path(__file__).with_name(name))
            for name in ("canonical_facts.py", "fact_curation.py", "contracts.py", "evidence.py",
                         "qualified_witnesses.py", "generation.py", "query.py")
        },
        "grading_changed": False, "release_approved": False,
    }, indent=2) + "\n")
    curator_tools = FactInspectionTools(resolver)

    def validate_proposal(value: SourceFactProposal) -> None:
        resolver.resolve(task, validation, value)
        selected = {ref.citation for claim in value.claims for ref in claim.references}
        if selected - curator_tools.observed:
            raise ValueError("curator must inspect all selected source records with returned source _record_id")

    proposal = run_role(
        client, curator_tools, "fact-curator", CURATOR_INSTRUCTIONS, {**context, **revision_context},
        SourceFactProposal, output / "curator",
        validate_result=validate_proposal,
    )
    bundle = resolver.resolve(task, validation, proposal)
    (output / "canonical-facts.json").write_text(bundle.model_dump_json(indent=2) + "\n")
    reviewer_tools = FactInspectionTools(resolver)

    def validate_review(value: CanonicalFactReview) -> None:
        if value.bundle_fingerprint != fingerprint(bundle):
            raise ValueError("fact reviewer returned an unbound bundle fingerprint")
        if value.recommendation == "pass":
            selected = {ref.citation for claim in proposal.claims for ref in claim.references}
            if selected - reviewer_tools.observed:
                raise ValueError("reviewer must independently inspect all selected source records with returned source _record_id")

    review = run_role(
        client, reviewer_tools, "fact-reviewer", REVIEWER_INSTRUCTIONS,
        {**context, "proposal": proposal.model_dump(mode="json"), "facts": bundle.model_dump(mode="json"),
         "bundle_fingerprint": fingerprint(bundle)},
        CanonicalFactReview, output / "reviewer", validate_result=validate_review,
    )
    passed = review.recommendation == "pass" and all((
        review.source_properties_relevant, review.subjects_roles_times_preserved,
        review.claim_coverage_complete, review.no_value_only_merging,
    ))
    if passed:
        canonical = canonical_fact_footprint(baseline, bundle, review)
        (output / "canonical-footprint.json").write_text(canonical.model_dump_json(indent=2) + "\n")
    result = {
        "task_id": task.task_id, "task_fingerprint": fingerprint(task),
        "status": "canonical_facts_reviewed" if passed else "needs_fact_revision",
        "fact_count": len(bundle.facts), "claim_count": len(bundle.claims),
        "bundle_fingerprint": fingerprint(bundle), "review": review.model_dump(mode="json"),
        "exact_claim_signature_ids": [feature.feature_id for feature in baseline.facts or ()],
        "grading_changed": False, "release_approved": False,
    }
    (output / "fact_report.json").write_text(json.dumps(result, indent=2) + "\n")
    return result

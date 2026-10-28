# Agentic QA Generation for SecRL

**Status:** I0-I4 foundations and native pilots complete; full public MySQL snapshot verified; I5 development cohort audited and seed-42 36/11 split approved; production policy and release approval remain open.  
**Date:** 2026-10-23  
**Branch:** `feature/excytin-qa-redesign`  
**Evidence baseline:** [Graph generation, coverage, and evidence audits](GRAPH_GENERATION_COMPARISON.md).

## 1. Objective

Build an opt-in SecRL QA-generation feature that uses agents to discover useful
investigation tasks over raw telemetry and an enriched tenant graph, then admits
only tasks that pass strict evidence, scope, answer, and evaluation-environment
validation.

The feature must support two generation scopes:

1. **Tenant-wide:** discover investigations anywhere in the available tenant.
2. **Incident-specific:** generate questions about a selected incident, while
   allowing discovery and verification agents to inspect the full tenant.

The graph helps agents discover and explain relationships. It does not replace
the raw logs as the source of evidence, and graph connectivity is not proof of
maliciousness or causation.

## 2. Agreed decisions and boundaries

| Decision | Design |
|---|---|
| Generation approach | Agent discovery followed by strict validation; not a template-first generator |
| Framework/dataset versions | Preserve legacy generation as v0, o1 datasets as v0.1 and current Opus datasets as v0.2; this feature is the v1 generation framework |
| Graph construction | Clean rebuild from reconciled observations with versioned enrichment rules, followed by comparison against the existing graphs |
| Integration target | SecRL first, using its agent/environment interface and MySQL evaluation path |
| Evaluation compatibility | v1 tasks must support SecRL evaluation and ACESEvals task export with the same evidence/checkpoint contract |
| Tenant scope | Not restricted to the ten selected incidents |
| Incident scope | Full tenant access is allowed, but the question must remain anchored to its incident |
| Selected incident views | **5, 34, 36, 38, 39, 55, 133, 134, 166, 322** |
| Positive scenario designation | Treat all ten as TP benchmark scenarios. The original eight and 133 have explicit project approval; 36 also has an exported TP classification |
| Source classifications | Preserve exported labels and reasons separately; never overwrite them with project designations |
| Active incident state | Use the latest complete row per incident across included sources; do not retain old incident rows as active QA state |
| Historical membership | Derive removed incident-alert associations from source updates, store them separately with provenance and a not-current/relevance caveat |
| Incident 5 exclusion | No gold answer may depend on unavailable evidence from alert `46f3d4b8-060c-4022-c190-4d88954a6a2e` |
| Incident 322 exclusion | No gold answer may depend on unavailable `SquidProxy` source/function output |
| FP/BP-targeted QA | Deferred at incident, alert, and event levels; no such tasks are eligible for the current release |
| Negative investigation | Generally deferred; the user authorized a narrow removed-membership investigation on 2026-10-23, not a general negative-QA workstream |
| Answer/evidence contract | Typed final answers with supporting evidence; report answer correctness and grounded success separately |
| Partial credit | Include evidence-backed intermediate discovery checkpoints, following the ACESEvals task concept; numerical cap and task weights remain open |
| Default reward policy | Full grounded final success earns full credit; otherwise checkpoint progress earns capped partial credit below full success |
| Scoring configurability | Preserve all component results and policy metadata for user-configurable per-task scoring; the default aggregate must not be the only retained result |
| Checkpoint visibility | Private by default; public task text must not reveal answer-bearing rubric details |
| Benchmark overlap | Shared checkpoint responses and source evidence are permitted for distinct QA objectives, including across question-level splits; report within- and cross-benchmark overlap rather than forcing shared-evidence groups |
| Split setting and similarity | Per-incident train/test splits plus a separate full-tenant benchmark; retain a numeric weighted evidence-subgraph similarity score and its components for later data-driven split/deduplication policies |
| Existing benchmark | Existing datasets, default runners, and legacy scoring stay unchanged |

An incident-level TP designation does not make every associated event or entity
malicious. Conversely, an alert's `Benign` investigation state does not make its
original detection a false positive.

This deferral concerns investigation/generation targets, not removal of raw
records from the tenant graph or logs. Preserve FP/BP-related observations and
source annotations when needed as context for tenant-wide or incident-anchored
tasks; do not blanket-filter the selected TP scenarios by alert labels. Research
candidates are not automatically promoted into the active QA set.

### Non-goals for the first implementation

- Rebuilding existing O1/O3/Opus datasets or changing their published scores.
- Generating FP/BP-targeted incident, alert, or event QA; continuing negative-lead
  investigation/data recovery; or building a standalone rule-review benchmark.
- Automatically recovering unavailable data, repairing anonymized identities by
  guesswork, or fabricating missing telemetry.
- Replacing SecRL with an external evaluation harness.
- Requiring every question to use a fixed graph depth or defeating every frontier
  solver as a condition of validity.
- Supporting arbitrary free-text incident reports before their scoring contract
  is defined.

### 2.1 Framework, dataset, and evaluation versioning

The following naming is agreed; it does not rename or rewrite existing files:

| Version | Meaning |
|---|---|
| QA-generation framework **v0** | Existing SecRL alert/path-based generation |
| Legacy dataset **v0.1** | Existing o1-generated questions |
| Legacy dataset **v0.2** | Current Opus-generated legacy questions |
| QA-generation framework **v1** | This source-reconciled, enriched-graph, agentic generation feature |

Existing o3 artifacts and their provenance remain intact under the legacy
framework. They are not silently reassigned to either named dataset release.
Use manifest aliases to document the version mapping; keep existing paths,
default behavior, dataset bytes, and published results unchanged.

Agreed evaluation-versioning direction; exact schema/profile names remain to be
finalized:

- Preserve a legacy evaluation profile for existing datasets and scores.
- Give v1's typed-answer, evidence and discovery-checkpoint evaluation contract
  its own explicit schema/profile version, implemented by SecRL and ACESEvals
  adapters rather than duplicating two independent definitions of correctness.
- Record generator version, dataset release, task/rubric revision, source/graph
  snapshot, evaluation profile, reward policy/configuration, and backend adapter
  revision separately. A change of judge or reward weights is not a new
  generation-framework version.
- Export public task context separately from private gold/rubrics. Validate
  equivalent submissions and trajectories in both backends; do not silently
  downgrade a v1 task to legacy answer-only scoring.

## 3. Architecture: one source graph, two scoped workflows

```text
Pinned raw tables + source metadata
             |
             v
Observation ledger + coverage/dependency manifest
             |
             v
Versioned canonical graph + explicit weak/contextual relationships
             |
       +-----+--------------------------+
       |                                |
       v                                v
Tenant discovery context        Incident context and anchor manifest
       |                                |
       +---------------+----------------+
                       v
          Scout -> lead -> explorer draft
                       |
                       v
          Executable task/evidence contract
                       |
                       v
      Strict validators + blind solving + refutation
                       |
                       v
       SecRL/MySQL parity check + reviewer approval
                       |
                       v
       Immutable release, split manifest, and evaluation logs
```

The incident graphs are reproducible **views of the same canonical graph**, not
ten independently maintained copies. Views may be materialized for performance.
Their definitions and provenance remain in the case manifest.

FP/BP investigation is not an active input to this workflow. If explicitly
reopened later, it could reuse the same workflow rather than require a third
independent graph.

## 4. Data, observations, and graph provenance

### 4.1 Pinned source snapshot

Register the supplied [DuckDB files](secgym/database/duckdb_data) as read-only
inputs. Record table schemas, row counts, data hashes, acquisition provenance,
source code revision, and extractor versions in a snapshot manifest.

Use the **latest complete incident row** across the included sources as the
active incident state. Each update is a new source row, not a new incident.
Do not retain the older incident rows in the active QA dataset or independently
aggregate nullable fields from them. Read historical source updates only as
needed to derive membership changes and their provenance; the original files
remain unchanged. Historical membership unions are not current membership.

The audit baseline includes 306 incident IDs, 1,039 distinct raw alerts,
62 source tables, and 13,339,265 source rows. These are regression references
for the supplied **post-cleanup DuckDB**, not an inventory of every available
source export.

The [cleanup-impact audit](GRAPH_GENERATION_COMPARISON.md#15-preprocessing-provenance-and-impact-on-the-audits)
found 608 additional incident IDs and 30 excluded alert IDs in the available
incident CSVs, including later incident history and two omitted negative-signal
leads. The source union contains 914 historical incident IDs and 1,069 alert IDs;
these are not independent attack counts or certified complete cases. Incident
175 has a newer source TP label absent from DuckDB. The ten project scenarios
and FP/BP deferral remain unchanged.

Before freezing the source manifest, reconcile all inputs so newer incident
updates are not skipped, then materialize one latest incident row and the
historical membership metadata described below. Preserve omitted alerts as
observations without requiring current incident membership. Keep original
versus transformed values and process-time recovery provenance separate.
Recompute coverage and label inventories; do not silently mix the old graph
snapshot with newly restored source records.

#### Latest state and historical membership (agreed)

Keep three concepts separate:

| Concept | Purpose | Example |
|---|---|---|
| Active incident row | Select the latest whole available source row at the pinned snapshot | Incident 175 uses its August 22 TP update, not the superseded August 2 unclassified row |
| Historical-membership metadata | Retain evidence that a specific incident-alert association existed and was later absent | Store the last-present and first-absent source snapshots without serving all historical incident rows |
| Project scenario manifest | Define benchmark selection and project assumptions separately from SIEM labels | The selected ten remain TP scenarios; a newer source label for 175 does not automatically add it to the benchmark |

Illustratively, A/B in an earlier update followed by A/C means current membership
A/C and historical removed membership B. Never present A/B/C as current.

Use separate relation types or an equally explicit status distinction:

- `current`: present in the latest incident row.
- `historical_removed`: observed previously, absent from the latest row.
  Record `last_present_at`, `first_absent_at`, before/after source references,
  other current parent incidents, and any explicit transition metadata.

The time bounds describe exported snapshots, not necessarily the exact removal
action time. A verified past membership is reliable as a historical observation
but weaker evidence of relevance to the **current** incident. Removed edges are
not current incident anchors, causal links, or FP/BP labels; using one to support
an incident question requires additional claim-specific relevance.

Null/malformed membership is unknown, not an empty list proving removal.
**Approved conflict policy:** if rows tied for the latest update disagree on
meaningful incident fields, report the conflict and block QA for that incident;
continue with unaffected incidents. Deduplicate identical observations, but do
not select an arbitrary source/row ID or mix fields from conflicting rows.
Retain source references for resolution. If a link is later re-added,
its current status follows the latest row, with any earlier removal recorded
separately. Consolidation relationships require supporting source evidence,
not merely shared entities or overlapping alert lists.

### 4.2 Observation ledger

Preserve what the source actually contains before graph filtering:

- One latest complete active incident record per incident, with source locator.
- Historical membership transitions and supporting references derived from
  source updates, not full superseded incident rows in the active dataset.
- Available alert observations and entity evidence, including unassigned alerts.
- Typed entity definitions, nested objects, `$id`/`$ref` relationships, and
  field-only identifiers.
- Event participants and their source roles.
- Raw verdict/classification annotations and their timestamps, marked as
  annotations rather than independently verified truth.
- Source JSON path, table/row reference, observation time, and identity mapping.
- Explicit reasons for unsupported types, exclusions, unresolved identities,
  invalid placeholders, and truncation.

Represent original identifiers independently of a canonical identity. Keep
numeric cloud-application IDs, Entra application IDs, and service-principal
object IDs in distinct namespaces.

Do not force a record without adequate identity information into an invented
canonical node.

### 4.3 Graph enrichment priorities

| Priority | Change | Admission constraint |
|---|---|---|
| Foundation | Reconcile the supplied graph with checked-in extraction rules | Reimplement the four stored-but-unversioned relation types only where their semantics and source support can be validated; otherwise exclude them with an audit reason |
| Foundation | Latest incident state, historical-membership edges and observation ledger | Keep current and removed memberships distinct; historical relevance is not assumed |
| Foundation | Reconcile pre-merge incident/alert exports with the supplied DuckDB | Include later source updates before selecting latest incident rows; derive removed edges and preserve input provenance/exclusions |
| High | Expand all relevant audit targets and cloud activity participants | Preserve actor/target/resource roles; do not create arbitrary causal links between all participants |
| High | Click-message/source/redirect and Graph API resource-target relationships | Require source-supported identifiers and relation semantics |
| High | Filename/script references from complete command text | Emit references, not assumed file creation or execution |
| High | Namespace-aware application aliases and instance metadata | Never merge on a shared display name alone |
| High | Process-identity recovery with conflict handling | No blind `CreatedTimeUtc` fallback when raw creation time disagrees |
| Medium | Azure resource hierarchy and cloud session/request identifiers | Validate namespace and joins before use as gold evidence |
| Medium | Explicit contextual/weak associations | Must not silently count as causal proof or hard identity |

Use distinct relation classes:

- `observed`: directly supported event participation/activity.
- `resolved_identity`: a documented alias or identity mapping.
- `derived`: produced by an explicit rule with supporting inputs.
- `contextual`: inventory, metadata, or weak affinity.
- `hypothesis`: an investigative possibility, not admissible proof by itself.

For aggregated edges, retain all required source references or an executable
selector defining the aggregation. One representative row must not be presented
as proof of an entire count, set, or time span.

The imported frozen graph is a comparison baseline, not the new graph's build
foundation. Retain an enrichment in the rebuilt evidence graph only when its
semantics and source support are validated; never add it solely for old-graph
compatibility. Unsupported old relationships are excluded and recorded in the
comparison audit. Use a reason such as "unsupported by available sources":
noise/corruption is possible, but absent supporting evidence does not itself
prove that diagnosis. No attempt to recreate an unsupported edge is required.

### 4.4 Agreed build strategy: clean rebuild with versioned rules

The agreed direction is a clean graph rebuild with enrichments, followed by
comparison against the old graphs. This replaces the earlier bootstrap
recommendation. The graph rebuild has run against the full ledger. The
source-coverage comparison and legacy alert/entity semantic checks are complete;
the scoped graph acceptance and its limits are recorded in Sections 17.8-17.10.

Rebuilding and versioning are compatible. Build fresh graph artifacts from the
reconciled observation ledger, with the source manifest, extraction/identity rule
revision, and build configuration pinned. "Versioned enrichments" means tracking
which rules and inputs produced a relationship, not requiring incremental
patching of the old graph or a separate plugin framework.

Because the original full-tenant CSV is unavailable locally, a clean **graph**
rebuild must not be described as a pristine raw-tenant re-export. Its input ledger
combines the imported DuckDB baseline with available incident CSV observations
and explicitly records transformations and exclusions.

Compare the new graph against both the supplied ExCyTIn 2.0 tenant graph and the
eight original SecRL alert/entity graphs. Separate differences caused by source
restoration, intended enrichment, identity-rule changes, and unexplained losses.
Compare common-source cohorts as well as full outputs; raw count equality is not
an acceptance criterion. Include source-backed relationship checks, membership
and alias checks, known incident paths, and the four stored-but-unversioned
relation types. An omitted source-backed relationship is a potential regression;
an excluded unsupported old relationship with a recorded reason is not.
Exact quantitative checks remain to be frozen.

## 5. Scope contracts

### 5.1 Tenant-wide generation

Scouts may start from raw events, alerts, entities, temporal patterns, or
investigative hypotheses anywhere in the available tenant snapshot.

They are not required to touch an alert seed or one of the ten selected incidents.
Every accepted task still needs:

- A realistic, discoverable starting point.
- Explicit answer/time scope.
- Supported evidence and adequate source coverage.
- A bounded task rather than "find anything malicious in the tenant."

Partition discovery by time, domain, entity type, and analyst goal to control
cost and avoid a few high-degree entities dominating the output.

### 5.2 Incident-specific generation

The incident manifest defines:

- Incident number and current alert membership.
- Source/project classifications and designation basis.
- Available alert/entity/event anchors.
- Suggested starting window, exclusions, and source-availability warnings.

Agents may inspect earlier baselines, other hosts, related identities, and later
activity across the entire tenant. The initial map/window is a navigation aid,
not an access boundary.

The final task must identify a demonstrable connection to the selected incident:

1. Its starting artifact belongs to or is evidenced by that incident.
2. The investigative objective is about that incident's activity, context,
   consequences, or a specific competing explanation.
3. Any out-of-window or cross-incident evidence has an explicit relevance link.
4. The question states the scope an investigator needs; it does not depend on a
   hidden generation-time window.

Merely mentioning an incident number, sharing a common filename, or following an
unrelated rare event is not sufficient anchoring.

Historical removed membership alone is likewise insufficient to treat an alert
as current incident activity. It may be investigated as contextual evidence, but
its historical status and independently established relevance must be explicit.

The same evidence can support a tenant task and an incident task, but their
relationship must be recorded for provenance and overlap reporting. The two
scopes are separate benchmarks: cross-scope overlap is permitted and does not
force joint deduplication or a common split assignment. Section 13 defines the
within-benchmark controls.

### 5.3 Evaluation visibility

**Agreed:** serve both new scopes against the same sanitized full-tenant
MySQL dataset. Incident mode changes the task anchor, not the available evidence.
This preserves the generator's ability to use justified external context.

Graph tools are for generation and validation. The default evaluated-agent
interface remains SQL over the sanitized data; graph access would be a separate,
explicit evaluation variant.

Do not export a question requiring full-tenant evidence into a legacy
incident-only database without independently validating that variant.
The existing legacy incident databases remain unchanged.

## 6. Coverage and exclusion policy

Coverage is a per-task evidence requirement, not a binary property of an entire
incident graph.

Each task declares:

- Required tables, streams, and any query-function dependencies.
- Relevant event-time columns and time ranges.
- Entity/role bindings needed by its answer.
- Whether the claim depends on exhaustive absence, counts, or ordering.
- Known missing sources and assumptions.

The gate must distinguish source presence, relevant rows, graph support, and
evidence sufficient for the claim. Populated hourly bins alone do not establish
completeness.

Exclusions apply transitively to the gold proof:

- The absent incident-5 alert cannot be reconstructed from a title or linked
  incident record.
- Missing proxy output for incident 322 cannot be substituted by a model
  narrative. A different available source is acceptable only if it independently
  establishes the required fact.
- July 23-31 gaps and source-specific holes must be surfaced to discovery agents
  and validators.
- Lack of data cannot serve as proof of benignness or non-occurrence.

Incomplete candidates receive a blocked/rejected status with a reason. Do not
convert them into FP answers, positive answers, or accepted "insufficient
evidence" tasks automatically.

## 7. Agentic generation workflow

The following are proposed stages in a new opt-in engine.

1. **Inventory and context preparation**
   - Load the snapshot and case manifest; expose scope and coverage warnings.
   - Build tenant or incident starting contexts.
2. **Scouting**
   - Inspect data before using the goal catalogue to label/rank leads.
   - Explore both supporting and contradictory evidence.
   - Preserve counterevidence and uncertainty without deciding the gold; do not
     pursue deferred FP/BP-targeted leads.
3. **Lead screening**
   - Verify cited rows and identities.
   - Check scope/anchor relevance and source prerequisites.
   - Deduplicate repeated alert families and already-covered evidence.
4. **Exploration**
   - Investigate a selected lead with graph tools and raw SQL.
   - Produce a candidate question, typed answer, evidence and counterevidence,
     scope constraints, and why the task matters.
5. **Task contract formation**
   - Write an executable answer query or supported structured claim checker.
   - Bind the answer to explicit source evidence and required coverage.
   - This follows discovery; it does not replace discovery with templates.
6. **Strict validation and repair**
   - Apply the gates in section 9.
   - Allow bounded repair using concrete failures.
   - Any material rewrite invalidates affected validation results.
7. **Difficulty measurement**
   - Run blind solvers and shortcut probes; preserve traces and errors.
   - Calibrate accepted tasks rather than changing truth to make them harder.
8. **SecRL export and release**
   - Validate against the actual student-visible MySQL data.
   - Assign leakage-safe splits and publish an immutable release.

Shared tools: schema discovery, read-only SQL, raw-row retrieval, graph
neighbors/paths, identity lookup, temporal comparison, coverage inspection, and
draft validation. Enforce read-only access and resource limits at the database
and execution layer, not solely through prompts or a SQL prefix check.

Keep timestamps and directions explicit. Backward investigation is valid, but a
claim that one event caused or preceded another requires a separately checked
temporal relationship.

## 8. Deferred benign/FP investigation: research and future protocol

**Current decision:** FP/BP-targeted QA remains deferred. On 2026-10-23 the user
authorized a narrow check of removed incident-alert memberships as a possible
source of negative leads. This does not reopen general negative generation.
The [research report](BENIGN_FP_QA_RESEARCH.md#35-removed-incident-memberships)
records the result: all 155 historical-only links have another current parent,
and the additional scheduled-task lead did not establish a verified negative
verdict. No new QA was admitted.

### 8.1 Earlier research scope

Dedicated FP/BP incident datasets were excluded. The subsequent research examined
**individual alert/event claims throughout the tenant**, including those inside
TP scenarios. That research is now paused as well.

If reopened, a qualifying negative task would need to establish one of:

- **Benign positive:** the detected behavior occurred and a legitimate/expected
  explanation is independently supported.
- **False positive:** the scoped detection claim is refuted by sufficient,
  attributable evidence.

A prevented malicious execution can still be a true-positive detection. "Blocked,"
"remediated," a trusted binary, or a `Benign` automated investigation state must
not automatically become an FP/BP label.

### 8.2 Initial screen performed for this design

The latest 1,039 raw alerts contain:

- 87 `InformationalExpectedActivity` classification annotations.
- One `FalsePositive` classification annotation.
- 26 `Benign` automated-investigation states.
- Their union is **111 candidates**, not 114 distinct alerts.

Initial evidence screening found:

| Screen result | Alerts |
|---|---:|
| Some graph-linked operational raw rows in the context window | 91 |
| No operational rows in the context window | 17 |
| Window context exists but no graph-linked operational support | 3 |
| **Total candidates** | **111** |

Important qualifications:

- 87 candidates belong to the ten selected TP scenarios.
- Eleven alerts are simultaneously annotated `TruePositive` and investigation
  state `Benign`.
- Eight are notices that an automated investigation was started manually, not
  independently established malicious or benign behaviors.
- **No new negative task has been admitted by this screen.** It measures
  candidate availability, not authorization or verdict correctness.

For example, the August 1 Kekeo alert `SecurityAlert#9685` has same-window
`DeviceFileEvents#683830` and `DeviceEvents#307461` evidence. That is a better
investigation starting point than the July 30 BP incident with missing logs, but
the records do not establish authorized use. It remains an unadjudicated lead.

See the [candidate inventory][alert-negative-candidates] and
[screen evidence][alert-negative-evidence].

The [consolidated tenant study](BENIGN_FP_QA_RESEARCH.md) collected evidence for
all 111 leads and reviewed 79 stratified packets spanning all 47 detection-title
families, including a six-alert detailed case subset. It also investigated 27
latest resolved identity-risk events linked to 12 additional alerts, plus three
platform-agent ASR events. The result is three locally verified negative
factual/configuration QA candidates and **zero verified benign/FP verdicts**.
These are separate task categories: a negative boolean answer is not a BP/FP
classification. Risk clearance, successful authentication, signed service
identity, and blocked operations do not alone supply the missing benign
explanation. These findings support the current deferral; cleared states and
prevalence must not become automatic negative gold.

### 8.3 Future investigation and admission protocol, only if reopened

After explicit approval to resume, for each candidate:

1. Freeze its exact claim and the source version; separate alert, investigation,
   incident, and project labels.
2. Retrieve the underlying events using stable identifiers, time, and source
   fields; verify every proposed identity match.
3. Seek evidence for legitimate intent or a false detection premise: authorized
   change/test context, a demonstrated parser/correlation error, or direct
   counterevidence. A repetitive baseline alone is insufficient.
4. Investigate competing malicious explanations and relevant activity beyond the
   initial window.
5. Check whether missing sources could explain the apparent absence of harm.
6. Write a case-specific evidence dossier and executable factual checks.
7. Obtain reviewer approval for the scoped verdict and expected reasoning.
8. Generate a question only after admission; hide final adjudication metadata
   from the evaluated agent.

Result states: `admit_benign`, `admit_false_positive`, `reject_missing_evidence`,
`reject_ambiguous`, `reject_not_a_negative`, and `needs_review`.

Admission applies to the **specific alert/event claim**, not to every use of an
account, IP, hash, host, or process name. Do not reopen an excluded FP/BP incident
set simply because one alert in it later passes.

This workstream must be allowed to produce zero accepted negatives. There is no
minimum negative quota that overrides the evidence requirement.

## 9. Validation contract: fail closed for release

Use one registry with scope/type-specific required gates. Gate results are
`pass`, `fail`, `error`, or `not_applicable`, with recorded reasons and evidence.

A task is release-eligible only when **every required gate passes**.
`not_applicable` is allowed only for a gate explicitly optional for that task
type; missing required evidence is not a successful skip.

| Gate | Required checks |
|---|---|
| Schema | Correct field types, nonempty text, declared answer shape, valid scope and stable IDs |
| Source/coverage | Snapshot matches; all required evidence and dependencies exist; exclusions satisfied |
| Identity and evidence | Actual source rows support bindings and relationship semantics; preserve ambiguity/confidence |
| Evidence independence | Identify detector-derived rows and shared source lineage; a detector-description echo cannot independently validate the same detection |
| Scope eligibility and anchoring | Reject deferred FP/BP-targeted tasks; incident task remains about its incident; tenant task has a discoverable start without requiring an incident seed |
| Executable answer | Queries/checkers return the required shape and computed answer; run deterministically with explicit ordering where needed |
| Checkpoint rubric | Every reward-bearing checkpoint has a valid claim, attributable evidence, executable checks where applicable, and serving-data parity; reject redundant or unsupported reward targets |
| Query integrity | No hidden `_rid`/record-ID shortcuts or hardcoded target/intermediate IOCs; literals must be public anchors, question-defined constraints, or justified domain constants |
| Uniqueness/completeness | Check competing interpretations, look-alikes, ties, set completeness, and temporal boundaries; no first-row-only acceptance |
| Wording/leakage | No answer aliases, hidden path hints, final adjudication metadata, or accidental overly precise filters |
| Blind verification | A separate verifier derives facts from public briefing/question/schema and tools before seeing author evidence/gold |
| Refutation | Challenge premise, attribution, answer, scope, and alternative explanations with full-tenant access |
| Serving parity | Answer and required evidence remain valid in the exact student-visible MySQL snapshot |
| Release review | Required human decisions complete; split/duplicate checks pass; validation metadata matches current content |

Specific corrections to known 2.0 behavior:

- A failing executable path specification is a failure, not a bypass.
- Deduplicate evidence and repeated hops before computing structural depth.
- A three-hop chain is not a substitute for source validity; no universal
  three-hop minimum for sound triage tasks.
- Enforce scalar cardinality: exactly one scalar result, not the first row of
  several. Validate set/list semantics and duplicate treatment explicitly.
- Numeric, time, and boolean answers require derivation, not `SELECT <gold>`.
- Keep full account domains, file identities/paths, and explicit timestamp
  tolerance units when the question requires them.
- Treat API errors, timeouts, unavailable dependencies, and truncated query
  results as validation errors. They cannot make a task "very hard" or make a
  shortcut probe pass.
- Two author-informed SQL programs agreeing is supporting evidence, not
  independent proof. Add blind retrieval and semantic review.
- After any answer, scope, or wording change, recompute all dependent gates
  against the final item.

Define task-specific acceptance semantics rather than claiming that SQL alone
can establish human intent. Any future FP/BP verdict tasks would additionally
require independent benign/refuting evidence, adequate coverage, and a reviewed
claim dossier as described in Section 8; they are not currently eligible.

For example, the tenant study found a `DeviceEvents` row with
`ActionType=OtherAlertRelatedActivity` that only repeated an alert description.
It can document a reported detection, but must not count as an independent
behavior observation merely because it resides outside the alert tables.

The study also found multiple authentication substeps/update rows for
the same sign-in request ID. Preserve those observations and validate the
question's attempt/outcome scope instead of assuming request ID is a unique
event key or choosing an arbitrary first/latest outcome. Latest whole-row risk
state selection and sign-in-attempt reconstruction are different operations.
Similarly, a precise host/PID/creation-time match to a System process or ancestor
does not establish that every attached event supports the alert's specific claim.
Record causal relevance separately from identity-match confidence.

## 10. Artifact and question contracts

### 10.1 Private build artifacts

Keep these versioned and separate from student-visible data:

- Source snapshot, schema, extraction rules, and graph manifests.
- Current/historical incident manifests and project-designation policy.
- Coverage profiles and explicit exclusions.
- Scout leads, tool traces, drafts, rejected items, and repair history.
- Gold programs, source selectors, evidence/counterevidence, and review dossiers.
- Per-gate results, model configuration, token usage, errors, and costs.

Each evidence reference includes `snapshot_id`, table, private row reference,
and a content/identity check. A bare `Table#rid` is not portable across rebuilds.

### 10.2 Logical task record

Proposed contract, not an existing SecRL API:

```text
schema_version
generator_version, dataset_release, benchmark_id
task_id, revision_id, content_hash, lineage_group
snapshot_id, graph_version, serving_view_version
scope:
  mode: tenant | incident
  incident_id: integer | null
  anchor_refs, answer_window, relevance_rationale
  required_sources, exclusions_checked
context, question, answer_format
private_gold:
  answer_type, semantic_kind, value, normalization, tolerance
  programs, evidence, alternative_evidence_sets, counterevidence
  claim_checks
  discovery_checkpoints:
    id, objective, typed_fact_check, evidence_requirements
    alternative_evidence_sets, semantic_dependencies, max_score, weight
  default_reward_policy, reward_policy_version
  evidence_footprint:
    observation_refs, typed_relationships, decisive_facts, checkpoint_targets
difficulty:
  evidence_rows, tables, identity/temporal operations, measured solver outcomes
validation, review_status, provenance, split
```

Initial answer types: entity, set, ordered list, number, timestamp, and boolean.
Defer a typed FP/BP verdict-plus-evidence extension until that scope is reopened.
Do not accept general free-text rationale as an unvalidated substitute.
Store timestamp tolerances explicitly in seconds and numeric tolerances in
declared units; never inherit the older minutes-versus-seconds ambiguity.

`task_id` identifies the logical task. A material edit produces a new
`revision_id` and invalidates dependent results. Cross-scope variants and
paraphrases share a `lineage_group`.

Execution-resume keys include content, snapshot, serving view, extractor/prompt version,
model configuration, and gate version. Changing any relevant input prevents
reuse of a stale validation pass.

Discovery checkpoints above are grading milestones, not pipeline-resume
checkpoints. Their exact serialized schema, numerical cap and weights remain
under design; the default aggregation policy is agreed in Section 11.3.
Expected values and answer-bearing rubric descriptions stay private.

### 10.3 SecRL/ACESEvals exports and identity

Keep compatibility text fields: `context`, `question`, string `answer`, and
`solution: list[str]`. Add typed `answer_meta`, `task_id`, `revision_id`, `scope`,
and provenance to the new dataset format.

`solution` is a rendered, validated explanation of admitted evidence, not a
second unconstrained model-generated gold answer.

Do **not** invent `start_alert`, `end_alert`, or `shortest_alert_path` for new
tasks merely to satisfy legacy code. New task identity and difficulty are not
alert-pair identity or old bipartite path length.

Generate both exports from the same admitted canonical task record:

- **SecRL:** opt-in v1 task loading, structured answer/evidence submission,
  observable trajectory capture and checkpoint scoring; unchanged legacy route.
- **ACESEvals:** public task context plus private submission/checkpoint scorers,
  evidence requirements and per-task aggregation configuration.

The exports retain stable task/checkpoint IDs and source/public citation
mappings. Validate matched submissions and recorded discoveries against the same
snapshot and scoring policy in both adapters. Exporting compatible YAML alone
is not sufficient to establish equivalent rewards.

## 11. SecRL integration and student-visible data

### 11.1 Existing integration surfaces

| Existing surface | Required opt-in change |
|---|---|
| [ExcytinEnv](secgym/excytin_env.py) | Load a versioned dataset manifest and explicit connection configuration instead of requiring a hardcoded legacy `ATTACKS` entry |
| [Experiment runner](experiments/run_exp.py) | Route v0 legacy and v1 tasks explicitly; resume v1 by task/revision/snapshot and evaluation policy, not just start/end alert |
| [Reevaluation](experiments/run_reevaluation.py) | Match logs by the same new task identity; preserve legacy alert-pair matching for legacy datasets |
| [Evaluator interface](secgym/evaluator.py) | Add typed final-answer/evidence scoring and intermediate discovery-checkpoint credit; freeze aggregation in Section 16; retain legacy evaluator behavior |
| [Result analysis](experiments/result_analysis/analysis.py) | Report scope, task family, evidence depth, answer accuracy, grounded success, checkpoint progress, and aggregate reward; branch away from mandatory `shortest_alert_path` access |
| [Agent action parsing](secgym/agents/agent_utils.py) | Support structured submissions without truncating content as if it were SQL; preserve legacy protocol behavior |
| [Question rendering](secgym/utils/utils.py) | Expose only public task text and answer-format instructions |

Audit agent reset/logging paths, including agents that receive the entire question
dictionary. Gold fields must never enter an agent's prompt, memory, or tool-visible
schema, even if they remain available to the environment/evaluator.

### 11.2 MySQL parity and permissions

Generation may use DuckDB and graph tools internally. New SecRL evaluation uses
an exported **sanitized, read-only MySQL view of the same source snapshot**.

- Re-run gold factual checks against MySQL, not merely DuckDB.
- Validate typing, null/empty-string conversion, timestamps, JSON handling, case
  semantics, ordering, and duplicate behavior.
- Map private source refs to public, stable record locators where evidence
  citations are required. Do not reveal private gold selectors.
- Remove or mask final classifications, determinations, reviewer answers, and
  investigation verdicts from all relevant versions and nested fields. Keep
  intended alert observations; document what was removed.
- Block access to private manifests, query-history answer artifacts, cached
  generations, and adjudication tables through database permissions.
- Use a read-only evaluation identity, not the legacy unrestricted connection.
- New manifest connection routing must not mutate the global legacy `ATTACKS`
  configuration.

Existing incident-only databases, default dataset choices, and legacy rewards
must remain unchanged unless the user explicitly selects the new release.

### 11.3 Scoring

For factual answers, use explicit typed comparison. Avoid substring acceptance,
unbounded enumerations, domain-stripping account equality, and filename-only
equality when stronger identity is requested.

**Agreed:** evaluate typed final answers with evidence and award partial credit
for evidence-backed intermediate discoveries. A source-grounded gold answer does
not itself establish grounded student reasoning. Report final answer accuracy,
grounded final success, checkpoint progress, and aggregate reward separately.
FP/BP verdict-specific scoring remains deferred.

Verified prior art is the [ACESEvals ExCyTIn task format][aces-task-example]:
separate `submission` and `checkpoint_*` scorers, `target: trajectory` for
checkpoints, and per-checkpoint `max_score`, `weight`, title and description.
Its [checkpoint judge][aces-checkpoint-judge] evaluates discoveries in the
trajectory, not just the final answer, and credits a checkpoint once.
The inspected task uses `max(submission, checkpoint_group)`; its
[pinned runtime][aces-aggregation] normalizes the weighted checkpoint group.
This is a verified example, not a requirement to copy every existing scoring
choice or use an LLM judge for facts that can be checked deterministically.

Checkpoint safeguards:

- Reward supported facts and relationships, not a particular SQL query or fixed
  authored traversal. Accept equivalent evidence and valid investigation order.
- Use observed tool results and explicit findings/evidence references; do not
  require access to a model's hidden reasoning.
- A raw result containing the right IP/name is not enough without the correct
  subject, role, and time binding. Bulk enumeration must not complete the rubric.
- Credit each logical discovery once; avoid redundant checkpoints and double
  counting the same final-answer fact.
- Use dependencies only where the claim genuinely requires them, not to force
  an investigation sequence.
- Validate every checkpoint alongside the final answer against the public MySQL
  view. Generated prose alone is not a validated reward function.

**Agreed default: final-success-first with capped partial credit.**

```text
F = 1 only when the final answer and its required evidence pass; otherwise 0
P = normalized evidence-backed checkpoint progress, between 0 and 1
R_default = max(F, alpha * P), where 0 < alpha < 1
```

The policy is approved; the numerical cap and task weights still need
calibration. A correct answer without sufficient evidence does not set `F=1`,
although separately verified intermediate discoveries may earn partial credit.
The formula applies to completed, valid evaluations. Scorer errors or unknown
results remain explicit error/incomplete statuses, not fabricated zero scores
or comparable completed rewards.

Users may configure scoring per task, including other aggregations. Retain the
components rather than baking one aggregate into the generated dataset:

- Final answer correctness, final-evidence validity, and grounded final success.
- For every checkpoint: stable ID, raw score, maximum, completion status,
  decisive facts, supporting public evidence/visible trajectory references,
  first completion step, and validation or judging outcome.
- Full available tool/explicit-finding traces and replayable evidence references,
  under the appropriate access/redaction policy; no dependency on hidden model
  reasoning.
- Task/rubric/evidence revisions, evaluator/model versions, errors and unknown
  results, and the aggregation configuration, weights, normalization and cap
  used to produce each reported reward.

Changing only aggregation or weights can reaggregate existing component
results without rerunning discovery or judging. Changing a checkpoint's claim,
evidence requirements, rubric or judge invalidates the affected evaluations;
cached scalar scores are not sufficient for those changes.

The ACESEvals export must preserve separate component scorers and explicit
per-task policy. Its runtime normalizes score groups: merely reducing
`max_score` does not necessarily cap the normalized checkpoint contribution.
Add an adapter/aggregation fixture proving that checkpoint-only success stays
below 1 under the default policy while full grounded final success reaches 1.
Do not assume that the inspected example YAML already implements this cap.

Checkpoint feedback timing remains open: post-run evaluation versus online
training rewards have different leakage and repeated-guessing risks. Rationale
text cannot override failed factual/evidence checks. Scores computed under
different user policies must not be compared as if they used the same reward.

## 12. Source reuse and proposed code organization

Use ExCyTIn 2.0 as reviewed prior art, not a runtime dependency on a sibling
checkout or its local gateway configuration.

| Reusable concept | Source reference | Required adaptation |
|---|---|---|
| Typed extraction and identity resolution | [graph builder](../Excytin_2_0/src/excytin2/graph/build_edges.py), [resolution](../Excytin_2_0/src/excytin2/entities/resolve.py) | Provenance, missing rules, namespace handling, complete event participants |
| Graph/raw exploration tools | [tools](../Excytin_2_0/src/excytin2/explore/tools.py) | Full-tenant access in both modes, explicit coverage, safe raw access, no hidden window dependence |
| Data-first scouting and goal catalogue | [brainstorming](../Excytin_2_0/src/excytin2/explore/brainstorm.py), [playbook](../Excytin_2_0/src/excytin2/explore/playbook.json) | Tenant starts, incident relevance, neutral claim investigation, diversity controls |
| Agent loop and repair | [explorer](../Excytin_2_0/src/excytin2/explore/agent.py) | Typed protocol, honest failure states, bounded retries/cost, reproducible checkpoints |
| Validation and refutation | [gates](../Excytin_2_0/src/excytin2/pipeline/gates.py), [question checks](../Excytin_2_0/src/excytin2/questions/generate.py) | Mandatory fail-closed gates, cardinality, literal/ID checks, independent derivation, serving parity |
| Configuration and cached calls | [settings](../Excytin_2_0/src/excytin2/settings.py), [LLM client](../Excytin_2_0/src/excytin2/llm/client.py) | Existing SecRL model configuration; no mandatory local Copilot proxy; accurate unknown-cost reporting |

Proposed package boundary:

```text
secgym/qagen/agentic/
  contracts.py       typed manifests, task records, and gate results
  sources.py         raw snapshots, evidence retrieval, coverage, agent-visible views
  graph.py           versioned rule/identity integration and scoped graph access
  scopes.py          tenant and incident context/anchoring policies
  agents.py          scout/explorer/verifier tool loops
  validation.py      shared registry and task-specific required gates
  pipeline.py        stages, checkpointing, retries, and budgets
  export.py          release manifests and SecRL compatibility records
```

Add a separate proposed entry point, `experiments/run_agentic_qa.py`, rather than
changing the default behavior of [run_qa_gen.py](experiments/run_qa_gen.py).
Finalize file boundaries during implementation; avoid duplicate normalization,
question-ID, or provider helpers.

Dependencies belong in an opt-in generation extra where feasible. Preserve the
project's declared Python minimum unless a separate support change is approved.
Confirm source-reuse permissions and attribution before copying implementations.

Model roles are configurable through the existing SecRL configuration approach:
scout/explorer, verifier, blind solver, refuter, and reviewer. Do not bake audited
model names, local machine paths, or gateway ports into the feature.

## 13. Splits, duplication, and experimental control

### 13.1 Agreed benchmark boundary

Tenant-wide and incident-scoped generation produce **distinct benchmarks**.
Overlap between those benchmarks is allowed. Preserve cross-scope lineage and
report overlap, but do not require a tenant question and its incident variant
to share a split or delete one solely because they share evidence.

Within the incident benchmark, protect both:

- Train/test separation between questions about the same incident.
- Separation of related questions across different incident IDs when they share
  decisive events, answer-bearing facts or checkpoints.

Different incident numbers do not guarantee independent evidence: the known
322/340 shared alert is one example if both scopes later contribute tasks.
The tenant benchmark also needs its own internal duplicate/split controls.
If an experiment combines training data from both benchmarks, explicitly
report cross-benchmark exposure; permitted overlap is not a claim of unseen-data
generalization for such an experiment.

### 13.2 Numeric question similarity based on evidence subgraphs

The existing [split notebook](notebooks/question_split.ipynb) extracts every
other node of `shortest_alert_path` to obtain alert sequences. It scores shared
ordered alert-to-alert links, compares aggregate overlap across randomized
train/test assignments, and stores low/median/high-overlap splits per incident.
That is useful prior art for overlap-aware splitting, not a guarantee that all
related facts or questions are disjoint.

The agreed similarity basis is a **question evidence subgraph**, rather than an entire
incident graph or one author's shortest path. Include:

- Canonical source observations and typed, directed, role-aware relationships
  supporting the final answer and reward-bearing checkpoints.
- Entity identities and event/time scope needed to distinguish occurrences.
- Required alternative evidence paths/sets when known, and logical question,
  answer-target and checkpoint signatures.

Use reconciled observation identity across exports/rebuilds, not raw file-local
row numbers, to avoid missing duplicates merely because evidence was reimported.
Mere shared filenames, generic host/account nodes, common signed binaries or
inventory records are weak similarity signals, not automatic duplicates.

Compute a symmetric scalar similarity in `[0,1]` for each comparable question
pair and retain its components. The initial metric contract is:

```text
S(q1,q2) = w_E * J_E + w_O * J_O + w_F * J_F + w_C * C
w_E, w_O, w_F, w_C >= 0; their sum is 1
```

| Component | Definition |
|---|---|
| `J_E` | Weighted Jaccard of typed, directed, role/time-bound evidence-edge occurrences |
| `J_O` | Weighted Jaccard of canonical source observations supporting the questions |
| `J_F` | Weighted Jaccard of canonical source facts supporting final/checkpoint claims, including their necessary identity, scope, time and role bindings |
| `C` | Symmetric containment: shared weight divided by the smaller nonempty decisive evidence-footprint weight |

For a component's sets A/B, weighted Jaccard is the total feature weight in
their intersection divided by that in their union. Use fixed, versioned
feature weights for a comparison run, with routine context downweighted.
Fact identity includes subject/relationship/value/time scope: the same answer
string alone is not a shared fact. Exact scoped answer/proof signatures remain
separate diagnostics, not the current canonical fact component. For containment, use the namespaced union of
decisive observation and fact features. It detects a smaller investigation
embedded in a larger one even when their Jaccard overlap is modest.

Coefficient values, feature weighting, and action thresholds will be calibrated
on actual task pairs. The weighted-sum form is agreed; no arbitrary numerical
threshold currently defines a duplicate. Record task/rubric/snapshot revisions,
metric version, feature-weight version, component values, coverage/availability
mask, coefficients and final score. This allows recomputation and explanation
of every pair's similarity.

Missing required footprints produce an explicit unscorable/incomplete status,
not zero similarity. A genuinely inapplicable component, such as a graph-edge
component for an otherwise validated raw-only task, must be declared; use a
documented metric variant with normalized applicable weights. Do not treat
empty evidence on both sides as perfect similarity or silently compare scores
computed under different metric variants.

Validate symmetry, boundedness, identical-footprint similarity, disjoint-evidence
behavior and containment with fixtures. Repeated edges must not inflate overlap.
Semantic question equivalence remains a supplementary duplicate-review signal;
the initial numeric metric is evidence-based rather than an unvalidated text
embedding score.

A similarity score is a signal, not an automatic deletion decision. A second
path to the same answer/checkpoint facts must not evade comparison, while
different questions about shared events may remain useful.

### 13.3 Question-level splits with disclosed overlap

1. **Review genuine duplicates separately:** same investigative objective,
   scoped target and evidence-supported answer, including paraphrases.
   Different response strings alone do not establish distinct objectives, and
   matching strings from different scoped events do not establish duplicates.
   Preserve revision provenance; deletion/adjudication actions remain explicit.
2. **Retain distinct questions without evidence-based grouping:** shared
   checkpoint responses, supporting facts and source records are allowed.
   Neither a shared response-bearing record nor a shared checkpoint imposes a
   same-split constraint. The earlier grouping scenarios are diagnostics only.
3. **Partition at question level and disclose overlap:** preserve meaningful
   coverage and report pair-level and aggregate cross-split evidence overlap,
   including high-overlap pairs. Retain all metric components so users can
   distinguish source-record overlap, fact overlap and containment.
4. **Validate the actual generated task footprints:** discovery may move beyond
   the initial graph region or add checkpoint evidence, so a pre-generation path
   split is not sufficient. Freeze the task/rubric revision and split manifest.

**Agreed setting:** per-incident train/test question splits, matching legacy
intent, jointly checked across the ten selected incidents for duplicate
questions and reported evidence overlap.
A separate full-tenant benchmark may investigate all available incidents and
unassigned activity, subject to coverage and task eligibility. Tenant/incident
cross-benchmark overlap remains allowed. Whole-incident/episode holdouts are not
the initial setting.

Shared-evidence grouping is not required under the user's clarified policy.
Shared checkpoint responses and raw records remain in the overlap metric;
reporting them does not remove their possible contribution to test performance.
This evaluates new questions over potentially shared incident evidence, not
unseen-episode or evidence-independent generalization.

Still open: numerical feature/component weights, duplicate adjudication,
split sizes/manifests, overlap presentation and release approval. Do not impose
automatic grouping or rejection thresholds merely to obtain lower overlap.

Namespace collisions and different hashes with the same basename must not be
mistaken for duplicate entities. Report shared-tenant limitations and do not
claim independent-tenant generalization.

The first pilot compares generation approaches on the same pinned data and
serving visibility. Do not attribute score changes solely to better questions
when the database, judge, tool budgets, or source availability also changed.

## 14. Operations, reproducibility, and failure handling

- Sequential resource-bounded graph/data preparation; configurable parallelism
  for independent model tasks.
- Per-role and per-run action/token/time/cost limits; explicit pause/stop on
  exhaustion.
- Durable writes with atomic replacement and per-item completion records.
- Resume only compatible stages; do not reuse results across changed task
  content, scope, source data, or validation code.
- Keep rejection reasons and acquisition blockers visible in coverage/yield
  reports.
- Store model usage and retries; unknown billing information is `unknown`, not
  zero cost.
- Do not silently substitute a different model or relaxed gate after failure.
  Any configured fallback is recorded and still must pass the same checks.
- No production input mutation during generation or validation.

Suggested commands below are **proposed interfaces, not commands available now**:

```bash
python experiments/run_agentic_qa.py inventory --config <config>
python experiments/run_agentic_qa.py graph --config <config>
python experiments/run_agentic_qa.py discover --scope tenant --config <config>
python experiments/run_agentic_qa.py discover --scope incident --incidents 5 34 36 38 39 55 133 134 166 322 --config <config>
python experiments/run_agentic_qa.py validate --run <run-id> --config <config>
python experiments/run_agentic_qa.py export --run <run-id> --config <config>
```

## 15. Implementation phases and acceptance criteria

### M0. Freeze contracts and the data baseline

- Commit reviewed design/config/schema fixtures, not raw databases or credentials.
- Reconcile the available incident CSVs and post-cleanup DuckDB; freeze inclusion,
  latest-row selection, removed-membership derivation, transformation, and
  graph/source-version policies before generation.
- Record all ten scenario designations, current memberships, and exclusions.
- Register or reconcile graph/source version differences.
- Define public/private schemas and immutable task/revision IDs.
- Freeze the versioned similarity feature/score record, retaining configurable
  weights and leaving action thresholds to data-driven calibration.
- Record v0/v0.1/v0.2/v1 naming without changing legacy artifacts; freeze the
  dual-backend task and evaluation-profile compatibility contract.

**Exit:** inventory reconciles all selected cases; unknown inputs and missing
dependencies produce explicit statuses; source-only incident/alert records and
later label updates have explicit handling; no source records are rewritten.

### M1. Observation and graph foundations

- Implement raw ledger and identity/provenance handling.
- Add the highest-priority audited enrichments with source-backed fixtures.
- Preserve weak correlations and system/context observations without promoting
  them to causal/attacker status.

**Exit:** every original node/edge has an explainable mapping or exclusion;
regression fixtures cover nested entities, all targets, conflicting identities,
filename families, and truncation.

### M2. Scope-aware discovery

- Implement tenant starts and incident anchor manifests.
- Port/adapt scouts and explorer tools with full-tenant access.
- Enforce the FP/BP-targeted task exclusion without removing raw tenant context.
- Keep out-of-scope findings as tenant leads rather than mislabeling them as
  incident tasks.

**Exit:** tests show that valid out-of-window contextual evidence is accessible
and incident-relevant, while unrelated tenant questions fail incident anchoring.

### M3. Strict task validation

- Implement required-gate registry, typed answer contract, evidence/query checks,
  blind verification, and refutation.
- Validate the final answer and every reward-bearing discovery checkpoint.
- Invalidate dependent results after repair.

**Exit:** regression cases reject missing rows, wrong aliases, repeated-hop depth,
  failed path specs, extra scalar rows, constant-gold SQL, hidden record IDs,
  answer leakage, stale caches, and model/time-limit failures.

### M4. SecRL/MySQL integration

- Add opt-in dataset routing, public task payloads, stable-ID logging/resume,
  typed scoring, and analysis.
- Build sanitized read-only serving data and replay gold checks there.
- Export canonical v1 tasks to ACESEvals and test checkpoint/final-evidence
  scoring and default cap semantics against the SecRL adapter.

**Exit:** legacy fixtures preserve existing behavior; new tenant and incident
tasks run through SecRL and have validated ACESEvals exports; equivalent
component inputs agree under the declared scoring contract; no gold metadata is
reachable by the evaluated agent; all accepted release items pass MySQL parity.

### M5. FP/BP investigation (deferred; not an active milestone)

The 2026-10-22 scope decision pauses this work at incident, alert, and event
levels. Preserve the completed audits and unresolved leads; do not implement a
negative-specific generator, continue the lead audit, or promote research
candidates as part of the current feature.

The explicitly requested 2026-10-23 removed-membership check is a bounded research
exception and is complete; it admitted no negative QA. It does not turn M5 into
an active generation milestone.

**Reopening:** requires an explicit scope decision and the evidence/admission
protocol in Section 8. M6 does not depend on this deferred milestone.

### M6. Pilot, review, and release

Proposed pilot: start with incident 34, added incident 133, and scoped incident
322, plus tenant-wide leads. Then exercise all ten incident manifests before
release. Cap candidate production and spend; do not require an accepted quota.

**Release criteria:**

- Every accepted task passes every required gate against its final revision.
- Zero unresolved evidence references.
- No FP/BP-targeted release items while that scope remains deferred.
- No unreviewed duplicate-question/revision leakage across splits. Shared
  checkpoint responses and source evidence are allowed and reported, within
  each benchmark and across the tenant/incident benchmarks.
- Accurate stage yield, blocked-source, coverage, solver-error, and cost reports.
- All ten case scopes exercised; lack of acceptable tasks is reported, not
  hidden by forced generation.
- Existing benchmark files remain byte-for-byte unchanged.

## 16. Implementation readiness and remaining contract details

**Readiness review (2026-10-23):** the core product and architecture decisions
are settled and sufficient to plan implementation. The latest-row incident
policy, historical-membership treatment, clean evidence-backed rebuild,
framework/dataset/evaluation versioning, dual evaluation targets, checkpoint
reward policy, numeric similarity approach, and benchmark split setting are
agreed. The narrow removed-membership research is complete; no further broad
data or FP/BP investigation is a prerequisite.

This does not mean every numeric setting, schema field, or operating limit is
already frozen. Those details have explicit decision gates below and in
Section 17. They do not block planning or the local M0/M1 foundations.
I0 contracts, I1 state/source reconciliation and I2's exact typed observation
ledger and initial clean evidence graph are implemented and verified on the
supplied sources. Source/identifier comparisons and all 1,603 legacy alert/entity
semantic dispositions are available. The I2 coverage follow-up is complete for
the supplied snapshot with explicit limits; live evidence validators,
evaluators/adapters and model-driven generation remain pending.

The two scopes, ten TP scenario designations, evidence exclusions, SecRL-first
integration, discovery-plus-validation workflow, legacy compatibility, and
FP/BP deferral are fixed. The following details do not reopen those decisions.

### 16.1 Details to freeze at their implementation gates

Agreed directions are distinguished from remaining details. Do not reopen the
core scope merely to choose a field name or calibrate a numerical threshold.

| Item | What remains unresolved | Recommended direction | Needed by |
|---|---|---|---|
| Source-manifest reconciliation | Canonical observation identity, meaningful-field comparison and historical-membership provenance serialization | Latest whole-row state and blocking only the affected incident on conflicting latest rows are agreed. Derive removed memberships without serving old incident rows; preserve unassigned alerts. See Section 4.1. | I1, before dataset freeze or model-driven generation |
| Graph rebuild and comparison | Exact quantitative regression fixtures and source-supported enrichment coverage | Clean rebuild and evidence-only enrichment are agreed. Unsupported old edges may be excluded with reasons; no forced compatibility. See Section 4.4. | M0/M1 graph interfaces |
| Checkpoint and evidence scoring | Exact JSON/citation format, numerical cap/weights, export normalization, and post-run versus online feedback | Private by default and final-success-first with capped checkpoint credit are agreed. Preserve every component and policy version for user-configurable per-task aggregation. See Section 11.3. | M0 schemas; evaluator/action parsing |
| Evaluation versioning | Exact evaluation-profile names and adapter/version compatibility matrix | Separate evaluation semantic versions and dual SecRL/ACESEvals adapters are agreed, alongside the generator/dataset version scheme. See Section 2.1. | M0/M4 |
| Serving-data contract | Exact private-to-public record mapping, field/nested-JSON redaction policy, and engine-specific gold execution | Freeze a versioned public-view manifest and stable locators. Make the actual sanitized MySQL result authoritative for release; require explicit gold adapters/checks rather than assuming arbitrary DuckDB SQL is portable. | Before export and end-to-end validation |
| Initial QA portfolio | Which analyst goals to prioritize and how many candidates to attempt in the pilot | Use a small goal catalogue covering attribution, activity sequence, scope/counts, configuration changes, and observed outcomes. Retain agent-led discovery, not fixed question templates or accepted-item quotas. | Before model-driven pilot |
| Models, budgets, and review ownership | Role assignments, call/action/token/cost limits, repair limits, and who approves the pilot release | Reuse SecRL configuration; separate blind verification from author context; approve bounded run limits and review ownership before paid generation. | Before model calls and pilot release |
| Similarity, splits and release policy | Numeric coefficients/feature weights, duplicate adjudication, split sizes and release thresholds | Numeric weighted evidence-subgraph similarity, per-incident question splits and a separate full-tenant benchmark are agreed. Shared checkpoint/source evidence is allowed and reported, not an automatic grouping constraint. See Section 13. | Metric contract in M0; calibration before release |

Coverage wording also needs fixtures: counts, ordering, and absence claims should
be explicitly about the supplied observations unless capture completeness is
independently established. Near-complete incident support is not a license to
make exhaustive claims about the real environment.

Current decision status:

1. **Feedback:** private answer-bearing rubrics approved; post-run evaluation
   initially remains the recommendation. Retain first-completion steps to
   support later training reward policies.
2. **Incident state (approved):** use only the latest whole incident row as active
   state. Derive removed membership links from source updates, with explicit
   historical status and current-relevance caveats. Do not keep full old
   incident rows in active QA data or infer negative verdicts from removal.
3. **Graph acceptance (approved direction):** foundation/high-priority enrichments in Section 4.3;
   source-backed relationships, reproducible common-input builds, no unresolved
   evidence references, and no unexplained losses of baseline relationships.
   Unsupported old edges are excluded with recorded reasons, not forced parity.
4. **Evaluation visibility (approved):** both scopes use sanitized full-tenant MySQL;
   graph tools remain generation/validation tools, not an unannounced expansion
   of the evaluated agent's SQL interface.
5. **Pilot operation (approved sequence):** one incident-34 and one tenant task end to end, then 133
   and scoped 322 with varied factual goals. Freeze candidate caps, model roles,
   run/repair budgets and reviewer ownership before model-driven generation.
6. **Similarity and splits (approved direction):** numeric weighted similarity
   with stored components; per-incident train/test splits and a separate tenant
   benchmark. Tenant/incident cross-benchmark overlap is permitted. Tune weights,
   thresholds and split/deduplication actions on actual question data.

### 16.2 Recommended implementation sequence

1. **M0 contract finalization:** freeze the first schemas and policies above;
   reconcile the pre-merge exports, then create snapshot/case manifests,
   exclusion fixtures, and source/public ID mappings. No model-driven generation
   is required to do this.
2. **Minimal M1 foundation:** establish the observation ledger, provenance-aware
   graph access, coverage metadata, and two scoped context builders.
3. **First end-to-end slice:** exercise incident 34 and one tenant-wide lead
   through discovery, typed validation, sanitized MySQL replay, submission, and
   scoring. Do not postpone serving compatibility until after bulk generation.
4. Expand the pilot to 133 and scoped 322, then exercise all ten manifests as
   required by M6. Add further enrichment and question diversity with regression
   evidence rather than assuming the first successful example proves coverage.

The current implementation step is I5 question-level split planning and
overlap disclosure over the reviewed development cohort, not another research
pass or an unapproved QA-generation batch. The foundations and native pilots
above have been exercised; actual split counts, aggregate coefficients and
release approval remain explicit decisions. M5 remains deferred.

## 17. Implementation plan

Build in bounded, independently verifiable increments. The phase names in
Section 15 remain the capability milestones; this sequence deliberately brings
serving/evaluation checks forward instead of postponing them until bulk
generation.

| Increment | Prerequisites | Deliverables | Completion gate |
|---|---|---|---|
| **I0 - Contracts and legacy baseline (M0)** | None | Versioned source/case/task/checkpoint/similarity/result schemas; public/private boundary; legacy dataset aliases and regression fixtures; explicit configuration validation | Schemas reject incomplete required evidence and unknown/error-as-success results; v0.1/v0.2 mappings leave old files/defaults unchanged |
| **I1 - Reconciled observation layer (M0/M1)** | I0 | Read-only input inventory; canonical source references; one latest whole incident row; separate historical removed-membership edges; ten-case manifests and coverage/exclusion records | Known counts and source differences reconcile; missing lists are not removals; historical links are not current anchors; input hashes remain unchanged |
| **I2 - Clean graph rebuild and comparison (M1)** | I1 | Versioned extraction/identity rules and source-backed enrichments; reproducible graph outputs; old/new relationship comparison with explained exclusions | Required evidence-backed relationships pass fixtures; unsupported old edges are excluded with reasons; no unexplained losses on common supported inputs |
| **I3 - Validation, scoring and serving slice (M3/M4)** | I0 and I1; can proceed alongside I2 using fixtures | Fail-closed gates; typed answer/evidence and checkpoint scoring; private/public MySQL mapping; opt-in SecRL adapter; ACESEvals export; similarity component implementation | One controlled task/trajectory fixture round-trips through both adapters with matching component outcomes; checkpoint-only reward stays below full success; legacy behavior is preserved |
| **I4 - Scope-aware discovery pipeline (M2/M3)** | I2 and I3 | Tenant/incident context builders; scout/explorer/verifier/refuter interfaces; bounded repair/resume; canonical draft tasks with executable answers and validated checkpoint rubrics | One incident-34 and one tenant task traverse the real end-to-end pipeline, including public MySQL verification and both evaluation outputs; errors or zero accepted yield are reported explicitly |
| **I5 - Pilot calibration and splits (M6)** | I4 | Extend to 133 and scoped 322; inspect similarity matrices/component explanations; calibrate checkpoint weights/cap and split/deduplication thresholds; exercise all ten scopes | Reviewed rubric/evidence and overlap fixtures support the chosen policies; per-incident partitions pass cross-incident checks; permitted cross-benchmark overlap is reported |
| **I6 - Versioned release (M6)** | I5 and reviewer approval | Immutable v1 dataset releases for the two benchmarks; SecRL/ACESEvals exports; source/graph/evaluator/reward/similarity/split manifests; reproducible release report | Required gates pass against final revisions, backend compatibility is checked, and legacy artifacts remain unchanged |

### 17.1 Validation strategy and implementation boundaries

- Implement focused offline fixtures first: latest-row selection, tied updates,
  empty versus missing membership, removal/re-addition, missing incident-5
  evidence, missing incident-322 proxy data, and source-ID reconciliation.
- Cover graph regressions with observed/derived/contextual relationship
  distinctions, namespace conflicts, full command references, nested/multi-target
  entities, and recovered process-time provenance.
- Cover reward and similarity mathematics using synthetic task/trajectory
  fixtures before applying them to generated questions. Do not claim synthetic
  checks establish real-world question quality.
- Check answer/evidence/checkpoint parity and redaction in the actual
  student-visible MySQL view, not merely an in-memory DuckDB approximation.
- Reuse existing helpers and package configuration. This checkout uses
  [setup.py](setup.py) and [requirements.txt](requirements.txt), with Python
  `>=3.10`; framework/dataset labels do not imply changing the package version
  or dropping supported runtimes. I0 establishes the focused standard-library
  `unittest` suite described below; no pre-existing full-suite coverage is
  implied.
- Keep research audit scripts/results as evidence, not an unreviewed runtime
  dependency. No sibling-checkout imports, machine-specific paths, or raw
  datasets are to be embedded in production code.
- No database mutation, dataset migration, paid model call, or release occurs
  merely because the implementation plan is recorded.

### 17.2 Decisions scheduled before use, not blockers to planning

| Gate | Details that must be fixed before crossing it |
|---|---|
| Before I1/I3 interfaces are frozen | Exact schemas, citation/observation ID mapping, latest-row tie/conflict behavior, evaluation-profile names and public redaction policy |
| Before aggregate rewards are reported | Numeric checkpoint cap/weights and policy version; component results remain independently available |
| Before any model-driven I4 run | Model-role assignments, candidate/action/token/cost budgets, repair limits, checkpoint feedback timing, and pilot review ownership |
| Before split/redundancy actions in I5 | Similarity feature weights/coefficients, duplicate-review criteria, split sizes and disclosed overlap profiles; no mandatory shared-evidence grouping |
| Before I6 release | Reviewed release criteria, final split sizes/manifests, compatible backend/evaluator versions, and human approval |

Post-run scoring remains the recommended initial feedback mode; private rubrics
are already agreed. Online training feedback is not silently enabled by the
checkpoint feature. Numerical calibration should use development examples, not
be tuned against the final held-out scores.

### 17.3 I0 delivery checkpoint

Implemented in the opt-in [agentic package](secgym/qagen/agentic/README.md):

- Strict, versioned snapshot/case/task/evidence/checkpoint contracts and an
  explicit public-task projection, with no private-gold or rubric fields.
- Content-bound gate reports and score-component/evaluation/similarity records.
  Error and incomplete evaluations cannot publish completed aggregate rewards;
  known component results remain available for diagnostics and reaggregation.
- Contract checks for explicit capped reward configuration, checkpoint
  dependencies, required evidence, source/project label separation and the
  incident-5/322 exclusions. Production reward caps/weights remain unset.
- The user-confirmed **v0.1 alias points to corrected `o1/v1`**, not original
  `o1/v0`. The v0.2 alias points to current Opus. A generated checksum baseline
  pins 109 legacy question/graph/code files, including the 32 release files:
  o1 has 589 test / 418 train questions; Opus has 599 test / 418 train.
- Offline schema, contract validation, public-preview and legacy-check commands,
  plus synthetic and actual-file regression tests in
  [test_agentic_i0.py](tests/test_agentic_i0.py).
- Validation: 40 offline tests pass in the selected Python 3.11 environment;
  focused Pylance diagnostics/syntax checks pass, and changed Python source
  parses using Python 3.10 grammar. This is not a Python 3.10 runtime test.
- The next-stage latest-row conflict policy is approved: block only the affected
  incident and report the conflicting evidence; do not silently prefer a source.

Use the existing project interpreter with the optional `agentic` extra:

```bash
python -m unittest discover -s tests -p 'test_agentic_i0.py' -v
python -m secgym.qagen.agentic check-legacy --repo .
python -m secgym.qagen.agentic schema task
```

This is a contract foundation, not a functioning end-to-end generator or scorer.
It does not certify supplied SQL, raw evidence, public wording, task difficulty
or backend parity. The fixture is synthetic and not release-approved QA.
I1 source reconciliation and current/historical membership extraction are
recorded in the next delivery checkpoint.

### 17.4 I1 delivery checkpoint

[sources.py](secgym/qagen/agentic/sources.py) and the `reconcile-sources` CLI
implement the latest-state/source foundation using only read-only input access.
The actual-data verification produced:

- A content-hashed inventory of **760 input files**.
- **914 latest incidents** and **1,069 latest alerts**, reconciling 1,980
  incident rows and 13,155 alert rows from the supplied database and CSVs.
- **155 historical removed-membership links**, with before/after references,
  other current parents and an explicit relevance caveat.
- All ten case manifests; cases 5 and 322 retain their approved exclusions.
- Baseline coverage and table inventory for **62 tables / 13,339,265 rows**.
- Zero unresolved latest-state conflicts after the explicitly approved
  field-specific placeholder rule below; original input hashes are unchanged.
- Verification: 72 combined I0/I1 offline tests pass; focused Pylance checks are
  clean. Output checksums, canonical observation IDs, historical/case references
  and all ten earlier baseline coverage totals were checked on the real bundle.

The first strict run found 20 latest-alert and three historical-alert ties
differing only in `CompromisedEntity`: empty in CSV versus `"N/A"` in DuckDB.
The user approved treating these as equivalent unavailable values **only for
that field**, preserving original locators and recording normalization.
`source-normalization-v1.1` applies that rule; genuine identity/membership/label
differences still block the affected entity. The verified run records 267
normalization applications across input alert rows, not 267 conflicting alerts.

The private output bundle contains latest incident/alert payloads, provenance
references, historical memberships, case manifests, table coverage, issues and
a final completion report with output checksums. Superseded full incident rows
are not active QA state. A missing/malformed membership cannot masquerade as an
empty incident or a removal.

**Boundary:** other telemetry CSVs are inventoried and readable but have not been
declared fully merged/deduplicated by I1 itself; the I2 ledger checkpoint below
provides that separate layer. I1 coverage is
explicitly baseline-observed support, not capture completeness or a graph/QA
admission certificate. No original data or legacy datasets were changed.

### 17.5 I2 diagnostic column policy

The user approved consolidating the seven audited AzureDiagnostics case-name
variants into single canonical fields: `clientIp_s`, `socketIp_s`, `errorInfo_s`,
`hostName_s`, `originIp_s`, `pop_s`, and `probeUrl_s`.

An explicit mapping handles both original CSV names and the known `_1` names
in the imported database. Retain one nonempty value, merge identical values,
and fail explicitly on differing nonempty values. Preserve original files,
source locators and field-origin provenance; do not create artificial duplicate
logical columns or indiscriminately case-fold every field.

The [column normalizer](secgym/qagen/agentic/columns.py) and
[telemetry utilities](secgym/qagen/agentic/telemetry.py) materialize normalized
baseline and CSV streams separately. These are not yet a deduplicated union.
Every original populated value is checked against the canonical output; other
columns must remain unchanged.

The audit's CSV reader is also corrected: source CSV is read case-sensitively
with Python and transferred losslessly into DuckDB. The cloud-activity record
previously flagged as malformed is valid source JSON and must not be repaired
to compensate for a reader error. Dynamic Python-literal-to-JSON repair is a
separate policy, now approved and implemented in the next checkpoint.

Actual-data validation completed against 982,864 imported diagnostic rows and
115,090 original CSV rows in seven files, kept as separate overlapping streams.
Every stream's data schema loses exactly seven redundant columns; all original
populated values and other fields are preserved, with zero mismatches.
The derived database includes 155,533 populated-field origin records.
All 96 focused v1 tests pass and the 109-file legacy baseline remains unchanged.
Rerunning the full 378-file telemetry audit reports no parsing failures or
unmapped metadata columns; its only remaining value finding is the 11,472
previously identified malformed file-event JSON values. No repair was applied
by the column normalizer; the approved dynamic-field normalizer handles them
separately.

### 17.6 I2 dynamic-field normalization checkpoint

The user approved scoped literal-data-to-JSON repair on 2026-10-23.
[dynamic.py](secgym/qagen/agentic/dynamic.py) and `normalize-dynamic-fields`
implement this in new private derived data, with immutable original sources.
The normalizer:

- Limits repair to schema-declared dynamic fields; preserves valid JSON and
  unrelated text without rewriting.
- Accepts only literal JSON-compatible data through a restricted AST traversal,
  not expression evaluation; verifies value/type preservation through JSON.
- Quarantines ambiguous or unsafe values, including duplicate keys, unsupported
  data types, nonfinite/precision-losing numbers and resource-limit violations.
- Retains original values, reasons, source locators, transformation versions and
  per-field status. Unusable normalized fields are explicit quarantines, never
  evidence of absent original data.
- Materializes only changed source streams and verifies that every unaffected
  field and every source row is preserved. Dependent graph/QA work must respect
  the field-level quarantine status.

The actual-data run checked 230 declared-dynamic baseline/CSV streams.
It left **10,104,440 nonempty field occurrences unchanged**, repaired
**11,472 occurrences of eight distinct file-type literal values**, and found
**zero quarantines**. The single changed stream is the incident-34
`DeviceFileEvents` CSV. All 11,472 repaired records passed an independent
source-literal versus JSON comparison; CloudAppEvents streams remained
unmodified. These are field occurrences across overlapping exports, not unique
events.

Validation: **118 focused v1 tests pass**, Pylance checks are clean, and the
109-file legacy baseline is unchanged. Inputs remain read-only; output includes
a checksum-pinned database and completion report. The separate row
reconciliation and graph checkpoints follow.

### 17.7 I2 exact telemetry observation ledger

[ledger.py](secgym/qagen/agentic/ledger.py) and the
`build-observation-ledger` command now produce the reconciled graph-input layer.
The implementation uses full typed content, source-field availability and
quarantine state for observation identity. It preserves ordinary text exactly,
canonicalizes declared dynamic-JSON key order/formatting without rounding numeric
tokens, and retains every source origin when exact duplicates merge.

The completed build covers all 62 source tables:

| Verified result | Count |
|---|---:|
| Canonical observations | 13,276,306 |
| Source-origin references retained | 16,051,309 |
| Additional non-core CSV observations absent from the normalized baseline | 8,778 |
| Latest active incident rows | 914 |
| Latest active alert rows | 1,069 |
| Historical removed memberships | 155 |
| Selected case manifests | 10 |
| Repaired-field provenance records retained | 11,472 |

The 8,778 CSV additions are 5,548 file events, 2,841 registry events, 387 sign-ins
and two device records. They are distinct source-content observations, not
certified additional real-world events. Sample file/registry variants differ
in command text, and sign-in examples differ in ASN fields. Keep them distinct
rather than applying the old global quote or numeric-string replacement rules.

Only latest incident/alert payloads are active; historical source references
remain separate. The origin total includes non-core source rows and origins
of the active core records, not every superseded incident/alert payload.
All source locators, canonical column maps, field repairs/quarantines, source
schema variants, current case data and removed-membership references are
retained in the private ledger.

Data-scale verification caught and fixed bounded-memory issues in wide payload
comparison and core JSON loading, plus explicit empty/null handling needed by
the DuckDB scalar converters. The final complete run passed with one thread
and a 1 GB engine memory budget; payload equality is still checked in full.
Independent checks verified the database checksum, every table's row/unique-ID/
origin counts, all historical and repair references, and the unchanged latest
classification breakdown. **137 focused tests pass**, Pylance checks are clean,
and all 109 legacy-file checksums remain unchanged.

This completes the source-reconciliation portion of I2. The graph checkpoint
below remains subject to its semantic acceptance gate. No original database/CSV
was mutated and no model-driven QA generation or runtime evaluation adapter was
run.

### 17.8 I2 initial clean graph and comparison checkpoint

The fresh [graph builder](secgym/qagen/agentic/graph.py) uses source observations
as explicit nodes and [reviewed participant rules](secgym/qagen/agentic/graph_rules.py)
for typed entity links. It does not copy old edges. Each edge records source
observation, role, rule, field/JSON path and interpretation class; evidence
lineage, event time and quarantine status remain on the observation.
Current versus historical removed membership remains distinct.

Implemented enrichments include all audit targets, identifiable cloud activity
objects with source roles, click/message/account/IP/redirect context, Graph API
resource targets, full-command lexical references, provisioning/Intune
participants, exact process identities and nested alert entities. Later
validation added file-hash threat-intelligence participants, mail-cluster message
IDs, sender/host IP fields, `.txt` command references and URL-host references.
Filename, account-name and application-name mentions remain explicitly weak
references, not inferred physical identity or authorization. App IDs and
instance IDs retain namespaces; full hostnames and account labels are not
blindly merged to recreate an old path.

Real-source validation corrected two initial extraction assumptions:

- Graph `SignInActivityId` values match sign-in `UniqueTokenIdentifier`, not
  `Id`: 540,073 source observations matched token identifiers, none matched
  request IDs. These now use a token-reference relation, not a causal inference.
- Schemeless firewall domain/path values are URL references, not malformed URLs
  or invented `https` URLs.

The corrected `evidence-graph-v1.2` rule revision produced:

| Artifact | Count |
|---|---:|
| Source observation nodes | 13,276,306 |
| Typed entity nodes | 6,191,517 |
| Source-linked edges | 64,134,168 |
| Historical removed membership links | 155 |
| Rule executions | 332 |

These are graph-rule revisions within the v1 framework, not changes to the
legacy v0.1/v0.2 dataset aliases.

The larger edge count is a representational difference, not an improvement
metric. Observation-centered graph depth is not comparable to legacy alert
paths or the old telemetry graph's compressed relationships.

The [comparison utility](secgym/qagen/agentic/graph_compare.py) resolves all
186 legacy alerts. Of the old graph's 6,357,495 source rows, 6,357,361 map to
active ledger observations.
All **6,357,361 active mapped source rows** now have participant relationships;
the earlier three-row file-hash TI gap is closed. The only source-row difference
is 134 superseded incident rows excluded by the latest-state policy.

The original 1,603 alert/entity links are classified as:

| Comparison status | Links |
|---|---:|
| Same-alert reported entity identifier | 810 |
| Same-alert weak/lexical reference | 400 |
| Compound identity requiring contextual mapping | 268 |
| Filename case variant requiring platform context | 68 |
| Identifier represented elsewhere | 19 |
| Invalid/unsupported legacy identifier form | 35 |
| Basename found inside a path, requiring context | 1 |
| Identifier not represented by the exact matcher | 2 |

The two remaining absent exact strings are older URL spellings; source
observations retain case-sensitive URL variants rather than blindly lowercasing
paths. These counts do not establish whether all alternative evidence paths are
equivalent.

A focused process screen found same-alert exact PID/start-time representation
for 261 of 262 legacy compound-process links; full command/context equivalence
is not implied by this screen. Real pivots for the renamed executable in 55,
task creation in 34 and file content in 330 were verified through exact process
identity or content hashes, not only shared host/name nodes.
This remains **coverage evidence, not complete semantic parity**.

At this initial comparison checkpoint, remaining I2 acceptance work was:

1. Investigate remaining source-backed identifier/participant omissions;
   do not label an unimplemented supported rule as unsupported source data.
2. Validate contextual compound-process/account/filename mappings and
   representative investigation paths without forcing old normalization.
3. Decide any evidence-supported process-time/alias recovery rules from actual
   source matches. The current build leaves absent or conflicting times explicit;
   it does not import the old ASOF assumptions.
4. Finish source-only/unsupported entity-type dispositions and semantic
   regression fixtures before using the graph for the model-driven pilot.

No new user policy decision is required by the completed checks. These are
implementation/validation gaps, not a reopening of FP/BP generation.
The graph and ledger checksums, source/endpoint references, enrichment counts,
current/historical memberships and legacy file preservation were checked.
**172 focused tests pass**; input databases and legacy artifacts are unchanged.

### 17.9 I2 legacy alert/entity semantic acceptance checkpoint

The source-aware [semantic checker](secgym/qagen/agentic/graph_semantics.py)
now accounts for all **1,603 original alert/entity links**, with no unresolved
links. The immutable [per-edge report][v1-semantic-report] binds the graph,
ledger, legacy graph files and checker implementation by checksum. The initial
identifier-only classifications in Section 17.8 are not the final dispositions.

| Source-semantic disposition | Links |
|---|---:|
| Same-alert source-reported identifiers | 788 |
| Supported weak/lexical/contextual references | 515 |
| Same-alert process identities with verified command projection | 261 |
| Authoritative same-account UPN corrections of old synthesized emails | 35 |
| Exact message/recipient-linked alternative paths | 3 |
| Intentional unsupported legacy identity exclusion | 1 |

Process checks require the same source host, PID, qualified `CreationTimeUtc`,
graph process identity and matching legacy lowercase command projection.
Filename/basename and old URL-case projections are checked as references only;
they do not introduce global case folding or physical identity aliases.
The 35 email corrections use the authoritative UPN on the same raw account,
not a similarly named account elsewhere.

The last three mail-related links in incident 134 have exact alternate paths:
the direct alert mail-message ID and recipient bind an `EmailEvents` record
containing the sender address/IP and a `UrlClickEvents` record containing the
HTTPS redirect. Actual graph message and participant edges are checked. An
arbitrary mail cluster, another recipient, an unrelated sender or a guessed
HTTP/HTTPS conversion cannot satisfy this check.

One incident-322 process tuple remains **intentionally excluded**, not recovered:
PID 4256's old `2024-08-01T13:42:52.04` label is timezone-free `CreatedTimeUtc`,
not a qualified process-start assertion. The report separately records the
unique raw same-host/PID/full-command process with creation time
`2024-08-01T12:25:23.612698+00:00` and its existing graph node. This is not an
assertion that the two timestamps or identities are equivalent. No ASOF rule,
timezone assumption or new alert/process edge was added.

The command fails closed on unresolved links or invalid input checksums.
**201 focused v1 tests pass**, including 29 semantic tests covering wrong
host/command, message/tenant/recipient mismatches, raw-value/graph-row mixing,
wrong URL case/scheme, absent graph roles, ambiguous process candidates,
checksum failure, immutable outputs and nonzero unresolved CLI status.
Pylance and Python 3.10 grammar checks pass; no 3.10 runtime matrix was run.
All 109 pinned legacy files remain unchanged, as do the graph/ledger inputs.

This closes the **legacy alert/entity** portion of acceptance. It does not
certify all 64 million new relationships as causal, every tenant entity type,
or every candidate investigation path. Before the model-driven pilot, remaining
source-only/unsupported-type dispositions and task-level evidence checks must
be explicit. `Alert`, `HuntingBookmark`, `Operation`, `SentinelAudit`,
`SentinelHealth`, `Usage` and `Watchlist` remain source-only; unimplemented
NIC/IoT/Kubernetes/container entity handling is a coverage limitation, not a
claim that those source records are noise or absent. Their ledger rows remain
queryable. I3 validation/scoring/adapter work can proceed with fixtures as
planned; no new model calls, QA admission or user policy decision occurred here.

### 17.10 I2 source-only/type coverage follow-up and scoped acceptance

The remaining audit identified source-backed extraction gaps rather than absent
evidence. All 1,042 previously unmapped typed source definitions were inspected:
431 IoT devices, 558 NICs, 17 clusters, 17 namespaces, 12 services, two pods,
two containers, two images and one blob container. These are source definitions
across alerts, not counts of distinct physical devices or runtime instances.
Repeated references explain the higher 1,653 old traversal exclusions.

The new rules use explicit hub/resource scope for IoT IDs and explicit
cluster/namespace/pod/storage scope for named runtime references. MACs and
container images remain references, not physical-device identities or content
hashes. No nearest-event or process-time recovery was introduced.

The fresh `evidence-graph-v1.3` build contains 13,276,306 observations,
6,191,661 entity nodes and 64,176,753 edges across 341 rule executions. The
delta is 42,585 source-participant links:

| Source | Added links |
|---|---:|
| SecurityAlert | 2,034 |
| Alert | 3 |
| HuntingBookmark | 24 |
| Operation | 1 |
| SentinelAudit | 60 |
| SentinelHealth | 4,986 |
| Usage | 35,477 |

The [coverage verification][v13-coverage-report] checked every one of 32,071
valid replayed alert/anomaly/bookmark entity mentions against its exact graph
observation, tenant, kind, value, source path and role: zero missing. No current
alert entity type remains unmapped or missing its new explicit scope.
The [new semantic run][v13-semantic-report] retains all 1,603 previous
dispositions, including the intentional legacy process-time exclusion.
The repeated old telemetry-graph comparison still resolves all 186 original
alerts and all 6,357,361 active mapped source rows with participant coverage.
The same 134 superseded incident rows are deliberately outside active state.

`Watchlist` is the only remaining wholly source-only table. All 790 rows have
empty `EntityMapping` objects; generic search keys are not promoted to entity
identity, authorization or benignness. Partially linked tables remain partial:
only three of ten `Alert` rows and one of 36 `Operation` rows gain participants.
No row is dropped from the ledger.

The audit also records 20 `SentinelAudit` rows whose top-level resource differs
from the updated-state resource ID. The graph preserves a
`reported_sentinel_resource` metadata role and does not equate it to the actual
modified target. `SentinelAudit` has metadata lineage, `SentinelHealth` context
lineage, and bookmark entities remain context. Source state and contradictions
must be inspected before admitting claims about a configuration change.

This closes the **scoped I2 build, coverage and legacy-regression gate** for the
supplied snapshot, not universal entity/field coverage, acquisition completeness,
or causal interpretation of all graph paths. Process/invalid-value exclusions
remain explicit and do not discard raw observations. Task-level source,
identity, independence and public-serving gates remain mandatory in I3/I4.
The full 223-test suite, Pylance, Python 3.10 grammar and 109-file legacy
preservation checks pass. No model generation, FP/BP targeting or live backend
evaluation occurred.

### 17.11 I3 deterministic scoring foundations

The first [scoring implementation](secgym/qagen/agentic/scoring.py) provides
typed answer comparison and aggregation of already-adjudicated component
verdicts. This is an offline foundation, **not an operational evidence judge,
serving adapter, QA admission gate or backend-parity demonstration**.

Typed comparison enforces the declared format/normalization/units/tolerance.
Exact entities are not matched by substring, stripped domain or filename-only
guessing. Sets require equality, ordered lists retain order and multiplicity,
booleans are not numbers, and numeric/timestamp boundaries are deterministic.
Large integers and microsecond timestamps are not rounded through floating
point before comparison.

Aggregation preserves all source component verdicts and metadata, binds
checkpoint IDs/maxima/weights to the task rubric, requires first-completion
metadata for completed checkpoints, and rejects credit whose semantic
dependencies are incomplete. Dependencies do not force trajectory order.
Unknown/error components cannot produce a completed aggregate, even if another
component reports full final-answer credit. The existing normalized checkpoint
formula uses rational intermediate arithmetic to avoid finite-value
overflow/underflow.

Explicit policy overrides retain their policy version and components for
reaggregation. No production cap, task weight or model setting was chosen.
Fourteen new scoring tests and the existing I0 contracts pass. The evidence
verifier, checkpoint adjudicator, sanitized MySQL serving/parity, actual SecRL
and ACESEvals adapters, and similarity computation remain pending. In
particular, changing a serialized `backend` label is not evidence that either
runtime adapter was executed.

### 17.12 I3 serving, witness and adapter fixture checkpoint

The opt-in runtime now provides:

1. An exhaustive reviewed table/column projection policy, including explicit
   JSON scalar paths, nested encoded-JSON handling and separate private/public
   locator/content maps. No unspecified source column inherits public access.
2. Structural SELECT-only guards, source/function allowlists, reviewed literal
   inputs, bounded results and timeouts. Errors never become accepted truncated
   answers; scalar/ordering/constant-answer shortcuts are checked explicitly.
3. Executable answer and witness programs. Witness rows group complete
   alternatives by `evidence_group`, `table_name`, `record_id`; row content,
   source origins, graph/view/snapshot identity and lineage are checked.
4. A new-database-only MySQL loader and a SELECT-only reader, with complete
   schema/type/collation and per-row parity checks. Statement autocommit avoids
   leaving metadata locks held between queries.
5. A SecRL reset/step adapter and a native ACE task export, tools, strategy
   registry and scorer-factory path. Private goals remain evaluator-side.
   Every episode has a version-bound private result/trajectory; repeated
   findings are credited once, not by scanning for answer substrings.
6. Numeric evidence-overlap components with explicit weights and version
   matching; no automatic split/removal threshold was chosen.

The fixture contains all six actual ledger scalar types, large integers,
submicrosecond JSON values, Unicode/case/trailing-space distinctions, nulls and
one quarantined row. Multi-batch projection is tested separately. Both adapters
run against a private temporary MySQL 8.4 instance and retain matching component
outcomes. Native ACE task parsing, tools, registry, scorer factory and
normalization are exercised using pinned SABER 0.2.0 and Inspect 0.3.283 in a
separate Python environment. No model API is called. The checkpoint-only
fixture yields 0.5 in both backends without accidentally normalizing to 1.0.

The canonical ACE reward is the default aggregation input; per-component
diagnostics and full raw component metadata remain available for user
reaggregation. Backend adapter versions are `secrl-env-v1` and `aces-native-v1`,
separate from `source-witness-v1`, schema and reward-policy versions. Canonical
ISO timestamp comparison retains submicrosecond precision.

The full 249-test suite passes with both optional integrations enabled; the
[persisted verification report][i3-runtime-verification] records runtime
versions and implementation/test hashes.
The test servers are socket-only and cleaned up; legacy containers, databases,
datasets, launchers and prompts are not modified. Core Python remains 3.10+;
the optional pinned ACE SDK requires a separate Python 3.11-3.13 environment.
Grammar checks are not a substitute for a 3.10 runtime matrix.

These are **controlled fixture results**, not full-tenant serving certification
or real QA admission. Mechanical preflight does not fill missing semantic,
scope, independent verification, refutation, split or release-review gates.
Literal justification and projection policies are reviewed inputs. Source-row
witness sets exceeding the configured limits fail rather than being sampled.
The remaining full-source projection and pilot gates still apply.

### 17.13 Approved conservative public-view profile

Explicit incident/alert classification and investigation annotations are
already agreed to be private. The source audit confirms why field-specific
handling is needed:

- `SecurityAlert.ExtendedProperties.Classification` occurs in 562 latest alerts;
  Defender investigation-state metadata occurs in 320.
- `SigninLogs.RiskState` mixes `atRisk` with `remediated`, `dismissed` and
  `confirmedSafe`; `RiskDetail` mixes actual MFA-response signals with automated
  and administrative safe/dismissal decisions.
- The same mixture occurs in `AADRiskyUsers` and `AADUserRiskEvents`.
- Other status keys, such as authentication/protocol status, are genuine
  observations and must not be removed by a blanket status-name filter.

The user selected the **conservative profile**: hide mixed current/post-review
risk and investigation-state summaries, while preserving event-time signals
and concrete response events. This decision is settled.

The full audit inventoried all 62 tables and 2,355 source columns, including
66 schema-declared dynamic columns and additional observed JSON-encoded
fields. The resulting source-pinned policy has 29 explicit changed/excluded
column/table decisions. It excludes private investigation bookmarks and
case annotations, query-history text and mixed risk-state summaries.

Five structured columns were checked exhaustively: **295,070 nonempty field
occurrences**, of which **3,414 change**, removing **21,908 metadata-field
mentions** with zero unrelated-value mismatches. Literal commands and
unrelated encoded payloads are not reparsed or repaired.

Source context matters. Cloud `EditIncidentClassification` values are private,
whereas `TIMailData-Inline` Malware/Phish verdicts are native detection signals
and remain visible. Configured transport-rule comments are retained as action
payload; case comments and submission-triage judgments are not. Event risk
levels remain; mutable current-user risk levels do not.

Thirty-one `AirInvestigationData.Data` strings contain duplicate JSON keys
inside serialized investigation packages. Their investigation-only payloads
are kept private through an operation-specific rule, not repaired, collapsed,
or mistaken for independent activity. The source files remain unchanged.
The same audit identified copied cloud detector/investigation records that
need corrected graph lineage before serving: native detections are
`detector_derived`, investigation-package snapshots are `metadata`, and
concrete response actions retain their action lineage.

Policy objects are pinned to the exact source snapshot and ledger checksum.
Reviewed field removals may be operation-specific; they cannot accidentally
apply an empty-field or data-dependent decision to a different source version.
Full view materialization and verification follow this checkpoint. The policy
does not reopen FP/BP-targeted generation or change the ten case designations.

The completed public projection is
`view:ae2b0d21c6496b2c2e5248e4d7dd5dc897e384d49b7f5f766311c523eb0ecd5f`:
61 public tables and 13,276,298 rows, including all 914 incident and 1,069 alert
rows. Private mapping data remains a separate database. No prohibited
top-level classification/risk-state/provenance columns are exposed.

Full MySQL preparation identified physical portability constraints rather than
missing evidence: five native diagnostic column names exceed 64 characters,
and the 405-column projected diagnostics table exceeds the default 16KB-page
row layout. The serving adapter retains deterministic storage-name mappings
and uses a private 32KB-page instance; canonical source names and row hashes
remain unchanged. A wide-row sort exceeded the bounded loader memory budget,
so loading now streams rows and orders only the narrow verification keys.
The full MySQL row verification is still required before backend pilot
acceptance. Preliminary discovery may use the completed public DuckDB
projection while the separate MySQL load is verified.

### 17.14 Approved pilot endpoint and execution limits

The user selected the `gpt-6-sol` Azure OpenAI deployment configured in the
sibling `oss_saber` workspace, using Entra authentication. The user explicitly
chose **no aggregate model-spend ceiling and no aggregate model-call limit**.
The proposed checkpoint cap of 0.5 is used for the pilot, not frozen as a
release-wide calibration. Technical SQL/result/time bounds remain separate.

An Entra-authenticated readiness call succeeded using API version
`2025-03-01-preview`; the probe returned `READY` and consumed 15 tokens.
No tenant data was sent in that probe and no API key was used. Discovery,
blind verification and refutation still require separate contexts, even when
using the same deployment.

### 17.15 Real isolated-role discovery checkpoint

The I4 runner now has schema-validated scout, author, repair, blind-solver and
refuter roles, public SQL/schema tools, and bounded generation-only graph
pivots. Every request, response, tool result, error and model usage record is
kept in private artifacts. No aggregate model budget/call ceiling is imposed;
transport timeouts, query limits and finite response sizes remain technical
bounds.

Actual endpoint behavior required the Responses API for `gpt-6-sol` reasoning
with function tools. The client retains encrypted reasoning state between
turns and filters response-only input fields. Server-side token throttling
is handled with recorded retry waits and same-context resume, not a new scout
run that discards previous evidence. No API key is used.

Two source-grounded candidates now pass DuckDB mechanical checks and separate
blind/refuter roles:

- **Incident 34:** the recorded scheduled-task `Exec.Command` and
  `Exec.Arguments`, preserving their observed split rather than repairing a
  path or claiming successful execution. The private checkpoint identifies
  the related file-creation path from its source chain.
- **Tenant:** reported Graph response bytes between the observed
  AllPrincipals Mail.ReadWrite grant/removal for the application discovered
  from creation telemetry. App and service-principal object namespaces are
  joined by the recorded application ID, not display-name equality alone.

The first tenant draft was not accepted: it asked for two outputs despite a
single numeric final shape, and the blind citations did not match the complete
gold proof. A new revision corrected wording and source-ID binding and passed
fresh blind/refutation runs. No evidence restriction was silently relaxed to
make the original candidate pass.

Candidate status is **not release approval**. Actual MySQL claim parity,
fresh MySQL blind verification and native adapter replay remain required.
Private-pilot admission may defer missing split/release reviews only; every
other required gate must pass, and an explicitly failed review still blocks
execution. Production reward/similarity calibration and final release review
remain separate.

Full-source MySQL loading also reproduced a connector text-batch failure on
stored script payloads. The loader now uses prepared parameter batches and
round-trip DOUBLE representations. Explicit resumption verifies all existing
rows before continuing, rejects content/schema mismatches, and does not
overwrite or drop completed source data. Only a fully verified load receives
its completion report.

### 17.16 Completed full MySQL and initial private evaluations

The entire public snapshot has passed MySQL schema and exact per-row
verification: **61 tables, 13,276,298 rows**, including 914 incidents and 1,069
alerts. The dedicated reader has only SELECT permission. Source databases,
legacy data and original graphs remain unchanged.

Actual query plans required source-generic non-unique identity/action/time
indexes. Exact process subject/parent indexes were added when ancestry queries
exposed repeated scans; no private answer value or hidden row selector is
indexed as a special case. The statement timeout was not increased to disguise
these failures.

Incident 34 also exposed a genuine dialect difference: MySQL `LIKE` interprets
backslashes in a Windows path as escapes. Literal substring matching now uses
engine-correct `STRPOS`/`LOCATE` expressions. Subsequent refutation rejected an
unjustified one-second correlation constant; the final revision uses actual
task-name/process/path relationships and the public incident window, and
explicitly asks for the initial creation record rather than a later update.

The [two private evaluations][i4-private-evaluations] completed actual MySQL
answer/witness parity, fresh blind solves and native SecRL/ACE replay:

| Task | Answer correct | Grounded final submission | Reward in both adapters |
|---|---|---|---:|
| Incident 34 r3 | Yes | No: required alert citation omitted | 0.0 |
| Tenant r2 | Yes | Yes | 1.0 |

The complete independent witness sets were retrieved in both runs. This
verifies the candidate evidence without pretending an incomplete submitted
citation set deserves grounded-final credit. The evaluator separates
`complete_witness_observed` from `blind_evidence_grounded`; it does not keep
resampling a student until the score is one. No explicit checkpoint findings
were emitted in these blind traces, so no checkpoint credit was fabricated.
Checkpoint-discovery calibration must test that channel on real observations
before interpreting its zero scores or choosing production weights.

### 17.17 I5 coverage and overlap checkpoint

All ten public incident contexts resolve, preserving their approved exclusions.
Additional scoped discovery has reached:

- **Incident 133:** corrected the ambiguous group-related alert choice and the
  unclear `/` versus Windows `\` account serialization. The current r3 keeps
  the full lowercased domain/name format explicit and has passed independent
  source checks, actual MySQL answer/witness parity and both native adapters.
  The baseline student's correct answer was under-cited, yielding 0.0 in both.
- **Incident 322:** removed private-selector justifications and retained exact
  process ancestry, proxy-source exclusion and no inferred cloud-request
  causation. The original MySQL correlated-range plan exceeded the timeout. A
  logically redundant bound derived from the same public incident's scalar
  activity limits returned the unchanged answer in 0.168 seconds. The recorded
  r3 program revision has now passed fresh independent checks, MySQL parity
  and native adapter replay; the baseline student earned grounded 1.0 in both.

Unit-weight audit footprints for all four validated tasks contain 5/6/12/8
canonical observations, 77/27/183/111 deduplicated typed edges, and two fact
targets each. All four overlap components are zero for every pair in the
[six-pair matrix][i5-four-task-matrix]. This is a first measured
input, not enough evidence to invent production weights or split thresholds.
No split, deduplication deletion or release action has occurred.

The full local suite now passes **269 tests**, including real isolated MySQL
and native ACE integration. Validation includes the distinction between
complete observed proof and an under-cited final submission. Periodic shared
monitoring is not used; project-owned temporary database runtimes are closed
after their checks.

### 17.18 Checkpoint finding-channel development run

The original blind harness offered only final answers, so its zero checkpoint
scores could not measure intermediate discovery. The public `record_finding`
tool now accepts typed observations and complete source citations while keeping
checkpoint objectives, IDs, weights and feedback private. Descriptive finding
labels need not equal hidden `semantic_kind` strings. The rubric, not the
submitted label, still determines kind, units, normalization, tolerance and
required source evidence. This is the `source-witness-v1.1` evaluator policy.

The [development run][i5-finding-calibration] used the same four validated
tasks with the finding channel enabled. The interrupted first role resumed
from its retained request/tool history rather than being resampled:

| Task | Finding attempts | Valid finding shapes | Authored checkpoint matches | Grounded final reward |
|---|---:|---:|---:|---:|
| Incident 34 | 2 | 2 | 0 | 0.0 |
| Tenant | 3 | 3 | 0 | 1.0 |
| Incident 133 | 3 | 3 | 0 | 1.0 |
| Incident 322 | 4 | 2 | 0 | 1.0 |

Two timestamp attempts omitted required units and were explicitly rejected.
The ten valid findings described facts such as task names, application/principal
IDs, permission intervals and account-process ordering, not the authored
checkpoint's exact target. No unrelated finding was retrospectively relabeled
for credit. The actual values and proof coverage are preserved in the
[diagnostic report][i5-finding-diagnostic].

This run exposes a rubric-selection question before numerical calibration:
several useful solver pivots differ from the single authored checkpoint, and
some authored goals are ancillary investigations rather than necessary steps
to the final answer. Fixing that requires an explicit rubric-development
decision and newly validated task revisions, not lowering the scorer's
evidence standard or adjusting weights until a known trace passes.

**User clarification:** checkpoints are mandatory. Every task needs at least
one genuinely relevant, evidence-backed intermediate checkpoint. Checkpoint
errors require correcting/reworking the question and rubric together, then
rerunning validation. Empty-rubric tasks are not acceptable. Neither legacy
parity nor a minimum checkpoint count justifies an irrelevant target. The
tenant role-assignee and incident-133 ancillary ancestry targets therefore
require new task revisions; their earlier results are audit history, not
current release approval.

Gold-informed positive/negative controls use the same real rows separately
from blind discovery, to check whether correct evidence earns the declared
cap and wrong/missing/unobserved evidence does not. Their results are control
tests, not model success rates. The calibration driver also retains wrong or
uncertain student finals instead of classifying them as task-revision requests;
supported checkpoint credit remains available on such failures.

All [real-data controls][i5-checkpoint-controls] passed: four tasks, four
scenarios per task and two adapters, for 32 evaluations. Correct observed,
fully cited checkpoint findings earned 0.5 with no final answer. Wrong values,
missing citations and unobserved evidence each earned zero. Repeating a finding
did not double its credit; first-completion steps remained 4/2/7/3 respectively.
No additional model calls were used for these controls.

### 17.19 Mandatory relevant checkpoints and corrected questions

The user's clarification is implemented end-to-end: `TaskDraft`, `PrivateGold`
and `EvaluationRecord` require nonempty checkpoint arrays, and aggregation
rejects an empty rubric. Generators must rework or reject a question if they
cannot justify a relevant intermediate discovery. Review prompts reject
ancillary targets, irrelevant replacements, final-answer restatements and
legacy-parity padding. The brief proposal to permit zero checkpoints was
withdrawn; no such task was generated or admitted.

The two [reworked revisions][i5-relevance-evaluations] now have:

| Revision | Question correction | Required material checkpoint |
|---|---|---|
| Tenant r3 | Follow the resolved service principal into the matching delegated-grant window and Graph response | Derive the service-principal object ID from the application-creation identity |
| Incident 133 r4 | Attribute actual net/net1 pairs, grouping and ordering by their distinct cmd.exe parents | Resolve those source-bound parent processes before account attribution and ordering |

The tenant revision removes the role-only audit evidence/anchor, query
selectors and solution prose. Incident 133 removes the unrelated
RunCommandExtension/PowerShell ancestry proof and adds the actual parent
observation needed by the revised question. These changes are independently
source-backed, not derived from legacy question assertions.

Both revisions passed fresh blind and refutation runs, MySQL answer/evidence
parity, and native SecRL/ACE replay. Both measured final submissions are
grounded with reward 1.0; submitted checkpoint findings receive no credit
unless they actually satisfy the rubric. Task correctness is not inferred
from a high student score, and the previous defective revisions remain audit
history only.

The refreshed four-task unit-weight footprints have 5/5/10/8 observations,
77/23/154/111 edges and two fact targets each. All six pairwise overlaps remain
zero, with no production weight, split or deduplication threshold selected.
The full suite passes **270 tests**, including real MySQL and native ACE
integration; all 109 pinned legacy files remain unchanged.

### 17.20 Overlap calibration expansion

The next private development slice adds same-episode questions with different
investigative objectives and explicitly labeled paraphrase controls. These are
not automatically releasable duplicates or split assignments. Each question
retains mandatory relevant checkpoints and its own independent validation.

Related candidates receive distinct task IDs and share the seed episode's
lineage group; actual revisions keep their logical task identity. Resume binds
the source-task fingerprint, resolved task ID/revision and lineage before
reusing any role output, and rejects a changed seed rather than overwriting
that provenance.

The metric implementation is corrected to the agreed Section 13.2 definition:
`evidence-overlap-v2` uses a namespaced union of decisive observation and fact
features for containment. The earlier implementation's observation-only
containment was an incomplete proxy. Old v1 results remain available but are
not interchangeable with v2. Namespace, conflicting-weight, missing-feature,
symmetry and shared-fact/disjoint-observation cases are tested explicitly.
No production coefficient or action threshold is selected by this correction.

The [validated development matrix][i5-overlap-positive-matrix] now has seven
private instances and 21 pairs. The two paraphrase controls have identical
scoped final/checkpoint facts and evidence: all four components equal one.
The distinct tenant credential-list-reduction question shares four of six
combined observation IDs with the response-byte question, but asks a different
objective and has a distinct removal-boundary checkpoint. Its measured
components against either tenant paraphrase are:

```text
J_E = 16/27 = 0.59259259
J_O = 4/6  = 0.66666667
J_F = 0
C   = 4/7  = 0.57142857
```

The other 17 pairs are disjoint under the measured features. No aggregate
score is published without an explicit coefficient choice, and no removal or
split follows automatically from these components. In particular, evidence
overlap must not collapse distinct supported investigative objectives.

The three new accepted development instances passed actual MySQL claims and
witness parity plus native adapter replay. The paraphrase students earned
grounded 1.0; the distinct tenant student's correct answer was under-cited and
earned 0.0 in both adapters. Those measured student outcomes are not used to
retrofit task truth or relax evidence requirements.

A fourth proposed instance (incident-34 RunOnce value investigation) is held:
its independent blind run found the correct value via AlertInfo/AlertEvidence
but did not retrieve the currently required creation-command/SecurityAlert
proof. That alternative route remains unadjudicated. It is not in the
validated matrix and was not forced through by resampling or waiving proof.

The full suite passes **273 tests**. Resume regression tests also reject a
changed seed fingerprint/lineage before reusing completed roles or overwriting
task identity. Only two episode families currently provide overlap-positive
pairs, so this slice is diagnostic evidence, not sufficient justification to
freeze release-wide weights, thresholds or partition sizes.

### 17.21 Approved 60-attempt development expansion

The user approved five candidate attempts for each of the ten selected
incident scopes plus ten tenant-scoped attempts: **60 total**. This volume is
not an acceptance quota or a new model-spend/call ceiling. Source exclusions,
mandatory relevant checkpoints, private/public isolation, and release gates
remain unchanged.

The versioned batch runner interleaves scopes, assigns distinct task IDs and
passes only earlier same-scope question text to scouting/authoring as a
diversity hint. It does not share prior gold with blind solvers or fabricate
novelty when the evidence cannot support another question. Its manifest,
per-attempt outputs and task fingerprints are pinned; resume reuses only
unchanged completed outcomes.

Abstentions, runtime failures and candidates needing question/rubric revision
are recorded explicitly. Completion of the 60 discovery attempts is not
acceptance of 60 questions: repairs, source review and MySQL/native-adapter
validation remain required before admitting candidates. The local suite passes
276 tests, including batch cardinality, diversity context, resume/tampering
guards, explicit failure counts and the existing real MySQL/ACE checks.

### 17.22 Completed discovery inventory and post-batch repair

All 60 requested attempts completed: 21 passed discovery checks and are
candidates for MySQL validation, 36 need revision/proof follow-up, and three
encountered execution errors. These are discovery outcomes, not accepted
release counts.

The 36 cases divide into:

- 29 reviewer-identified defects, predominantly undisclosed source-specific
  literal filters, with additional scope, ambiguity and causal-wording issues.
- Two correct factual answers whose exact delimiter/timestamp serialization
  was not disclosed in the public question. These require question/format
  correction, not treating an alternate conventional rendering as false.
- Five blind runs with incomplete accepted witness coverage. These are held
  for proof-route review rather than admitted by dropping requirements.

The 31 question/format defects receive recorded feedback and fresh revision
attempts. Corrections must preserve a materially relevant checkpoint, derive
private identifiers from public anchors, and avoid arbitrary timing or
array-position selectors. If a valid question cannot be supported, the
outcome remains explicit instead of filling an accepted-question quota.

The execution errors were two unresolved scout citations and one token-limited
refuter response. Scout output is now source-validated inside the tool loop so
the role can correct a citation before completing. A specifically recognized
token-truncated response may be retried on explicit resume from its original
request; partial output is neither replayed as evidence nor treated as success.
The failed response and recovery provenance are retained.

Read-only JSON-array expansion is supported through DuckDB `json_each` and
MySQL `JSON_TABLE`, with all other table-source/private-reader restrictions
preserved. Tests verify extraction by parameter name under reordered arrays
and reject external/private sources nested inside those functions.

The initial 21 candidates completed their first actual MySQL/native-adapter
pass: six completed private pilots and 15 remained blocked. The blockers were
11 query timeouts, two unapproved date functions, one zero-row scalar result,
and one invalid MySQL datetime literal. Of the six completed pilots, four had
grounded correct finals and two did not; one also earned checkpoint credit.
All six produced matching SecRL/ACE components. These are validation and
student outcomes, not release acceptance counts.

Every failure retains its gate report; no timeout, dialect error or incomplete
proof is accepted as a score.
The full regression suite passes 279 tests with real MySQL/ACE enabled, and
all 109 legacy hashes remain unchanged.

### 17.23 Native query diagnostics and checkpoint-focused rework

Native EXPLAIN plans exposed repeated scans of endpoint and sign-in telemetry.
The source-generic `mysql-access-indexes-v3` policy adds non-unique access paths
for initiating-process identities, host/action/time, file hashes, registry keys,
sign-in identities and Office activity. Forty applicable indexes were installed
and their definitions verified on the existing snapshot. Source rows, public
columns, query limits and proof requirements were not changed. The actual
isolated MySQL/ACE integration test and 12 serving tests pass with this policy;
Pylance reports no diagnostics in the changed serving module.

Rechecking all 15 blocked originals resolved seven of the 11 timeouts with
unchanged candidate queries: those seven now pass actual answer/witness and
source/MySQL parity checks and can proceed to native student evaluation.
Four timeouts remain. Their broad serialized-entity searches and relation
scopes receive typed-selector/query rework rather than larger time budgets.
The other four original blockers remain separately recorded until their
specific policy/dialect repairs pass validation.

The scalar failure was reproduced as **zero rows**, not competing accounts:
MySQL interpreted Windows backslashes in a dynamically constructed `LIKE`
pattern as escapes. Literal containment returned the same unique source result.
That diagnostic alone does not admit the task: fresh review also identified an
undisclosed command-wrapper offset, requiring further program/literal repair.
The tenant datetime case requires a valid `+00:00` offset for the same UTC
instants, not a shifted or widened interval. Its subsequent execution must also
pass the existing time limit. `DATE_SUB` and `TIMESTAMPDIFF` AST/native probes
confirmed the tested arithmetic, but their allowlist integration remains
pending; the running discovery processes retain their original code policy.

An audit of the five held blind-proof traces identified four question/rubric
rework cases, rather than treating every missing gold row as a student error:

- Incident 5 used an undisclosed near-alert tolerance and positional entity
  paths.
- One incident-34 task required a process-creation lookup that was not clearly
  necessary to the question; its process selector also used an array position.
- Another incident-34 question referred to a PowerShell alert by a second
  containing three distinct alert starts.
- Incident 38 silently required process-creation corroboration and a
  parent-child condition absent from the question; its checkpoint repeated a
  PID already available in the API observation.

Each receives joint question, checkpoint, source-program and witness rework
with fresh independent review. Relevant nonempty checkpoints remain mandatory.
The tenant count task instead has a demonstrated evidence-capture gap: its
complete witness contains 412 records, and 405 qualifying OfficeActivity
records were not observed in the blind trace. It remains held; neither the
count-proof requirement nor the question is weakened merely to improve a
student outcome.

A subsequent compiler-task audit distinguished an over-restrictive proof route
from a genuine capture gap. The unchanged blind trace had already observed and
cited the incident, alert, compiler and converter records. The compiler's
recorded parent device, PID, creation time and full command line supported an
alternative to retrieving a separate PowerShell creation record. Source/MySQL
diagnostics returned the same answer and four record identities, and independent
review accepted the revised witness alternatives. The final retains both the
four- and five-record routes; the compiler checkpoint retains both three- and
four-record routes. This is an explicitly verified alternative proof, not a
waiver of identity bindings or a score-only student resample.

That audit also reproduced a native MySQL 8.4 `JSON_TABLE` error in the original
nested-CTE query, including raw SQL outside the validator's rendering. A
`DISTINCT` anchor projection preserved the observed cohort and resolved this
query-shape failure; witness projections retain source record identities so
different evidence rows are not collapsed. No optimizer hint or larger timeout
was introduced. Full native-adapter admission remains a separate required step.

### 17.24 Early backend validation and recorded-count guard correction

The second 30-candidate native pass completed 20 private pilots and retained
10 validation failures. Across the two native passes, 26 latest task revisions
have completed private validation with identical SecRL/ACE components and
nonempty checkpoints. Seventeen student runs had grounded final success; five
earned checkpoint credit, including one whose final was unsuccessful and whose
reward was 0.5. Eight received zero. These development outcomes do not freeze
production reward calibration or approve a release.

A static audit of all 60 logical tasks exposed a producer gap: discovery
compilation checked only the active backend's SQL policy. Generator
`discovery-pilot-v1.3` now checks every final/checkpoint answer and witness
program in both dialects before executing claims. It reuses the verifier's
source-derivation and ordering checks, preserves the literal/table/function
restrictions, and reports the failing engine and program. Unreviewed string
capacities are not globally exempted; their definitions need legitimate
justification or a source-preserving text representation.

The final task in the 31-question repair pass encountered a separate validator
bug: `COUNT(DISTINCT _record_id)=2` was incorrectly treated as selection by a
literal record ID. After 27 failed compilation attempts, only that stuck worker
was stopped for correction; its 30 completed outcomes and every failed trace
were preserved. The guard now distinguishes counts from identifier values.
Direct ID comparisons, `MIN`/`MAX` ID comparisons and ID predicates nested
inside counts remain rejected, including case-varied column names. No model
call/spend ceiling was introduced; the remaining task continues separately
under the corrected implementation.

Reviewed `DATE_ADD`, `DATE_SUB`, `TIMESTAMPDIFF` and character construction are
supported, with native tests for leap-day arithmetic, exact microseconds,
negative/zero differences and text delimiters. Binary query results still fail
explicitly rather than being silently decoded. The full 284-test suite passes
with real MySQL and native ACE enabled. New native-run policies pin source-code
hashes as well as task fingerprints, index reports and query limits; recorded
blind replay across different pinned runtimes is rejected.

Further measured registry and host/action access gaps led to four additional
source-generic indexes (`mysql-access-indexes-v4`, 44 applicable indexes).
Unchanged incident-39 and incident-55 tasks then passed complete preflight and
source/MySQL parity; the remaining timed-out tasks were not admitted on the
strength of a warm or partial query. The physical-index integration test still
verifies exact rows and both adapters.

Another Windows-path case reproduced zero native answer rows. Literal
containment restored both unchanged source answers; staging the complete
remote/launcher/match bindings with all source IDs preserved reduced its final
witness from a timeout to about 0.7 seconds, returning exactly the same five
source witness rows. This diagnostic is input to a recorded task repair, not
automatic admission. A separate file/process case has NULL initiating-process
creation times in both relevant file events; its rework must describe supported
attribute matches rather than inventing process-instance identity.

### 17.25 Latest development inventory and native translation follow-up

The latest completed-revision inventory still contains exactly 60 logical tasks:
52 pass discovery and eight remain held for captured-proof follow-up. All
programs in those latest revisions pass the static SQL policy in both dialects.
This does not replace native execution: the third native pass completed
13 further private pilots and retained six concrete preflight failures.

Thirty-nine latest revisions have completed actual native validation, all with
matching adapter components and nonempty checkpoints. Twenty-four student runs
had grounded final success; six earned checkpoint credit, including two
partial-only rewards of 0.5. Thirteen received zero. These retained outcomes
are not a target to rewrite questions toward.

The native failures distinguish separate causes: comma-style join visibility,
nested `JSON_TABLE` query shape, mixed character sets in witness-group labels,
JSON presentation whitespace, and execution-time limits. Verified probes use
explicit `CROSS JOIN`, source-identity-preserving materialization and lossless
conversion of ASCII record-ID label operands to UTF-8. They do not change global
collations or relax string comparison. The LDAP question's ambiguous serialized
array representation requires a clearly specified flat ordered-list answer,
not a permissive scoring fallback. Time-ordered outputs must sort by the actual
time rather than coincidentally ordered IP text.

Source-generic `mysql-access-indexes-v5` adds a cloud-event timestamp index
(45 applicable indexes). The corrected management-request queries then matched
both source answers and complete witness rows within unchanged limits. New
candidate revisions still require independent review and complete native
validation before admission.

An API timeout in an unfinished blind run was resumed from its unchanged
context; hashes confirmed the existing task and model responses were preserved.
The eight proof-held traces were separately audited. Their missing record IDs
were not present in the returned SQL results, so no citation-lineage recognition
failure or silent waiver was used to admit them. Alternative proof routes still
require explicit source verification and independent review.

The fourth native pass completed one additional task and retained seven
preflight failures; a successful diagnostic run does not override a failing
native admission run. Query-by-query tracing isolated a slow checkpoint whose
plan joined broad device-only process and file scans. Two source-generic
composite access paths (`mysql-access-indexes-v6`, 47 applicable indexes)
resolved that unchanged candidate's complete preflight without changing rows
or limits. Four other query-time cases remained blocked.

Further review found an exclusion-list task assuming fixed array positions and
private 1→2→1 cardinalities, and an authentication question ambiguously asking
for “password-step detail” when gold expected only
`authenticationStepResultDetail`. Both require question/rubric correction,
not broader grading tolerances. A policy-task author also abstained because
the discovery tool could not execute MySQL-specific SQL; this was a workflow
limitation, not an unsupported source claim. `discovery-pilot-v1.4` explicitly
identifies each SQL tool's dialect and distinguishes source testing from later
native admission. The full 285-test suite passes with real MySQL/ACE enabled.

The corrected policy task subsequently passed ten isolated semantic
counterexamples, including reordered/unrelated members, reported empty lists,
missing-versus-empty data, renamed/intervening same-ID snapshots, cross-day
successors and consistent/contradictory timestamp ties. A local native CTE
materialization fix preserved all four source answer/witness results and then
completed native admission. Global optimizer changes were tested only as
diagnostic controls and were not adopted.

The latest inventory now has 47 native-completed revisions, three remaining
query-time holds and ten captured-proof holds. The latter are not automatically
reclassified as wrong questions or resampled for a better score. All 60 original
attempts and every later revision remain recorded.

Validated-only overlap calibration uses a batch footprint builder that verifies
the graph once and reads it through one read-only connection. Tests establish
equality with the existing single-task results and reject unvalidated,
duplicate, mixed-graph and changed-graph inputs. The full suite now passes
288 tests with native integrations enabled. Unit-feature overlap components
remain diagnostic: aggregate coefficients, deduplication thresholds, split
assignments and release approval are still unset.

The 47-task audit produced 1,081 complete component comparisons: 66 within an
incident, 754 across incidents, 246 tenant/incident and 15 tenant/tenant.
No cross-incident or tenant/tenant pair shared a selected source observation.
Five tenant/incident pairs shared behavioral records; such cross-benchmark
overlap remains permitted and reported.

All 66 within-incident pairs shared some source evidence, but 36 shared only
the incident record and 42 shared only incident/alert records. Only 24 shared
behavior/security-control observations. These are diagnostic counts, not a
decision to assign weights or remove those anchors from proof.

No pair had identical full observation footprints or complete decisive
containment. The strongest within-incident observation overlap was 7/12 and
containment 7/11. Inspection found related objectives rather than a demonstrated
duplicate: for example, an earlier PowerShell ancestor versus a later extension
descendant, or task action path versus configured trigger.

The original unit-audit fact identifiers are exact scoped answer/checkpoint
contract-and-support signatures. Their zero shared-fact count must not be read
as absence of semantic fact reuse: two incident-166 checkpoints identify the
same mailbox through the same rule observation but use different alert anchors,
descriptive labels and comparison policies. Canonical source-fact granularity
versus exact scoped-claim identity required a separate identity decision before
freezing production coefficients or deduplication/split rules.

### 17.26 Approved canonical source facts and private curation

After reviewing positive and negative examples, the user approved canonical
source-fact matching, retaining exact scoped answer/proof signatures as
secondary diagnostics. `canonical-source-facts-v2` identifies a fact by source
snapshot, canonical source-observation subject, table/column/JSON-leaf property,
exact recorded value and recorded source-time context. Structural property
paths preserve roles. It does not merge equal strings across observations,
infer global entity equivalence, or treat a shared source fact as proof that
two questions are duplicates.

The deterministic resolver derives values from integrity-checked public rows;
the model supplies only property references. Every reference must belong to
that final/checkpoint claim's validated evidence. The proposal must cover the
final answer and all mandatory checkpoints. JSON numbers remain lossless,
missing/ambiguous ordinary value paths fail, and null is only a projected source
value, not proof of absence. V2 additionally supports an explicitly tagged
`json_member_presence` observation: after verifying every ancestor and an
existing object parent, the resolver records whether that object's exact key
is present. Missing parents and non-object parents fail; absence of a member
is not an invented null or a real-world absence claim. The property kind is
part of the canonical fact identity.

Private curation and independent review use separate conversations and fresh
outputs. Both roles must retrieve every selected source record, with source
IDs verified against SQL lineage rather than literal projections. The review
binds the resolved bundle fingerprint and checks relevance, coverage, subject,
role and time preservation, and absence of value-only merging. Mechanical
source validation does not replace semantic review. Derived facts use reviewed
source inputs. Actual scope and event-type selectors are necessary even when
given in the question; unrelated metadata and outside-window examples are not
required merely as padding.

A passing annotation replaces only the fact component under
`unit-canonical-source-facts-v2`, retaining the exact baseline edge/observation
features. Original signatures remain separately available. Missing or failed
annotations are incomplete/unscorable, never zero or an implicit fallback.
No grading, task gold, checkpoint objective, native outcome, production
weight, threshold, split or release decision is changed.

The first six real-task annotations were all correctly held by independent
review. Curator guidance had discouraged selecting supplied incident/alert
identifiers even when they were material source predicates; some process
ActionType predicates were also omitted. The scheduled-task annotation needed
to represent a missing `Exec.Arguments` member precisely, motivating the
versioned structural observation above. These annotation failures do not
change the validated tasks or their native outcomes.

Fresh fact-only revisions pin the prior artifacts and require unchanged
task/validation/baseline fingerprints. Prior review feedback is available to
the curator but not copied into the new independent review conversation.
Feedback remains a diagnostic, not authority to expand a claim's scope or
modify its gold. Original v1 annotations and failed reviews remain retained.

All 302 implementation tests pass with native MySQL and ACE enabled, including
source integrity, identity/role/time separation, exact JSON values, separate
source inspection, review binding, precise member-presence semantics,
immutable annotation revisions, explicit holds and unchanged task gold.
All 109 pinned legacy files remain unchanged.

All six revised real-task annotations subsequently passed independent review
and five explicit control assertions. The mailbox checkpoint pair shares the
same OfficeActivity observation's UserId fact despite different labels and
alert anchors. The two identical executable-path answers remain associated
with disjoint event subjects and distinct facts. The earlier/later PowerShell
objectives retain separate command targets and time contexts.

Their 15 complete comparisons contain two pairs with shared source facts:
incident 166 Q1/Q2 has fact Jaccard 5/28, and incident 133 Q2/Q4 has 34/72,
instead of the old exact-signature zero. These are unit-feature diagnostics,
not duplicate determinations or selected production coefficients. Baseline
edge and observation features are unchanged.

The full 47-task rerun reuses the six reviewed annotations without resampling
them and curates the remaining 41. Its report distinguishes behavioral/control
fact sharing from context/detector-only sharing. Failed annotations remain
unscorable; full-corpus results and production decisions remain pending.

### 17.27 First full canonical pass and explicit recovery holds

The initial 47-task pass produced 41 independently reviewed annotations,
820 complete comparisons and 261 incomplete comparisons. All incomplete
fact/containment components remain null. Among the complete pairs, 56 share
canonical facts: 21 share behavior/security-control facts and 35 share only
context/detector-derived facts.

The complete comparisons comprise 55 same-incident, 611 cross-incident,
148 tenant/incident and six tenant/tenant pairs. Shared facts occur in all
55 same-incident pairs (20 with behavioral/control sharing) and one
tenant/incident pair. No complete cross-incident or tenant/tenant comparison
shares observations or canonical facts. These counts exclude incomplete
comparisons, not treat them as disjoint.

The largest preliminary unit containment is 0.9 for incident 36 Q3/Q5:
configured executable action versus configured TimeTrigger StartBoundary.
They share task-identification evidence but have distinct target properties.
This is a calibration example, not a deletion decision. Production
coefficients, thresholds and split assignments remain unset.

Four annotations stopped at unfinished curator roles: two API interruptions
and two explicit 12,000-token completion truncations. Recovery resumes only
those unfinished roles into fresh outputs, preserves original request/response
bytes, revalidates captured source inspections and independently reviews the
result. Truncated output is never executed or treated as evidence. Recovery
uses a 24,000-token per-response limit and 600-second model timeout, without
changing SQL limits or imposing an aggregate call/spend cap.

Tenant Q3's annotation omitted the recorded initiating-process filename and
command line that establish its Schedule-service qualifier. Both claims now
include those properties and have passed fresh independent review, without
changing the validated task. A fingerprint-bound, no-model merge raises the
reviewed total to 42, with 861 complete and 220 incomplete comparisons. The
merge reproduces all 1,081 original component rows exactly when run without
overlays, and rejects changed snapshots, baseline observations and duplicate
results. Incident 5 Q2 instead
has a proof-description mismatch: its gold rationales discuss six host/file
launches and two connections, while the corresponding claim witnesses bind
only the qualifying launches and matching connection. Additional records
elsewhere in the task do not authorize citing them for another claim.

That mismatch is being repaired through a fresh question/checkpoint/proof
revision, explicitly separating event-time selection from process-creation-time
ranking and retaining the source-side limitation. Unsupported incidental
cardinality claims must be removed or supported by the actual claim witnesses;
they cannot be fixed by weakening canonical review. New source/blind review
and native admission are required before a changed task can replace its
previous audited fingerprint. Original outcomes and accepted annotations
remain immutable.

### 17.28 UNION source-citation recognition and recorded-proof recovery

Exact resume of the four interrupted curator roles completed without changing
their original traces. Three passed independent review; incident 38 Q1's
annotation still needs the inspection event's recorded InitiatingProcessId=0
to substantiate its stated socket-only attribution limitation. The resulting
pre-fix aggregate contains 45 reviewed annotations, 990 complete comparisons
and 91 incomplete comparisons.

Incident 5 Q2's corrected r5 question/checkpoint/proof descriptions passed
semantic review, with a correct grounded blind answer. Its initial
complete-witness flag was nevertheless false. A direct trace audit disproved
the hypothesis that its network ID was absent: the actual SQL result contains
the required record in a UNION of DeviceNetworkEvents and DeviceEvents.
SQLGlot exposes multiple lineage branches there, while the verifier previously
accepted only a single downstream chain.

Evaluator `source-witness-v1.2` recognizes branch-local direct source projections.
All possible origins of a credited ID column must be actual source `_record_id`
fields. Accompanying values must match the same source table, alias chain and
branch. A UNION cannot make literal IDs, unrelated join fields or ID-only
retrievals into observed evidence. Three positive regression subcases first
reproduced false negatives; the corrected implementation passes all 304 tests
with real MySQL and native ACE enabled.

Rechecking r5's original blind trace now recognizes 11 source records and
complete witnesses for both final and checkpoint claims, with zero new model
calls. The original task, responses and failed report remain unchanged. A
fresh source-admission derivative records the evaluator correction and full
artifact hashes; native admission still runs afresh because r5 is a genuine
question/rubric revision, not a rescore of the old student for a better result.

The 45 previously reviewed canonical bundles are separately re-resolved from
source and their curator/reviewer SQL inspections rechecked under v1.2.
Revalidation must preserve every fact, footprint and task fingerprint and the
original independent review; it records old/new implementation hashes instead
of bypassing runtime binding. No historical native outcome, reward formula,
threshold, split assignment or release decision is changed.

The corrected incident-5 r5 task subsequently passed fresh MySQL/native-ACE
admission with matching adapter components and grounded final success (1.0).
Its mandatory checkpoint remained available; the student's checkpoint
progress was 0.0 and was not adjusted to obtain a better score. A new
graph-verified baseline and independently reviewed canonical annotation bind
the r5 fingerprint, rather than reusing r4's baseline or validation.

Incident 38 Q1's PID-zero attribution-limitation annotation also passed.
All 47 current annotations now have passing independent reviews. Final
assembly explicitly replaces only incident 5 Q2's old fingerprint, requires
the new native validation/baseline, and verifies the retained annotations'
post-fix inspection checks before publishing a complete component matrix.

### 17.29 Complete canonical component audit

Revalidation passed for all 45 retained annotations with zero model calls and
unchanged source facts, footprints and historical native outcomes. The
explicit revised cohort now contains 47 independently reviewed annotations
and 1,081 unique, complete pair comparisons. A separate check recomputed every
Jaccard and namespaced containment component directly from unit feature sets.
The incident-5 r5 task is the sole task-fingerprint replacement; even its
edge/observation footprint remains unchanged.

| Pair scope | Comparisons | Shared facts | Shared behavior/control facts | Context/detector-only facts |
|---|---:|---:|---:|---:|
| Same incident | 66 | 66 | 23 | 43 |
| Cross incident | 754 | 0 | 0 | 0 |
| Tenant/incident | 246 | 3 | 3 | 0 |
| Tenant/tenant | 15 | 0 | 0 | 0 |

Thus 69 pairs share canonical facts, versus zero old exact claim signatures;
26 share behavior/control facts and 43 only context/detector facts. Five
tenant/incident pairs share observations, but only three share selected
canonical properties. Maximum unit fact Jaccard is 14/29 and maximum
containment 0.9; no pair has complete decisive containment. Unit feature
weights are diagnostic, not the agreed eventual downweighting of routine
context or a chosen production coefficient vector.

The incident-322/tenant-Q2 forwarding example illustrates target versus support
reuse. Their identically valued target/checkpoint forwarding facts refer to
different rule observations and remain distinct. The tenant final proof also
uses the later identical rule as a temporal boundary; that later rule is the
incident question's target, so its event-bound properties legitimately overlap.
This is not value-only merging and does not make the investigative objectives
identical.

Before proposing coefficient or material-leakage thresholds, the canonical
layer is being applied to the seven existing native-validated controls:
two true-paraphrase pairs, a related-objective example and disjoint cases.
Their QA and native student outcomes are not regenerated. This checks fact
selection on known equivalence controls as well as the related objectives in
the 47-task batch. No production weights, deletion decisions, partition sizes
or release approvals have been selected.

The first canonical control pass reviewed six of seven annotations. Both
known paraphrase pairs have J_E, J_O, J_F and containment exactly 1.0, despite
independent property selection. All 13 complete disjoint comparisons are
exactly zero in every component. The related-objective annotation is held
because it selected the application's ID value without the source
modified-property label identifying that value as AppId. That role-label fact
is being added through a fresh independent annotation review, without changing
the question or its native outcomes. The six affected comparisons remain
unscorable, not zero.

The corrected related-control annotation subsequently passed independent
review. All seven controls and all 21 comparisons are now complete:
two paraphrase pairs have every component 1.0, 17 disjoint pairs have every
component 0.0, and the two related-objective comparisons have:

```text
J_E = 16/27 = 0.59259259
J_O = 4/6   = 0.66666667
J_F = 32/47 = 0.68085106
C   = 36/43 = 0.83720930
```

The related task asks about a credential-list reduction rather than the
response-byte observation; high shared support is not question equivalence.
For any nonnegative coefficient vector summing to one, its scalar score lies
between 0.59259259 and 0.83720930. The two positive episode families therefore
verify invariants but do not identify a unique production coefficient vector
or establish a release-wide leakage threshold.

A separate **unselected sensitivity scenario** connects any same-incident
pair sharing a behavior/security-control fact, without using allowed
tenant/incident overlap as a grouping edge. It places all four current
incident-38 questions in one connected group and all four incident-166
questions in another. Other incident group sizes are: 5 = 1/1/1/1,
34 = 2/1, 36 = 4/1, 39 = 2/1/1, 55 = 2/1, 133 = 2/2,
134 = 3/1/1 and 322 = 2/1/1/1. This demonstrates the coverage impact of a
strict overlap rule; it is not a chosen split, a deletion decision or a waiver
of the agreed per-incident split intent.

Further controlled calibration attempts would expand beyond the approved
60-attempt development batch and require a scope decision. No additional QA
attempts, coefficients, feature weights, grouping thresholds or partition
sizes have been authorized by these measurements alone.

### 17.30 Approved twenty-attempt calibration expansion

The user approved 20 additional diagnostic attempts: one intended paraphrase
and one intended different shared-episode objective for each of incidents
5, 34, 36, 38, 39, 55, 133, 134, 166 and 322. These extend the calibration
scope, not the release or accepted-question quota. The original 60-attempt
batch, its revisions and measured outcomes remain unchanged.

Ten native-validated seeds are pinned by task, validation and baseline
fingerprints. They cover observed outcomes, configuration, attribution,
sequence and artifact identity. Each pair uses the same frozen incident
seed; new controls receive new task IDs and retain its lineage group.
Related-objective authors receive the existing incident questions to avoid
unnecessary repetition; deliberate paraphrases are not given contradictory
anti-duplication instructions.

Every attempt still requires mandatory relevant checkpoints and independent
source/blind/refutation checks, followed by native admission and canonical
comparison when eligible. Intended relationship labels are explicitly
unconfirmed until checked against the generated task; a valid new question
is not automatically a valid paraphrase control. Errors, abstentions and
proof holds remain recorded outcomes, not reasons to force 20 acceptances.
No production weights, thresholds, split sizes or release approval are
included in this authorization.

The initial 20 attempts completed with 11 source-ready candidates and nine
holds, without execution errors. All ten intended paraphrases retain their
seed's strict final/checkpoint answer contracts, declared answer window and
lineage; this mechanical precheck does not by itself confirm equivalence.
The 11 source-ready candidates are undergoing fresh MySQL/native-ACE
validation. A source student's under-cited submission is not a task defect
when the required witness was actually captured.

Six holds have concrete reviewer defects: missing exact public alert-name
anchors, an arbitrary five-second window extension, a fixed mail-entity array
position, unsupported SQL width justifications, or an answer window that
excludes an answer-bearing alert/entity representation. The question/context,
checkpoint rubric and both dialects' answer/witness programs are being repaired
together in new revisions. The three proof-only holds were checked against
actual captured SQL results: their missing alert/process IDs were not returned,
so no citation-lineage waiver or blind resampling was used.

Inspection also found tightly coupled inherited selector defects in the
incident-34 Q4, incident-134 Q2 and incident-322 Q5 seed revisions. Those
existing logical tasks are being corrected separately, preserving their old
native results and the frozen calibration manifest. In particular, the
incident-134 seed itself used the fixed mail-array slot. The incident-55 seed
already supplied its exact alert title; that title was lost only in the new
related control's wording. Historical component matrices remain valid
measurements of their pinned revisions, not release certification for a seed
whose query/public contract is now under correction.

All 11 initially eligible controls subsequently completed actual MySQL/native-
ACE admission with equal adapter components. All final values were correct;
eight submissions had complete grounded final success and three remained
under-cited with reward 0.0. All retained their mandatory checkpoint and
checkpoint-credit availability; measured checkpoint progress was 0.0
throughout this native slice and was not retrofitted.

These 11 controls are now receiving fresh graph-verified footprints and
independent canonical source-fact annotations while the nine question/seed
repairs continue. Calibration relationship labels remain unconfirmed until
their paired objectives, scopes and source facts are checked. No unsuccessful
student is resampled merely to raise its score.

The first repair pass produced six source-ready revisions (three controls and
the three affected seeds). Two other controls passed semantic review but
remain captured-proof holds; their missing process/registry records were not
present in returned SQL rows. The URL-representation control still required
typed entity selection, justified/public filtering labels and a window that
does not truncate its seven-digit entity timestamp.

The repaired incident-134 mail selectors passed **112 actual-SQL mutation
checks** across DuckDB and an isolated MySQL fixture: reordered entities,
mail first/last, unrelated and unmatched extra entities, and a missing-mail
negative case. Every final/checkpoint answer and witness program was tested
for both repaired tasks. The original fixed-slot defect was reproduced in
both dialects, and original source data was not modified. All six source-ready
revisions are undergoing fresh native admission.

The first 11 native-admitted controls also completed independent canonical
annotation: 11 reviewed footprints and 55 complete within-control
comparisons. Pairing them with the correct seed revisions and adjudicating
their intended calibration relationships remain separate steps; native
admission or matching answer text alone does not confirm a relationship label.

### 17.31 Broader calibration and atomic-selection correction

All six source-ready repaired revisions passed fresh native admission, and
the remaining URL-representation control subsequently passed source/native
checks with an explicit July-17 UTC calendar-day scope. No source metadata
timestamp was truncated to make it fit. The expanded slice now has 15
native-admitted controls and five captured-proof holds; the three corrected
seed revisions are separate replacements of existing logical tasks.

The first broader seed/paraphrase comparison retained identical
edge/observation footprints, while some fact components differed. Inspection
separated harmless extra support properties from omitted event/role facts and
a deterministic defect: selecting an entire serialized AlertIds array with
json_path=null bypassed the promised atomic-fact requirement. An initial
65-annotation audit found ten such selections, all in SecurityIncident.AlertIds.
They must not be hidden by coefficient choices or treated as atomically valid
merely because a semantic reviewer passed the bundle.

`source-fact-curation-v1.1` rejects valid serialized JSON containers, including
nested encoded containers, during source resolution and resolved-fact loading.
Exact scalar strings/numbers remain unchanged; non-JSON literal text is not
mistaken for a container, and duplicate-key ambiguity still fails explicitly.
Fact identity remains canonical-source-facts-v2 for valid atomic facts.
Feature eligibility is versioned as unit-canonical-source-facts-v2.1 so old
container-admitting footprints cannot silently mix with corrected ones.
All 306 tests pass with native MySQL and ACE enabled.

Revalidation covers the explicit current inventory: 47 development tasks,
seven original calibration controls and 15 expanded controls, using the new
native-validated seed revisions. Unaffected bundles retain their exact fact
content and independent review. Non-atomic selections, existing review holds
and specifically identified coverage omissions remain unscorable and receive
fresh annotation revisions. Mechanical invalidation is recorded separately
from the retained original review rather than forging a new reviewer verdict.
Task gold, native outcomes, reward rules and historical artifacts are not
rewritten. No production coefficients, thresholds or split/release decisions
have been selected.

The 69-item revalidation retained 56 annotations unchanged and explicitly held
13. Fresh fact-only revisions resolved nine. One execution-format
failure contained a complete, schema-valid JSON review in the original model's
text output rather than a finish tool call; it was recovered with zero model
calls after rechecking the bundle and captured source inspections. The
original response was preserved and no finish call was fabricated.

Two remaining event-type omissions required the actual process ActionType
facts. Both have passed; the API-interrupted reviewer resumed from its recorded
state with the completed curator and all original trace bytes preserved. The incident-34
seed's checkpoint instead had a real scope mismatch: it claimed a comparison
of updates on both sides of relocation without binding those updates in its
checkpoint evidence. The seed and its paraphrase control were reworked
together to establish the rename timestamp as the lower boundary needed for
the final update selection, including the destination-path support.
Both preserve their exact answer/checkpoint output contracts and passed fresh
source/blind/reviewer and MySQL/native-ACE admission checks. Both native runs
had complete grounded final success, reward 1.0 and equal adapter components;
their mandatory checkpoints remain creditable, with measured progress 0.0.
Fresh graph-verified baselines explicitly replace the immediately previous
seed/control fingerprints, not the older frozen generation seeds. New
task-bound canonical annotations subsequently passed independent review. This is a question/rubric
correction, not an annotation waiver or checkpoint removal.

### 17.32 Current-policy calibration results and remaining policy choices

The explicit current `unit-canonical-source-facts-v2.1` inventory is complete:
47 development tasks, seven original controls and 15 admitted expanded controls.
All 69 have reviewed task/native-bound annotations, producing **2,346 complete
comparisons**. Independent unit-set arithmetic verified all four components
and both retained exact-signature diagnostics: **14,076 numerical checks**.
The assembly records exact annotation provenance and the two incident-34
predecessor replacements. Historical v2 matrices and student outcomes remain
unchanged.

The 1,081 within-development comparisons retain 66 same-incident pairs,
754 cross-incident pairs, 246 tenant/incident pairs and 15 tenant/tenant pairs.
All 66 same-incident pairs share some facts, but only 23 share selected
behavior/security-control facts. Three tenant/incident pairs share such
facts. No cross-incident or tenant/tenant pair shares canonical facts in this
cohort. Across all three cohorts, 163 pairs share facts: 78 include
behavior/security-control facts and 85 have only context/detector/metadata
overlap.

Direct comparison of the expanded controls' public scopes, final and checkpoint
objectives, strict contracts and reviewed source facts establishes:

| Admitted controls | Adjudicated relationship |
|---|---|
| 9 | Genuine paraphrases of their current seed revisions |
| 4 | Distinct objectives with material shared behavioral evidence: incidents 34, 38, 133 and 166 |
| 2 | Distinct objectives sharing only incident metadata: incidents 36 and 134 |

The last two remain valid questions but are not positive material-shared-
evidence calibration controls. The five captured-proof-held attempts remain
outside the admitted cohort; no new students were sampled to force acceptance.
The original seven-control regression still has two pairs with every component
equal to 1, 17 pairs with every component equal to 0, and the same two
intermediate related-objective pairs.

All nine expanded paraphrases have identical edge/observation footprints and
containment 1. Six also have fact Jaccard 1. The other three retain legitimate
support differences: an alternative process candidate's PID, an explicit
mailbox entity type, and a second sufficient later deletion observation.
Their fact Jaccards are respectively 38/39, 12/13 and 31/35. These differences
were not erased to manufacture perfect scores.

The combined 36 labeled control pairs still do **not** identify production
coefficients. For both diagnostic objectives (paraphrases versus other
relationships, and shared behavioral evidence versus context/disjoint pairs),
the minimum positive value exceeds the maximum negative value in every
component. Consequently every nonnegative, sum-one blend of these unit
components admits a separating threshold on these controls. This is an
identifiability result, not a held-out accuracy estimate or a chosen threshold.

An explicitly unselected sensitivity scenario connects development tasks
within each incident/benchmark whenever they share any selected behavioral or
security-control fact. It excludes all 22 deliberate controls and does not
group across incident/tenant benchmarks. Under this conservative rule,
incidents 38 and 166 each form one four-task component and cannot populate
both train and test without violating that rule. The other incidents and the
tenant cohort retain multiple components. This result is not permission to
relax leakage constraints merely to fill a split quota.

Production feature weights, component coefficients, material-overlap grouping
policy, split sizes and release approval remain unset. No grouping, deletion,
partition or release action has been applied by these diagnostics.

### 17.33 Task-relative response targets versus supporting observations

The user selected an inspection of response targets versus support before
choosing a grouping rule. The first inspection covers the four development
tasks in each of incidents 38 and 166: eight tasks, 16 final/checkpoint claims
and 12 within-incident pairs. It executed 32 original/instrumented answer
queries, plus source-integrity checks. Instrumented queries retain the
original answer-value sets while returning the actual source record IDs and
raw source columns used by each output expression. IDs must be attributed
through source SQL lineage and remain inside the claim's validated evidence.
No source observation is equated merely because its output value matches.

Roles are task-relative diagnostics, not changes to canonical identity:

- **Response input:** a selected source property actually forming the final
  or checkpoint output, including substring/concatenation operands.
- **Support-only:** a selected fact not used as either response operand for
  this task. It can still be essential to identity, temporal scope, matching,
  qualification or proof, and is not automatically safe across splits.

The eight tasks share no final-response facts with each other, but four
pairs share checkpoint-response inputs. Incident-166 Q1/Q2/Q3 checkpoint the
same rule observation's mailbox UserId; Q4 uses it as supporting account/time
boundary information. Incident-38 Q2 extracts the response-file path from
the same compiler command line returned by Q5's checkpoint. The identical
source cell does not make those two emitted checkpoint answers identical:
one returns a substring and the other the complete command.

Checking only selected shared response facts is insufficient. Incident-38
Q1's proof includes the remote-thread record supplying Q3's initiating-image
checkpoint, even though Q1's selected canonical facts omit that particular
property. Likewise, the rule record used for support/checkpoints in other
incident-166 tasks contains Q2's final rule parameter. Such record overlap
indicates **potential response exposure through a shared source record**,
not proof that a student transcript displayed or memorized every field.

The unselected sensitivity results for the pinned revisions are:

| Pair-link condition | Incident 38 component sizes | Incident 166 component sizes |
|---|---|---|
| Both tasks use a shared fact as a final/checkpoint response input | 2, 1, 1 | 3, 1 |
| A shared selected fact is a response input for either task | 2, 1, 1 | 4 |
| A response-bearing source record is used in the other task's proof | 2, 2 | 4 |

These are diagnostics, not applied partitions. They show why distinct final
answers do not eliminate checkpoint leakage, and why removing support-only
facts from the metric could hide source-record exposure. A task-relative
response-role view should complement, not replace, the existing observation
and supporting-fact views.

Distinct-set outputs also require care: incident-166 Q4's final SQL has 17
qualifying sign-in observations but two distinct returned combinations. Its
reviewed facts include a complete representative for each combination.
Additional equivalent qualifying rows are recorded separately by the
inspection; they are not merged into the representative's event identity or
silently treated as missing answer coverage.

This deeper trace exposed another concrete selector defect in the pinned
incident-38 Q2 revision. Its final/checkpoint queries read the process from
alert entity slot zero. A read-only query-local mutation that prepends an
unrelated entity while retaining all original entities makes both answers
disappear. The source data and SQL allowlist were unchanged. A fresh
question/query/checkpoint revision subsequently passed source/blind/reviewer,
MySQL/native-ACE and canonical-fact checks. Its typed process/host selectors
preserve the exact final/checkpoint outputs and answer window, use qualified
process identity, and no longer rely on array position.

The repair passed **64 actual DuckDB/MySQL mutation checks**, covering every
final/checkpoint answer and witness program with reordered entities, extra
unrelated/unmatched entities, and missing process/host negative cases. The
old defect was reproduced in all eight original answer/witness/backend
combinations. The isolated fixture server was stopped and its directory
removed; original source data was untouched. Fresh native evaluation had
grounded final success and reward 1.0 with adapter parity; checkpoint credit
remains available and measured progress remains 0.0.

The current 69-task matrix was rebuilt with this explicit replacement and
all 14,076 numerical checks passed again. The target/support inspection was
also rerun against the fresh task/native/bundle bindings; the four
checkpoint-sharing pairs and the scenario component sizes above are
unchanged. Old task outcomes, matrices and role audits remain immutable
history, not proof reused under a new fingerprint.

The user subsequently clarified that shared checkpoint responses and source
records are acceptable for distinct questions and should be disclosed through
the overlap metric, not used to force groups. This supersedes the earlier
proposed shared-evidence grouping step. The target/support and response-record
exposure analyses remain explanatory diagnostics; they do not impose split
constraints. Final-question objectives and scoped targets still determine
genuine duplicate review, rather than answer-string equality or inequality
alone. Section 13.3 records the current policy.

### 17.34 Question-level split inventory and proposal tooling

The opt-in split interface consumes explicit native-admitted task revisions,
their original unit baselines and reviewed canonical annotations. It validates
the task/native/baseline/bundle/review/runtime bindings and final/checkpoint
claim membership before computing a cohort fingerprint. It rejects duplicate
task IDs/revisions and incompatible source, graph, serving or feature versions.
It does not infer that different answer strings prove semantic distinctness.

`audit-question-splits` can report a cohort without assigning any questions or
choosing weights. It preserves every pair's edge, observation, canonical-fact
and containment components, with separate scope/bucket/train-test summaries
and explicit metric-availability counts. Aggregate scores remain absent until
the caller supplies weights; missing required components remain unscorable
even if their coefficient is zero. Reports contain fingerprints and counts,
not private gold, checkpoint objectives or executable SQL.

`propose-question-splits` requires explicit positive train/test counts for
every included incident/tenant bucket and an explicit seed. Counts must cover
the existing cohort exactly; no new questions are generated to fill them.
The versioned hash ranking is deterministic and independent of input order.
Shared evidence, checkpoint responses and lineage metadata do not impose
grouping. Explicitly authored assignments can also be audited, but must bind
the exact cohort and place each question once.

These are private proposals and reports, not release exports. They always
record that semantic duplicate review has not been performed, split review
is not approved and release approval is false. Outputs must be new and cannot
be written inside canonical annotation bundles. The focused split, similarity
and CLI contract tests cover these policies, including source-claim binding
and orientation-independent bucket-pair summaries.

The first real inventory audit includes the 47 current development revisions
and explicitly excludes the seven original and 15 expanded diagnostic
controls. All 1,081 pair comparisons are complete; 4,324 component values
match the independently verified current calibration matrix. The inventory
binds 377 input artifacts, leaves every question unassigned and supplies no
aggregate coefficients. No held attempt was promoted.

The focused split, similarity and CLI contract suite passes 69 tests, and
Pylance reports no diagnostics in the new module, tests or changed CLI. The
per-incident pools contain three to five questions and the tenant pool six.
An actual development split proposal still requires the user's explicit
counts and seed; production release and semantic duplicate adjudication are
not implied by this inventory audit.

### 17.35 Authorized development split proposal

The user selected one held-out question per incident and one tenant question,
then confirmed seed **42** before the assignment was generated. The user also
selected equal component coefficients **0.25 each for diagnostic reporting**,
not production coefficient calibration.

The resulting private proposal contains **36 train / 11 test** questions.
All 47 native-admitted development revisions are included once; all 22
diagnostic controls and previously held attempts remain outside this cohort.
The fixed seed/count request reproduces the assignments independently of
input order or overlap scores. No seed search, evidence grouping, question
deletion, model call or training run was used.

Independent verification reproduced all assignments, all 1,081 diagnostic
aggregate scores and the 4,324 unchanged component values. The 396 train/test
comparisons comprise:

| Scope relation | Cross-split pairs | Mean diagnostic overlap | Maximum |
|---|---:|---:|---:|
| Same incident | 31 | 0.138104 | 0.422302 |
| Different incidents | 279 | 0 | 0 |
| Tenant/incident benchmarks | 81 | 0 | 0 |
| Tenant/tenant | 5 | 0 | 0 |

These are overlap measurements, not student performance or proof of unseen-
evidence generalization. Within-incident overlap is allowed under Section 13.3.

A separate assistant semantic review compared all 47 pinned public question
contexts and final objectives, including all 81 same-incident/tenant-scope
pairs (36 across train/test). It identified no genuine duplicates. In
particular, the related registry questions differ in temporal predicates and
output classes, hostname questions differ in qualifying activity and ordering,
and earlier/later process command questions preserve different source roles
and instances. Shared checkpoints and records were not treated as duplicates.

The semantic review is a later, separately fingerprint-bound artifact.
The automated audit's original `semantic_duplicate_review="not_performed"`
marker is preserved rather than rewriting history. The proposal, source/native
outcomes and assignments remain unchanged.

The user subsequently **approved this development split**. A separate
development-review record binds that approval to the exact cohort, plan,
overlap audit, semantic assessment and verification artifacts. The original
proposal and its earlier approval flags remain unchanged. This approves the
36/11 development partition only: production scoring policy, release, model
training and additional QA generation are not authorized by it. No released
dataset or legacy split was modified.

This document specifies the proposed implementation. The comparison document
remains the evidence appendix; neither document certifies the entire tenant as
fully observed or the 111 alert candidates as benign/false positives.

[alert-negative-candidates]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/alert-negative-screen/alert_negative_candidates.csv
[alert-negative-evidence]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/alert-negative-screen/alert_negative_screen.json
[aces-task-example]: https://github.com/microsoft/ACESEvals/blob/2c76fbdea415d6fa6a87bbad846686fefd6ee9bb/domains/excytin/tasks/latest_cleaned_test_set/incident_134/incident_134_1.yaml
[aces-checkpoint-judge]: https://github.com/microsoft/ACESEvals/blob/2c76fbdea415d6fa6a87bbad846686fefd6ee9bb/domains/excytin/prompts/judge/checkpoint_judge_system.md
[aces-aggregation]: https://github.com/microsoft/ACES/blob/a9bdce1343fd1c331aafda3119cbf0d48f215382/src/saber/scoring/aggregation.py
[v1-semantic-report]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i2/semantic-check-accepted/semantic_report.json
[v13-coverage-report]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i2/coverage-verification-v1.3.json
[v13-semantic-report]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i2/semantic-check-v1.3/semantic_report.json
[i3-runtime-verification]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i3/runtime-verification.json
[i4-private-evaluations]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i4/mysql-evaluation-04/summary.json
[i5-four-task-matrix]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i5/four-task-footprints/matrix.json
[i5-finding-calibration]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i5/finding-calibration-02/summary.json
[i5-finding-diagnostic]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i5/finding-calibration-02/diagnostic.json
[i5-checkpoint-controls]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i5/checkpoint-controls-v1/report.json
[i5-relevance-evaluations]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i5/relevance-mysql-01/summary.json
[i5-overlap-positive-matrix]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i5/overlap-pool/validated-matrix-v2/matrix.json

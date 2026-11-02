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

This is a logical view: the difficulty implementation will initially use the
private versioned sidecar proposed in Section 17.37, not add fields to or
invalidate the existing frozen task records.

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
| **I5b - Pre-production expansion and capacity study** | I5 and explicit capacity/overlap policy | Target 50 validated questions for each selected incident and 500 tenant questions; resumable generation/validation waves, objective-diversity review, scalable overlap reports and per-scope capacity estimates | Quality gates remain intact; actual yield and shortfalls are reported; capacity claims state tested policies, search limits and uncertainty |
| **I6 - Versioned release (M6)** | I5b and reviewer approval; bundle tooling may be built earlier | Immutable v1 dataset releases for the two benchmarks; SecRL/ACESEvals exports; source/graph/evaluator/reward/similarity/split manifests; reproducible release report | Required gates pass against final revisions, backend compatibility is checked, and legacy artifacts remain unchanged |

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

### 17.36 Requested pre-production expansion and capacity study

The user requested a larger pre-production version rather than promoting the
small development cohort directly to production:

| Scope | Requested validated-question target |
|---|---:|
| Each of the ten selected incidents | 50 |
| All incident-scoped questions | 500 |
| Tenant-scoped questions | 500 |
| Combined pre-production target | 1,000 |

The existing development cohort is 47 questions (41 incident-scoped and six
tenant-scoped), with its approved 36/11 split retained unchanged. The user
selected **1,000 new pre-production questions**, separate from those 47.
Diagnostic paraphrase/related controls are not promoted into the new benchmark.

The expansion also needs a per-incident and tenant capacity study. Its result
will be an empirical achievable-capacity estimate under the frozen source,
question-quality rules, overlap policy and search procedure, not proof of an
absolute maximum over every possible question. A finite candidate pool can
support a verified retained-set size and, where available, bounds on a
threshold-constrained selection problem. Reaching a search ceiling without
observing saturation gives a lower bound, not a proven source-capacity limit.

The user selected **capacity curves only**, not a hard overlap rejection cap.
The approved exploratory thresholds are **0.25, 0.50, 0.75 and 0.90**, using
the existing unit feature policy and equal-weight diagnostic aggregate.
Study maximum pairwise overlap within each incident and within the tenant
pool; cross-incident and cross-benchmark overlap remains separately reported.
Shared checkpoints/source records do not force groups or automatic rejection.

The initial exploration envelope is **up to 100 new logical candidate
attempts per incident and 1,000 tenant attempts: 2,000 total**. This is not an
accepted-question quota or a model-call ceiling. Report observed yield,
capacity bounds and saturation evidence before requesting an extension.

Implementation proceeds through:

1. Freeze cohort membership, target-versus-attempt semantics, overlap/capacity
   policy and a bounded exploration/stopping schedule.
2. Profile per-scope evidence and meaningful objective families, then run
   resumable generation/validation waves with auditable candidate inventories.
3. Keep source, native, mandatory-checkpoint, semantic-distinctness and
   canonical-fact gates unchanged. Do not count wording variants, manufacture
   checkpoint work, waive proof or resample completed students to fill quotas.
4. Report accepted yield, genuine duplicates, overlap exclusions if authorized,
   source insufficiency, captured-proof holds and operational failures
   separately. Timeouts or under-cited students do not establish that an
   incident's evidence has been exhausted.
5. Produce capacity curves and observed saturation/lower-bound reports for
   each incident and the tenant scope. Retain uncertainty and the dependence
   on the search strategy; a small incident may support fewer than 50 suitable
   questions, while a larger one may support more.
6. Package the resulting pre-production cohort with a newly reviewed split;
   do not reuse the development one-test-per-bucket allocation automatically.

The 1,000-question target does not authorize weakening any gate or imply
production-release approval. FP/BP-targeted QA remains deferred. No expansion
run has started. Scalable run/report tooling and the difficulty annotation
design below precede the first wave.

### 17.37 Difficulty heuristic bootstrap and separate model calibration

The user requested difficulty annotations during the pre-production expansion,
with later, separately configured model evaluations to test whether the
heuristic predicts performance differences, including Astra versus Luna.
Current `TaskRecord` instances have no implemented difficulty field or label;
Section 10.2 was a proposed logical schema, not a delivered classifier.

#### Verified ExCyTIn 2.0 starting points

The read-only inspection used sibling commit
`b32f7ad80380ad5b32c8579b15a3793750c2bf0b`. Three distinct mechanisms exist:

1. [Structural hop bands](../Excytin_2_0/src/excytin2/explore/ground.py):
   effective hops are `min(verified_chain_hops, shortest_selective_hops + 2)`
   when a shortest path was found, otherwise the chain length. Bands are
   L1 below four, L2 at four/five, L3 at six/seven, and L4 at eight or more or
   for a composite. The selective search excludes certain hubs/edges, is
   bounded, and traverses graph edges in both directions. These bands are not
   proof of minimum time/role-valid investigative reasoning depth.
2. [SQL-gate metadata and preliminary tier](../Excytin_2_0/src/excytin2/questions/generate.py):
   evidence rows/tables, SQL tables, pivot count, evidence-time span, answer-in-
   alerts, SQL repairs, revealed-path count and one-shot solver results.
   A successful one-shot probe gives `easy`; otherwise no detected alert-answer
   shortcut plus at least two raw SQL tables or three pivots gives `hard`;
   remaining cases give `medium`. The generation gate also rejects one-shot
   successes as `too_easy`. That is not a rule we inherit.
3. [Final solver-panel tier](../Excytin_2_0/src/excytin2/pipeline/gates.py):
   with the [configured model groups](../Excytin_2_0/src/excytin2/settings.py),
   neither of Astra/Opus solving gives `very_hard`, one gives `hard`, both
   with neither Luna/mini gives `medium`, both plus an easier-group model
   gives `easy`, and every solver solving gives `very_easy`. This is measured,
   model/configuration-dependent labeling, not a pre-solver heuristic.

The sibling design also proposes distractor counts, aggregation/negation/
ordering flags and richer structural features. Those proposals should not be
confused with the smaller implemented tier functions. Its solver tier uses
answer-match results; our primary evaluation requires grounded final success.
Operational errors can appear as `solved=false` in that implementation, and
an unknown alert-shortcut result can satisfy a negated Boolean check. We will
not import those missing/error-as-hard behaviors or its permissive answer
normalizations.

#### Separate structural prediction from empirical difficulty

Keep two independently versioned records:

- **Heuristic profile:** computed before the evaluated model runs, from the
  public task, verified source evidence, reviewed proof routes and query
  semantics. This is the predictor to test.
- **Empirical profile:** per-model/configuration grounded success, answer
  correctness, checkpoint progress, actions/tokens/time and failure categories.
  These outcomes can calibrate a later heuristic version but must not define
  the heuristic used to test that same model comparison.

Model identities and an assumed Astra-greater-than-Luna ordering are not
heuristic inputs. The later evaluation tests that hypothesis; it must allow
individual items where the ordering reverses. Difficulty is not novelty or
overlap: report those axes independently.

#### Proposed model-independent feature profile

| Axis | Grounded measurements | Guard against misleading proxies |
|---|---|---|
| Evidence breadth, B | Canonical observations and raw tables in a complete necessary proof; material entity/relation types and cross-domain bindings | Do not count the whole incident graph, unrelated properties, repeated exports, or both SQL dialects as extra evidence |
| Dependency depth, P | Required logical bindings, longest dependency chain, branch convergence, and the shortest independently verified alternative route | Collapse representation/alias/membership edges; preserve direction, time and actor/target roles; one SQL query can still require several reasoning steps |
| Reasoning operations, R | Necessary ranking/ordering, aggregation, request deduplication, nontrivial dynamic-JSON interpretation, temporal-role alignment, comparison or recorded-member-presence reasoning | Count semantic operation families, not SQL length, CTE count, formatting, optimizer workarounds or decorative predicates |
| Search ambiguity, A | Distinct plausible candidates at necessary decision points before applying the disambiguating criterion, within the public anchor/scope | Use source-verified diagnostic probes, not global node degree or the final unique query result; deduplicate aliases and repeated observations |

Node and edge counts and node-type histograms remain useful descriptors.
Types matter because of the required binding (for example process-instance
identity or message-to-mailbox-to-audit correlation), not an arbitrary rule
that every process or IP node contributes a fixed difficulty weight.

Keep additional, separate descriptors for output cardinality/exact-format
burden, citation workload, public anchor specificity, source-time roles,
query latency/result volume and generator repair effort. A long command
string, slow server or authoring failure does not by itself prove difficult
reasoning. Ordinary filtering on a supplied time window is not equivalent to
resolving event-time versus process-creation-time semantics.

Features must distinguish the final objective, each checkpoint and the combined
task. Use one complete verified proof alternative, not the union of all
alternatives as though every route were required. Preserve ranges across
alternatives and identify the scored route. "Least demanding verified route"
is not a claim that every possible shortcut has been ruled out.

The existing overlap footprint deliberately includes all edges emitted from
selected observations and all relevant proof alternatives. It is therefore
not automatically a minimal reasoning graph and must not be fed unchanged
into a difficulty score. In the current 47-question inventory, observation
unions range from 2 to 21 and raw footprint edges from 10 to 413; raw evidence
table counts are one for 11 tasks, two for 25, three for ten, and four for one.
Every task currently has one checkpoint. These measurements are descriptive,
not assigned difficulty labels; checkpoint count alone has no discrimination
in this cohort.

#### Provisional scoring rubric to prototype, not a calibrated policy

Start with four ordinal axes, each in `[0,3]`, retaining all raw measurements:

- **B:** maximum of reviewed breadth bands: observations 1 / 2-4 / 5-10 / 11+;
  raw tables 1 / 2 / 3 / 4+; material cross-domain bindings 0 / 1 / 2 / 3+.
  Only necessary proof structure contributes; count ranges/alternatives remain
  visible rather than rewarding an unnecessarily bloated witness.
- **P:** required discovered bindings 0 / 1 / 2-3 / 4+, with one additional
  point for a necessary branch reconvergence, capped at three. The logical
  proof view, not storage-edge count, supplies these measurements.
- **R:** number of distinct materially necessary operation families beyond
  simple selection/projection, capped at three. Mere JSON serialization,
  duplicate SQL implementations or extra checkpoints add no points.
- **A:** maximum verified look-alike count at a necessary decision point:
  one / two-three / four-ten / eleven or more. Keep each decision point's
  probe and counts; an unmeasured ambiguity feature is unknown, not zero.

One candidate bootstrap index is:

```text
H = (100 / 3) * (0.20 * B + 0.30 * P + 0.30 * R + 0.20 * A)
```

Candidate descriptive bands are `<25 easy`, `25-<50 medium`, `50-<75 hard`,
and `75-100 very_hard`. **These coefficients and cutoffs are design hypotheses,
not fitted results, release defaults or generation acceptance gates.** They
are separate from the approved 0.25-per-component overlap score.

Prototype the extractors and test this rubric on development items first.
If any required axis is unavailable, retain a partial feature profile with
`score=null` and an incomplete/unclassified status; do not silently replace
unknowns with zero or renormalize the available axes. A rigorously verified
count bound can support a band only when the whole bound lies in that band.
No level should be made harder by hiding required public anchors, adding
irrelevant source rows/checkpoints, inventing causation, or selecting a
needlessly complicated reference query.

#### Artifact and pipeline integration

Use a private, immutable **difficulty sidecar** bound to task, source/graph/
serving view, native validation, proof selection, canonical bundle and
measurement-profile fingerprints. Store feature definitions/version, actual
counts or bounds, provenance, availability states, axis scores, heuristic
version and a clearly provisional band. Gold edits or measurement-policy
changes require a fresh annotation; they do not silently reinterpret history.

Initially do not add a difficulty field to the frozen `TaskRecord` or rebind
the approved 47-question split. The sidecar avoids invalidating existing
native/canonical validation fingerprints. It is not part of the blind
student's prompt, and private proof features must not leak through public
metadata. For new pre-production candidates, measure after source/native/
canonical verification and before any difficulty-calibration evaluation.
Difficulty annotation does not remove valid easy questions or impose a hard-
question quota. Capacity/yield reports can later stratify by available
difficulty features while retaining unclassified counts explicitly.

#### Later Astra/Luna calibration experiment

This is separate testing, not started or authorized as a model run by this
design work. Before running it, freeze exact model deployments/versions,
reasoning settings, prompts, SQL-only tool interface, sanitized snapshot,
query/action/token/time budgets and replication schedule. Use fresh independent
student contexts with no gold or private checkpoint objectives. Record actual
usage and distinguish tool-budget-matched from cost/compute-matched comparisons.

Primary measurements are grounded final success; additionally report answer
correctness, checkpoint progress, citation/format errors, valid-attempt
failures and infrastructure errors. An API outage, skipped model or missing
result is not evidence that a question is hard. Retain all scheduled outcomes
and uncertainty; do not reroll completed students to obtain the desired model
ordering or discard valid questions just because a model solves them quickly.

Check whether success decreases across heuristic bands, inspect paired
model differences and confidence intervals, and inspect exceptions by task
family and source scope. Fit/revise weights only on designated development/
calibration items, then freeze the next heuristic before held-out evaluation.
Account for shared-source/incident correlation in uncertainty estimates; this
is statistical analysis, not a new forced grouping rule for dataset splits.
One trial from two models cannot identify a reliable item-level pass rate or
a two-parameter IRT model; a wider panel/repeated design can be considered
later if justified.

The next concrete work from this design is a tested feature/sidecar prototype
on the frozen development cohort, followed by integration into the bounded
pre-production runner. The design step itself produced no difficulty labels,
generation waves or Astra/Luna evaluations.

### 17.38 Implemented four-axis difficulty sidecar prototype

The user approved the four-axis heuristic and keeping model evaluation
outcomes separate. [difficulty.py](secgym/qagen/agentic/difficulty.py) now
implements `difficulty-heuristic-v0.1` without changing `TaskRecord`, native
validation, canonical-fact identities, blind prompts, rewards or split
assignments. The coefficients and bands in Section 17.37 remain provisional.

The prototype takes a fingerprint-bound reasoning plan and an explicit
semantic feature review. Each route selects one complete native-validated
evidence alternative for the final and every checkpoint. A dependency DAG
describes given anchors, discovered bindings, material cross-domain bindings
and necessary operation families. Code rejects missing/cyclic dependencies,
unused padding, missing claims, stale bindings and steps that do not cover
exactly their claim's chosen evidence. Genuine branch convergence requires
distinct binding branches, not a redundant dependency on an ancestor.

Code derives breadth, logical depth and unique operation-family counts from
the reviewed plan. Semantic necessity, domain labels and the completeness of
the chosen decision points remain review responsibilities; this is not a
fully automatic proof-minimality judge. No author-supplied easy/hard label,
model name or solver result is a scoring input.

Ambiguity is measured by read-only source queries. Candidate locators must
be attributed to actual accompanying source fields through the existing
verifier. Counts use distinct source observations or reviewed qualified
identity fields, not joined-row multiplicity or literal-ID projections.
The initial implementation requires complete exact candidate retrieval:
LIMIT/OFFSET/sampling, missing identities, empty scopes and query/result-limit
errors produce explicit measurement errors, not easy or hard labels.
Bound-only ambiguity probes remain a later extension.

An explicit reviewed empty probe list means no additional choice point was
required; a missing probe list means ambiguity is unknown. Any unavailable
required axis leaves the route unscored, and an incomplete reviewed
alternative is not silently ignored in favor of another route. Final,
checkpoint and combined-work profiles remain distinct; shared work is not
summed repeatedly across checkpoints. Saved axis values, scalar arithmetic,
bands and selected-route state are validated when loaded.

The new `difficulty-profile` CLI reuses the admitted-question input manifest.
Without plans it emits descriptive inventories only. With reviewed plans and
explicit serving/query-limit configuration it measures candidate scopes and
emits private per-task sidecars plus a summary/CSV. Output directories must
be new and outside source/annotation bundles. Errors remain explicit, and
requested incomplete measurements produce a nonzero CLI exit status.

The prototype was exercised against the frozen 47-question cohort. Two
manually source/program-reviewed controls now have complete provisional
profiles; the other 45 retain descriptive profiles with no score or band:

| Control | B | P | R | A | Provisional H | Band |
|---|---:|---:|---:|---:|---:|---|
| Incident 166 Q2, named mailbox-rule parameter | 1 | 1 | 1 | 0 | 26.666667 | medium |
| Incident 133 Q2, earliest net.exe extension ancestry | 2 | 3 | 2 | 1 | 70 | hard |

Source probes found one qualifying rule observation in the first case and
three distinct device/PID/creation-time process instances in the second.
The latter uses nine proof observations and five discovered bindings, despite
having only one raw evidence table; this demonstrates why table count alone
is insufficient. Its checkpoint profile is 50, while the combined task is 70.
These results do not validate the heuristic against model performance.

All 106 focused difficulty, split, CLI-contract and canonical-fact tests pass,
including all 256 ordinal-axis combinations and source-attribution/error
controls. Pylance reports no diagnostics in the new module, tests or changed
CLI. The exact approved development cohort and its approval/proposal artifact
hashes remain unchanged. No new QA attempts, model evaluations, training runs
or pre-production generation wave was started.

Next: build/review measurement plans for the remaining development questions,
then automate this feature-review stage for pre-production generation.
Unmeasured items remain visible as unclassified; no heuristic label is
invented merely to complete coverage.

### 17.39 Source-inspecting difficulty feature curation

[difficulty_curation.py](secgym/qagen/agentic/difficulty_curation.py) adds a
private curator and a separate feature-reviewer conversation for existing
native-admitted questions. Their contexts contain the public task, private
source programs/claim proofs and canonical source facts, but no student
outcomes, reward traces, heuristic axis scores or difficulty bands. The
curator proposes reasoning routes and ambiguity queries, not a numerical
rating. The server binds the proposal to the existing task/native/fact
fingerprints.

Both roles must actually retrieve every source record in the chosen proof
alternatives with source-attributed IDs and accompanying fields. Curator
finish validation checks route structure, claim coverage and executable
ambiguity probes; private witness/observation IDs cannot be used as oracle
selectors in those probes. Pre-review measurements report source counts and
errors, not heuristic scores. Only after an exact plan-bound feature review
passes does the deterministic scorer produce a provisional sidecar.

Feature holds, unmeasured axes, operational errors and suspected task/rubric
defects are separate outcomes. A task defect cannot pass as an annotation-only
correction. Fresh feature revisions preserve the old artifacts and expose
previous feedback only to the new curator, not the independent reviewer.
Resume verifies the same inputs/runtime and restores source inspections from
captured SQL results. Completed roles are reused without new model calls;
an interrupted reviewer does not regenerate its completed curator.

Controlled source/role tests cover independent inspection, private-ID
rejection, missing measurements, immutable revisions, runtime binding and
reviewer-only recovery. The first real automation run is deliberately limited
to three structurally different development tasks before expanding to the
remaining queue. These are feature-curation model calls under the existing
approved configuration, not Astra/Luna ability evaluations or new QA attempts.

### 17.40 Pilot method checks and complete-set witness repairs

The three-case feature-curation pilot completed with two provisional reviewer
passes and one suspected task/proof defect. Operator inspection deliberately
preceded the remaining queue rather than treating those first passes as final
calibration truth.

The two initial ambiguity plans included probes that removed already-resolved
path/account/request/IP bindings to manufacture competitors, or counted
repeated request representations. Their original reviews and scores are
preserved, but separate audit-hold records request feature-only revisions.
`difficulty-feature-curation-v0.2` clarifies that known entity bindings and the
outer public scope remain fixed; deterministic exact-key lookup is not
ambiguous merely because its table is large. Genuine final ranking, temporal
or eligibility criteria can still distinguish plausible candidates. Correct
set members are not automatically distractors, and candidate identity must
match the decision unit. This changes neither the four-axis coefficients nor
the rule separating model outcomes from heuristic inputs.

The v0.2 model context also carries compact canonical property references
rather than repeating every fact's values/timestamps/snapshot metadata.
Actual source retrieval remains mandatory. The earlier pilot's runtime,
requests, source observations and independent pass reviews are archived; new
operator feedback is sent only to the fresh curator, not its reviewer.

The third case exposed a genuine collection-proof problem: incident-5 Q1,
incident-5 Q5 and tenant Q6 have witness alternatives representing individual
hosts/members even though the claim expects a complete set. A targeted
read-only fixture audit checked all 17 multi-valued development claims and
30 alternatives; the 18 failing alternatives belong to those three tasks.
The full declared-evidence fixture reproduces each gold set, but a single
claimed alternative loses answer members.

The first diagnostic that added all private scope anchors to each proof
masked the issue because these tasks listed most/all evidence as anchors.
Private anchor references are not source records automatically shown to the
student and do not augment the scoring rule's cited proof group. The corrected
diagnostic tests each alternative alone. It is a regression check for lost
answer members, not a universal sufficiency proof for scalar, negative or
aggregate claims.

The first fresh question/rubric/witness revisions completed source review for
the three tasks. Incident-5 Q5 r5 and tenant Q6 r3 subsequently passed fresh
native admission. Incident-5 Q1 r4 remained held at the captured-witness gate;
its later source-qualified repair is recorded below.
The final and checkpoint objectives must remain meaningful and their entire
answers must be supported by each alternative; no checkpoint removal,
annotation-only waiver or old-proof transfer is permitted. Source/native/
canonical/difficulty checks and an updated split review are required before
promoting changed fingerprints. The original approved development split and
all prior outcomes remain immutable history, with current quality holds
recorded separately.

The corrected v0.2 feature revisions passed independent source review:
incident-34 Q4 is B2/P3/R2/A0 (63.333333, hard), and incident-166 Q4 is
B3/P2/R3/A0 (70, hard). The original inflated profiles remain historical
audit-held results. Together with the two unchanged manual controls, this
provides four measured profiles under the prior pinned runtime; 40 unaffected
tasks remain queued, and the three question repairs need fresh bound feature
annotations. The verifier change below requires explicit runtime revalidation
before reusing those profiles in a current export.

Incident-5 Q1 r4 exposed a separate representative-selection limitation.
Its complete final witness chooses four qualifying rename observations by
`MIN(_record_id)`. The completed blind student instead retrieved and cited
four other qualifying observations, choosing earliest timestamps. All four
gold-selected locators really are absent from the captured trace; this is not
a SQL lineage-recognition failure.

A read-only source fixture restricted to the student's 11 submitted citations
reproduces the unchanged complete two-host final answer. Four negative
controls each omit one required rename-category observation; every omission
loses one host and fails full-answer equality. Thus this captured alternative
supports the complete positive set claim, rather than merely matching its
answer strings. The diagnostic does not establish a general sufficiency rule
for ranking, absence, aggregation or common-value claims.

The original enumerated-witness contract does not recognize that alternative.
No historical outcome has been regraded, no checkpoint or proof gate has
been waived, and no completed student has been resampled. A grading-contract
decision was presented explicitly. The user selected source-qualified complete
proof obligations rather than adding only this particular alternative to the
enumerated list. That authorizes a versioned verifier change and explicit
revalidation, not automatic admission, historical regrading or weaker proof.

No new pre-production logical candidate attempts or Astra/Luna ability
evaluations have run. A transient Azure CLI/WSL authentication failure on the
feature-revision launch was checked without exposing a token; authentication
recovered and the unchanged interrupted request was resumed.

### 17.41 Source-qualified witness contract

The opt-in `source-qualified-obligations-v1` contract adds full-source required
obligation catalogs and source-qualified candidate bundles to each backend's
witness program. The original three-column query remains a complete
representative for canonical facts, overlap and difficulty annotations.
Existing enumerated programs retain their serialization and task identity.
The runtime verifier is versioned `source-witness-v1.3`; generation is
`discovery-pilot-v1.5`.

Every complete alternative group requires every cataloged obligation. Each
obligation may have multiple interchangeable candidate bundles, but every
record within the chosen bundle is mandatory. Source-record binding keys
must agree across chosen bundles, preventing cross-instance/role splicing.
Candidate queries receive an explicit, server-built citation relation and
must qualify those locators against actual public source tables. Required
catalogs cannot use that relation. No automatic MIN rewrite, implicit private
anchor support or citation-filtered answer-query fallback is introduced.

Submitted evidence must remain relevant and contain a coherent complete
proof, including behavior/security-control support where required.
Separately measured captured-observation coverage may include exploratory
rows but must still contain a complete source-qualified proof. Existing
attributed-retrieval checks remain in the adapters. Query limits and bounded
coherence-search exhaustion are explicit errors.

Source/refuter review must establish semantic completeness, including all
set members and comparison cohorts for counts, ranking, absence and common
values. Passing representative examples alone does not certify these
predicates. Backend parity includes the obligation/candidate/binding data for
declared proofs, with additional alternative and incomplete-proof probes.
Changed task fingerprints require fresh admission and downstream annotation
bindings. The archived prior runtime, historical student outcomes and split
approval are retained; none is automatically upgraded by this implementation.

The complete feature suite passes 381 tests with actual isolated MySQL and
native ACE enabled, including alternative-proof final/checkpoint credit,
incomplete-cohort rejection and captured-source attribution. All 69 historical
task fingerprints and all 109 pinned legacy files remain unchanged.

Incident-5 Q1 now has an explicit r5 source-qualified revision, not an edit to
r4 or its recorded outcome. Full-source checks accept both the completed
student's alternative and an independently selected latest-event alternative.
Omitting each of the 11 submitted proof records in turn fails; the full
four-host checkpoint remains supported by the captured observations.
That r5 retained the typed goals, answer SQL and public task content except
for the revision identifier. Its independent reviewer accepted the complete
source-qualified proof semantics but requested clearer wording and literal
justifications. The public phrase "previously unsuffixed filename" was
ambiguous because the earlier names can have another extension. Private
bookkeeping labels also should not be described as general domain constants.

The explicit r6 changes that phrase to "previous filename not ending in
.lockbit" and uses source/public/table-derived binding roles and standard
Boolean category tags instead of the misclassified bookkeeping strings.
Its source goals and answer SQL remain unchanged. Because public wording
changed, a fresh blind run and fresh independent review were performed; both
passed, including mandatory source-field inspection of the complete final
and checkpoint proof. Earlier outcomes and the r5 revise verdict are retained.

All three current repairs passed real full-snapshot MySQL parity and native
SecRL/ACE private-pilot admission. The incident-5 Q5 and tenant Q6 native
students produced grounded final answers; checkpoint progress was respectively
0 and 1. The incident-5 Q1 r6 native student answered correctly and retrieved
a complete proof, but submitted an invalid file locator, leaving one required
host/category unsupported in its cited proof. Both adapters retain final
reward 0 and checkpoint progress 0 for that run; it is not rerun to improve
the score or treated as evidence of heuristic difficulty.

Fresh graph baselines now bind all three changed fingerprints. New canonical
and difficulty annotations and an updated split review are still required.
The 44 unaffected development annotations are undergoing explicit runtime
revalidation: exact source-fact/footprint equality and both original
source-inspection traces, following hash-checked earlier revalidation
provenance rather than inventing new reviews or silently changing producer
hashes. The three held historical task revisions are excluded from that reuse.

The r6 incident-5 Q1 canonical annotation passed fresh independent review.
The first annotations for incident-5 Q5 and tenant Q6 were held for missing
process `ActionType` properties, not invalid QA: the executable gold already
requires the process-creation events. Fresh annotation-only revisions are
adding those event-bound properties with independent re-review. Difficulty
curation has restarted for the repaired questions using their new exact
native, baseline, canonical and review bindings; native student outcomes
are excluded.

Runtime revalidation subsequently completed for all 44 unchanged development
questions, including both recorded source-inspection roles and exact
source-fact/footprint equality. Re-executing the four retained difficulty
controls' source measurements preserves their bindings, scores and bands
without new model calls. The approved 40-question feature-curation batch is
now running against those explicitly revalidated inputs.

The repaired incident-5 Q1 feature plan required a source-backed correction:
selecting the subsequent rename categories is a discovered behavioral binding,
not an already-given representation lookup. Its fresh independent review
passed B3/P2/R3/A2 (83.333333, very_hard). Incident-5 Q5 passed B3/P2/R2/A2
(73.333333, hard). Their ambiguity populations are respectively four and five
source-scoped candidate hosts before the relevant eligibility test, not
repeated qualifying file observations or the distinct final-answer paths.
These remain provisional heuristic labels, not model-validated difficulty.

The Q5 canonical revision passed. Tenant Q6's interrupted curator was resumed
from its unchanged request after verified token truncation, retaining all
original traces; its fresh reviewer did not receive the curator's prior
revision feedback. That review found another annotation-only gap: necessary
earlier-process cohort/parent facts were selected for the checkpoint but not
the final claim itself. A further fact-selection revision is addressing that
claim-specific coverage without changing QA, native scores or checkpoints.
That revision subsequently passed independent review. Tenant Q6's fresh
difficulty review also passed B3/P2/R3/A0 (70, hard): its complete 16-record
cohort proof is retained, and deterministic bound lookups plus aggregation
are not turned into manufactured ambiguity.

### 17.42 Repaired development cohort and split verification

The current 47-question cohort now combines 44 explicitly runtime-revalidated
questions with the three source/native/canonical/difficulty-reviewed repairs.
Only incident-5 Q1 (r3 to r6), incident-5 Q5 (r4 to r5) and tenant Q6 (r2 to r3)
change task fingerprints. Their final typed goals and checkpoint IDs remain
unchanged. The new native/canonical cohort fingerprint is
`74d6a0e91fda15aaabe3a8a44e8542ff6e69669d15440112826a0b9d6aabd906`.

Two explicitly unapproved split updates were generated: preserving the old
logical-question membership with method `explicit`, and recomputing the
original bucket counts with seed 42 and `sha256-ranked-v1`. Both yield the
same 36-train/11-test logical membership, including the same 11 held-out
questions. This is verified against the new fingerprints, not an assumption
that the historical approval automatically transfers.

Both proposed audits contain all 1,081 complete pair comparisons with the
unchanged diagnostic quarter weights. Edge and observation components are
unchanged for every pair; canonical-fact/containment components and aggregate
scores change for only two within-training pairs. All 396 train/test pair
components and scores are exactly unchanged. No overlap-based grouping,
rejection or production threshold is introduced.

The 40-question difficulty batch remains active. Completed annotation-only
holds are revised with fresh independent reviews; initial examples concern
a checkpoint-specific temporal operation, unnecessary ranking of a singleton
eligible cohort, and a representation lookup incorrectly marked as a newly
discovered identity. These are not new QA failures or reasons to resample
students. Final quality review and explicit updated split approval remain
separate gates before promoting the revised development snapshot.

### 17.43 Authentication-step selector regression

Further inspection of a held incident-322 Q3 difficulty plan found a genuine
gold/checkpoint defect rather than only a feature-annotation issue. Its
answer and witness programs use `AuthenticationDetails[0]` for role-defined
OATH/MFA selections. The public question names authentication roles, not an
array position. A targeted screen of the current 47 gold/witness contracts
identified this task's eight affected backend programs.

A read-only, isolated fixture reproduces the defect while preserving the
named semantic targets: prepending an unrelated Password/Primary-authentication
step to the interrupted record makes both final and checkpoint outputs
disappear; prepending it to the result-0 record changes the final answer to
the password-step detail instead of the still-present MFA-step detail.
The source databases, historical model outcomes and original review are
unchanged. This is separate from the legitimate fixed leaf paths used to
annotate properties of an immutable source record.

An explicit operator quality hold now blocks promotion of the otherwise
assembled 47-question proposal. The feature review is not rewritten to
pretend that it detected the task defect. A fresh question/rubric/program
repair is using typed OATH/MFA and mail-message roles, public temporal scope,
and the complete interrupted-IP checkpoint. It must pass independent source
review, actual DuckDB/MySQL reorder/prepend/removal regressions, native
admission and fresh downstream bindings. Unaffected difficulty curation
continues; no feature-only waiver or success resampling is permitted.

The first attempted authentication repair was not promoted: it unnecessarily
changed the earliest-observation scalar question into an all-later-observations
set and added a discovered method as a selector. A later source revision
restored the original objective but retained an unjustified Password exclusion
and bookkeeping literal; those were removed surgically. Neutral public
background wording also replaced an unsupported limitation about quarantine,
after a reviewer found a matching post-delivery quarantine record. That
background correction did not add an irrelevant checkpoint.

The resulting r7 preserves the original scalar goal and meaningful source-IP
checkpoint, selects typed authentication/mail roles, and uses the first later
same-account/IP sign-in. Its unchanged private programs passed 172 actual
DuckDB/MySQL mutation checks, including reordered/unrelated steps and
entities, missing-role negatives, additional matching-MFA ambiguity, and a
later-event/citation-omission test preventing a later cited success from
replacing the uncited earliest one. Fresh source review and full-snapshot
native admission passed. The native grounded-final reward is 1 and checkpoint
progress is 0; both are retained as measured. New canonical annotation and
difficulty review have also passed. The provisional difficulty is B2/P2/R3/A0
(63.333333, hard): each fixed-scope stage has one qualifying request, repeated
interruption observations are deduplicated, and the reference SQL's ranking
of a singleton is not counted as additional reasoning. Historical reviews,
outcomes and split approval remain unchanged.

### 17.44 Endpoint-proof regressions and difficulty batch follow-up

The full 40-question initial difficulty pass completed: 21 independently
reviewed feature plans, 17 feature-review holds, one API timeout and one
unmeasured ambiguity population. Completed feature-only holds are receiving
fresh revisions with feedback isolated from their reviewers; completed
students are not rerun. The API-interrupted curator is being resumed under
the exact original batch policy, with its first summary retained separately.

Direct source checks of two holds found actual task/proof issues:

- Incident-38 Q1's final and socket-checkpoint SQL required the connection
  timestamp to equal an alert's start, although the public alert only locates
  the endpoint. Shifting that detector timestamp by one microsecond in an
  isolated fixture removed both outputs; removing the incidental equality
  preserved both outputs before and after the shift.
- Incident-322 Q5 required both same-path deletion records in its one complete
  witness group. Either six-record whole-chain proof independently reproduces
  the requested hash/existence answer, yet the seven-record group rejected
  both legitimate alternatives. This is redundant proof, not justification
  to remove a checkpoint or ignore an entire claim.

Explicit private revisions preserve public content, typed final/checkpoint
goals and rewards. The HTTP task now has four complete alert/endpoint-chain
alternatives; the file task has two complete final alternatives, one for each
qualifying deletion. Source-qualified candidates keep each joined chain
indivisible. Both independently passed source review and 354 actual
DuckDB/MySQL mutation/omission checks, including wrong sockets/processes,
either deletion alone, neither deletion, wrong deletion paths and missing
anchors. Both subsequently passed full-snapshot native admission. The HTTP
student's grounded-final reward is 1; the deletion student's answer is correct
and its trajectory contains a complete proof, but its five submitted records
omit a required process record from the six-record chain, so its reward
remains 0. Both checkpoint scores remain 0. These measured outcomes are
retained, not used as difficulty features or resampled. Fresh graph baselines
are complete and canonical review is in progress. The operator findings
remain separate from the original feature-review verdicts and block promotion
until all new downstream bindings are complete.

The deletion task's canonical annotation passed; fresh difficulty curation is
running on its complete alternative proof. The HTTP annotation's independent
review requested the source-observed initiating PID zero that establishes its
socket-only attribution limitation. That annotation-only correction passed
fresh review without changing the repaired question, checkpoint, or native
score; fresh HTTP difficulty curation is running.

Tenant Q10's independent feature reviewer verified 1,599 distinct eligible
sign-in requests under the fixed editor, policy and post-edit same-day scope.
Its ambiguity remains unmeasured because the implemented exact-retrieval
probe is bounded to 500 result rows. That operational limit is not an easy
label, an excuse to sample, or permission to hand-fill a score from model
prose. An explicit source-verified large-population measurement path is
pending; runtime-pinned workers must finish before changing that implementation.

The latest native/canonical assembly remains 47 logical questions and now
contains six repaired task revisions relative to the original approved
snapshot. Its cohort fingerprint is
`2fc564f9cc0777953847d32f953247c4f42a31c3a06c72ba59beaa5aa1920b26`.
All 1,081 pair components are complete. Unlike the earlier three-repair
proposal, recomputing seed 42 on these additional fingerprints swaps
incident-38 Q1 from test to train and Q2 from train to test. The separate
explicit-membership proposal retains the historical held-out logical
questions and the 36/11 counts. Neither proposal has been approved; after
the remaining difficulty/quality checks, the user must choose the updated
split binding rather than having the old approval silently transferred.

### 17.45 Complete positional-selector screen and exhaustive measurement

The final feature-scope audit found that the deletion question's valid
existential-proof repair still inherited positional alert-entity selectors.
Rather than continuing one-off discovery, all 47 current questions were
screened across answer, witness, obligation and candidate programs for
numeric JSON paths. Five tasks remained: incident-134 Q1, incident-322 Q5,
incident-34 Q5, tenant Q2 and tenant Q10.

Nine read-only source-preserving mutations confirmed defects in all five.
They retain named roles and values while prepending/reordering unrelated
entities, parameters, targets or modified properties, or changing only JSON
whitespace. The coupled tenant-Q2 successor-boundary predicate compares
serialized rule parameters instead of their complete named configuration;
tenant Q10 also parses a policy result using JSON key adjacency/string
offsets. Those defects are not repaired by assigning a difficulty label.
Exact numeric source tokens are preserved in the fixture mutations, and no
source database or historical result is changed.

A five-case source-revision batch now enforces the original typed final and
checkpoint goals and reward policy, while requiring typed/named traversal,
serialization-independent configuration comparison, coherent complete proofs,
actual backend mutations and fresh downstream validation. It does not create
new logical QA attempts. The current 47-question proposal remains unapproved
and held until these repairs complete. In particular, tenant Q10's old
unmeasured feature plan cannot be promoted merely by fixing its population
measurement capability.

Separately, opt-in `exhaustive-record-ranges-v1` measurement has been added
without changing the four-axis formula or legacy probe shapes. It keeps the
entire original candidate query inside server-generated disjoint locator
ranges, checks an exact whole-scope census, preserves every query limit, and
verifies every returned record before counting distinct observation or
qualified identities. A typed private audit proves contiguous coverage and
matching row totals. Incomplete retrieval, invalid locators, oversized
indivisible blocks, query errors and explicit resource-budget exhaustion
remain errors with no count or difficulty score.

Curation v0.3 also clarifies that defining public roles/types remain fixed:
different executable names are not candidates for a named child, and
unrelated event types are not competing requests. Earlier pass reviews and
operator feature holds remain distinct artifacts. Paged measurements keep
the full attributed citation inventory privately while giving the reviewer
its count/digest and complete partition audit, not a numerical difficulty
target or student outcome.

The focused validation passes 51 tests, including exact retrieval of 1,599
synthetic source records, cross-page qualified-identity deduplication,
unchanged row/byte bounds, malformed/missing/forged locator rejection,
preserved window/UNION scope, fail-closed census/resource checks, compact
review context and actual MySQL execution with native adapter regressions.
The full feature suite passes 393 tests with actual MySQL and native ACE
enabled. An independent real-snapshot typed-policy check verified exactly
1,599 qualified requests and 1,599 attributed source observations across
eight exhaustive partitions, without changing the 500-row, 64-KiB or
30-second per-query limits. It used no model calls and does not waive the
tenant-Q10 QA hold or assign a score to that held task.

The consistency sweep also inspected the currently reviewed feature plans,
separately from QA correctness. Six older passes were operator-held for
counting alternatives outside explicitly supplied roles/properties (such as
Network logons for a RemoteInteractive question, OfficeHome for Exchange
Online, or other registry-value names for Start/DeleteFlag). Their original
reviews and scores are retained; fresh source-based revisions receive no
desired score. Genuine selection of an initially unknown target among
same-role candidates remains valid, rather than treating every source
eligibility decision as a deterministic identity lookup.

All seven follow-up feature revisions (those six scope holds plus the
recovered URL-click task's anchor-operation correction) passed independent
review under v0.3. Re-executing the retained source probes produced 42 complete
provisional profiles for the explicitly non-held questions, with exact
task/native/canonical/plan/review bindings and zero new model calls.
The other five remain explicitly excluded pending QA repair; there is no
silent replacement of their missing profiles with easy or zero scores.

The typed-selector source batch preserved every original typed goal and
checkpoint. The two tenant revisions reached source admission, but actual
MySQL preflight exposed a merged-CTE `JSON_TABLE` argument error and an
over-budget policy-array expansion. Both failed before student evaluation.
Local source-key-preserving materialization rewrites have been prepared and
remain pending actual backend equivalence/robustness checks; no global
optimizer switch, changed source scope or raised time limit is permitted.
The mailbox-context correction and deletion-entity revision passed fresh
source review, while the Word/launcher case remains on captured-proof hold
pending investigation of an alternative direct parent-identity proof.

### 17.46 Typed-selector repair validation

The five remaining selector repairs now pass source and actual full-snapshot
MySQL/native validation. The two tenant backend failures were corrected by
local, source-key-preserving materialization and an explicit grouped-count
alias in `HAVING`, not by changing the question, source scope, query limits or
global optimizer settings. Their original independent source reviews and
captured blind results were retained only through explicit equivalence
certificates; no fresh model verdict was fabricated.

The mailbox, deletion and two tenant revisions passed 256 actual
DuckDB/MySQL mutation checks. These cover array/object order, JSON whitespace,
typed/named-role negatives, complete named-rule configuration equality,
next-identical-rule boundaries and earliest matching-policy selection.
Two fixture issues were corrected without changing QA: a synthetic earlier
rule initially introduced another seed within the public seed day, and
backend-specific timestamp strings were incorrectly compared as witness
labels instead of comparing complete citation groups. The earlier harnesses
and failed logs remain available.

The Word/launcher source student had not fetched the separate parent creation
record, but its captured Word creation and two network observations formed a
valid direct-parent proof. A five-record source-only fixture reproduced the
complete answer and rejected all five single-record omissions. A new private
revision adds that complete alternative alongside the six-record corroborating
route, retains the exact launcher-path checkpoint, and preserves public
content and rewards. Fresh independent review and native validation passed,
as did 108 actual backend role/identity/endpoint mutation checks. The captured
source student was not resampled to fetch the originally selected parent row.

All five repairs have fresh graph baselines. Both typed-incident canonical
and difficulty reviews passed (incident-134 Q1: 36.666667, medium;
incident-322 Q5: 63.333333, hard). Both tenant canonical reviews passed and
their difficulty curation is running. The Word canonical review is running.
Native rewards and checkpoint outcomes remain separate recorded measurements,
not heuristic inputs. Final current-cohort assembly and updated split
approval still await completion of these downstream bindings.

The Word canonical review subsequently passed, followed by its independent
difficulty review: B2/P3/R2/A1 (70, hard). Its final shared-endpoint comparison
retains both qualified process identities and chronology; the three candidate
Word connection observations are not three different parent processes.
Tenant Q2's feature review requests only removal of a nontrivial ranking
operation for its sole later identical rule, without changing the gold's
next-event semantics. Tenant Q10's feature measurement/review remains active.

The latest complete 47-question native/canonical assembly is
`development-repaired-cohort03`, fingerprint
`840efd8d3065780b3a50282c825e976e38cdc66c99af5f58e8e134028f3ddadc`.
Its 412 answer/witness/obligation/candidate SQL surfaces across both backends
contain no constant numeric JSON-path selectors. This screen does not prohibit
dynamic ordinal traversal or immutable canonical property references, and is
not a universal semantic-correctness certificate. The five historical source
holds are resolved only by their explicit new validated fingerprints.
All 1,081 pair comparisons are complete; the unapproved seed-42 proposal still
swaps only incident-38 Q1/Q2 compared with the historical held-out membership.

### 17.47 Complete current development difficulty coverage

All 47 current questions now have exact-bound, independently reviewed
provisional difficulty profiles: 41 incident-scoped and six tenant-scoped
questions, with one meaningful checkpoint each. The distribution is
10 medium, 31 hard and six very_hard; no easy quota or rejection gate was
imposed. Tenant Q2's corrected plan is 63.333333 (hard). Tenant Q10 is
B1/P2/R3/A3, 76.666667 (very_hard), with 1,599 distinct eligible requests
verified across eight exhaustive partitions and independently checked by
its reviewer. Model outcomes are not inputs, and empirical model calibration
has not been performed.

The consolidated private inventory at `difficulty-current47-v03-01` preserves
all original producer/review artifacts and verifies current task, native,
canonical, plan, review, source-measurement and implementation bindings.
Its construction made no new model calls and did not rerun completed
students. A direct review of the ten changed logical questions confirms
the original investigative targets, final/checkpoint typed goals and answer
windows are retained; context and implementation corrections are explicit.

The current 47-question cohort is ready for an explicit updated development
snapshot/split decision, not production release. Both proposals retain
36 train and 11 test. The recommended explicit-membership proposal preserves
the original held-out logical questions; recomputing seed 42 swaps only
incident-38 Q1 and Q2. Both contain all 1,081 complete overlap comparisons and
396 train/test comparisons. With the unchanged diagnostic quarter weights,
the same-incident cross-split mean is 0.1419883764852382 for preserved
membership and 0.14412111114539375 for recomputed membership; both maxima
are 0.4223024316109422. Other cross-scope train/test overlap remains zero.
No historical approval is transferred automatically.

The user subsequently approved the repaired 47-question development snapshot
with the **original logical 36-train/11-test membership preserved**. Its new
plan is explicitly `method="explicit"`; seed 42 is retained as historical
selection provenance, not claimed as the ranking rule for the new
fingerprints. The separately recorded approval binds the exact cohort,
plan, overlap audit, difficulty inventory and source-review artifacts.
The historical proposal/approval and all native outcomes remain unchanged.
This approval does not authorize production release, training or an
Astra/Luna ability panel, and does not change the separately approved
1,000-new-question target or initial 2,000-attempt envelope.

### 17.48 Observed-pool capacity reporting

The next I5b readiness component is implemented as
`observed-overlap-capacity-v1`. It uses the approved diagnostic quarter
weights and thresholds 0.25/0.50/0.75/0.90 to report compatible subsets and
capacity bounds independently within each represented incident/tenant pool.
Threshold equality is allowed. No question is rejected, deleted or grouped,
and no train/test assignment changes.

A deterministic bounded search uses feasible compatible subsets for lower
bounds and graph-coloring bounds for upper bounds. It labels an observed-pool
maximum exact only when the bounds coincide. An explicit search-state budget
is part of every request; reaching it retains the bounds and their gap rather
than claiming an optimum. Missing pair components make the relevant bucket
unscorable. Pair measurements are streamed, and no model calls are needed.

On the approved 47-question development pool, all 44 scope/threshold points
were solved exactly and independently checked by exhaustive subset enumeration.
All 81 within-scope aggregate scores and 324 component values match the
approved overlap audit, and every example subset satisfies its threshold.
The sums of independent scope capacities are 36, 44, 47 and 47 at the four
thresholds, respectively. These are diagnostic retained-subset counts within
this small observed pool, not new split sizes, pre-production acceptance
quotas, saturation evidence or absolute source-capacity estimates.

The approved 36/11 development split is unchanged. The separate target
remains 1,000 new pre-production questions within the initial 2,000 logical
attempt envelope. Automated quality safeguards and resumable larger-scale
orchestration remain prerequisites before starting that generation wave.

Capacity validation includes exhaustive comparison against all 1,024
five-vertex graphs, a genuinely budget-limited case, 1,000-question trivial
graph controls, exact threshold-boundary tests, missing-component handling
and CLI/schema checks. The complete feature suite now passes 405 tests with
actual MySQL and native ACE enabled. The approved snapshot/plan hashes and
all 109 pinned legacy files remain unchanged.

### 17.49 Pre-blind source quality safeguards

The next I5b foundation is the opt-in `source-quality-v1` gate in
[quality.py](secgym/qagen/agentic/quality.py). It screens all final/checkpoint
answer, representative witness, unconditional obligation and citation-conditioned
candidate SQL in both dialects. Positional JSON selectors, computed paths and
potentially serialization-dependent comparisons require explicit independent
semantic review. A real public ordering or exact-representation objective can
justify a selector; the gate does not blanket-ban array positions or quietly
rewrite a question to excuse an incidental role index.

For multi-member sets/lists, isolated read-only DuckDB views execute each
representative alternative alone under the existing query limits. Uncited
tables are empty, and private scope anchors are not automatically added.
A union-of-declared-evidence control is retained as a diagnostic, never used
to augment an incomplete individual proof. Non-reproduction holds the candidate
before any blind solve; operational errors remain explicit errors. These checks
do not establish general sufficiency for counts, absence, ranking/common-value
cohorts or every qualifying candidate bundle. Independent semantic review and
targeted backend mutations remain necessary.

The opt-in source pilot requires an independent quality/refutation conversation
to retrieve all required representative records with source fields, disposition
every selector finding and review whole-claim support. Genuine ordered or
representation-sensitive exceptions require an exact public quote and source
justification. Its ordinary refutation result is projected verbatim for native
validation; no new model verdict is fabricated. A failed literal-justification
review also prevents the blind solve. Inspection traces, audit/assessment
fingerprints, runtime hashes and query policy are bound and validated.

Completed roles are recovered rather than rerolled. Interrupted inspection
recovery reuses the existing exact captured-source verification helper, without
editing the runtime-pinned canonical/difficulty implementations. Set-result
ordering is normalized only in diagnostic serialization; ordered lists and
grading are unchanged. Existing non-opt-in source/native callers retain their
behavior. Pre-production callers must opt in on source generation and require
the bound gate on native admission.

Validation covered all 412 SQL surfaces in the frozen 47-question cohort and
17 multi-member claims: all 17 individual representative proofs and 17
union controls reproduced their complete collections. The scanner found no
numeric JSON positions. It retained 40 conservative text-matching flags across
four questions and 11 computed-path flags on the tenant rule question.
These are review findings, not five automatic QA defects or rejections;
the diagnostic does not replace independent semantic or backend mutation review.
Against the three retained historical incomplete-proof revisions, the new
checker reproduced all 18 failing alternatives while their union controls
still passed. No source model calls or student resampling were used.

The full 422-test feature run passed with actual MySQL/native ACE enabled.
A final missing-artifact/no-legacy-downgrade guard then passed the 34 focused
quality, generation and real-MySQL/native tests. Coverage includes unobserved
or ID-only reviewer evidence, immutable completed-role recovery, preserved
failed students, public/private context separation, source-bundle mismatch,
tampered policies/traces, legitimate public ordering and all query surfaces.
All 109 legacy files and the approved cohort/input/split hashes are unchanged.
The existing canonical loader still accepts all 47 exact current bindings.
The diagnostic audits retain their original producer hashes; a subsequent
input-binding-only tightening was checked by AST equivalence of the remaining
measurement code and exact source identity, not by rewriting those hashes.

The standalone `audit-source-quality` CLI is a no-model diagnostic and grants
no admission, split or release approval. The approved 47-task snapshot and
36/11 split remain frozen. No pre-production question has been generated by
this work. Per-scope attempt/revision accounting, complete resumable
source/native/canonical/difficulty orchestration and broader backend robustness
automation remain pending before starting the approved 1,000-new-question
target within its initial 2,000-logical-attempt envelope.

### 17.50 Backend robustness and frozen-selector triage

`isolated-source-robustness-v1` adds reusable, exact-task-bound finite
counterfactual plans. It copies verified source records into disposable
DuckDB/MySQL fixtures, checks baseline representativeness before interventions,
and measures typed answers, complete witness alternatives and available-citation
proof support. The probe inventory includes all records, none and every
single-record omission. Source-qualified catalogs, candidate bundles and shared
bindings execute on both backends. Bookkeeping witness labels are not treated
as semantic identities. Explicit edits cannot alter opaque record locators,
and missing/no-op JSON interventions are not reported as successful tests.
Original source databases and recorded student outcomes remain unchanged.

The five retained selector flags were investigated with 80 actual backend
claim checks and 16 full-source comparisons against equivalent typed JSON
membership predicates. All serving-contract controls passed. The tenant rule
question's computed JSON paths implement complete named-parameter traversal;
formatting, array reversal and a common unrelated parameter preserve its
answers/proofs. Four alert questions depend on the core producer's compact,
sorted JSON representation. Exact producer round trips and full-source typed
equivalence confirm their current frozen-snapshot behavior. Direct post-serving
reformatting produces 16 retained portability mismatches; these are not
silently waived or relabeled as invariant.

This distinction allows evaluation of the existing approved fixed snapshot
without changing task fingerprints, the split or historical model outcomes.
It is not retrospective admission under the new source-quality gate or a
general portability claim. New generation continues to prefer typed,
serialization-independent selectors. Fixture sufficiency, complete
count/absence/ranking cohorts and semantic expectations remain review obligations,
not facts established by a finite test matrix.

### 17.51 Approved external difficulty-validation panel

The user explicitly approved 141 new evaluation episodes: all 47 development
questions once each on `gpt-6-luna`, `gpt-6-sol` and `gpt-6-astra` using the
existing approved Azure endpoint. A second explicit approval fixed medium
reasoning effort, 64 model responses and 64,000 total output tokens per episode,
16,000 output tokens per response, a 300-second request timeout, and the
500-row/64-KiB/30-second SQL limits. Model availability or unsupported settings
are operational issues, not reasons to substitute a different profile.

The panel pins the cohort/approval/native/canonical/difficulty artifacts,
serving snapshot/index reports, runtime/library versions, public prompts and
budget configuration. Model order rotates deterministically between questions;
each episode starts with an isolated public-only context. No difficulty,
private gold or checkpoint labels are supplied. Original Sol students remain
historical; these separately recorded comparison episodes are not retries
chosen to improve scores.

Grading uses the new opt-in captured-result replay profile. Successful captured
SQL fields must verify against actual sources; failed or unexecuted queries
cannot earn evidence from a later reexecution. SecRL and native ACE must agree
on the same captured trajectory. Completed failures are retained, interrupted
grading can resume without new inference, and ambiguous model-completion
boundaries do not trigger automatic resampling. Budget exhaustion, abstention,
invalid completion and operational errors remain distinct.

Grounded final success is the primary outcome, with answer correctness,
citation grounding, checkpoint progress and resources reported separately.
Analysis includes per-model success versus continuous heuristic score and bands,
paired question-level contrasts, descriptive intervals and scope-cluster
bootstrap uncertainty. Operationally ungraded and pending episodes remain
unknown, with explicit denominator/bounds reporting.

The score and band boundaries remain fixed hypotheses. This cohort contains
10 medium, 31 hard, six very-hard and no easy questions, so a panel cannot
validate every boundary or support strong claims from tiny bands. Results are
exploratory deployed-model comparisons, not causal parameter-count evidence,
training authorization, release approval or permission to tune on held-out
outcomes. Any subsequent tuning requires independent pre-production validation.
The first three live episodes verified all deployments and the native harness;
the completed comparison is reported in Section 17.53.

Implementation validation passed 453 feature tests with actual MySQL/native ACE;
the six focused statistical-analysis tests also pass. Pre-production
1,000-new-question generation and full attempt/revision orchestration remain
separate pending work.

### 17.52 Explicit private-grader timeout amendment

The original panel recorded 63 completed outcomes and a further completed
student whose private grading repeatedly exceeded 30 seconds. A no-model
diagnostic measured the affected answer query at 22.16 seconds cold and
5.25 seconds warm; its checkpoint query took about 0.008 seconds, but a
representative witness query still timed out. These are private evaluator
execution failures, not incorrect student outcomes.

The user explicitly selected `grader_only_120s`. Private grading now uses a
separate verifier/connection with a 120-second query ceiling. Student SQL
remains at 30 seconds, with unchanged models, medium reasoning, token/response
budgets, result limits, prompts, questions and difficulty annotations.
Captured failed student queries remain failed observations; they are not rerun
under the larger grading allowance.

The original manifest, evaluator source archive, 63 outcomes and completed
ungraded student are hash-pinned and retained. `manifest-amendment-01.json`
records its parent, the approval, the new evaluator producer and the original
student profile. Parent outcomes are referenced rather than overwritten.
The completed student's exact trace is imported into a separate grading output
with zero model calls. SecRL/native ACE grading completed under the amended
ceiling, bringing the recorded panel to 64 outcomes; the remaining 77 student
episodes subsequently completed under their original limits.

The same explicit evaluator revision closes an interrupted-finish boundary:
an accepted finish without its completion files cannot trigger another model
answer. The new grading/import paths and amendment-aware analysis passed
28 focused tests, including actual MySQL/native ACE. No SQL programs, source
rows, task/canonical fingerprints, existing scores or split assignments were
rewritten.

### 17.53 Completed external difficulty-validation results

All 141 planned episodes are recorded and scored: 140 submitted completions and
one Luna abstention, with no pending, ungraded or budget-exhausted outcomes.
All 451 pinned source/cohort/heuristic artifacts and 127 preserved original
outcome/trace artifacts verified unchanged. Student limits remained identical;
63 successful grading executions retain the original private 30-second ceiling
and 78 use the explicitly approved 120-second private-grader amendment.

| Band | Questions | Luna grounded | Sol grounded | Astra grounded |
|---|---:|---:|---:|---:|
| Medium | 10 | 7 (70.0%) | 10 (100.0%) | 9 (90.0%) |
| Hard | 31 | 7 (22.6%) | 23 (74.2%) | 24 (77.4%) |
| Very hard | 6 | 0 (0.0%) | 2 (33.3%) | 0 (0.0%) |
| Overall | 47 | 14 (29.8%) | 35 (74.5%) | 33 (70.2%) |

Continuous heuristic score versus grounded final success has Spearman
correlations of -0.391, -0.433 and -0.413 for Luna, Sol and Astra respectively.
This is directional support for the heuristic's ordering of grounded
investigation completion under the frozen witness policy. It is not proof of
production-calibrated boundaries or general model-size scaling.

Paired comparisons cover the same 47 questions. Sol succeeds on 21 questions
where Luna does not, versus zero in the reverse direction; Astra similarly
has 19 such wins and zero reverse losses. Sol/Astra is not clearly separated:
six Sol-only successes, four Astra-only successes and 37 ties. The Astra-minus-
Sol difference is -4.26 percentage points, with an exploratory scope-cluster
bootstrap 95% interval of approximately -17.31 to +10.42 points
(10,000 resamples, 11 scopes, seed 42). A stronger-Astra-over-Sol ordering is
not established.

The critical interpretation caveat is answer versus evidence:
typed final answers were correct on 45/47 Luna, 47/47 Sol and 47/47 Astra runs.
Thus 57 of 59 unsuccessful grounded outcomes had correct answers but did not
satisfy the submitted-proof/observed-evidence policy. The present signal is
primarily evidence-grounding difficulty, not inability to identify the answer.
Full checkpoint credit was earned on two, ten and eight questions respectively.

Offline structural triage, without model calls or changed grades, labels
45 unsuccessful submitted sets as lacking a complete declared representative
group, seven as containing a complete group plus extra citations, six as
requiring source-qualified proof review, and one as having no final submission.
This is not semantic adjudication of alternative valid proofs. Most missing
checkpoint credit also corresponds to a checkpoint value not explicitly
recorded; typed-value/evidence cases and one type/unit discrepancy remain
separate review candidates. These diagnostics must not be used to manufacture
passes, reroll students or silently rewrite the frozen rubric.

The final JSON/CSV analysis preserves the original measurements and reports
answer-only accuracy separately from grounded success, checkpoint progress,
resources and paired uncertainty. Eight focused statistical-analysis tests pass.
The four-axis formula, all bands and the explicit 36/11 split remain unchanged.
Next, review retained-trace grounding failures for actual proof/rubric defects
before interpreting the score as calibrated difficulty; any tuning still needs
independent pre-production confirmation, especially for absent easy cases and
the six-question very-hard band.

### 17.54 Source-reviewed grading corrections and reflection

The user approved investigation and repair of the Astra/Sol discrepancies and
asked for a grader reflection pass analogous to legacy SecRL. The two
very-hard Sol-only successes were reproduced against actual MySQL and retained
tool results. In both, Astra supplied the exact accepted Sol proof plus
genuinely observed, relevant comparison records. Removing only those extra
citations restored the old verifier's acceptance:

- Incident 5 Q1: two other incident-member recovery-setting-tampering alerts.
- Tenant Q10: a later non-interactive sign-in for the same editor and policy.

Tenant Q10's checkpoint also rejected Astra's editor object ID although the
same audit `InitiatedBy.user` object binds it to the UPN accepted for Sol.
This is a private representation restriction, not a missing identity discovery.

The explicit `source-reviewed-grading-v1` amendment is a sidecar bound to the
unchanged task fingerprint. It does not silently edit the frozen task, old
verifier or historical results. A complete original proof is still necessary;
additional source-attributed context must satisfy a reviewed, claim-local
DuckDB/MySQL scope query. Same-source checkpoint identity alternatives require
distinct atomic properties of the same cited subject object, with the canonical
property equal to the original checkpoint value. No fuzzy aliasing, missing-core
substitution, observation bypass or checkpoint removal is allowed.

Legacy answer/solution reflection can replace an initial model verdict. The
new workflow instead requires both an independent source-inspecting policy
review and a separate reflection challenge to pass before deterministic scoring
can apply the correction. Reviews contain no evaluated-model identities,
desired pass rates or difficulty bands. Reflection can block a policy for
repair, but cannot award unsupported credit by opinion. Runtime, policy,
review, reflection and trace fingerprints are retained and checked.

Both very-hard amendments passed the two review stages. All six captured
model episodes were replayed on actual MySQL through SecRL/native ACE, without
new student inference. Astra now passes both finals, and its Tenant Q10
checkpoint receives credit. Sol's outcomes remain unchanged. The same
correction also fixes Luna's complete-proof-plus-context submission for incident
5 Q1; its Tenant Q10 failure remains a failure.

With these two amendments only, aggregate grounded successes become
Luna 15/47, Sol 35/47 and Astra 35/47; very-hard successes become 1/6, 2/6 and
2/6. The original 14/35/33 result remains immutable history. Thirty-seven
actual single-core-record omissions still fail and six fabricated-extra controls
are rejected. This removes the original two-question Sol/Astra gap without
model resampling or changing the difficulty heuristic.

Validation passed 475 feature tests with actual MySQL/native ACE, including
source-scope, mandatory-proof, observation, claim-isolation, same-object identity,
review/reflection independence and artifact-integrity cases. Canonical runtime
pins, the 47-question cohort and explicit 36/11 split remain unchanged.

The remaining four Sol-only cases are not dismissed as reasoning failures.
Two more complete-proof-plus-context policies passed source review and
reflection and completed uniform three-model replay: incident 5 Q5 permits
another typed-host incident-member PRT comparison alert; tenant Q3 permits
same-device, same-controller task-operation context within the unchanged
task-create/launch interval. These records still cannot replace any original
behavioral chain member. Both corrections restore Astra's final evidence score;
Sol and Luna retain their original outcomes on those questions.

After these four task-bound corrections, the comparison is Luna 15/47,
Sol 35/47 and Astra 37/47, retaining all original grades as history. Very-hard
counts remain 1/6, 2/6 and 2/6. The paired Astra-minus-Sol difference is now
+4.26 percentage points, still uncertain: two Sol-only wins, four Astra-only
wins, 41 ties, and an exploratory scope-cluster bootstrap 95% interval of
approximately -6.52 to +15.91 points. There is still no clear model ordering
between Sol and Astra. Twelve evaluations were deterministically recomputed
from unchanged traces; 129 were retained unchanged. No student was resampled,
and all 451 frozen source/annotation/difficulty inputs remain unchanged.

The other two discrepancies
use different source records: a CloudAppEvents representation of the same
New-InboxRule audit event, and a typed process-linked incident alert rather
than the gold query's exact alert-start timestamp. Proof-alone DuckDB fixtures
reproduce the full answers from Astra's citations and every single-record
omission breaks those alternative routes. Actual isolated MySQL/DuckDB
verification passed 22 positive/omission controls. Those finite tests establish
answer reproduction, not complete public-scope equivalence. Independent source
review and reflection subsequently distinguished the two cases as described
below; they do not justify a supporting-context exemption.

### 17.55 Remaining route review and pre-production source accounting

Both independent reviewers accepted the incident 166 Q1 CloudAppEvents route:
its raw payload represents the same New-InboxRule audit event as the original
OfficeActivity row, with the same event ID, object, mailbox, status and event
time. It is an alternate representation, not independent corroboration.
The existing mailbox-resolution checkpoint remains required.

An explicit r2 candidate retains every original answer/witness program and
adds complete CloudAppEvents alternatives for both final and checkpoint goals.
Its public question, context, expected values, checkpoint objective and reward
are unchanged except for revision identity. Both claims have two executable
complete alternatives. The source-quality gate passed, and the unchanged
captured source student was revalidated without new inference. Actual native
replay, canonical annotation and model-independent difficulty rebinding are
separate gates; the old cohort approval is not transferred to the new task
fingerprint.

In contrast, both reviewers rejected the proposed incident 36 Q5 relaxation:
it omitted the public alert-at-process-observation-time requirement and admitted
two additional alerts outside that criterion. A typed process identity and the
same returned trigger value do not waive an explicit public time condition.
The current question and Astra grade are therefore retained. The candidate
query would need the original time predicate, or a separately approved public
scope change; we do not broaden the question merely to obtain a pass. This is
a concrete example of reflection finding a defect in a proposed correction.

The next pre-production foundation is
`preproduction-source-waves-v1`, with a fixed 2,000-logical-attempt envelope,
scope-local novelty context, immutable private allocations/outcomes, run-local
ownership, and exact model/endpoint/source/graph/runtime pins. All source
pilots require the opt-in quality gate. Compile repairs and model calls are
tracked separately from logical attempts. Safe unfinished tool boundaries can
resume, but completed failures, accepted finishes and ambiguous completion
boundaries cannot silently trigger student resampling.

Reports distinguish source insufficiency, post-compilation quality/solver holds,
operational errors, unfinished attempts and remaining scope budgets. Source
readiness is explicitly not native admission or a validated question; the
module currently reports source-stage counts only. There is no overlap/difficulty
admission cap or absolute source-exhaustion claim. Full native/robustness/
objective-review/canonical/difficulty orchestration remains pending before any
live pre-production wave. All 488 feature tests pass with actual MySQL/native
ACE, including 13 focused source-wave tests and preserved development-batch
behavior.

### 17.56 Revalidated development snapshot and final admission receipts

The incident 166 r2 repair completed actual MySQL validation, source/native
parity, captured SecRL/native ACE replay, fresh canonical-fact curation and
independent difficulty review. Astra now receives final and checkpoint credit
on its original trace; Sol and Luna retain their previous outcomes. No student
was resampled. The corrected comparison is Luna 15/47, Sol 35/47 and Astra
38/47, with one Sol-only success and four Astra-only successes; the small
paired difference remains uncertain.

The fresh source-only feature review retained the same five-observation
OfficeActivity route but stopped counting a single named scalar JSON lookup
as a separate reasoning family. Its profile changes from B2/P2/R2/A0
(53.33, hard) to B2/P2/R1/A0 (43.33, medium), under the existing formula and
curation guidance. This is explicit annotation refinement, not a result of
the new alternative being inherently easier or a fit to model outcomes.
The original profile remains historical.

The user explicitly approved the refreshed 47-question private development
snapshot, fingerprint
`7931eaf7bc92e496bb586386d4907d97ce7ad1892c250334e7cf63849d883908`.
Only incident 166 Q1 changes task revision. The explicit 36-train/11-test
logical membership is unchanged; the new profile inventory has 11 medium,
30 hard and six very-hard questions. The previous approvals and artifacts
remain intact. This is not training or production-release approval and does
not change the separate 1,000-new-question target or initial 2,000-attempt envelope.

`preproduction-private-admission-v1` now provides the final admission boundary.
A receipt requires an allocated source-ready question with unchanged source
artifacts, current source-quality approval, matching native validation records,
pinned snapshot/index/model/student-query settings, native SecRL/ACE agreement,
an actual complete passing robustness matrix with a bound semantic review,
a separately reviewed grading policy, canonical facts, reviewed difficulty
and scoped-objective uniqueness against the current seeded/admitted pool.
Contradictory robustness summaries, stale comparison reviews, unbound revisions
and changed accepted artifacts fail explicitly.

Admission is independent of the measured student's success. Unavailable
difficulty measurements remain unknown without a numeric/band quota, while
actual task defects still block admission. Each logical question counts once;
accepted receipts are immutable, source generation skips scopes whose validated
targets are reached, and surplus candidates are not silently promoted.
The overlap policy remains reporting-only.

The complete feature suite passed 499 tests with actual MySQL/native ACE.
The final exact-validation-record/grading-policy guards also passed 27 focused
source/admission/development-batch tests. All 109 legacy artifacts remain
unchanged. The source and final-admission boundaries are implemented, but the
middle-stage execution/recovery coordinator remains pending. With the repaired
baseline approved, one bounded source-readiness attempt has now started inside
the existing 2,000-attempt envelope. It is not an admitted question, and bulk
generation remains held until every downstream stage has been exercised and
its final receipt verified.

### 17.57 First readiness hold and same-attempt repair

The first pre-production source attempt, `preprod-v1-incident-5-01`, was held
before any blind student started. Its proof, ordered answer and parent-process
identity checkpoint were supported, but gold SQL selected an exact alert
DisplayName that the public question only paraphrased. The source-quality
review requested publication of the exact alert title. The hold is retained;
it is neither a validated question nor a reason to weaken the literal gate.

The prepared correction changes only the public question/context to quote that
source title. It preserves all programs, expected values, checkpoint objectives,
scope and reward, including the actual `cmd.ee` spelling in one recorded
command line. No new author sample is needed and no old student is rerolled.
Independent source-quality checking precedes the first blind solve.

`preproduction-source-revision-v1` adds immutable numbered repair receipts to
the original logical allocation. The parent outcome, task fingerprint, request,
source directory and revised outcome are bound explicitly; source-progress and
admission resolve the latest committed revision. Historical holds and all role
artifacts remain verified. Revisions add zero logical attempts.

The original run implementation was archived before enabling revision
bookkeeping. An explicit orchestration-only runtime amendment preserves the
original plan, source/model/budget settings and original outcome; changes to
source, SQL, grading or curation kernels are not allowed by this mechanism.
Thirty-one focused source/revision/admission tests and all 506 feature tests
pass with actual MySQL/native ACE enabled. The wording-only r3 repair passed
source quality and its first blind source solve. Actual native validation and
the first native student also completed, with grounded final success and
matching SecRL/ACE grading; checkpoint progress was zero.

At that stage the attempt still had one explicit source revision and was not
admitted. Independent grading-contract review and reflection,
without student outcomes in their context, identified unnecessary downstream
records in the intermediate checkpoint proof and an event-time/creation-time
predicate mismatch. The private repair preserves the public question and
typed goals, reduces the checkpoint core to incident/alert/parent, and uses
process-creation clocks for creation-window predicates.

The r4 source review accepted those semantics but objected to a MySQL
`JSON_TABLE` `VARCHAR(128)` capacity declaration. That is a structural SQL
parameter, not a hidden answer selector; its conservative review hold is
preserved rather than relabeled as an answer defect. The r5 implementation
uses width-free `TEXT`, with eight actual DuckDB/MySQL equivalence checks
confirming unchanged answers/witnesses. Fresh source quality passed, and the
original source student was revalidated with zero new student calls.

The original eight-call native trace was regraded under r5 without inference.
Independent source review and reflection approved only observed children of
the exact source-device parent instance, within the public creation-time bounds,
as optional comparison context. Complete final and checkpoint proofs remain
mandatory. Both actual backends passed 36 positive/missing-core/unrelated-record
controls; native SecRL/ACE replay still reports grounded final success and
zero checkpoint progress. No student was resampled to obtain checkpoint credit.

An independent semantic reviewer approved 24 explicit source counterfactuals
before execution. All 100 baseline/case/claim/backend checks passed on owned
DuckDB/MySQL fixtures, covering JSON membership representation/order, event
versus creation clocks, ordered exact commands, process-instance/device/action
qualification, missing collection members and independent parent checkpoint
support. These are finite checks, not a proof of universal acquisition
completeness or source exhaustion.

Canonical facts and independent difficulty curation passed. The source-only
profile is B2/P2/R2/A0, **53.33 hard**, with no formula/band changes or student
outcomes supplied to the feature roles. Scoped-objective review against all
47 development seeds passed; shared incident evidence with the existing
remote-port question does not make this command-line sequence a duplicate.

The immutable admission receipt has now been written and independently
verified: **one validated NEW question out of 1,000**, from **one logical
attempt out of 2,000**. Three source revisions still consume only that original
attempt; all holds and completed traces remain intact. Incident 5 has 49
validated questions left to reach its target. The original 47-question cohort
and its approved split are unchanged.

Before admission, a receipt-only orchestration amendment pinned the archived
runtime ZIPs themselves as well as their amendment records. A regression test
first reproduced the missing archive binding; all 32 focused admission,
revision and source-wave tests now pass. The actual receipt pins 214 artifacts,
including both verified runtime archives. Source, grading and curation kernels
were unchanged. Middle-stage execution/recovery automation and the portable
exporter remain next; bulk generation and release/training have not started.

The bounded continuation launcher now loads the immutable original plan rather
than reconstructing its producer fingerprint. It separately checks current
source/model/settings and the explicit effective-runtime amendment chain,
preserving the original launch policy and archived launcher. Read-only
continuation verification passed, rejected changed model settings and unamended
runtime changes, and made zero wave/model calls or new logical attempts.

### 17.58 Reusable middle-stage execution and exact recovery

The opt-in `preproduction-candidate-pipeline-v1` coordinator now connects the
readiness stages through immutable, task/runtime/input-bound stage receipts.
It performs independent contract review and reflection before a native student;
actual MySQL validation; captured-result SecRL/ACE replay; exact graph baseline;
source-authored and independently reviewed counterfactual plans executed on
owned DuckDB/MySQL fixtures; canonical and independent difficulty curation;
scoped-objective review against all approved seeds and admitted questions; and
the existing strict final-admission check.

Neither a completed hold nor a failed student is resampled to manufacture
success. Interrupted native grading retains the completed student and creates
a separate grading attempt. A selected completed replay survives interruption
while publishing its final artifacts. Canonical orchestration reuses the
existing prompts, source resolver and contracts, with separate orchestration
provenance and restored source inspections; it can resume an unstarted reviewer
without calling a completed curator again. Historical producer hashes are not
retagged. Ambiguous inference or accepted-finish/file boundaries still require
explicit recovery. A new revision with an existing native student is blocked
pending supervised retained-trace import.

The public CLI is `finish-preproduction`, with explicit run/task, source,
graph, verified MySQL bundle, private model configuration, owned scratch and
output paths. It separates student/grader query limits and owns only its
verified snapshot's MySQL process. Outputs cannot be placed in source revision
history. Sixty-five focused tests pass, including actual MySQL counterfactuals,
native ACE replay, immutable holds, trace tampering, no-reroll guards and
interrupted canonical/grading/publication recovery. Production Pylance
diagnostics and Python 3.10 syntax checks pass.

A second bounded source attempt, incident 34 question 1, was held before any
blind student for two actual public-anchor provenance defects: an unquoted
exact alert title and a private unexpanded Desktop-reference prefix. Its source
proof and meaningful registry-reference checkpoint were otherwise accepted.
A same-attempt revision is correcting that wording without revealing the
executable basename or changing the final/checkpoint goals; the original hold
is retained. That wording repair was accepted, but its source reviewer found a
further unjustified assumption that the observed `C:\Users\` profile root was
an invariant Windows constant. The subsequent r4 repair derived the destination
from observed file telemetry and relative-path/account bindings, passed source
quality, and completed its first 12-call source blind.

That completed student found the correct timestamp but did not observe the
`SecurityAlert` record linking the incident's system alert ID to the alternative
vendor-alert representation it used. Its attempted incident/`AlertInfo` join
also returned an explicit unsupported-function error, not observations. Direct
source/captured-result verification confirmed the missing bridge. Neither a
matching title/time nor private grader knowledge substitutes for that evidence.

The repair coordinator also detected a paraphrase of the checkpoint objective,
after the student had completed. A supervised r5 recovery restored the exact
original private wording, retained every r4 proof/answer program and public
content apart from revision identity, and preserved the 12-call trace with
zero new inference. The candidate remains held, not promoted; a fresh current-
revision quality pass is not fabricated. The original operational error and
all prior holds remain intact.

The orchestration now checks compiled scope/goals before the next inference,
binds valid task artifacts even on errors, and recognizes retained source
students when blocking rerolls. Legacy unbound errors can be followed only
through explicit, hash-bound recovery requests. This control-only change was
archived and registered as a third runtime amendment; protected source,
scoring and curation kernels were unchanged. The continuation launcher writes
content-addressed policies for subsequent explicit control amendments rather
than overwriting previous launch policies.

A third bounded source attempt, incident 36 question 1, initially exposed a
public-window mismatch: its raw opening process precedes the incident's recorded
FirstActivityTime. A prepared r4 edit now states the actual lower bound and
ordering clock (`ProcessCreationTime`) through incident LastActivityTime,
inclusive. Every private goal, checkpoint objective, program, evidence set and
reward remained exactly unchanged. Fresh source quality passed, and the first
12-call source blind returned the correct answer with grounded evidence and
the complete required proof observed.

That source-ready candidate passed independent contract review/reflection,
actual native validation and same-captured-result SecRL/ACE grading. Its first
10-call native student has grounded final success and zero checkpoint progress.
The pipeline then correctly held a flawed counterfactual annotation: three
negative cases expected no raw witness rows even though two comparison records
and their incident/alert anchors remained.

Diagnostic execution of the unchanged original plan produced exactly six
mismatches across 36 backend/claim checks, limited to those three cases on both
backends. All baseline checks, including the citation-omission probes, passed.
Six further actual-backend checks invoked the real claim verifier: all
unsupported final answers were blocked before accepting witnesses. This is
an expected-output annotation defect, not permission to award partial proofs.

A prepared correction retains all eight interventions, the complete five-record
baseline proof, every answer/checkpoint expectation and the unchanged task.
Only the three incorrect raw witness groups and availability-support vectors
are corrected. Fresh independent review and all 36 backend checks passed in
the annotation-only continuation. The exact parent producer was
archived; completed contract review, native grading, baseline and both students
remain immutable. Protected source/scoring/curation kernels are unchanged.
The reusable continuation API validates those bindings and supports subsequent
annotation revisions without rerolling a completed native student.

Canonical curation, independent difficulty curation and scoped-objective review
against all 47 development seeds plus the first new question also passed.
Incident 36 r4 is now the second admitted new question. Its provisional
source-only profile is **60.0 hard, B2/P1/R3/A1**; no formula, band or weight
was tuned from student outcomes. The original source/native students remain
12/10 calls respectively, with no resampling.

Both admission receipts and the retained parent/student artifacts were
independently reverified. Repeating the admission command is idempotent and
does not add another question. The complete candidate pipeline and its
annotation-only recovery path have therefore been exercised successfully on
the actual source/native snapshot.

At this milestone, totals are **two new admissions from three completed logical
attempts**. Incident 34 remains held for its recorded missing evidence rather
than being rerolled. The next bounded source wave requests three more attempts
(incidents 38, 39 and 55), under the unchanged initial 2,000-attempt envelope
and all existing gates. Source readiness still never substitutes for admission.
Bounded batch scheduling/reporting, portable private export and continued
generation remain in progress; no training or release approval is implied.

The subsequent three-attempt source wave stopped after incident 38's first
10-call blind solve because the coordinator compared a returned Python tuple
of mechanical blockers directly with its persisted JSON array. Both source
and revision comparisons now use the same JSON representation, while still
rejecting changed report contents. The exact defect was reproduced against
the recorded report and in regression tests; all 62 focused tests pass.
The control-only change was archived and explicitly registered without
changing generation, grading, curation, model settings or any question.

Incident 38's recorded task and source result were recovered through an
immutable reconciliation entry with zero new model calls. The original error
and every prior artifact remain intact. The source result itself is still a
hold: the correct hostname was returned, but the current required raw
process-creation observation was not retrieved. The completed student was not
rerolled or given missing observations retroactively. The unstarted incident
39 and 55 slots are now continuing as a bounded two-attempt wave; the admitted
total remains two.

Those two source attempts subsequently completed with pre-blind literal-policy
holds, bringing the allocated total to six. Incident 55 needs the exact
credential-alert title supplied publicly. Incident 39 needs its executable,
command shape and explicit inclusive-zero/exclusive-one-second observation
matching window stated publicly rather than treated as general constants.
The differing process/directory actors must not be conflated into causation.
Prepared public-context/justification edits preserve every private claim,
checkpoint, program and literal value, and do not expose the private answers.
They are undergoing fresh source review; a first student runs only after its
gate passes. These repairs add no logical attempts.

Incident 39's prepared r4 repair passed source review and its first 13-call
source blind returned the correct answer with grounded evidence and the full
required proof observed. Incident 55's title repair exposed a remaining
classification problem: entity/resource/operation/status/property schema
constants were mislabeled as quoted public anchors. A prepared r4 correction
uses explicit domain-constant rationales for those schema selectors and makes
HTTP 200 plus successful audit-operation scope public. Private claims,
checkpoint objectives, SQL and permitted literal values remain unchanged.
Incident 55's r4 source review and first 13-call blind solve have now passed
with correct, grounded, completely observed evidence. Both incident-39/55
candidates are proceeding through the full pipeline without rerolls; source
readiness does not yet count as a new admission.

Incident 55 has subsequently passed all downstream gates and is the third
admitted new question. Its 52 actual backend robustness checks passed; its
source-only difficulty is **70.0 hard, B2/P3/R2/A1**. The first native student
completed 12 calls with grounded final success and zero checkpoint progress.
The immutable receipt and idempotent admission were independently verified.
Its actual task and pipeline revision is r4, not the r5 label used in an earlier
progress note.

Incident 39 passed native evaluation and 28 backend robustness checks, but the
canonical reviewer rejected an annotation containing only two answer scalars.
The missing incident membership, alert, operation, identity and time predicates
must be included for the matching chain. A new canonical-only continuation
retains the completed contract/native/baseline/robustness stages and students,
and supplies the original annotation plus source-backed feedback to a new
curator/reviewer pair. Material reference changes are required; prose-only
resampling is rejected. The corrected annotation now has 22 source-bound facts
covering both claims and passed independent review. Difficulty and objective
review also passed, producing the fourth immutable new-question admission.
Its source-only profile is **43.33 medium, B2/P2/R1/A0**. The retained parent
and student artifacts were independently reverified; no completed student or
passed validation stage was rerun.

The exact parent producer was archived, and the task, grading, source and model
bindings are unchanged. Sixty-five focused tests, including this recovery path,
pass. The verified milestone is four admitted new questions from six completed
logical attempts. A bounded five-attempt source wave is now covering incidents
133, 134, 166 and 322 and the first tenant-scoped slot, within the original
envelope and unchanged gates.

That five-attempt source wave completed, bringing the allocated total to 11.
Incidents 133 and 134 and tenant question 1 passed source quality and their
first grounded blind solves (10, 14 and seven calls); all three are now running
the full admission pipeline. Incident 166 has a prepared title/width repair:
14 MySQL JSON_TABLE declarations use width-free TEXT, with eight actual
DuckDB/MySQL equivalence checks passed. Fresh source review remains required.

The retained incident-322 student used OfficeActivity instead of the gold's
CloudAppEvents audit representation. Source inspection verified the same
upstream event, event time, mailbox, operation/result, client role, Bind
property, folder-item membership and source IP. The populated OfficeActivity
Client_IPAddress field is distinct from its null ClientIP field. Both
independent review and reflection accepted a complete five-record alternative,
and 24 actual backend positive/record-omission checks passed. The original
route and meaningful checkpoint are retained; broader source checks explicitly
do not establish universal equivalence between the two tables. This proposal
has not yet changed source readiness, grades or admission, and its original
16-call student has not been resampled.

An independent observed-pool diagnostic now covers the approved development
47 plus the two admitted new questions. All 90 within-scope pairs were
measurable. Summed capacities across the independent scope buckets are exactly
**36 / 46 / 49 / 49** at **0.25 / 0.50 / 0.75 / 0.90**. The unchanged equal
component weights were used; no admission cap, deletion, grouping or split
change was applied. These bounds describe only the observed 49-question pool,
not absolute source capacity or exhaustion.

### 17.59 First tenant admission and source-preserving proof repairs

The first tenant question passed every admission gate and became the fifth
new admission. Its source-only difficulty is **46.67 medium (B1/P2/R2/A0)**,
with grounded native final success and full checkpoint progress. The verified
milestone is **five admitted new questions from 11 logical attempts**; the
approved development 47 and its explicit 36/11 split are unchanged.

The prepared incident-166 title/TEXT repair and incident-322 complete
OfficeActivity alternative both passed fresh source quality as r3 tasks.
Incident 166 received its first source student; incident 322 reused the exact
original 16-call source student. The retained-student certificate is written
before quality review, so even a new quality hold cannot accidentally reopen
student inference. Immutable same-attempt revision receipts now record both
source-ready outcomes, bringing source readiness to nine of 11 attempts.
Neither source readiness nor these repairs substitute for admission; both
candidates entered the complete downstream pipeline.

Incident 166 subsequently passed every gate and became the sixth admission.
Its original source/native students each used eight calls, with grounded
native final success and zero checkpoint progress. All 56 actual robustness
checks passed. The reviewed source-only score is **36.67 medium
(B1/P2/R1/A0)**. Its immutable admission receipt was verified, bringing the
current total to **six admitted new questions from 11 logical attempts**.

Incident 322 subsequently passed native validation with its first 13-call
native student, grounded final success and full checkpoint progress. The
actual robustness matrix held on exactly two of 36 checks: removing the
OfficeActivity representation leaves the CloudAppEvents answer intact and
the OfficeActivity answer empty, on both engines. The declared witnesses and
citation-support vectors are correct; the remaining 34 checks pass.
The current annotation format can only apply one answer expectation to every
program, so it cannot faithfully represent this mixed alternative-route
output. This is a robustness-contract expressiveness gap, not justification
to drop the removal control, alter valid task SQL or reroll either student.
Explicit program-bound answer expectations must be checked consistently by
both the fixture runner and final admission. Runtime archives and verified
continuation/replay are required before changing those pinned modules.

Incident 133's contract review found redundant per-record logon obligations
for a distinct-IP result. A prepared private repair instead catalogs every
qualifying device/account/session/IP group and accepts any matching logon
observation for each group. Incident, onset and every later process remain
required, with actual identity/session/time joins. Equal IPs do not merge
different source observations into one event. **44 actual DuckDB/MySQL
controls passed**, including reproduction of the original rejection,
alternative representatives, omitted core records, extra IP groups and
ineligible identity/session/time matches.

Three preparation-driver failures before any model inference were retained:
missing table-label permissions in fixture validation, a string value for a
BIGINT fixture cell, and an invalid dictionary fingerprint call during review
setup. The completed backend controls are not an independent semantic review.
A supervised source-quality revision and exact original 10-call student
revalidation passed after the candidate batch released its lock. Fresh
downstream contract review, native evaluation and all 32 robustness checks
also passed. The first native student used nine calls with grounded final
success and zero checkpoint progress.

Canonical review then requested the inspected ActionType='ProcessCreated'
property for the onset and both later process observations in both claims.
The original selection lacked these event-role facts. A canonical-only
continuation is adding the exact references under fresh independent review
while retaining every passed stage and the original source/native students.
Its exact parent runtime was archived before continuation. No student is
resampled to obtain a pass.

Incident 134's robustness review found two genuine predicate defects:
inclusive audit-at-click matching contradicted public "before" wording, and
the delivered-message qualifier was not enforced. Its prepared r3 retains
public wording and typed final/checkpoint goals, adds the Delivered predicate
to all eight answer/witness queries and makes the four final audit upper
bounds strict. Eight baseline-equivalence checks and six original-defect
regression checks passed on both actual backends. The expanded 18-case plan
passed **76 backend/claim checks**, including audit-at-click rejection,
just-before-click and at-delivery positives, blocked/null delivery negatives
and an independent within-window delivery/click ordering control. The
original out-of-window diagnostic remains, with its rationale corrected.

That preparation has not revised incident 134's source outcome or admission.
Both completed students remain intact. Fresh source/contract review, actual
native revalidation and an explicitly bound retained-native replay are still
required; annotation-only continuation cannot authorize a changed task
fingerprint. Incidents 34 and 38 remain held for their original evidence gaps.
All 109 legacy artifacts remain unchanged. No training or release approval
is implied.

### 17.60 Program-bound robustness outputs and seventh admission

Incident 133's canonical continuation passed independent source review.
Difficulty and objective review also passed, producing the seventh immutable
new-question admission. Its reviewed source-only difficulty is **63.33 hard
(B2/P2/R3/A0)**. The original 10-call source and nine-call native students and
all passed stages remain unchanged. Current totals are **seven admissions
and nine source-ready candidates from 11 logical attempts**.

Robustness annotations now support an explicit `answer.by_program` mapping
for every answer-program ID across both dialects. Each value is a typed
answer or null. Existing scalar/null/baseline expectations retain their
strict per-program meaning and existing serialized plan fingerprints.
Unknown/missing IDs and changed public formats are rejected before review
or fixture startup. A shared resolver and exact-length comparison are used
by both the fixture runner and independent final-admission verification;
missing, duplicated, reordered or incorrect outputs cannot be hidden by a
passing summary. Null remains distinct from an empty collection and from
an operational SQL error.

The incident-322 correction preserves every original intervention and
adds symmetric single-representation removal and both-representations
removal. All **44 actual backend/claim checks pass**, with the unchanged task,
two complete five-record alternatives and meaningful message checkpoint.
The original 16-call source and 13-call native students are retained.
A fresh independent semantic review and downstream continuation are running;
these prepared measurements alone do not admit the question.

For a robustness-held continuation, its not-yet-passed robustness runner
and final-admission coordinator may change alongside orchestration. The
exact prior producer must still be archived; module inventory and all
imported-stage generation, native grading, source and curation kernels stay
protected. Canonical-held continuations continue to protect their already
passed robustness runtime. No passed stage is silently reinterpreted.

The change passes **86 focused tests**, including actual isolated native
fixtures, mixed surviving/empty alternatives, exact program coverage,
public formats, forged vector lengths and stage-specific archive guards.
It also exposed and corrected a synthetic admission test fixture that
previously declared MySQL measurements without a MySQL answer program.
Production Pylance diagnostics are clear and Python 3.10 syntax remains
supported. A verified admission-only source-runtime amendment was appended;
all seven receipts and 109 legacy artifacts reverify. The original held
reports and producer hashes were not rewritten.

### 17.61 Eighth admission and goal-equivalent retained-native replay

Incident 322's robustness continuation passed fresh independent review,
all 44 backend/claim checks, canonical curation, difficulty and objective
review. It is the eighth new admission, with **70.0 hard (B2/P2/R3/A1)**.
Its original 16-call source and 13-call native students remain intact;
native final success and full checkpoint progress are unchanged.
All eight receipts reverify across the 11 logical attempts.

The pipeline now has an explicit retained-native mode for private task
revisions with unchanged public content except revision ID, typed goals,
checkpoint dependencies and reward. It requires the exact original task,
direct held pipeline with a passed native stage and complete producer archive.
Snapshot/index, model, query-limit and generation/capture/grading bindings
are verified before inference. The initial implementation requires the
unchanged default grader and rejects annotation-parent or policy overrides.
Unrelated student recordings still fail closed.

The original native student is never copied, overwritten or rerolled.
Completed answers, abstentions, SQL errors and captured tool boundaries are
validated against their recorded hashes. Fresh native validation checks the
new task SQL; SecRL and ACE then grade the same captured results under that
task. Interrupted replay recovery keeps the original student and selected
completed replay. Omitting import arguments cannot reopen an imported native
stage. Final receipts pin every original dependency, not just a certificate
that mentions its hashes.

Prepared robustness corrections retain every original intervention while
the old task, plan and review keep their original fingerprints. A separately
bound current plan receives fresh independent review and actual measurements.
Candidate runtime manifests now include all native-stage dependencies.
For incident 134, the old native binding supplied the exact private-pilot
validator hash missing from the parent manifest; its unchanged bytes and all
parent-bound modules were preserved in a new 29-module archive. No original
archive or producer hash was rewritten.

The integration passes **94 focused tests**, including real captured-result
replay, failed-query and abstention preservation, interrupted grading,
incompatible goals/models, trace/archive tampering, foreign students and
receipt dependency checks. Production diagnostics and Python 3.10 syntax
checks pass. An admission-only source-runtime amendment records the change;
all eight admissions and 109 legacy artifacts remain intact.

Incident 134's strict-before/Delivered repair passed fresh source quality and
every downstream gate through this workflow. It is the ninth admission,
with **53.33 hard (B2/P2/R2/A0)**, grounded native final success and zero
checkpoint progress. Both original students used 14 calls and were retained;
the new native stage made zero student calls and pins 222 original
dependencies. Eight baseline equivalences, six original-defect regressions
and all 76 fresh robustness checks passed. The readiness round therefore
ended with nine admissions from 11 logical attempts.
No training or release approval is implied.

### 17.62 Portable private packet and the next bounded source wave

A portable private exporter and loader now preserve exact task/native,
baseline, canonical, difficulty and grading-policy bindings, together with
original approval/admission artifacts and their dependencies. The approved
development roster and explicit split remain unchanged; admitted
preproduction questions receive no implicit train/test assignment.
Difficulty uses exact reviewed sidecars, including incident 166's revised
development profile, rather than reconstruction from summary CSV values.

The initial packet contains **56 questions: 47 development and nine new
admissions**, with **36 train, 11 test and nine unassigned**. All five reviewed
grading policies are included. There are 3,445 hash-bound artifacts.
The ZIP is 19,149,740 bytes; its cohort fingerprint is
`db05d61dc4407142d2b5c4addfc4920f940c17030e27f18833fd4f09267c4bbb`.
Actual extraction and relocation loaded all 56 questions while opening any
original data path was forbidden; the original-path access count was zero.

Operational paths are relative. Historical absolute paths remain provenance
keys resolved exclusively through the packet's verified mapping. The
student directory contains only the public-task projection; private gold,
source reviews and retained grading evidence remain outside it. The full
source database is not embedded, so evaluation still requires the compatible
snapshot/graph/serving environment. Neither packaging nor relocation
authorizes training or release.

Eight focused tests pass, covering relocation without originals, exact
bindings, byte tampering, altered partitions/difficulty, admission dependency
coverage, path escape, extra files and student-directory leakage. Production
diagnostics and Python 3.10 syntax checks pass. All 109 legacy artifacts are
unchanged. Export code did not change the active source worker's pinned
generation or grading modules.

The next source wave is bounded to eleven new logical attempts: the second
slot for each of the ten selected incidents and tenant slot two. It runs
under the original 1,000-new-question target, 2,000-attempt envelope and
unchanged gates. The original incident-34/38 evidence holds are retained,
not rerolled or silently admitted.

### 17.63 Second source round and bounded repair queue

The second source round completed all eleven slots: **22 logical attempts
and outcomes, 16 source-ready candidates and nine admissions**. Seven new
source-ready candidates entered full downstream validation: second-slot
incidents 5, 34, 55, 133, 134, 322 and tenant question two. Four candidates
were held before any student: second-slot incidents 36, 38, 39 and 166.
These source outcomes do not imply additional admissions or source exhaustion.

Prepared incident-36/39/166 repairs publish the exact hidden non-answer
selectors and matching rules identified by source review. The typed answers,
checkpoint objectives, scope and reward remain unchanged. Thirty-eight
MySQL JSON_TABLE width declarations become TEXT, removing incidental
capacities from the literal policy. Twenty-four actual answer/witness
checks passed across both engines. Incident 39 additionally exposed four
original MySQL join-scope errors, reproduced before repair: explicit ON TRUE
clauses for its JSON_TABLE joins restore access to preceding source aliases.
Its repaired MySQL results match the original DuckDB outputs; original
MySQL equivalence is not claimed. The exact failed producer/error were
archived, not rewritten.

Incident 38 had a substantive ancestry defect, not merely an unpublished
selector. Full-source traversal finds six linked creation observations and
seven output entries, including the oldest observation's recorded parent;
the original fixed-depth SQL returned only five entries. The prepared
correction uses recursive parent joins and an explicit no-matching-creation
stopping rule, without claiming real-world absence or restricting older
ancestors to the incident interval. Its original direct-parent checkpoint,
answer format, scope and reward are preserved. Twenty-eight actual backend
checks passed, including an eighth counterfactual generation and independent
device/PID/creation-time/filename/action mismatches. The corrected final gold
is explicit, before any student; it is not disguised as an unchanged answer.
Fresh independent source quality must still approve it.

The ready batch has so far retained two downstream holds. Incident 5 has an
original MySQL join-scope error before any native student; its completed
source student must be preserved during repair. Incident 34's actual matrix
has eight answer-only mismatches: four negative ordered-list cases expect
null, whereas zero result rows correctly produce a typed empty list.
An annotation-only correction preserves every intervention, all witness and
support expectations, the task and both students. All 36 backend checks pass;
an empty list still does not satisfy the nonempty final gold.

The three selector repairs, full-ancestry repair and incident-34 annotation
continuation are queued behind the running candidate batch. A shared lock
serializes owned full-snapshot MySQL execution. Original holds, reviews,
students and preparation failures are retained; fresh independent review
and all remaining gates are mandatory. No pinned production module changed
during the active work. All 109 legacy artifacts remain unchanged.

### 17.64 Preserved timeout boundary and independent continuation

The ready-candidate batch stopped on an Azure API timeout during second-slot
incident 133's independent contract review. Five responses were recorded;
the sixth request has no response, result or completion receipt. The existing
safe-boundary check explicitly rejects automatic retry. This is a retained
operational block, not a question-quality rejection or a successful review.
The exact error, request and role inventory are preserved separately; no
native student has started and the source student is untouched.

The three remaining candidates had never started downstream inference:
second-slot incidents 134/322 and tenant question two. They are queued as a
separate explicit batch rather than rerunning the interrupted reviewer.
The launcher now supports an explicit lock-wait option and revalidates the
selected source-ready tasks after acquiring the lock. Both successful
dispatch and rejection of a task changed during the wait were tested without
model/native calls. The original interrupted launcher was archived exactly.

Second-slot incident 55's completed robustness hold has two support-only
mismatches. Its changed five-date answer and thirteen-record witness cohort
were already correct, but the availability expectation rejected the complete
cohort and probes omitting either now-nonqualifying July 7 record. The
correction derives support from the unchanged declared witnesses and exact
probe order. All 20 actual backend checks pass. This does not equate the
counterfactual answer with original gold or change the completed native
outcome: correct answer, unsupported final, zero checkpoint progress. The
original 10-call source and 12-call native students are retained.

Second-slot incident 5's four MySQL join-scope errors were reproduced, then
corrected with explicit JSON_TABLE ON TRUE and width-free TEXT. Eight actual
answer/witness checks match the original DuckDB outputs; original MySQL
equivalence is not claimed. Public wording, typed goals, checkpoint and
reward are unchanged. Its ten-call source student will be reused; the first
native student is allowed only after fresh source quality and native
validation. Both repairs are queued for fresh review and the remaining gates.

Other queued repairs continue independently of the ambiguous review. The
latest verified totals are **22 attempts, 17 source-ready candidates and nine
admissions**. All workers serialize owned full-snapshot access through the
same lock; no pinned generation/grading module or original trace was changed.

All three prepared selector revisions subsequently passed fresh source
quality and their first source students: incident 36 r3 used 15 calls,
incident 39 r4 used 12, and incident 166 r3 used 17. Their answers were
grounded with complete proof observed. This brings source readiness to
**19 of 22 logical attempts**, while admission remains nine.

The repair worker then stopped on a second Azure read timeout, this time
incident 36's contract-reviewer tenth request after nine recorded responses.
Both timeouts occurred approximately 300.3 seconds after their requests,
matching the pinned 300-second HTTP limit; no response or completed review
was captured. The evidence identifies a transport read timeout, not a SQL
timeout or proof of the provider's underlying cause. These two ambiguous
reviews remain blocked without automatic retry.

Incident 39 and 166's downstream roles had not started and are now queued
separately. The ancestry repair has already advanced to fresh source review;
other independent jobs retain their existing queue positions. No completed
review/student is restarted, no timeout policy is silently changed, and
every original failed request and error remains bound in the private record.

### 17.65 Approved reviewer-only HTTP override and audited recovery

The user explicitly approved increasing reviewer HTTP timeouts to **900
seconds** and recovering incomplete reviews from their saved contexts.
The scope is transport only: student HTTP remains 300 seconds, student SQL
remains 30 seconds, private grading SQL remains 120 seconds, and the model,
reasoning effort and per-response output budget are unchanged. Completed
students and completed/accepted reviews may not be restarted.

Two additional in-flight original-policy reviews timed out before the
change was applied: incident 34's robustness reviewer and incident 134's
contract reflection. The three workers still waiting on the batch lock were
stopped before inference; the active worker was allowed to finish rather
than being killed mid-request. All five interrupted histories have now been
verified against their exact request/response/tool-result sequence.

The opt-in transport client matches both a trusted reviewer result schema
and its actual recorded role/request. It retains the original default client
for students, authors and curators. Every overridden call records the
original/effective configurations, policy fingerprint and exact request
hash; received responses reference that receipt. The approved policy and
new execution producer are separately archived. Frozen source, grading,
role-interpreter and candidate-pipeline implementations remain byte-identical.
The opt-in native owner uses the same verified snapshot, lock, read-only
engines and lifetime checks rather than rewriting the historical runner.

Recovery is explicit and append-only. It requires a recorded HTTP timeout
with no response, no accepted finish and no result/completion/abstention.
All earlier model and tool messages must reconstruct the exact next request.
The existing role interpreter resumes that saved context at a new call
index; the original unanswered request and error are never overwritten.
Source inspections are restored and the original source/subject validators
remain mandatory. A second uncertain recovery is not automatically retried.

For the sealed incident-38 source error, recovery uses a copied, explicitly
linked same-attempt source revision; the original error packet stays intact.
Unsealed interrupted pipeline roles append audited calls in their existing
directories and preserve every completed stage/student. Successful review
recovery still must pass every remaining gate; it is not admission.

Twenty-nine focused transport/source-quality tests pass, including exact
history, accepted-finish protection, unchanged student routing, invalid
source-result rejection and a second-timeout hold. Actual owned MySQL
startup/readiness, matching DuckDB/MySQL reads, shutdown and unchanged SQL
limits were verified without model calls. Pylance and Python 3.10 syntax
checks pass. All 109 legacy artifacts remain unchanged.

The approved recovery batch is now running, beginning with incident 38's
source-quality review and then the four interrupted pipeline reviews.
Independent untouched work will use the same approved reviewer policy,
without retrying any completed student or silently changing an original
runtime/model binding.

### 17.66 Recovered decisions and verification of reviewer claims

All five approved timeout recoveries completed without another transport
failure. They did not automatically become admissions. Incident 38's source
quality passed, but its first 15-call source answer used `name (number)`
instead of the explicitly requested `name (PID number)` rendering. The
seven process/PID pairs and their order are correct; the observed strict
answer mismatch remains recorded. Gold must not be silently rewritten to
award success, and the completed student cannot be rerolled.

Incident 133's contract review identified an identity overclaim: the queries
compare reported AccountName, whereas the public wording implied verified
account identity despite failed-row domain/SID differences. Its retained
source student already explicitly disclosed the domain difference. A
correction must qualify the name comparison without introducing unseen
evidence or changing that student's recorded citation failure. Incident 36
requires an independently supported root-process checkpoint rather than
requiring the final task-update evidence; the public "later chain" criterion
still needs faithful source-comparison handling.

Incident 34's corrected robustness expectations passed, followed by a
canonical hold for one missing final-claim ActionType='ProcessCreated' fact.
The checkpoint already has that inspected fact. A canonical-only continuation
is queued, preserving the task, students and all passed stages.

Incident 134's two contract reviewers asserted that unquoted ROLE is a
reserved MySQL keyword and invalidates four programs. Actual isolated
MySQL 8.4 testing disproved that claim: `INFORMATION_SCHEMA.KEYWORDS`
reports ROLE with RESERVED=0, and all four original final/checkpoint answer
and witness programs execute and match DuckDB. No query or task was changed.
A distinct evidence-based reconsideration is queued: it first requires
full-snapshot native validation, then fresh independent review and reflection
against the original hold plus the newly measured backend evidence. The
original completed reviews remain intact, other real defects still block
admission, and no existing student is resampled.

This distinction is essential: model review is a fallible, source-inspecting
gate, not authority to change working SQL based on an unverified syntax
assertion. Reconsideration must introduce material, verified evidence rather
than repeatedly sampling the same review until it passes.

### 17.67 Tenth admission and approved non-student transport scope

Incident 34's second-slot canonical correction passed all remaining gates
and became the tenth new admission. Its source-only difficulty is **43.33
medium (B1/P2/R1/A1)**. The original task, source/native students and passed
grading/native/baseline/robustness stages were retained. Totals are now
**ten admissions, 19 source-ready candidates and 22 logical attempts**.

Incident 134's evidence-based reconsideration confirmed that the original
MySQL queries work, passed independent review/reflection and completed its
first native student. Actual robustness then identified annotation defects,
not the earlier alleged syntax error. A correction preserves every original
intervention, changes two null answer expectations to typed empty sets and
corrects the raw witness-support expectation for a same-address world.
All 28 backend/claim checks pass. Four additional actual-backend checks
invoke the real claim verifier and reject the original nonempty gold before
witnesses can be accepted. Task SQL, typed gold and students remain unchanged;
fresh independent annotation review and later gates are still required.

The remaining queue stopped on a different transport boundary: incident
322's robustness **author** timed out at its unchanged 300-second limit.
The reviewer-only policy had deliberately not applied to that role.
Its completed successful native student and prior gates were preserved.
The user then explicitly approved **900-second HTTP timeouts for all
non-student QA agents**, with audited incomplete-call recovery, while keeping
GPT-6-Sol, student HTTP/SQL limits, reasoning/token budgets and completed
outcomes unchanged.

A separate V2 policy records that approval and the exact V1 predecessor.
V1 policy files, execution bindings and producer bytes remain intact.
New transport-execution records append the V2 scope instead of rewriting
the old 300/900-second history. Scouts, task authors/repair authors,
robustness authors, fact/difficulty curators and reviewers are selected by
their exact recorded role plus trusted result schema. Blind/native-blind
students still use the original 300-second client.

Robustness-author recovery restores the exact unanswered context and
original tool interface. It retains all original source-inspection,
claim coverage, program-answer, fixture-membership and citation-probe
validators. Accepted/completed outcomes cannot be restarted; another
uncertain recovery is not automatically retried. Thirty-three focused
transport/source-quality tests pass, including V1 compatibility,
scope-specific routing, author recovery and immutable policy transition.
The real ten-request/nine-response author history was verified before
recovery. Frozen source/generation/grading kernels and all 109 legacy
artifacts remain unchanged.

The V2 batch is now running: recover that author, then process untouched
tenant/incident candidates and the prepared source/annotation corrections
under the shared batch lock. These operations do not add logical attempts
or authorize training/release.

### 17.68 V2 completion, thirteen admissions and the next source wave

The seven-job V2 batch completed without another timeout. Three candidates
became new admissions:

| Candidate | Source-only difficulty | Retained native final/checkpoint |
| --- | --- | --- |
| Incident 39, second slot | 36.67 medium, B1/P2/R1/A0 | true / 0 |
| Incident 322, second slot | 63.33 hard, B2/P3/R2/A0 | true / 0 |
| Incident 55, second slot | 70.0 hard, B3/P2/R3/A0 | false / 0 |

This milestone has **13 admitted new questions from 22 logical attempts**,
with 19 source-ready candidates. Incident 322's interrupted author recovered
from its exact context. Incident 55 demonstrates the intended distinction:
a valid, fully checked question can be admitted while its original native
student failure remains unchanged. No failed student was rerolled or awarded
retrospective success.

The remaining holds are retained explicitly. Incidents 5/36 need genuine
intermediate checkpoint proofs, incident 166 needs a complete-cohort
distinct-path proof alternative, and incident 133 needs truthful
name-versus-identity wording. Tenant question two needs the inspected
ProcessCreated source property in both canonical claims; its canonical-only
continuation is queued without changing task/student data.

Incident 134's prior corrected measurements were accepted, but two rationale
sentences still incorrectly called an empty set null. Those descriptions
are corrected without changing any existing intervention or expectation.
A directly related missing-client-address negative control adds substantive
coverage: SQL NULL is not an observed different address. The revised plan
passes 32 actual backend/claim checks and six real claim-verifier checks
rejecting original nonempty gold in the negative worlds. Fresh independent
review and downstream gates remain queued; no prose-only pass or weakened
final condition is assumed.

An immutable private packet now contains **60 questions: 47 approved
development plus 13 new admissions**, with **36 train / 11 test / 13
unassigned**, all five grading policies and 4,843 hash-bound artifacts.
Its cohort fingerprint is
`1fcf993cd78f58b09af4f0d6c51effd8f2eb5262dd4867d3f578bb18977006e5`.
Actual ZIP extraction and relocation loaded every question while access to
all original data paths was forbidden; zero original accesses occurred.
The ZIP is 28,048,637 bytes. The earlier 56-question packet is unchanged,
and neither packet authorizes training or release or embeds the full database.

The next bounded source wave covers eleven third-slot incident/tenant
attempts under the same original 2,000-attempt envelope and approved
non-student V2 policy. Source/annotation corrections remain queued behind
its shared lock; held histories and completed students are not discarded.

### 17.69 Third-wave holds and the fourteenth admission

The third eleven-slot source wave completed under V2. The verified milestone
is **33 logical attempts, 20 source-ready candidates and 14 admitted new
questions**. The new admission is incident 134's second slot: its reviewed
32-check robustness matrix and six original-gold rejection guards passed,
followed by canonical facts, source-only difficulty and objective novelty.
Its difficulty is **63.33 hard (B2/P2/R3/A0)**. The original completed students
remain unchanged.

Tenant question two passed its canonical correction and difficulty stages
but remains held at objective novelty. Its SID-History target/result is the
same scoped objective as admitted incident 39's first slot; a tenant entry
point alone does not make that objective new. The question and its history
are retained, not deleted or counted as an admission.

Only incident 134's third slot was initially source-ready in the new wave.
The other ten were held before any student started. Nine have exact
public-selector or observation-window omissions, including misleading task
ownership wording in incident 34 and an independence overclaim in incident
36. Deterministic public clarifications for these nine were compiled and
verified with **unchanged private gold, SQL, checkpoint goals, literal
values, anchors and reward**. Preparation made zero model calls. Fresh
source quality and only then the first source student are queued, followed
by every downstream gate for qualifying candidates. Incident 134's ready
third-slot candidate subsequently passed contract review, native
validation/parity and the exact baseline, and completed its first native
episode. Its robustness
review passed, but actual measurements found four support-only mismatches.
Two interventions correctly excluded the original earliest Bind and
declared the remaining six-record witness; their support vectors marked
the wrong single-omission probe. Deriving support from unchanged witness
membership and the actual ordered probes corrects index 4 to index 5.
All 32 backend checks then pass, while four real claim-verifier guards
still reject original gold when the answer changes. An audited annotation
continuation is queued with the original task, students, controls and
passed stages retained. This is not a new admission.

Incident 5's third slot has a distinct mechanical collection failure:
each per-host witness bundle covers only one member of the two-host
answer. Partial bundles cannot be alternative complete proofs of the set.
Its prepared repair combines the original eight-record union into one
complete incident-cohort proof, without changing public content, answer
predicates, checkpoint proofs or reward. Both original partial-bundle
failures were reproduced. The repair passes 12 actual DuckDB/MySQL
answer/witness checks, four original-full-set rejection guards in partial
source worlds, and six citation-availability probes. Each five-record
host-only bundle is rejected; the complete eight-record bundle passes on
both backends. Fresh source quality and subsequent gates are queued; this
is a verified preparation, not a new admission or collection-gate waiver.

No further logical slots are being allocated while these yield problems
are addressed. GPT-6-Sol remains selected, with non-student HTTP timeout
900 seconds and student HTTP timeout 300 seconds; SQL budgets are unchanged.
No completed student is resampled. The 56- and 60-question portable packets
remain immutable historical milestones: the 60-question packet contains
13, not 14, new admissions. No release or training approval is implied.

### 17.70 Preserving meaningful earlier-parent checkpoint credit

Incident 5's second-slot checkpoint previously demanded the complete
later four-command sequence to identify the earlier parent. A prepared
private-proof revision instead requires the complete earlier sequence,
both parent creation times, and the later parent's earliest first-command
cohort. Strict earlier-finish/later-start ordering remains required, and
aggregate minima prevent selecting a convenient later duplicate.

The new seven-record intermediate proof and the original ten-record full
proof are explicit alternatives in the same witness program. Retaining
the full alternative matters: otherwise strict citation relevance would
reject a previously valid complete finding merely for including the
later sequence's remaining records. Neither alternative changes the
final requirement for both complete ordered sequences.

Actual DuckDB/MySQL fixtures pass 32 goal checks: baseline, the valid
intermediate-only world, equal finish/start, tied parent creation times,
and removal of each required earlier command. The original overconstraint
is reproduced in the intermediate-only world; the repaired checkpoint
passes there while the final still fails. Full and intermediate citation
availability also pass, while missing comparison evidence does not.

The public contract, typed final/checkpoint goals, checkpoint objective,
reward and original ten-call source student are unchanged. Fresh source
quality and all downstream gates are queued as a same-attempt revision.
No native student had started, and no source student is resampled.

During the queued public-contract repairs, a subsequent verified checkpoint
reached **23 source-ready candidates from the same 33 logical attempts**.
Admissions remained **14**; readiness gains are not counted as admissions
before the remaining gates pass.

### 17.71 Received protocol stop and source-verified follow-up

All nine public-contract revisions finished: third-slot incidents
34/36/38/55/133/166 became source-ready. Incident 39's first source student
answered correctly but did not observe a complete proof; that outcome is
retained without resampling. Incident 322 remained pre-blind on arbitrary
MySQL declaration-width literals, and tenant question three remained
pre-blind on undisclosed exact Rubeus command syntax.

The downstream batch subsequently stopped at incident 55's contract
reflection. Its thirteenth response was received with status `completed`,
but supplied prose rather than a structured `finish` tool call. This was
not an HTTP timeout or a token-truncated response. The original request,
response and complete role history are hash-bound in a separate protocol
diagnostic; no structured result, tool result or accepted finish was
fabricated, and timeout recovery was not used. The two untouched ready
candidates, incidents 133 and 166, were queued separately rather than
restarting the batch.

The received prose reported a real checkpoint defect: either of two
process-bound connections to the directory destination identifies the
process, but the checkpoint required both. Independent DuckDB/MySQL tests
confirmed the defect and a material proof repair. Two complete five-record
alternatives replace the mandatory six-record bundle; their union preserves
the original complete finding as valid evidence. The final still requires
all seven records and the complete three-endpoint set. Twenty goal checks
and six availability checks pass. A new same-attempt task revision is
queued with unchanged public/final contracts, typed checkpoint goal and
original twenty-call source student. The stopped review is not retried.

Other holds remain genuine gates, not automatic admissions. Incident 134's
third-slot robustness correction and canonical facts passed, but difficulty
review requests correcting a binding attribution: matching an already
anchored message identifier is lookup; selecting the earliest Bind is the
discovered selection. Incident 5's second-slot checkpoint semantics passed
fresh review, but its private `:complete` group suffix lacks valid literal
provenance. Its source student remains retained. Incident 5's third-slot
complete collection also passed semantic review but remains pre-blind on
MySQL declaration-width literals. None of these holds authorizes changed
student scores, waived gates or additional admissions.

### 17.72 Verified literal repairs and a received JSON-only author result

Three further pre-blind corrections were prepared and queued under V2:
incident 5 and incident 322 each replace sixteen MySQL JSON_TABLE VARCHAR
declarations with TEXT, removing only their arbitrary capacity literals;
tenant question three explicitly supplies its two existing command-substring
patterns. All 24 original/corrected DuckDB/MySQL answer and witness checks
pass, including exact ordered-answer comparisons. The tenant's private gold
is unchanged. No source student had started for these revisions.

Incident 5's earlier-parent checkpoint also has a prepared source-namespace
correction: its arbitrary suffix is replaced by the actual public incident
table namespace. Sixteen backend comparisons preserve both the seven-record
intermediate and ten-record complete proofs, in full and intermediate-only
worlds. The first preparation's verifier incorrectly applied the new literal
allowlist to the archived old query; that harness failure and producer were
preserved, then corrected using separate original/new verifiers. The source,
student and new task's literal allowlist were not relaxed. This preparation
has not yet been applied.

The incident 55 checkpoint repair progressed past source quality, contract
review, native execution and baseline. Its robustness author then returned
a complete five-case plan in a JSON code block, not a `finish` call. The
received response is complete, and its single plan is schema-valid and
binds the exact repaired task, but it has not been published as an accepted
author result. Recovering an already-received JSON result is distinct from
the approved unanswered-HTTP-timeout recovery and requires an explicit
decision. No author request is repeated and no fictional tool call is made.

Both incident 133 and incident 134 third-slot candidates remain held on
source-only difficulty-feature attribution after passing their earlier
stages. Existing difficulty-curation revision support can be reused, but
pipeline continuation currently imports stages only for robustness or
canonical holds. An audited difficulty continuation must preserve the
verified canonical and all earlier stages, and will be implemented only
after the current bounded workers finish. No new logical slots or model
switch are authorized by these preparations.

### 17.73 Approved JSON recovery preserves the original inspection gate

The user explicitly approved the audited, validation-only recovery rule for
current and future non-student received-JSON stops. The isolated publisher
requires the exact trusted result schema, an intact request/response/tool
history, restored original inspections and the original role validator. It
has no model client, excludes students and accepted/closed outcomes, and
rejects prose-only, ambiguous, refused or truncated results. Successful
publication is explicitly marked as received JSON, not a fictional tool
call; partial publication is recoverable without resampling.

Forty-seven focused JSON-recovery, transport and source-quality tests pass,
with clear Pylance diagnostics and Python 3.10 syntax checks. All 109 legacy
artifacts remain unchanged. The approved policy, exact producer and user
selection are archived separately; frozen generation and grading producers
were not modified.

The first real validation correctly **did not publish** incident 55's
received author plan. Its incident, alert and directory rows had been queried
as concatenated summaries or identifiers, not the attributable raw-field
projections required by the existing inspection gate. Replaying the trace
therefore leaves three required rows uncredited. No source observations were
added retroactively, no result/completion/certificate was created and no
author call was repeated. An author continuation requiring new inference is
outside this validation-only approval and needs a separate decision.

### 17.74 Astra drafting and checkpointed review

The user explicitly changed the generation workflow to **GPT-6-Astra on the
same Azure endpoint**, with reviews at roughly **100-question checkpoints**
and targeted repair/regeneration after failures. This supersedes keeping Sol
for new drafting, not the preserved model identity of any existing trace.
Independent reviewers and students remain on Sol.

The new checkpoint policy preserves the original campaign, 2,000 logical
slots, 1,000-new-question goal, development cohort and admitted questions.
The default checkpoint contains 100 draft-ready candidates: five for each
selected incident and 50 tenant candidates. Drafting combines discovery and
authorship into one role, uses four independent workers and records the actual
Astra configuration per request. Deterministic source/collection/literal checks
run immediately; independent semantic review and students wait for the filled
checkpoint. Failed generation attempts remain counted and separately visible.

Checkpoint source reviews and downstream candidate pipelines are independent
jobs. A failed item is recorded in the repair queue rather than aborting the
remaining batch. A native-stage lease limits exclusive full-snapshot MySQL
ownership to native validation, the student episode and captured-result replay.
Source-only reviews, canonical work, difficulty work and isolated robustness
fixtures can overlap. Final objective review/admission remains serialized so
concurrent questions cannot validate against a stale admission inventory.

Selected pre-blind review failures have a reusable same-attempt Astra
repair/review command. Completed students and admitted questions are never
automatically regenerated. Old source-wave runners cannot adopt checkpoint-owned
attempts or accidentally resume Astra context using Sol.

Ninety-one focused checkpoint/source/pipeline/admission/revision tests pass,
including exact 100-candidate allocation, deferred reviews, parallel source work,
failure isolation, model routing and native-lease boundaries. Thirty prior
producer modules were archived before the orchestration change; the explicit
source-runtime amendment changes only `preproduction.py`. All 14 prior
admissions and all 109 legacy artifacts remain unchanged.

The first two real Astra drafts completed in the same 100-candidate batch with
an empty repair queue and no semantic reviewer or student started. Both provider
responses identify `gpt-6-astra`. The campaign has now allocated 35 logical
attempts; the two drafts do not increase the 14-admission total. The remaining
checkpoint generation and its later reviews use the same recorded policy.

### 17.75 Checkpoint readiness audit and finalization repair

The first Astra checkpoint produced 100 drafts from 102 new logical attempts.
Source-checkpoint processing yielded 92 source-ready candidates, seven revision
holds and one operational error. The stopped validation run had 33 held
candidate results, one operational error, four started prefixes without an item
result and 54 untouched source-ready candidates.

All 119 recorded completed-stage receipts passed integrity checks. Each of the
four interrupted prefixes had already passed grading, native validation,
baseline, robustness, canonical facts and difficulty; all original students
were complete and there was no unfinished model-call boundary.

The new orchestration had introduced a real lock defect: finalization held an
exclusive lock, then objective review requested a shared lock on the same file
through another descriptor. That blocked the first objective and left the other
three candidates waiting. A nonblocking OS-lock regression reproduced the
failure before the nested acquisition was removed.

The exact old 29-module producer was archived. A narrow, append-only execution
continuation now permits only this completed-prefix finalization boundary:
source/grading kernels, task, model and prior stages must remain unchanged, and
no objective request may have started. The four candidates resumed objective
review and admission, and **all four were admitted**, raising the campaign from
**14 to 18 admissions** with zero repeated source/native student calls.

A separate read-only native investigation found a recurring MySQL 1210
JSON_TABLE issue in generated CTE queries. Generic TEXT, CTE-string and SQL-NULL
inputs execute successfully, so this is not a blanket prohibition on those
constructs. Three actual failing queries execute when their JSON_TABLE inputs
are explicitly cast to JSON, with answers matching their typed source gold;
disabling derived-table merging also changes the observed behavior. These are
diagnostic comparisons, not silently applied query changes.

A read-only EXPLAIN screen detected all 12 known 1210 controls and flagged nine
of the 54 untouched candidates. Those nine are retained as explicit native
preflight repair holds, with no native answer validation claimed. The other
**45 candidates are continuing through every original admission gate**; passing
the planning screen is not native validation or admission.

Other robustness holds include empty-collection versus null annotations,
incorrect citation-support vectors, and negative-world witness queries that
emit nonbehavior-only fragments. These need targeted source-backed corrections;
the audit does not waive them. Focused finalization/pipeline tests and admission
invariant tests pass, and all 109 legacy artifacts remain unchanged.

### 17.76 Managed SQL service per snapshot

The user approved a persistent SQL service for remaining validation and the
next checkpoint. The service boundary is the **verified full-tenant snapshot**,
not an individual incident or question. One owned MySQL process serves bounded
concurrent native candidates through separate read-only connections.

The implementation leaves frozen query/scoring kernels and existing traces
unchanged. It adds server ownership, startup verification, read-only and
super-read-only enforcement, a private socket, nonce-bound instance identity,
health checks and graceful lease draining. Each candidate gets independent
student/grader sessions with the original limits. The native evidence verifier
uses the already verified source snapshot and its own private metadata cursor;
it does not relax source identity, witness or answer checks.

A registered service becomes the default for checkpoint review, pre-blind
checkpoint repairs and individual validation. A configured service that is
unavailable or bound to another snapshot fails closed. It does not trigger a
second server or switch an existing in-flight pipeline to another provider.
Mutation-based robustness fixtures remain separate.

Sixty-three focused service, actual-MySQL, checkpoint, finalization and CLI
tests pass. Real MySQL tests cover simultaneous native candidates, four
distinct reader connections, session-state isolation, denied writes, bounded
slots, rejected duplicate ownership, preserved source proof results and
shutdown waiting for active leases.

The tested producer and explicit approval are archived. The persistent owner
is started with a safe handoff barrier: it waits for the old checkpoint worker
to release its workflow before owning the datadir. A separate bounded
activation check verifies concurrent sessions on the real snapshot and then
registers it for the run. Until that readiness check finishes, deployment is
pending; no currently running student is interrupted for this change.

The safe handoff subsequently completed. Production verification exercised
two simultaneous candidate leases with four distinct reader connections on
the same server, checked source-row counts and the unchanged student/grader
limits, and registered the service as the run's validation default. This made
zero model calls and did not modify any original student. The service is now
live with four native-candidate slots and remains running for later work.

The first Astra checkpoint is sealed: of its 100 drafted candidates, 15 are
admitted, 76 have downstream holds, one has a downstream operational error,
and eight did not become source-ready. Two additional generation attempts
failed and remain recorded. Including the earlier 14 admissions, the campaign
now has **29 admitted new questions from 135 logical attempts**. Held items
remain in the repair queue; registration of the service does not waive their
validation requirements.

### 17.77 Corrected validation workflow and first-checkpoint repair

The user requested correction of the underlying pipeline and grading-contract
problems before fresh validation of the first 100 questions. The original
85-case audit, all original questions/students and the sealed checkpoint remain
preserved. A separate repair approval and exact pre-change producer archive
bind this work; further checkpoint and legacy-wave generation are blocked.

The corrected workflow adds:

- Versioned v2 robustness semantics: negative-world raw witnesses are distinct
  from admissible behavior proofs. Context-only leftovers have no behavior
  support; baseline and grounded-final requirements are unchanged.
- One structural validator for robustness authors and execution, rejecting
  unbound witness IDs and inconsistent enumerated support arrays before a
  reviewer call. Qualified proof availability is not inferred from a
  representative group.
- Fresh DuckDB table state for each mutation world. The two reproduced
  optimizer-dependent witness-ID substitutions disappear across 72 real
  backend checks without disabling optimization.
- Actual verifier omission diagnostics and explicit behavior/security-control
  semantics for grading-contract reviewers.
- Explicit selector issue fingerprints for source reviewers, rather than
  asking them to reconstruct identifiers or confuse them with query hashes.
- Early MySQL JSON_TABLE input-typing checks across answer, witness, obligation
  and candidate SQL. The author still owns its recorded proposal; compilation
  rejects unsafe typing rather than silently rewriting completed output.
- Explicit, source-justified control repairs that preserve old case identities,
  scopes and fixture members, with independent review of revised coverage.
- Fresh validation of unchanged admitted tasks with retained native students
  and separate revalidation receipts. Existing admissions are neither
  overwritten nor counted twice.

Preparation produced 55 versioned robustness proposals and 24 backend-query
repair candidates. Twenty-two SQL candidates pass full real source/native
parity, including the exact-case JSON property repair and its counterfactual
matrix. Subsequent source-derived performance revisions also reproduce all
eight native answer/witness programs for the two timeout candidates within
the unchanged 120-second limit. The incident queries complete below 0.2
seconds; the tenant queries complete below 84 seconds in that standalone run.
The tenant query subsequently exceeded 120 seconds during full validation,
so that standalone result does not establish a reliable repair. Those
query-only preparations capped no rows and changed no indexes or global
optimizer settings; distinct source IDs remained part of the materialized cohorts. Their fresh
source-quality review and full source/native parity remain required.
Prepared proposals are not admissions.
Fresh validation of the complete first checkpoint remains pending; no later
batch is authorized by these preparation results alone.

The first corrected robustness wave subsequently admitted 17 more candidates;
15 remained held and one difficulty role was unfinished. The following
24-candidate SQL wave exposed a writer-orchestration defect: 23 candidates
hit the nonblocking run lock before creating a revision or calling a model.
One completed its source revision and reached a robustness hold. These are
not 23 new question-quality failures. Short metadata transactions now have an
explicit waiting mode, while exclusive whole-run ownership stays fail-fast.
A real four-thread file-lock regression verifies queueing and complete,
serialized publication. Only the verified never-started candidates are
eligible for this lock-recovery retry.

The completed contract and optional-context waves subsequently added seven
admissions. Exact current-source, sealed-pipeline and admission-receipt
reconciliation now establishes **47 admitted and 53 unadmitted** in the
original 100. The original 15 admissions still require separate fresh
revalidation certificates; they are not implicitly certified by this count.
All 14 completed difficulty holds are source-feature annotation revisions,
with no task defect reported by those reviews. The pipeline now exposes the
existing feature-only revision process while retaining its five verified
predecessor stages and completed students.

The user explicitly approved a versioned generic native-index upgrade after
the tenant35 anchor lookup alone took 100.6 seconds despite selecting one row.
The v7 policy adds only
`MicrosoftGraphActivityLogs(RequestMethod(16), TimeGenerated)` as a non-unique
access path. Its deployment must drain active native episodes, verify exact
source/native content for every indexed-table row, retain the original
verification of untouched tables, append the native-index manifest and approval chain,
and register a replacement read-only service. Original plans, index manifests,
student histories, query budgets and admissions remain immutable. A versioned
service-execution view carries the new index digest, while retained native
episodes remain bound to their actual historical index version. This
infrastructure authorization does not admit tenant35 or authorize a later QA
batch; fresh parity, source-quality and downstream gates remain required.

The v7 deployment verified all **1,238,201 affected rows** against their
original per-record source digests and restored the four-slot read-only
service under a new, appended registration. Tenant35's exact previously
staged task now passes complete source/native answer-and-proof parity.
Four concurrent validation lanes also pass; the slowest complete parity
check takes **4.55 seconds**, below the unchanged 120-second per-query
grading limit. The earlier failed staging request and timeout report remain
unchanged. This is a verified infrastructure repair, not a source-quality
approval or an admission.

The subsequent feature-only continuation wave admitted nine of eleven
candidates, bringing historical checkpoint admissions to **56/100**. Fresh
validation of the original fifteen admissions produced **seven certificates
and eight holds** (five grading, two difficulty, one robustness), with no
student rerolls. These historical admissions are not counted as fresh passes
while their new holds remain unresolved.

Tenant05 exposed another context defect: its source-qualified candidate SQL
actually defines the disputed smaller proof and `ready` CTE, but difficulty
reviewers previously received only representative evidence sets and answer
SQL. Curation v0.4 includes the source witness programs and their obligation/
candidate contracts without changing difficulty mathematics or supplying
student outcomes. Audited continuations now follow the original student
through a retained-native replay, including fresh-validation holds on already
admitted tasks. The frozen native evaluators remain unchanged.

The source audit's broad implementation manifest also includes the difficulty
context module, although source-quality evaluation does not call that context
builder. A separate annotation-context amendment preserves exact old and new
producers and verifies their AST boundaries: curation logic, source-quality
semantics and the frozen evaluator kernels cannot change. This prevents an
unrelated context fix from invalidating or rerolling every completed source
review. The original audits/results remain immutable and must match a verified
historical producer; unrelated runtime changes still fail closed.

Recovery of a demonstrably author-history-contaminated robustness review is
explicit and single-use; it cannot change the prior plan, waive controls or
skip the actual backend matrix. Initially unsent credential/dispatch failures
use a separate evidence-bound authorization covering every request, not the
timeout certificate. Unknown send state and completed roles remain blocked.
The user confirmed that this repair pass keeps the original cohort fixed:
genuine exclusions are reported without replacement questions or later batches.

The corrected 16-case recovery wave completed with six new admissions, two
fresh revalidation certificates and eight holds, without operational
interruptions or completed-student rerolls. Historical checkpoint admissions
are now **62/100**; nine of the original fifteen have fresh certificates.
Tenant35 and incident3904 are fully admitted after their preserved staging/
transport histories were recovered.

Five newly reviewed historical admissions have correct typed answers but
overly exclusive proof contracts. Their prepared repairs preserve the exact
public task and typed goals. A separate admitted-contract authorization now
binds the historical admission, source-ready revision and both task
fingerprints. Full fresh validation must retain the original native student
and write a separate certificate; the old admission is never rewritten or
counted again. Objective comparison descriptors come from the task pinned by
the historical admission, so an unvalidated source revision cannot silently
alter another candidate's comparison inventory. Materially false control
rationales can be corrected through an explicit named source-backed repair,
without altering already-correct numerical expectations.

The following sixteen-case wave completed with six new admissions, three fresh
certificates and seven holds. Reconciliation distinguishes **68 historical
admissions from 65 current clearances**, including twelve current clearances
among the original fifteen. It verifies the current task revision and exact
certificate, not merely the existence of an older admission.

Mixed-context probes identified a further query-contract defect: a valid
source-qualified positive bundle already passes, but citation-availability
filters can hide an incomplete comparison candidate and thereby remove its
otherwise source-scoped records from the relevance set. Returning complete
required bundles for candidates activated by a real supplied/source join fixes
this without changing the frozen solver, inventing observed records, or
accepting missing positive proof. Three corrections passed full source/native
parity and 334 additional bounded mixed-context/partial-proof probes; they still
require independent review and publication. Diagnostics now separate complete
observed support from submitted-citation relevance.

An explicit interrupted-native-prefix authorization also permits reuse of a
completed native episode after a recorded robustness operational error, without
fabricating a terminal pipeline report or rerunning the student. The normal
native capture, producer, model, snapshot and bound checks remain mandatory.

The interrupted native-prefix case subsequently passed all admission gates
without another student episode. A ten-case annotation continuation then
produced three admissions, one fresh historical-admission certificate, four
downstream holds and two distinct transport interruptions (HTTP 500 and timeout).
Sealed reconciliation now records **72 historical admissions, 70 current
clearances and thirteen current clearances among the original fifteen**. Six
source-backed scoped-objective duplicates are documented as fixed-cohort
exclusions, not replacement slots; unresolved workflow failures remain separate.

Further verification distinguished complete qualified-catalog relevance from
representative evidence sets, corrected stale candidate-emission descriptions,
and repaired a boundary-list program that emitted invalid NULL elements when
an interval did not exist. Source/native comparison controls also showed that
binary JSON identity projections could defeat process-identity index access:
restoring the verified exact physical-column comparison reduced a complete
native parity check to 1.109 seconds while preserving the original case and
trailing-space controls. No index or query-budget change was needed.

Source repair publication follows earlier sealed student provenance through
quality-held and operational-error revisions. Two unadmitted checkpoints have
explicitly scoped, typed-goal-preserving wording clarifications prepared before
any native sample; one accidentally introduced public column typo is restored
to the original question. These proposals still require fresh source review.
HTTP 500 recovery is separately authorized against the exact nonstudent request,
error and dispatch, with unchanged model settings and no automatic second retry.

After both publication lanes covering eighteen candidates drained, sealed reconciliation
records **76 current clearances and all fifteen original admissions freshly
cleared**. Eight genuine scoped-objective duplicates are separately evidenced;
sixteen other questions still have actionable holds. The fixed checkpoint is
not yet complete, and subsequent generation remains blocked.

The next orchestration correction addresses a demonstrated reviewer-context
error: qualified support was described as "additionally" executing candidate
queries, which was read as requiring representative containment first. The exact
held plan passes both backends and supplies counterexamples to that extra
prerequisite. Policy-specific context and an exact, one-use review recovery
correct the explanation without changing the frozen solver or measured vectors.
Native physical-column collation facts now reach grading as well as source
review, preventing generic case-insensitive-default assumptions from rejecting
verified binary/NO PAD predicates. Correct controls are retained across actual
reviewed executable repairs, rather than forcing invented expectation changes.

Further native-retention checks distinguish call attempts from actual model
responses. The frozen generator counts explicit token-rate waits as calls.
Retained imports now require a contiguous request journal; each response-less
slot must have its exact recorded `retry_wait`, no executed tools, and an
identical following request. Missing/unknown responses remain errors. Neither
the student, failed SQL nor completed model output is rerun to repair accounting.

The separate received-JSON recovery path likewise preserves explicit token
waits while reconstructing the unchanged request history. A complete assessment
returned as text is published only through its original role validator and the
verified recorded inspection prefix, with zero inference and no fabricated
`finish` call. Its errors, requests, responses and original operational failure
remain in history; remaining gates resume on the original pipeline.

Verified physical-column collation/padding facts also reach robustness author
and reviewer contexts, including retained grading metadata and shared-service
continuations. Generic MySQL defaults are not evidence about the verified
snapshot; computed/JSON_TABLE text still needs its own exactness analysis.

Two canonical holds exposed a genuine representational gap: a material source
array can be empty, leaving no scalar member to select. The narrowly versioned
`json_array_empty_v1` fact records only the verified structural observation
`true` for that exact empty array. Null, missing, object and nonempty values are
rejected. Legacy scalar/member semantics, fact IDs, unit weights and native
kernels remain unchanged. An explicit dual-archive amendment checks the exact
additive AST change before retaining old source audits. Canonical continuations
must run fresh curation/review under the new producer; a difficulty continuation
cannot silently import an old canonical stage across that producer change.

The final fixed-cohort reconciliation accounts for **all 100 original questions:
92 freshly cleared questions and eight genuine scoped-objective duplicate
exclusions**. All fifteen original admissions are freshly cleared, no historical
admission lacks a current clearance, and no recoverable pipeline or grading
failure remains. Campaign historical admissions total 106; the original
development cohort remains separate. No replacement questions, later batches,
student rerolls, commits or pushes were introduced by this repair.

The last difficulty repairs distinguish recipient identities from repeated
delivery observations and an explicitly supplied message key from a discovered
binding. The existing smaller 22-record recipient proof is exposed as a
source-validated representative beside the full 35-record comparison route;
qualified obligations/candidates and typed goals remain unchanged. Future
drafting guidance requires such materially different representatives because
the current difficulty interface binds explicit evidence-set fingerprints.

An audited read-only source adapter also batches immutable private record-map
metadata lookups without changing public SQL, attribution, row hashes or frozen
native kernels. It reproduced the complete 495/765/33-row probe measurements
exactly in approximately 50 seconds; the original finish-validation callback
took 988 seconds. Its native cursor/lease compatibility and exact source/native
parity were verified. A pre-review adapter failure remains preserved with an
explicit exact-input, empty-stage recovery; no source/model history was erased.
The final report retains all exclusion reviews, current certificates, producer
archives and unique student-role inventory. Later generation remains blocked.

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

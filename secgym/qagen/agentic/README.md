# Agentic QA generation v1: source preparation, validation and evaluation

This opt-in package implements **I0-I3 contracts, source preparation, graph
construction, serving and evaluation**, **I4 private model-driven discovery
and native validation**, and **I5 canonical overlap and question-level split
planning**. It is not a released benchmark and does not reroute legacy datasets
or runners. The [design](../../../QA_GENERATION_DESIGN.md) records the remaining
weighting, split-review and release decisions.

## Installation and checks

From the repository root, use the project environment with the `agentic` extra:

```bash
python -m pip install -e '.[agentic]'
python -m unittest discover -s tests -p 'test_agentic*.py' -v
python -m secgym.qagen.agentic check-legacy --repo .
```

I0 uses Pydantic 2; I1/I2 additionally use DuckDB and `pytz`. I3 uses SQLGlot 27
for structural SQL checks and the project's MySQL connector. Tests use
standard-library `unittest` and synthetic databases. Core Python support remains
3.10+. Default discovery skips explicitly optional live integration tests;
it needs no LLM calls or original tenant data. Importing the contracts does not
initialize source readers, legacy agents or models.

The pinned ACE SDK requires Python 3.11-3.13 and is deliberately installed in a
**separate environment**, not into the legacy SecRL environment:

```bash
python3.11 -m venv /path/to/aces-env
/path/to/aces-env/bin/python -m pip install -r secgym/qagen/agentic/requirements-aces.txt
PYTHONPATH="$PWD" SECRL_MYSQLD=/path/to/mysqld \
  /path/to/aces-env/bin/python -m unittest discover -s tests -p 'test_agentic*.py'
```

The integration test initializes a private temporary MySQL data directory,
disables TCP networking, creates a SELECT-only account, and stops/removes its
own instance afterward. It does not use or modify existing containers. Tested:
MySQL 8.4.0, pinned SABER 0.2.0 and Inspect 0.3.283. No model provider is called.

## Contracts

[contracts.py](contracts.py) defines:

- Source snapshot and selected-case manifests, including source/project label
  separation and the explicit exclusions for incidents 5 and 322.
- Historical removed-membership metadata, separate from current incident state.
- Typed factual answers, evidence sets, SQL program declarations, private
  checkpoint rubrics and acyclic dependencies.
- An explicit **allowlisted public task** projection. Private evidence locators,
  answers, programs, checkpoints and scoring policies are not projected.
- Content-bound validation reports. Required gates cannot pass by being missing,
  errored or `not_applicable`.
- Per-component and aggregate evaluation records retaining evidence citations,
  first-completion/trajectory references, evaluator and policy versions, and
  explicit incomplete/error states.
- Weighted similarity result records that validate component ranges, weight
  normalization and aggregate arithmetic.

Contracts reject unknown fields, invalid answer shapes, unresolved task
evidence references, duplicate IDs, NaN/infinite numbers, naive timestamps and
success-shaped error results. Required configuration must be supplied explicitly:
there is **no chosen production checkpoint cap or similarity weighting**.

The default reward policy contract is
`max(grounded_final, checkpoint_cap * checkpoint_progress)`. Result validation
checks the declared arithmetic; it does not judge the submitted answer or
execute the evidence queries. A fully correct final answer with sufficient
evidence may earn full credit without following the author's intermediate path.
Alternative public citations are allowed: the future source/evidence validator
must check them rather than reject them solely for absence from the author's
listed evidence.

Example commands:

```bash
python -m secgym.qagen.agentic schema task
python -m secgym.qagen.agentic schema evaluation
python -m secgym.qagen.agentic validate-contract tests/fixtures/agentic_task.json
python -m secgym.qagen.agentic public-task tests/fixtures/agentic_task.json
```

The [fixture](../../../tests/fixtures/agentic_task.json) is entirely synthetic,
not a real incident question or released QA. Its cap of 0.5 and the test
similarity weights are test inputs, **not approved production defaults**.

**Structural validity is not evidence validity or release approval.** A report
declaring all required gates passed is a contract fixture until real gate
implementations verify it. Contracts alone store SQL without executing it;
the I3 query and witness layers below perform mechanical checks.
The public projection prevents structural private-field leakage, not an
answer-bearing sentence inserted into public question text; that requires the
wording/leakage gate. The opt-in runtime adapters below have controlled
integration tests; legacy experiment launchers and agent prompts are not
silently rerouted. Changing a backend label alone is not a parity test.

## I3: deterministic scoring primitives

[scoring.py](scoring.py) provides two offline building blocks:

- `compare_typed_answers` checks the task's exact declared answer format. It
  supports exact/explicit-casefold entities, exact sets, ordered lists with
  significant duplicates, booleans, numeric tolerance and timezone-aware
  timestamps. It does not accept substrings, supersets, stripped account
  domains, whitespace changes or a submission-selected looser policy.
- `aggregate_evaluation` binds supplied component verdicts to the task
  fingerprint, profile and checkpoint rubric. It retains every component,
  citation, evaluator version, trajectory reference and first completion step,
  and computes `max(F, cap * P)` only when every component is complete.

These are **not source/evidence verifiers or runtime backend adapters**.
The aggregator consumes trusted scorer verdicts; the presence of a citation
does not independently validate it. Merely comparing the right answer does
not establish grounded success. Neither function admits QA or approves release.

Checkpoint progress remains
`sum(score * weight) / sum(max_score * weight)`. Rational intermediate
arithmetic avoids floating-point overflow/underflow for finite component
maxima/weights. Numeric comparisons also preserve large integers and exact
decimal tolerance boundaries; canonical ISO timestamp comparisons also retain
submicrosecond source precision instead of silently rounding it away.
Unknown/incomplete or errored components yield no completed aggregate,
even when the final answer component is correct.

Checkpoint IDs, maxima, weights and completion metadata must agree with the
rubric. A credited dependent claim requires its semantic prerequisites to be
complete, but they need not appear earlier in the trajectory. Duplicate
checkpoint components are rejected rather than counted twice. A separately
versioned reward-policy override can reaggregate the same retained components;
production cap/weights remain unset.

Scoring tests exercise strict answer shapes, precision/tolerance
boundaries, checkpoint caps, semantic dependencies, malformed rubric bindings,
error/incomplete propagation and explicit reaggregation. Serializing either
backend label alone does not exercise an adapter. The following slice adds
actual serving, witness verification and native adapter integration.

## I3: public serving and source-bound evaluation

### Explicit projection and database isolation

[serving.py](serving.py) requires a `ServingPolicy` that names every source
table and, unless explicitly excluded, every non-internal source column.
Each column is kept, dropped with a reason, or projected through an explicit
JSON scalar-path allowlist. A data-pinned `redact_json` policy may instead
remove explicit reviewed field paths, optionally under an exact root-property
condition, while preserving unrelated literal/encoded payloads. Policies bind
the exact source snapshot and ledger digest; they are not defaults for future
data. Unknown columns fail rather than inherit a default.
JSON projection handles nested/encoded JSON, preserves number tokens and array
positions, and rejects unreviewed container shapes at scalar paths.
Quarantined rows are excluded with counts, not silently treated as valid.

```bash
python -m secgym.qagen.agentic export-public-view \
  --graph-bundle /path/to/evidence-graph \
  --policy /path/to/reviewed-serving-policy.json \
  --output /path/to/new-serving-bundle
```

The bundle is private build data:

- `public.duckdb` contains only projected tables and stable `_record_id` locators.
- `private_mapping.duckdb` separately retains private observation IDs,
  private-row/public-row hashes and lineage.
- `serving_report.json` binds source, graph, policy, implementation and output
  checksums. It does **not** approve a release.

Only the public database is exposed to students; never mount the complete
bundle, private ledger, mapping or review files into an agent environment.
Hashes describe ledger/projection values under their separately pinned schemas,
not original CSV-line bytes.

[mysql_serving.py](mysql_serving.py) loads only a **new** `secrl_v1_...` database,
never replaces an existing database, and checks every public row against the
projection. Types, complete table/column inventory and binary/no-padding
collations are checked. UTC microsecond database timestamps, nulls, booleans,
large integers, case, whitespace and JSON text survive the tested round-trip.
Five native diagnostic column names exceed MySQL's 64-character storage limit.
They receive deterministic storage aliases; schema tools expose the MySQL names
and original source-name mapping, and row hashes continue to use the canonical
source schema. No values or columns are discarded. The complete diagnostics
table also requires the isolated serving instance's 32KB InnoDB page layout.
Native JSON query semantics still require task-specific parity.
The reader factory rejects privileged accounts and indirect/unexpected grants;
it uses statement-scoped autocommit so idle readers do not retain metadata
locks. Deploy an immutable public snapshot with explicit SELECT-only grants.

### Executable answers and alternative witnesses

[query.py](query.py) enforces a reviewed table/function surface, one SELECT,
no external/system/private sources or mutation, and explicit row/byte/time
limits. Limits are errors, not accepted truncated results. Gold queries cannot
hide competing rows with LIMIT/OFFSET or filter through literal record IDs.
Literals must come from an explicitly reviewed allowlist; the validator does
not itself establish the justification for a domain constant.
This is a restricted query layer, not a replacement for database privileges
and deployment isolation.

[evidence.py](evidence.py) checks task/view/graph identity, source origins,
private content hashes, lineage and the exact current public row content.
Each runtime `ClaimCheck` needs answer programs and `witness_programs` for the
backend in use. Witness SQL must emit:

```text
evidence_group | table_name | record_id
```

Each group is a complete, source-derived proof alternative. Student citations
may use other query-derived alternatives, not just the author's listed set.
Incomplete, unrelated or duplicate citations do not establish grounding.
Scalar answers require one row/column; sets/lists preserve their declared
semantics, and ordered answers require outer ordering. Behavior claims cannot
use only detector/context rows as independent evidence. Setting
`requires_behavior_evidence=false` is an explicit source-report claim policy,
not permission to infer causality or benignness from metadata.

```bash
python -m secgym.qagen.agentic preflight-task \
  --task /path/to/private-task.json --serving-bundle /path/to/serving-bundle \
  --limits /path/to/query-limits.json --allowed-literals /path/to/reviewed-literals.json \
  --output /path/to/new-preflight.json
```

Preflight produces only mechanical gate results. Identity/causal relevance,
scope, coverage sufficiency, wording, blind verification, refutation, split and
release reviews remain separate required gates. Two author-informed programs
agreeing is not independent semantic validation. Large proof sets exceeding
the configured bounds are rejected, not sampled into purported completeness.
`serving_parity` executes all claims on both public DuckDB and MySQL and requires
the same typed answers and exact witness alternatives.

#### Source-qualified complete proofs

Verifier `source-witness-v1.3` additionally supports opt-in
`QualifiedWitnessProgram` objects with
`witness_policy="source-qualified-obligations-v1"`. Existing enumerated programs
keep their serialized shape, task fingerprints and matching semantics. A claim
cannot mix policies across its backend programs.

- `query` still returns complete representative witnesses for private source
  annotations and overlap/difficulty analysis.
- `obligations_query` returns a nonempty, unique
  `evidence_group, obligation_id` catalog from the full source scope. It cannot
  depend on the student's citations.
- `candidates_query` returns
  `evidence_group, obligation_id, candidate_id, binding_key, table_name, record_id`.
  It joins actual qualifying sources to the server-supplied
  `proof_citations(table_name, record_id)` relation; it must not define/shadow
  that relation. No arbitrary witness SQL is rewritten or source cohort filtered.
- Each candidate is a whole bundle of all rows sharing its group, obligation
  and candidate ID. One complete bundle is required for **every** obligation
  in a complete group. Bundles cannot be spliced. Non-null binding keys attach
  source-record identities that must agree across selected bundles; use
  subject/role-qualified keys, and NULL for ordinary evidence. Derive labels
  from source values or legitimately justified literals; private bookkeeping
  strings are not automatically general domain constants.

Required set members cannot disappear merely because their source records
were not cited. Ranking, counts, absence and common-value claims still require
their complete source comparison/support obligations, not a positive example
or answer-query replay over a smaller dataset. Independent source/semantic
review must establish that the catalog and predicates encode the whole claim.
Every representative must itself pass the qualified contract.

The grader checks citation relevance, coherent full-proof coverage and
behavior-source requirements; the adapters also retain actual source-retrieval
attribution checks. Observation coverage may include unrelated exploratory
rows, unlike submitted evidence. SQL row/byte/time limits and a 10,000-state
coherence-search limit are explicit errors, never truncated proofs or zero
difficulty scores. Serving parity compares catalogs, candidate bundles and
bindings for each representative and their union; new alternatives also need
explicit backend regression probes.

Pass the claim to `EvidenceVerifier.evidence_matches(..., claim=claim)` when
using qualified programs. Discovery, final/checkpoint grading and native
SecRL/ACE replay all use this path. Canonical runtime pins include the new
contracts and verifier module. Old approvals/reviews are not silently rebound
to changed task or runtime fingerprints.

### Opt-in SecRL and ACE adapters

[SecRLV1Env](secrl_adapter.py) implements reset/step, public question/schema
access, SQL queries, typed submissions and explicit findings. It refuses tasks
with missing review gates and never supplies private gold to an agent.
Checkpoint feedback stays private during the episode. Citation observation
uses SQL column lineage, including direct aliases/CTEs, and matching returned
source values; literal/guessed IDs alone are not observation proof.
Derived or ambiguous projections may require retrieving the source record.

Repeated findings earn credit once; first completion and supporting steps are
retained. A missing/invalid final answer may still earn supported checkpoint
credit. Scorer/serving failures instead retain error components and no numeric
completed reward. Resets retain completed episodes with distinct run IDs.
Optional private JSON logging is atomic; otherwise the hosting harness must
persist `get_logging()`.

[acesevals_adapter.py](acesevals_adapter.py) exports a native ACE task, registers
the `secrl_v1` strategy and supplies native SQL/finding/schema tools. Create a
separate environment/verifier/connection for each episode and bind its run ID
in trusted scoring metadata. Gold stays in evaluator bindings, not task context.
The default ACE aggregation includes only the already capped canonical reward;
diagnostic answer/evidence/checkpoint scores remain separately available.
It does not try to enforce a cap merely by lowering checkpoint `max_score`.

Backend adapter versions (`secrl-env-v1`, `aces-native-v1`) are recorded separately
from schema, evaluator and reward-policy versions. The controlled test traverses
real MySQL, both adapters, native ACE tools/registry/scorer factory and ACE
aggregation. Both retain identical component outcomes and a 0.5 fixture-only
checkpoint reward below full success. Existing v0 runners/prompts are unchanged;
model-driven v1 runner/prompt work remains part of the pilot stage.

### Similarity and remaining production gate

[similarity.py](similarity.py) computes weighted edge/observation/fact Jaccard
components. `evidence-overlap-v2` computes containment over the namespaced
union of decisive observations and facts, divided by the smaller union's
weight, as specified by the design. Earlier v1 observation-only containment
reports are historical and must not be mixed with v2 scores.
It requires matching snapshot/graph/feature-weight versions; conflicts are
errors and missing/empty footprints remain unscorable. Footprints must already
represent validated evidence. No production coefficients, split thresholds,
deduplication actions or model budgets are selected.

The last complete suite before the difficulty prototype passed **329 tests
with optional MySQL and ACE tests enabled**. The difficulty increment has
additional focused validation described below.
The fixture serving/evaluation slice is verified. The user has approved the
conservative full-tenant profile, and its source audit/policy verification is
complete. The public DuckDB projection now contains **61 tables and 13,276,298
rows**, retaining 914 incidents and 1,069 alerts; only the eight private
investigation bookmarks are excluded as a whole table. Full MySQL
materialization and exact verification of all **13,276,298 rows** are complete.
Mixed post-review summaries and
private investigation packages are hidden, but native event-time detections
and concrete response actions are preserved. Two tasks have completed private
pilot validation, but no QA release is approved.

### Canonical source-fact calibration

[canonical_facts.py](canonical_facts.py) adds the approved
`canonical-source-facts-v2` definition. A fact is bound to the verified source
observation, source column/JSON leaf, exact recorded value and recorded time
context. Source property paths retain roles such as actor/target and
parent/child. Question wording, descriptive answer labels, comparison
normalization and the surrounding proof bundle do not define its identity.
Equal strings from different events are not merged. This is observation-bound
fact reuse, not global real-world entity or relationship coalescing.

[fact_curation.py](fact_curation.py) exposes `curate_source_facts`, taking an
already validated task/report, retained unit footprint, source resolver,
completion client and fresh private output directory. It uses separate curator
and reviewer conversations. The curator selects public source references for
the final answer and **every checkpoint**; deterministic resolution supplies
values after verifying row content, lineage and claim-specific evidence
membership. Both roles must actually retrieve every selected source record,
with returned source IDs checked using SQL lineage. The reviewer binds the
exact resolved bundle and checks semantic relevance, coverage and preservation
of subject/time/role distinctions.

Passing current review produces a `unit-canonical-source-facts-v2.1` footprint, preserving
the baseline edges and observations. Failed, abstained or missing annotations
remain incomplete/unscorable, not zero similarity and not an old-signature
fallback. The original `unit-evidence-audit-v1` exact claim signatures remain
separate diagnostics. Canonical and original feature versions must not be mixed.

JSON numeric precision, key case and array position are retained. Ordinary
`property_value` references reject missing paths and terminal JSON containers.
The separately tagged `json_member_presence` kind records whether a named key
exists in an **existing source JSON object**. It distinguishes missing members
from explicit nulls, rejects missing/non-object ancestors, and never establishes
real-world absence. Its kind participates in fact identity.

`source-fact-curation-v1.2` also permits `json_array_empty_v1`: an atomic `true`
observation at an explicitly selected JSON path, only when that verified source
value is an empty array. An empty path selects the JSON root. Missing ancestors,
nulls, objects and nonempty arrays fail explicitly; this is neither a synthetic
count nor permission to select whole containers. Existing scalar/member facts,
their IDs, and unit weights are unchanged. Existing source audits require an
explicit dual-producer amendment with an AST-checked additive extension;
affected canonical stages are freshly curated and reviewed, not silently reused.

Materially different complete qualified routes also need source-validated
representative groups for annotation: the difficulty interface binds explicit
evidence-set fingerprints, not arbitrary qualified subsets. Representative
selection must preserve the full comparison route and every required obligation,
without introducing a representative-containment prerequisite into the solver.

The initial six real-task annotations were all held by independent review:
the curator omitted material scope/event-type predicates, and one annotation
needed to express the recorded absence of `Exec.Arguments` precisely. These
results are preserved, not reclassified as accepted or zero overlap. V2 adds
the structural observation and clarifies that actual incident/alert/action
selectors are necessary even if supplied by the question. Irrelevant metadata
and outside-window counterexamples are not required merely as padding.

`revision_from` permits a fresh annotation revision only for a recorded hold
with unchanged task, validation and baseline inputs. It pins the old artifacts,
gives correction feedback only to the curator, and obtains a fresh independent
review. Derived counts/orderings still require their source inputs rather than
fabricated source properties. Unit weights are diagnostic only. Gold,
checkpoint scoring, native outcomes and task fingerprints are unchanged.
All six revised real-task annotations passed independent review and the exact
mailbox/chronology/equal-path control assertions. The same rule's mailbox is
shared across different labels and alert anchors; the identical path returned
by different task events remains distinct; earlier/later PowerShell command
targets retain separate source facts and times. The control matrix contains
15 complete comparisons, with shared facts in the two related within-incident
pairs, not the equal-path cross-incident pair.

The 47-task canonical component rerun reuses these six frozen annotations and
curates the other 41. It reports shared-fact source lineages separately so
scope/metadata-only sharing is not mistaken for shared behavioral findings.
No production weights, thresholds, split assignments or release approval follow
from the controls.

The first full pass reviewed **41/47 annotations**, yielding **820 complete**
and **261 incomplete** comparisons. Of 56 shared-fact pairs, 21 share
behavior/security-control facts and 35 share only context/detector facts.
Incomplete fact/containment components are null, not zero. Four curator roles
were interrupted by API errors or response-token truncation; recovery preserves
their original traces and source bindings. Tenant Q3's initially omitted
recorded parent-process properties have now been added to both claims and
independently reviewed. The verified no-model merge now contains **42 reviewed
annotations, 861 complete comparisons and 220 incomplete comparisons**;
the original first-pass outputs remain unchanged.

The other hold exposed a task proof-description mismatch: incident 5 Q2's
descriptions discuss six launches/two connections beyond its corresponding
claim-bound witness sets. That requires a fresh question/checkpoint/proof
revision and later native admission, not out-of-claim similarity citations or
an automatic waiver. Original task outcomes and the 41 reviewed annotations
remain unchanged. The highest preliminary containment (0.9) is task action
versus configured trigger, demonstrating why support reuse is not automatic
question duplication.

Exact recovery of the four interrupted roles subsequently produced three
reviewed annotations and one substantive annotation hold (the inspection
event's recorded initiating PID 0 must support its attribution limitation).
The latest pre-evaluator-fix merge contains **45 reviewed annotations, 990
complete comparisons and 91 incomplete comparisons**.

The corrected incident-5 question then exposed a separate runtime bug: its
original blind trace **did** return the required network witness, in a UNION
query, but citation tracking accepted only linear SQL lineage. Evaluator
`source-witness-v1.2` follows genuine branch-local source projections, requires
every ID origin to be an actual `_record_id`, and still checks accompanying
source values from the same branch and alias. Literal-ID branches, unrelated
join aliases and ID-only projections remain uncredited. DuckDB and real MySQL
regressions cover these cases.

The unchanged recorded blind trace now satisfies the final and checkpoint
witnesses without model resampling. A fresh derived source-admission artifact
records the evaluator correction and retains all original artifacts; native
admission for the changed question remains required. Previously reviewed
canonical bundles are mechanically revalidated against their recorded role
inspections under the corrected evaluator, retaining exact fact/footprint
fingerprints and independent reviews rather than pretending old runtime hashes
match new code. Historical scores are not rewritten.

The revised incident-5 task has now passed fresh native admission: the final
answer is correct and grounded, both adapters return 1.0, and its one required
checkpoint remains available (the student earned zero checkpoint progress).
Its fresh graph-bound canonical annotation and the incident-38 attribution
limitation also passed independent review. All 47 current task annotations
therefore have passing semantic reviews; the retained-bundle revalidation and
explicit revised-cohort matrix assembly remain the final integrity steps.

Those integrity steps are now complete: **47 reviewed tasks / 1,081 complete
comparisons**, with every component independently recomputed from its feature
sets. The 45 retained bundles and footprints are unchanged. The r5 replacement
also retains its original edge/observation footprint while binding new task,
validation and exact-claim-signature fingerprints.

There are **69 shared-fact pairs**: 26 share behavior/security-control facts,
and 43 share only context/detector facts. These comprise 66 same-incident pairs
and three permitted tenant/incident pairs. No cross-incident or tenant/tenant
pair shares observations or facts. Maximum unit fact Jaccard is 14/29;
maximum containment is 0.9, with no complete containment.

The next calibration check applies the canonical layer to the seven existing
native-validated paraphrase/related/disjoint controls, without regenerating QA
or resampling native students. True paraphrases must be tested alongside
different objectives with shared support before selecting coefficients or
leakage thresholds. All weights and split/release decisions remain unset.

Both known paraphrase pairs now have **all four canonical components exactly
1.0**, and the 13 currently complete disjoint comparisons have all components
0.0. The related-objective control is temporarily unscorable: its annotation
omitted the AppId property label needed to establish the application/service-
principal identity binding. A fresh fact-only revision is adding that source
role label; its six comparisons are not treated as zero.

The corrected related control has now passed: **all seven controls / 21
comparisons are complete**. Both paraphrase pairs remain 1.0 in every
component, and all 17 disjoint pairs remain 0.0. The related comparisons have
fact Jaccard 32/47 and containment 36/43, despite different objectives.
These two positive episode families validate the intended behavior but do not
uniquely calibrate production coefficients or a release-wide leakage threshold.

An unselected grouping sensitivity check shows that linking every shared
behavior/control fact would join all four current questions in incident 38
and all four in incident 166, leaving no within-incident train/test separation
for those cohorts. No such grouping rule has been applied. Expanding the
controlled QA calibration set beyond the approved development volume requires
a user scope decision.

The user has approved **20 additional diagnostic attempts**: one intended
paraphrase and one different shared-episode objective per selected incident.
The ten native-validated seeds span five task families and are fingerprint-
bound to their validation reports and baselines. New task IDs preserve the
original data and outcomes; intended relationship labels require subsequent
verification rather than being assumed correct. Source, native and canonical
gates remain mandatory. This authorizes attempts, not 20 accepted questions or
any production split/release policy.

The initial expansion produced **11 source-ready candidates and nine holds**.
Native validation is running for the 11 eligible tasks. Six reviewer defects
are being corrected through fresh question/rubric revisions; three remaining
holds lack captured witness records and are not being forced through.
All ten intended paraphrases retain the original strict answer/checkpoint
contracts, windows and lineage, but relationship labels still require later
confirmation. Three inherited seed-selector defects (34 Q4, 134 Q2 and
322 Q5) are also under correction; old native outcomes and the frozen
20-attempt manifest remain unchanged.

All 11 eligible controls passed native admission with matching SecRL/ACE
components. Eight native submissions achieved grounded final success; three
correct but under-cited submissions retained reward 0.0. Mandatory checkpoints
remain present and creditable. Fresh batch footprints and canonical
annotations are in progress; intended paraphrase/related labels are not yet
treated as confirmed calibration truth.

All 11 native-admitted controls now have independently reviewed canonical
annotations. Six repaired control/seed revisions are in a second native
validation pass. The incident-134 typed mail-entity fixes passed 112 actual-SQL
mutation checks in DuckDB/MySQL, including reproduction of the old fixed-slot
failure. Two corrected controls remain genuinely proof-held, and the URL
control is being reworked again for entity-role selectors and full-precision
time scope. Relationship adjudication remains pending.

All three repaired controls and all three corrected seeds passed the second
native pass. The URL-representation control also passed fresh source and
native validation after adopting an explicit UTC calendar-day scope and typed
entity selection, without truncating its seven-digit metadata timestamp.
The expansion therefore has 15 native-admitted controls and five retained
captured-proof holds.

Broader paraphrase comparison exposed a canonical-selection defect: whole
`AlertIds` arrays could be selected as literal strings, bypassing the atomic
JSON-leaf rule. `source-fact-curation-v1.1` and feature version
`unit-canonical-source-facts-v2.1` reject valid serialized containers, including
nested encodings, both during resolution and when loading resolved facts.
Non-JSON literal strings, exact numeric tokens, quoted scalars and explicit
member-presence facts retain their existing semantics. Fact identity remains
`canonical-source-facts-v2`; eligible atomic facts keep their IDs.

The current 69 annotations (47 development tasks, seven original controls and
15 expanded controls) are being revalidated. Non-atomic selections and known
coverage omissions become explicit annotation holds, with original semantic
reviews and native outcomes preserved. Unaffected source facts remain
unchanged; only their versioned eligibility/footprint policy is updated.
Historical v2 matrices are not silently relabeled as current-policy results,
and small legitimate selection differences are not removed just to force
paraphrase scores to 1.0.

The mechanical pass retained 56 annotations and held 13. Nine fact-only
revisions passed; one schema-valid JSON-text reviewer verdict was recovered
without another model call or a fabricated finish call. Two ActionType
coverage revisions also passed, including an exact resume of one interrupted
reviewer that preserved its completed curator and original traces.
The remaining case required a real question/checkpoint correction, not just
fact selection: the incident-34 seed and its paraphrase now establish the
relocation timestamp as the lower boundary for the later update, without
claiming a complete before/after update comparison. Both passed fresh source
and native checks with reward 1.0, equal adapter components and mandatory
creditable checkpoints. Their new graph-verified baselines record the exact
immediate predecessors; fresh task-bound canonical annotations passed.

The current-policy assembly is complete: **69 reviewed annotations and 2,346
complete comparisons**, with **14,076 independent unit-set checks** covering
the four components and two historical exact-signature diagnostics.
The cohorts remain distinct: 47 development tasks, seven original controls
and 15 admitted expanded controls. Direct semantic comparison confirms nine
expanded paraphrases and four different-objective controls with material
shared behavioral evidence. The other two (incidents 36 and 134) share only
incident metadata with their seeds and are not positive shared-evidence
controls. Five attempts remain proof-held; no acceptance quota was imposed.

All nine expanded paraphrases have edge/observation overlap and containment
1. Six have fact overlap 1; three retain legitimate additional support facts
(an alternative process PID, mailbox entity type or another sufficient
deletion observation). These differences are preserved rather than normalized
away. The original seven-control regression remains unchanged.

Across the combined 36 labeled control pairs, every nonnegative sum-one blend
of the current unit components can separate the diagnostic labels with some
threshold; the controls therefore do not uniquely identify production
coefficients. An unselected conservative shared-behavior grouping scenario
leaves incidents 38 and 166 with one four-task component each, preventing a
within-incident train/test split under that particular rule. No coefficients,
grouping thresholds, split assignments, deletions or release decisions were
selected or applied.

The user then selected a target-versus-support inspection. For the eight
development tasks in incidents 38/166, 32 original/instrumented source queries
verified all 16 final/checkpoint response projections. There is no shared
final-response fact across the 12 within-incident pairs, but four pairs share
checkpoint response inputs. Task-relative roles preserve the difference
between a response-file substring and the full compiler command containing it.
They do not change canonical identities or mark supporting facts as split-safe.

Source-record exposure matters even when an output property is absent from
another task's selected facts: the other proof can still use the record that
contains that response. Under an unselected response-bearing-record grouping
scenario, incident 38 has two two-task components and incident 166 remains
one four-task component. No grouping rule has been adopted.

The trace also reproduced a positional alert-entity selector defect in the
pinned incident-38 Q2: prepending an unrelated entity removes both its final
and checkpoint outputs. The fresh typed process/host revision passed source,
native and canonical checks while preserving exact outputs and the answer
window. All 64 actual DuckDB/MySQL mutation checks passed, including missing-
anchor negatives; the old defect was reproduced in all eight original
answer/witness/backend combinations. The current 69-task matrix and all 16
response-role bindings were rebuilt/reverified without reusing old proof.
The target/support findings and unselected scenario sizes remain unchanged.
Historical outcomes remain intact, and no split constraint was adopted.

**Current split policy:** the user permits shared checkpoint responses,
supporting facts and source records between distinct questions, including
across question-level splits. Keep this overlap in the observation/fact/edge
components and containment; do not force shared-evidence groups or reject a
pair merely for overlap. The target/support analyses remain explanatory
diagnostics. Existing lineage metadata retains provenance, not an automatic
same-split requirement for different objectives. Genuine duplicate/revision
review remains separate, based on objective and scoped target rather than
answer-string equality alone. Results describe generalization to new questions
over potentially shared evidence, not an unseen-episode benchmark.

## I5: question-level split inventory and overlap audit

[question_splits.py](question_splits.py) accepts an explicit cohort of
native-admitted task revisions and independently reviewed canonical facts.
It checks each task, validation, exact-signature baseline, canonical bundle,
review, saved footprint and curation-runtime binding. Facts must remain inside
their particular final/checkpoint claim's evidence. Revisions of the same task
cannot enter a cohort twice, and mixed source/graph/serving versions are rejected.

The input manifest names existing artifacts, relative to the manifest or by
absolute path. For example, a **synthetic two-question cohort**:

```json
{
  "cohort_label": "synthetic-two-question-cohort",
  "questions": [
    {
      "task": "case-a/task.json",
      "validation": "case-a/private-pilot-validation.json",
      "baseline": "baselines/case-a.json",
      "annotation": "canonical/case-a"
    },
    {
      "task": "case-b/task.json",
      "validation": "case-b/private-pilot-validation.json",
      "baseline": "baselines/case-b.json",
      "annotation": "canonical/case-b"
    }
  ]
}
```

Audit the inventory without choosing any assignments or aggregate weights:

```bash
python -m secgym.qagen.agentic schema split-inputs
python -m secgym.qagen.agentic audit-question-splits \
  --inputs private-inputs.json --output private-inventory-audit
```

The new output directory contains `split-audit.json` and `pair-overlap.csv`.
These are **private review artifacts**, not student tasks or release exports.
They contain task/review fingerprints, per-incident and tenant counts, every
pair's four overlap components, shared-record/fact counts, lineage coincidence
and source-artifact hashes. They do not export answers, private checkpoints or
SQL. Summaries retain available-pair counts with minimum/mean/maximum, grouped
by scope, bucket pair and train/test relationship. Missing components stay
incomplete, not zero; missing aggregate weights leave scores uncomputed.

To request a deterministic proposal, provide a seed and exact positive
train/test counts for **every** included incident/tenant bucket. The counts
must sum to the existing admitted questions; this does not generate questions
or impose an acceptance quota. For the synthetic two-question example only:

```json
{
  "seed": 17,
  "counts": [{"bucket": "incident:34", "train": 1, "test": 1}]
}
```

```bash
python -m secgym.qagen.agentic schema split-request
python -m secgym.qagen.agentic propose-question-splits \
  --inputs private-inputs.json --request explicit-counts.json \
  --output private-split-proposal
```

`sha256-ranked-v1` orders questions independently within each bucket using
the explicit seed, bucket, task ID and task fingerprint. Input order does not
change the result. No edge, source, checkpoint or lineage grouping is imposed.
The output also contains `split-plan.json`, pinned to the full
task/native/fact-review cohort. Explicitly authored plans are supported too:

```bash
python -m secgym.qagen.agentic schema split-plan
python -m secgym.qagen.agentic audit-question-splits \
  --inputs private-inputs.json --plan reviewed-assignments.json \
  --output private-assignment-audit
```

Optional `--weights weights.json` supplies the existing `SimilarityWeights`
contract; no coefficients are supplied by default. A zero coefficient does not
make a missing required component scoreable. Output directories must be new
and outside annotation bundles. Invalid bindings/counts/assignments fail
explicitly; an incomplete component audit is saved and returns a nonzero CLI
exit status.

Every result explicitly retains `shared_evidence_grouping=false`,
`semantic_duplicate_review="not_performed"`, `split_review_approved=false` and
`release_approved=false`. A mechanical proposal does not perform semantic
duplicate adjudication or authorize an actual benchmark split/release.

Validation: 69 focused split/similarity/CLI tests pass. The first real inventory
contains 47 development revisions, excluding all 22 diagnostic controls.
Its 1,081 complete comparisons reproduce all 4,324 component values from the
reviewed calibration matrix. Every question remains unassigned and every
aggregate score remains uncomputed; no real counts, seed or coefficients
have been chosen by this validation.

The user subsequently authorized a **36 train / 11 test development proposal**:
one test question per incident plus one tenant test question, using seed **42**.
The requested equal coefficients (0.25 each) are explicitly diagnostic, not
production calibration. All assignments, 1,081 aggregate scores and 4,324
component values were independently checked. The 396 cross-split comparisons
include 31 same-incident pairs with mean overlap 0.138104 and maximum 0.422302;
the other 365 have zero measured overlap. No grouping or seed selection based
on those results was used.

A separate fingerprint-bound assistant review found no genuine duplicate
objectives among the 47 questions and 81 same-scope pairs. It does not rewrite
the automated audit's earlier review-status field, approve the split for
release, or reinterpret permitted shared checkpoints/source records as errors.
The user approved this exact 36/11 development split in a separate,
fingerprint-bound review record. The original proposal/audit artifacts remain
unchanged. Approval is development-only: production release/scoring choices,
training runs and additional QA generation remain separate decisions.

The next requested stage targets **1,000 new pre-production questions**:
50 per selected incident plus 500 tenant questions, separate from the frozen
47-question development cohort. The user selected capacity curves at overlap
thresholds 0.25/0.50/0.75/0.90, not a hard rejection cap, using the existing
equal-weight diagnostic score. The initial envelope is up to 100 new logical
attempts per incident and 1,000 tenant attempts (2,000 total), with yield and
capacity reporting before extension. No absolute capacity or accepted quota
is guaranteed. See design Section 17.36.

**Difficulty sidecar prototype:** the strict task contract remains unchanged;
computed difficulty lives in separate private sidecars. The ExCyTIn 2.0 bootstrap includes structural
hop bands and a small table/pivot heuristic, while its final tier comes from a
solver panel that already includes Astra and Luna. We must not use that
model-derived tier as the independent predictor for an Astra/Luna comparison.

Design Sections 17.37-17.38 describe private, versioned difficulty sidecars based on
necessary evidence breadth, logical dependency depth, reasoning operations and
source-verified ambiguity. Raw graph size, entity types, output/citation
burden and runtime statistics remain available as separate descriptors.
Full overlap footprints are not assumed to be minimal reasoning graphs.
Missing measurements stay unknown; existing task/native/fact fingerprints and
blind prompts remain unchanged. The proposed score/bands are explicitly
uncalibrated hypotheses, not generation gates or reward changes.

A later, separately configured model evaluation will test grounded-success
trends and paired model differences under recorded harness/budget settings.
The first bounded pre-production attempt has completed every admission gate:
one validated new question, from one logical attempt inside the approved
envelope. No bulk wave or release/training approval is claimed.
The separately approved, matched
Luna/Sol/Astra development panel has completed all 141 episodes; it changes
neither the heuristic nor its provisional labels or the frozen development split.

### Opt-in pre-blind source quality gate

[quality.py](quality.py) adds `source-quality-v1` without changing historical
task contracts, grading, admissions or the approved development split.
New guarded source pilots use `--quality-gate` (API: `quality_gate=True`).
Their native caller must use `require_source_quality=True`; native validation
also checks quality artifacts automatically whenever the candidate carries them.
These settings are required for the planned pre-production runner, not retroactive
changes to recorded development runs.

The gate:

- Screens every final/checkpoint answer, witness, obligation and candidate
  query in both dialects for positional JSON paths, computed paths and
  potentially serialization-dependent text comparisons. Named object keys
  containing brackets are not array positions.
- Executes each multi-member set/list answer on an isolated DuckDB view
  containing **one complete witness alternative alone**. Other tables are
  empty; private anchors and other alternatives are not implicitly supplied.
  A declared-evidence-union control distinguishes individual proof failures
  from an unresolved fixture. Existing result/time limits apply. Query errors
  remain errors, never empty answers or passing checks.
- Holds non-reproducing collections before a blind student starts. A question
  or rubric repair is required; removing checkpoints is not a remedy.
- Requires a fresh independent quality/refutation role to retrieve all
  representative source records with actual source fields, review whole
  claims and explicitly disposition every selector finding. Genuine publicly
  specified order or exact representation can be justified with an exact
  public quote; numerical paths are not universally banned.
- Keeps the review away from student outcomes and retains its exact ordinary
  review as the native refuter projection. Bound audit/review/runtime hashes
  and captured inspection artifacts are checked on native admission.
- Resumes completed roles without new model calls, preserves failed student
  outcomes and rejects changed policies, inputs or existing quality artifacts.
  Unordered set-result order is canonicalized for stable audit fingerprints;
  ordered-list semantics are preserved.

This is **not** a general proof of witness sufficiency. Scalar counts, absence,
ranking/common-value cohorts and all qualifying alternatives still need
semantic review and targeted robustness tests. The static scan is conservative,
not a complete SQL analyzer; derived scalar aliases and safe scalar membership
require explicit source-grounded review. The collection fixture executes
DuckDB, not MySQL. Actual native parity and appropriate backend mutations remain
separate gates. No difficulty/overlap quota or release approval is introduced.

The read-only diagnostic command makes **no model calls** and does not change
an existing question's admission:

```bash
python -m secgym.qagen.agentic audit-source-quality \
  --task private-task.json --serving-bundle public-view \
  --limits query-limits.json --allowed-literals reviewed-literals.json \
  --output private-quality-audit.json
```

Its output always requires independent review. It exits nonzero for failed
collection reproduction or operational errors and refuses to overwrite a file.
Schemas are available as `source-quality-audit` and
`source-quality-assessment`. Per-scope attempt accounting, complete resumable
multi-stage orchestration and backend robustness automation remain prerequisites
before the 1,000-new-question generation wave.

### Isolated backend robustness checks

[robustness.py](robustness.py) runs explicit source-bound counterfactual plans in
disposable DuckDB and MySQL fixtures. The MySQL process, datadir and socket are
created under an explicit scratch parent and removed after that process stops.
The runner never accepts a writable connection to an existing snapshot.
Source records are copied only after their actual values and provenance verify.

Each plan binds the exact task fingerprint, identifies cell edits or physical
record omissions, and specifies the expected answer, complete witness groups
and proof-support outcomes for every final/checkpoint claim. Baseline fixtures
must reproduce the full-source answers, representative witnesses and
available-citation support before counterfactuals run. All records, no records
and each single-record omission are tested as citation availability probes.
Qualified catalogs/candidates/shared bindings are executed, not inferred from
representative labels. Witness alternatives are compared as whole citation
groups, independently of backend-specific bookkeeping labels.

JSON helpers preserve numeric tokens exactly, distinguish whole-text formatting
from explicit array operations, and reject nonexistent/no-op interventions.
Singleton arrays cannot certify order invariance; prepend controls can still
test whether a selector incorrectly assumes the first member. Empty set/list
answers remain distinct from absent scalar answers. Incomplete baseline
fixtures and query errors remain different non-passing outcomes.

New plans use `isolated-source-robustness-v2`; archived v1 plans/reports remain
readable. In v2 counterfactuals, context-only residual witness rows are recorded,
but cannot support a behavior-required claim. Baseline behavior requirements,
unknown-record rejection and grounded-final grading remain strict.
Enumerated support is a program-level containment/lineage measurement, not a
certificate that residual rows prove the original interval or typed answer.
Independent plan reviewers receive only the current expectation arrays.
Author revision history and prior verdicts are excluded; explicitly authorized
intervention changes are compared without showing stale expected answers.

The author and executor share structural expectation validation. Expected
witness IDs must belong to the fixture. Enumerated availability vectors are
checked against independently declared witnesses, actual source lineages and
the exact probe order, not copied from counterfactual SQL output. Qualified
support is still resolved from its obligations/candidates, never inferred from
representative unions. Empty collections are not automatically coerced from
null. Each DuckDB world recreates its tables before loading rows, preventing
prior-world optimizer statistics from contaminating CTE/UNION witness results;
optimizations are not disabled globally.

Annotation-only revisions cannot change interventions. Explicit
`--robustness-control-repairs` mappings authorize corrections to named prior
controls with source-backed reasons. Every old case and its scope remain;
existing fixture records cannot be removed, and fresh source inspection and
independent semantic review are still required.

```bash
python -m secgym.qagen.agentic check-robustness \
  --task private-task.json --plan robustness-plan.json \
  --serving-bundle public-view --limits query-limits.json \
  --allowed-literals reviewed-literals.json --mysqld /path/to/mysqld \
  --scratch /path/to/project --output private-robustness-run
```

The report covers the finite declared tests, not general proof sufficiency,
complete negative/ranking cohorts or all candidate combinations. Plan semantics
still need review. A `portability_diagnostic` is not automatically an in-contract
defect, and no diagnostic rewrites a question or changes admission.

Fresh checkpoint validation is not the normal already-admitted shortcut.
`finish-preproduction --fresh-validation` requires the existing native student
trace for admitted questions and writes a separate immutable certificate under
`revalidations/<task-id>/`. It does not replace the original admission, resample
a student or increment the admitted count. A run-level
`checkpoint-revalidation-required.json` blocks both checkpoint generation and
legacy source waves while an approved revalidation is pending.
Concurrent reservation, source-publication and admission metadata writes must
queue using `locked_run(..., wait=True)`; contention is not a failed question.
Keep model/network work outside these short transactions. Whole-run ownership
continues to reject a second owner by default.

The original first Astra checkpoint is now fully reconciled as a fixed cohort:
**92 current validation clearances and eight independently verified scoped-objective
duplicate exclusions**, accounting for all 100 original logical questions.
All fifteen original admissions have fresh clearances; no historical admission
lacks current validation, and no pipeline/grading hold remains unresolved.
This does not mean all 100 were admitted. Original histories and completed
students were retained, no replacements were generated, and subsequent batches
remain blocked.

For the five development selector flags, 80 actual backend claim checks and
16 full-source typed-selector equivalence checks are retained. The tenant rule's
computed paths traverse every parameter and withstand formatting, order and
unrelated-parameter changes. Four alert questions rely on the verified compact
JSON emitted by the core source producer: in-contract controls pass, while
16 failures under direct post-serving reformatting remain explicit portability
limitations. This resolves the fixed-snapshot evaluation question, not a blanket
waiver for new generation; new questions should use typed, serialization-independent
selectors.

### Matched development model panel

[model_panel.py](model_panel.py) runs new episodes over the already admitted
47-question cohort. The approved panel is **141 episodes**, one per question
for `gpt-6-luna`, `gpt-6-sol` and `gpt-6-astra`, on the existing Azure/Entra
endpoint. Each episode has medium reasoning effort, at most 64 model responses
and 64,000 total output tokens, at most 16,000 output tokens per response,
a 300-second model request timeout, and SQL limits of 500 rows/64 KiB/30 seconds.
The final request's output allowance is reduced to the remaining episode budget.
Unsupported deployment/settings errors are not silently replaced by another model
or profile.

After repeated private-reference SQL timeouts, the user approved a versioned
amendment allowing **120 seconds for private grading queries only**. Student
SQL remains limited to 30 seconds; models, reasoning, tokens, response limits,
rows and bytes are unchanged. Separate student/grader connections prevent
the larger oracle timeout from reaching a model tool. Original manifests,
evaluator source and completed outcomes remain preserved. A completed captured
student can be imported into a new grading output with exact task/model/profile
and trace bindings, without another model call.

The amended panel explicitly distinguishes retained parent-runtime outcomes
from newly graded outcomes. Analyze it with
`--manifest manifest-amendment-01.json`; the report records the grading-timeout
distribution. This changes neither question fingerprints nor heuristic values.

Each model receives a fresh public-only context. Gold, checkpoint IDs and
difficulty labels never enter the prompt. `store=False` and encrypted reasoning
replay remain in effect. Original development students are not retried or
overwritten. Completed episodes, including failures, are immutable; known safe
boundaries can resume, but ambiguous completion boundaries require explicit
recovery rather than another model sample. Grading interruptions can recover
without restarting the student.

The opt-in captured-result adapter validates **the exact SQL results received
by the student**. It does not rerun failed student queries and accidentally grant
evidence from a later successful execution. Unexecuted truncated output supplies
no observations. SecRL and native ACE grade the same captured observations and
must agree. Budget exhaustion/abstention can retain grounded checkpoint progress
without inventing a final answer; operational failures remain ungraded/unknown.
Default live adapters and historical outcomes are unchanged.

[panel_analysis.py](panel_analysis.py) reports grounded final success, separate
answer/citation outcomes, checkpoint progress, resource use, continuous-score
correlation, per-band descriptive intervals and paired differences with
scope-cluster bootstrap intervals. Incomplete panels are labeled partial;
operational errors never become false zero-accuracy measurements.

```bash
python -m secgym.qagen.agentic analyze-model-panel \
  --panel private-panel-run --output private-panel-analysis \
  --bootstrap-samples 2000 --seed 42
```

This is exploratory validation of a frozen heuristic, not production
calibration or a controlled parameter-count experiment. The cohort has
10 medium, 31 hard, six very-hard and no easy questions. Small bands and shared
evidence limit precision. Any later tuning needs independent pre-production
confirmation; outcomes are never inputs to the four-axis score.

The completed panel's grounded successes were:

| Difficulty | Questions | Luna | Sol | Astra |
|---|---:|---:|---:|---:|
| Medium | 10 | 7/10 | 10/10 | 9/10 |
| Hard | 31 | 7/31 | 23/31 | 24/31 |
| Very hard | 6 | 0/6 | 2/6 | 0/6 |
| All | 47 | 14/47 | 35/47 | 33/47 |

This supports the ordering as an exploratory predictor of **grounded
completion**, not calibrated general reasoning difficulty. Typed-answer
correctness alone was 45/47, 47/47 and 47/47: 57 of the 59 unsuccessful grounded
outcomes had a correct final answer. Citation/proof requirements drive most of
the separation. Sol and Astra both outperform Luna on this cohort, but the
paired Sol/Astra difference is not clearly resolved. No weights or thresholds
have been tuned; retained-trace evidence review and independent pre-production
confirmation remain necessary.

The table above is the immutable **original grading** result. The subsequent
four-task source-reviewed corrections described below change grounded totals
to **Luna 15/47, Sol 35/47, Astra 37/47**, without new student samples. The
subsequently approved complete audit-event alternative brings Astra to **38/47**;
the time-unqualified alternative for incident 36 was rejected. Do not treat
these small differences as an established model ordering.

### Source-reviewed grading corrections and reflection

[grading_review.py](grading_review.py) provides an opt-in, exact-task-bound
grading amendment rather than rewriting the original task or evaluator:

- **Supporting evidence:** the submitted citations must still contain a complete
  original proof, including all qualified obligations and coherent bindings.
  Additional citations must match explicit, claim-local source queries and
  contain verified source IDs and fields. Other context cannot fill a missing
  core proof member; fabricated, unobserved or out-of-scope records remain
  uncredited.
- **Checkpoint identities:** an alternative identifier must be an atomic
  property of the same cited source record and, for JSON, the same source
  subject object. The canonical property must equal the original checkpoint
  value. This allows verified object-ID/UPN representations without fuzzy
  aliases, role splicing, format changes or final-answer normalization.
- **Review and reflection:** separate conversations inspect the actual source
  records, with the second pass challenging the first review. Both must pass
  all rules before the amendment is usable. Neither receives evaluated-model
  identities, aggregate scores or desired difficulty labels. Reflections can
  block a policy for repair; they cannot award a score by opinion or waive a
  checkpoint.

Legacy [evaluator.py](../../evaluator.py) permits its reflection model to replace
the initial answer/step verdict. This workflow instead keeps deterministic,
source-bound scoring authoritative and versions any approved rule correction.
The reflection step currently reviews **grading-policy corrections**, not every
student response. A rejected review is retained, not converted to a pass.

`GradingAmendment` and `ReviewedGradingAmendment` schemas are exposed through
`schema grading-amendment` and `schema reviewed-grading-amendment`.
`review_grading_amendment` records the independent traces;
`load_reviewed_grading` verifies their integrity and runtime bindings.
`ReviewedEvidenceVerifier` is compatible with the existing SecRL/native ACE
adapters. Its score components carry the reviewed-policy fingerprint. Existing
callers using `EvidenceVerifier` keep their original strict behavior.

For the two very-hard Sol-only successes, full-source investigation showed
that Astra submitted the same accepted proof as Sol, plus genuine comparison
records. The additions were two incident-member recovery-tampering alerts in
incident 5 Q1, and a later same-editor/same-policy non-interactive sign-in in
tenant Q10. All were genuinely retrieved. Tenant Q10 also recorded the editor's
object ID rather than the private UPN spelling. These observations motivate
the explicit amendments; they do not justify broadly accepting arbitrary
additional citations or weakening proof completeness.

Those two amendments now pass actual source/native validation and paired replay:
Astra passes both very-hard finals and its object-ID checkpoint, while Luna's
incident-5 complete-proof-plus-context submission also gains correct credit.
Two further reviewed context rules fix incident 5 Q5 and tenant Q3 for Astra.
Across the four corrected tasks, all three models were evaluated under the same
rules; no original outcome was overwritten. The incident 166 audit-event alternative subsequently passed source/native,
canonical and difficulty revalidation as an explicit r2 revision. Both original
and alternative complete proofs remain supported, including the checkpoint.
Incident 36's proposed route dropped a public time condition and was not admitted.

### Guarded pre-production source waves

[preproduction.py](preproduction.py) adds the source-wave/accounting foundation
for the approved **1,000-new-question target**. Its immutable plan fixes 100
logical attempts per selected incident and 1,000 tenant attempts: **2,000 total**.
The targets remain 50 validated questions per incident and 500 tenant questions,
not guaranteed yields. Existing development questions are novelty context,
not new accepted questions.

The plan pins the default validation/student model, endpoint digest/API settings,
source and graph identities, query limits, checkpoint cap and implementation
hashes. The legacy source-wave version accepts `gpt-6-sol`; the checkpoint
workflow below separately binds Astra drafting without rewriting that plan. Source
pilots always require `quality_gate=True`. The runner owns a project/run-local
lock and immutable logical allocations, role traces, terminal source outcomes
and wave reports.

- Compile repairs and model requests do not allocate another logical attempt.
- Completed attempts, including errors and quality holds, are not rerolled.
- Safe interrupted tool boundaries can resume the same attempt. An ambiguous
  completion, accepted finish without its result, or terminal abstention
  requires explicit recovery rather than another model sample.
- Source insufficiency, post-compilation review/solver holds and operational
  errors remain distinct. An operational error is persisted and raised.
- Per-scope reports expose source-candidate yield, remaining attempt budget,
  recorded model calls and compile repairs. An exhausted search envelope is
  not a claim of absolute source exhaustion.

`run_source_wave` executes an explicit bounded wave; the mechanical CLI can
verify its retained accounting:

```bash
python -m secgym.qagen.agentic schema preproduction-plan
python -m secgym.qagen.agentic preproduction-progress --run private-preproduction-run
```

#### Astra generation with 100-candidate review checkpoints

[checkpoint_batches.py](checkpoint_batches.py) separates drafting from semantic
reviews and final admission. Its versioned policy routes **new author/repair
roles to `gpt-6-astra` on the same endpoint**, with 900-second HTTP limits.
Reviewers and students retain their original Sol settings. Every generation
request records its actual model/configuration; started roles cannot switch
models or replay another model's encrypted context.

The default checkpoint contains **100 draft-ready candidates: five per selected
incident and 50 tenant questions**. Allocation uses the original campaign's
remaining logical slots, so neither the 2,000-attempt budget nor the 1,000-new
admission target is reset. Unsupported/failed generation attempts remain
recorded and counted. They do not count as completed drafts.

Four independent workers perform discovery and authorship in one role per
candidate, without a separate per-question scout/refuter cycle. Deterministic
checks still run before a draft is accepted: source compilation, whole-collection
proof coverage, explicit public-anchor literals and width-free MySQL declarations.
These checks are not semantic approval. Source reviews and blind students cannot
start until the checkpoint is filled.

```bash
python -m secgym.qagen.agentic generate-checkpoint \
  --run private-preproduction-run --batch-id astra100-01 \
  --serving-bundle private-public-view --graph-bundle private-evidence-graph \
  --env-file private-model.env --checkpoint-size 100 --workers 4 \
  --review-at-checkpoint --mysql-bundle private-mysql --workdir /tmp

python -m secgym.qagen.agentic checkpoint-progress \
  --run private-preproduction-run --batch-id astra100-01
```

`--max-new-attempts 2` supports a small generation smoke run in the same
checkpoint; omitting it later resumes the remaining slots without resampling
completed drafts. An unfilled checkpoint stays visibly unfilled. If all workers
in a generation wave return operational errors, generation pauses instead of
consuming the remaining campaign budget on a likely shared failure.

At the checkpoint, independent source reviews run concurrently. Each outcome,
including a hold or operational error, is persisted separately; one failed item
does not abort the other reviews. Source-ready items then enter the existing
admission gates in parallel. The full MySQL snapshot is leased **only during
native validation/student/replay work**, not while source-only model roles run.
Robustness fixtures remain isolated. Final objective novelty and admission are
serialized against the current global inventory.

The objective helper must not reacquire the finalization lock already held by
its caller. An exclusive lock followed by a shared lock on another file
descriptor self-deadlocks; a regression test now covers that exact case.
For an interrupted pipeline whose grading, native, baseline, robustness,
canonical and difficulty stages all passed, the explicit
`finalization_runtime_archive` API can resume only finalization. It requires the
exact archived original producer, unchanged task/source/student bindings and
no started objective-review request. Only pipeline orchestration may differ.
Original stage bindings remain intact; an appended execution certificate records
the new runtime. Completed students and earlier model roles are not rerun.

`review-checkpoint` runs review separately after generation. `repair-checkpoint`
accepts selected `--task-ids` from a completed checkpoint and regenerates/reviews
pre-blind source-quality failures as tracked same-attempt revisions. It preserves
their typed goals and scope. Started/completed students require supervised
retained-trace repair, not automatic regeneration. Later grading, robustness,
canonical, difficulty and novelty holds remain in the repair queue.

Progress reports distinguish drafts, source readiness, admission, retained
failures and cumulative campaign counts. The original admissions, development
split and legacy artifacts remain unchanged; 100 drafts never means 100
admitted questions or release approval.

#### Persistent read-only SQL service

[snapshot_service.py](snapshot_service.py) owns one long-lived MySQL process for
a verified tenant snapshot. Incident and tenant questions reuse that same full
snapshot; task scope does not create another database copy. The service holds
the existing datadir ownership lock and runs with both `read_only` and
`super_read_only`, networking disabled and a private Unix socket.

```bash
# Run under a long-lived process/service supervisor.
python -m secgym.qagen.agentic.snapshot_service serve \
  --run private-preproduction-run --service-directory private-sql-service \
  --serving-bundle private-public-view --mysql-bundle private-mysql \
  --workdir /tmp --native-slots 4 --wait-for-workflow

python -m secgym.qagen.agentic register-sql-service \
  --run private-preproduction-run --service-directory private-sql-service

python -m secgym.qagen.agentic sql-service-status --run private-preproduction-run
```

`--wait-for-workflow` waits for the existing checkpoint owner to finish before
starting MySQL. It does not kill or restart in-flight students. Registration
requires actual readiness; once registered, `finish-preproduction`,
`review-checkpoint`, `repair-checkpoint` and automatic review after
`generate-checkpoint` use the shared service. Unregistered runs retain their
legacy behavior. A registered but unavailable or mismatched service fails
explicitly rather than falling back to another server on the same datadir.

Each native candidate leases a bounded slot and receives **two fresh,
independent SELECT-only sessions**, one for the student and one for the grader.
Their existing row/byte/time limits are unchanged. Session state cannot leak
between candidates, and an instance nonce detects stale/restarted services.
Snapshot/schema verification occurs at service startup; the native verifier
reuses the candidate's already verified source snapshot with a separate private
metadata cursor. Existing query/grading methods are unchanged. The native stage
records the instance, connection IDs, source binding and effective limits.

Robustness mutations continue to use separate disposable fixtures. They never
modify the persistent public snapshot.

```bash
python -m secgym.qagen.agentic.snapshot_service stop \
  --run private-preproduction-run --service-directory private-sql-service
```

Shutdown rejects new leases and waits for existing native candidates to drain.
It cleans up its owned socket/process, not the snapshot data. New checkpoint
batches reuse the registered service without changing their Astra generation
or Sol validation/student model bindings.

Native index upgrades require an explicit, append-only amendment, not an edit
to the original run plan or index reports. The approved v7 addition is the
non-unique `MicrosoftGraphActivityLogs(RequestMethod(16), TimeGenerated)` index.
Drain the service, take exclusive datadir ownership, preserve all historical
reports, and verify every indexed-table row against its original source digest
before recording the upgrade through
`record_native_index_amendment`. Start the replacement under a new service
directory, then register it; routing appends a hash-linked revision and requires
the previous service to have stopped. The allocation plan and completed student
bindings retain their original index version. New native validation records
the effective version; only explicitly approved historical versions can be
imported. Student traces and query budgets are never rewritten or rerun.
Unchanged tables retain their original complete-snapshot verification; the
upgrade does not falsely claim a new full-snapshot scan.

Feature-only difficulty holds can continue with `--parent-pipeline`,
`--parent-runtime-archive`, and `--difficulty-feedback`. The continuation
verifies and reuses the completed grading, native, baseline, robustness and
canonical stages. It runs the existing source-only difficulty revision process
against the sealed prior review, followed by the remaining admission gates.
It does not rerun students, alter the question, waive a task defect, or reuse
a stage whose protected implementation changed.

Difficulty curation v0.4 supplies the complete DuckDB witness programs,
including qualified-obligation catalogs and candidate queries, alongside the
answer programs. Representative evidence sets are not an exhaustive list of
qualified proof alternatives. Neither role receives student outcomes or
requested difficulty scores.

Source audit manifests historically also included the difficulty-context module.
An archived annotation-context amendment can preserve those completed source
reviews only after AST checks prove that curation logic and source-quality
semantics are unchanged. Both exact producers are pinned; only the context
builder/version and the explicit producer-chain guard may differ. Unknown
producer histories or changes to source, query, scoring or difficulty rules
still require fresh validation. An interrupted role resumes its original
archived producer and original context, never a silently rewritten request.

`--recover-contaminated-robustness-review` is a one-use recovery for a captured
review that demonstrably included author-only history. It requires the exact
unchanged current-policy plan, its held parent, prepared-plan path and feedback.
It preserves every control, reserves the original request once, and still
requires independent source inspection and a fresh backend matrix. Clean
reviews, passing reviews and altered plans cannot use this route.

Initially unsent nonstudent calls have a separate
`authorize_pre_request_recovery` protocol. An explicit approval must bind every
request and the recorded failure evidence; all request contexts must match,
and no response, tool result or terminal completion may exist. Only proven
credential-preflight or dispatch-guard failures qualify. This never fabricates
a response or labels authentication failure as an HTTP timeout.
Versioned transport amendments preserve the original policy and role budgets;
run-level callers resolve their hash-linked current policy rather than silently
rebinding an old policy file.

An admitted question's private proof contract can be repaired only through a
separate `record_admitted_contract_revision` authorization after a sealed,
source-ready revision. The exact public task, typed goals, checkpoint weights,
scope, reward and evidence-lineage requirements must remain unchanged.
`--admitted-contract-revision` requires `--fresh-validation`, the original
retained native student and all current gates. It writes a new revalidation
certificate, never replaces the historical admission or counts the question
twice. Novelty comparisons use the exact task pinned by the historical
admission, not an unvalidated newer source revision.

Named source-backed control-repair authorizations can also correct materially
false rationale text without changing correct answer/witness/support vectors.
Unrequested prose-only changes remain prohibited, and independent review and
the actual backend matrix remain required.

An operational interruption after a completed native stage has a distinct
`record_native_prefix_import_authorization` path. It requires the owned,
inactive pipeline, its actual downstream error, exact native-stage receipt,
producer archive and unchanged artifact inventory. The authorization is not
a held/passing pipeline report and does not admit a question. Normal retained
import still verifies the original student termination, capture, limits and
frozen evaluator before any reuse.

Qualified proof diagnostics distinguish complete observed support from
submitted-citation relevance. Candidate SQL must return complete required
source bundles, even when some required rows are not supplied; the frozen
solver rejects incomplete availability. Source candidates can be activated
with actual supplied/source joins, but prematurely filtering out incomplete
comparison bundles can wrongly reject a complete smaller proof with legitimate
scoped context. Mixed-context, missing-essential-member and unrelated-extra
controls are required alongside minimal-positive probes.

An unanswered nonstudent call with an actual recorded HTTP 500 can use
`ServerErrorRecoveryApproval` and
`recover_review(..., server_error_approval=...)`. This is a separate, one-use
recovery, not a timeout or an unsent-request certificate. It binds the request,
error, dispatch receipt, original model settings and unchanged conversation;
it cannot restart completed roles, recover students, or retry a second failure
automatically. Deploy transport changes through the run's policy amendment
chain before recovering an existing role.

Checkpoint source repairs must follow sealed source ancestry when a failed
review left the latest revision without a student pointer. That absence is not
permission to resample an earlier completed student. Source reviewers also need
actual native physical-column collation/padding evidence, not assumptions about
MySQL defaults; computed/JSON-derived values require separate consideration.
Probe relevance comes from the source-qualified catalog, which may contain
legitimate records outside the representative evidence sets.

Robustness author/reviewer contexts declare each claim's witness policy.
Enumerated support requires whole emitted-group containment. Qualified support
instead requires a coherent complete obligation/candidate proof; it does not
add an emitted-representative-group prerequisite. Representative rows,
availability support and typed-answer correctness remain separate measurements.
This distinction does not waive semantic comparison/completeness review.

`--qualified-support-review-recovery` accepts an exact
`QualifiedSupportRecoveryApproval`. It requires the unchanged held plan, the
identified ambiguous prior context, and a passing, producer-bound diagnostic
covering every case/claim/backend with actual counterexamples to representative
containment on both engines. Its one-use certificate permits fresh independent
review and measurement, never admission by diagnostic result; the reviewer is
not shown those diagnostic outcomes.

Correct counterfactual controls may also survive a separately reviewed,
goal-equivalent executable-contract repair unchanged. A source-task revision
alone, program renaming, whitespace or comments cannot authorize resampling.
The changed executable contract is recorded and still needs fresh semantic
review and actual backend measurement.

Shared validation captures native physical-column collations in a separate
metadata-only SQL lease, then reuses the task/snapshot-bound context for grading.
It never starts a student during that inspection or reuses its lease receipt
for the later native stage. Context caches and their lease artifacts are
validated on resume.

Source readiness alone never counts toward the validated target.
[preproduction_admission.py](preproduction_admission.py) now verifies the final
private admission packet: exact native source/index/model/query bindings,
source-quality checks, native SecRL/ACE agreement, actual complete backend
robustness measurements plus their semantic review, a separately reviewed
grading contract, canonical evidence, reviewed difficulty and a distinct
scoped-objective review bound to the current comparison pool.

```bash
python -m secgym.qagen.agentic schema preproduction-admission-files
python -m secgym.qagen.agentic admit-preproduction \
  --run private-preproduction-run --files private-admission-files.json
```

Paths in the admission file are resolved relative to that file. Admission writes
an immutable receipt, counts the logical question only once and never silently
replaces an accepted revision. Sources stop generating new attempts for a scope
once its validated target is reached. Surplus candidates are retained, not
silently rejected or admitted beyond the target.
Receipts pin both runtime-amendment records and their verified archive ZIPs;
subsequent progress checks detect changes to either.

A measured student failure does **not** make a validated question inadmissible.
Likewise, reviewed but unavailable difficulty measurements retain a null score
and band rather than creating a difficulty quota; actual task defects still
block admission. There is no overlap admission cap or release/training approval.

The source-wave runner and final admission validator are implemented. The first
manually coordinated bounded attempt exercised every gate and produced one
verified admission. The second remains held because its retained source solve
did not observe the incident-alert bridge. The third completed the reusable
pipeline, including a reviewed robustness-annotation correction, with private
gold and completed students unchanged. The verified milestone is
**2/1,000 new questions from 3 completed logical attempts**; a bounded
three-attempt source wave is now underway within the original 2,000-attempt
envelope. Source readiness alone never counts toward the target.

[preproduction_pipeline.py](preproduction_pipeline.py) now connects contract
review and independent reflection, actual native validation and captured-result
SecRL/ACE grading, exact graph footprints, source-authored/semantically reviewed
backend counterfactuals, canonical facts, model-independent difficulty, scoped
objective review and the existing final admission boundary:

```bash
python -m secgym.qagen.agentic finish-preproduction \
  --run private-preproduction-run --task-id preprod-v1-incident-34-01 \
  --serving-bundle private-public-view --graph-bundle private-evidence-graph \
  --mysql-bundle private-mysql-snapshot --env-file private-model.env \
  --workdir /tmp \
  --output private-preproduction-run/attempts/preprod-v1-incident-34-01/pipeline/r1
```

This command makes approved-model calls and owns a temporary-socket MySQL
process on the verified snapshot; it never chooses an arbitrary existing
service. Student and private-grader query limits stay distinct. Add `--resume`
only for the same bound output; an already completed pass or hold is retained,
and completed students are never rerolled. Interrupted grading reuses captured
results, while partially published grades recover from a selected completed
replay. Ambiguous requests or accepted-finish/incomplete-file boundaries fail
closed rather than requesting another answer.

Stage receipts bind inputs, code and artifacts. Outputs must be in a direct
child of the attempt's separate `pipeline/` directory, never original/revised
source history. A new task/policy revision with an existing native student
requires supervised retained-trace import, not a fresh native episode. Existing
task-bound reviewed policies may be supplied with `--grading-policy-directory`.
For an equivalent private task revision, supply all three
`--retained-native-pipeline`, `--retained-native-task` and
`--retained-native-runtime-archive` paths, plus
`--prepared-robustness-plan` and `--robustness-feedback`. This explicit mode
currently requires a direct held parent with a completed native stage and
the unchanged default grader; it cannot be combined with annotation-parent
flags or a grading-policy override. Fresh source quality is required first.
Public content must match exactly except for the revision identifier, and
typed final/checkpoint goals, dependency structure, reward, snapshot, model,
limits and generation/capture/grading protocols must be preserved.
The archive must cover both parent-pipeline and native-stage producer bindings.
The original student directory is referenced read-only, including abstentions
and failed SQL. Native validation runs again for the repaired task, then both
adapters replay only the original captured results. All referenced files and
the archive are pinned in the final receipt. Missing import arguments cannot
reopen an imported stage as a fresh student.
Canonical orchestration reuses the established source resolver, prompts and
contracts, adding separately pinned exact-role recovery without rewriting
historical curation kernels or producer hashes.

Sixty-five focused tests pass, including actual isolated MySQL robustness and native
ACE replay recovery. An actual owned-snapshot cache check made zero model calls
and left the first admission unchanged. Fresh live end-to-end execution and
annotation-only continuation have now produced the second verified immutable
admission; this is not a claim that the 1,000-question generation is complete.

A held robustness **annotation** can continue in a new sibling output with
`--parent-pipeline`, `--parent-runtime-archive` and `--robustness-feedback`.
An optional `--prepared-robustness-plan` supplies a deterministic correction
instead of calling another author. This requires the unchanged task/source/
model/grading policy, an exact archived parent producer, unchanged protected
kernels, and hash-verified completed grading/native/baseline stages. Those
stages and their student recordings are referenced, not rerun or overwritten.
Every original intervention and fixture member must remain; a prose-only
change cannot resample a held proposal. Fresh independent source review and
actual backend measurements are still mandatory.
A robustness-held continuation may replace its unimported robustness runner
and final-admission coordinator, as well as pipeline orchestration, under
the exact parent archive. The runtime module inventory and every imported
stage's protected kernels must remain unchanged. A canonical-held continuation
still protects the already-passed robustness implementation.

A canonical-fact hold can similarly continue with `--canonical-feedback`
instead of `--robustness-feedback`. It also retains completed robustness
measurements, passes the previous source-fact selection and independent review
to the new curator, and requires materially changed references rather than
prose-only resampling. A fresh independent source review remains mandatory;
the task, baseline, grading and completed students cannot change.

Robustness answer, raw witness-query output and available-citation support are
separate measurements, not three interchangeable final-success signals.
Citation probes vary availability without deleting fixture records. A negative
world can have no scalar answer but nonempty cohort-query output; the real
claim verifier still requires its answer query to match typed gold before
accepting witnesses. Expected measurements must describe that behavior
accurately rather than incorrectly declaring the raw output empty.
For different alternative-program outputs, `answer.by_program` maps every
answer-program ID across both dialects to its exact typed answer or null.
Missing/unknown IDs and changed public answer formats fail before execution.
Scalar, null and `"baseline"` expectations retain their existing strict
meaning for every program. Both fixture execution and final admission verify
the exact output-vector length and each program's result; null is not an
empty collection or permission to ignore a failed SQL call.
The incident-36 continuation passed all 36 checks and subsequent canonical,
difficulty and objective reviews. Its reviewed source-only difficulty is
**60.0 hard (B2/P1/R3/A1)**. The original 12-call source and 10-call native
students were retained; native final success and zero checkpoint progress
remain unchanged.

Incident 55's actual r4 task has now become the third admitted question after
52 passing backend checks and all remaining reviews. Its source-only difficulty
is **70.0 hard (B2/P3/R2/A1)**; the first native student used 12 calls with final
success and zero checkpoint progress. Incident 39's corrected 22-fact annotation,
difficulty and objective reviews then passed without rerunning its completed
native or 28-check robustness stages. It is the fourth admission, with
**43.33 medium (B2/P2/R1/A0)**. The verified milestone is **4/1,000 new admissions
from 6 completed logical attempts**; a bounded five-attempt source wave is
underway. No release or training approval is implied.

The first incident/tenant source round has now allocated 11 attempts. Three
additional source-ready candidates (incidents 133/134 and tenant question 1)
entered downstream validation. Tenant question 1 passed all gates, becoming
the fifth admission with **46.67 medium (B1/P2/R2/A0)**, grounded native final
success and full checkpoint progress. Incidents 133/134 were held for actual
proof/predicate defects rather than dropped or resampled.

The incident-166 title/storage-width repair and incident-322 complete
alternative audit representation subsequently passed fresh source quality
as r3 tasks. Incident 322 retained its original 16-call source student;
incident 166 used its first student. Incident 166 then passed all downstream
gates, including 56 robustness checks, and became the sixth admission:
**36.67 medium (B1/P2/R1/A0)**, grounded native final success and zero
checkpoint progress. Its source/native students each used eight calls.
The completed first per-scope readiness round produced **nine admissions
from 11 logical attempts**; the two original source-evidence holds remain.
Incident 322 passed native evaluation (13 calls, grounded
final success and full checkpoint progress), but two of its 36 robustness
checks exposed an annotation-format limitation. Removing one alternative
audit representation correctly produces an answer from the surviving route
and no answer from the removed route. A single claim-wide answer expectation
could not express that result. Program-bound expectations are now implemented
in both robustness execution and admission verification; the revised
44-check matrix passes, including symmetric and both-route removals. Fresh
independent review and every remaining gate passed, making incident 322 the
eighth admission: **70.0 hard (B2/P2/R3/A1)**, with both students preserved.

Incident 133's prepared session/IP-group proof repair passed 44 actual
two-backend controls without merging distinct source observations or dropping
incident/onset/later-process coverage. Its supervised fresh source quality,
retained-student revalidation, grading/native evaluation and 32 robustness
checks passed after that batch released its lock. Its first native student
used nine calls with grounded final success and zero checkpoint progress.
Canonical review requested the three process observations' inspected
ProcessCreated action-type facts in both claims. The canonical-only
continuation passed, followed by difficulty and objective review, making
incident 133 the seventh admission: **63.33 hard (B2/P2/R3/A0)**. No passed
stage or student was rerun.
Incident 134's prepared strict-before/Delivered correction
passed eight baseline-equivalence checks, six original-defect regressions and
76 backend/claim robustness checks. The tested retained-native workflow is
passed its source revision and all downstream gates while preserving
the original 14-call source and 14-call native students. It is the ninth
admission: **53.33 hard (B2/P2/R2/A0)**, grounded native final success and zero
checkpoint progress. Its new native stage made zero student calls and pins
222 original dependencies. The held reviews remain intact.
Preparations and source readiness are not
admissions, and no training or release approval is implied.

The program-bound robustness change passes 86 focused regression tests,
including actual isolated DuckDB/MySQL execution and native ACE replay.
Production Pylance diagnostics are clear and Python 3.10 syntax is preserved.
The admission-only source-runtime amendment preserves the exact prior
producer archive; all nine receipts and all 109 legacy artifacts reverify.
The subsequent retained-native integration passes 94 focused tests, including
real captured-result replay, failed-query and abstention preservation,
interrupted replay recovery, foreign-student rejection and receipt dependency
tamper detection. New candidate manifests also include every native-stage
runtime dependency, including the private pilot validator.

### Portable private question packets

`export-private-bundle` packages the approved development snapshot and,
optionally, every admitted question in a preproduction run. It preserves
the explicit development split; new preproduction questions remain
unassigned. It copies exact task/native/canonical/difficulty/policy files,
original approvals, admission receipts and their dependencies. It does not
reconstruct difficulty sidecars or imply training/release approval.

```bash
python -m secgym.qagen.agentic schema private-difficulty-index
python -m secgym.qagen.agentic export-private-bundle \
  --development "$DEV_SNAPSHOT" --difficulty-index "$DIFFICULTY_INDEX" \
  --preproduction-run "$RUN" --output "$PRIVATE_PACKET"
python -m secgym.qagen.agentic check-private-bundle --bundle "$PRIVATE_PACKET"
```

The difficulty index lists each development task's exact plan, review and
sidecar paths and SHA-256 values. The loader verifies those bindings against
the approved axes/score/band or immutable admission. Operational paths in the
packet are relative; original host paths remain historical provenance keys,
never fallback locations. Every packet file is hash-bound. The only file in
the student directory is `student/tasks.json`, generated from public task
contracts; the whole packet remains private because it includes gold and
review evidence. The full source database is not embedded and must be supplied
separately using its existing snapshot/graph/serving bindings.

The first private packet contains **56 questions: 47 development plus nine
new admissions**, with **36 train / 11 test / nine unassigned** and all five
reviewed grading policies. Its 3,445 artifacts were ZIP-round-tripped and
loaded with access to every original data path forbidden: zero original
accesses occurred. Eight focused export tests cover relocation, byte
integrity, altered assignments/difficulty, authorization dependencies, path
escape and private-data leakage into the student directory.

A new bounded eleven-attempt source wave is now covering the second slot
for each selected incident and tenant slot two under the original
1,000-new-question target and 2,000-attempt envelope.

That wave completed with **22 total logical attempts, 16 source-ready
candidates and nine admissions**. Seven new source-ready candidates are
running full downstream gates. Four pre-blind holds have prepared source
corrections: three public-selector/type repairs passed 24 actual backend
checks, while incident 38's complete observed ancestry repair passed 28.
The latter corrects a hidden five-entry cutoff to the seven-entry observed
chain, preserving the direct-parent checkpoint and explicitly reporting
the limited observed stopping boundary.

Second-slot incident 34 also has a prepared empty-list-versus-null robustness
annotation correction: all 36 checks pass without changing its task or
students. These repairs await fresh independent review and downstream gates
behind the current batch lock. Second-slot incident 5 remains held on a
native JSON_TABLE join-scope error before its first native student.
Source readiness and prepared passing controls are not admission.

The seven-candidate batch later stopped on an Azure API timeout in
second-slot incident 133's contract review. Its sixth request has no recorded
response; the ambiguous boundary is preserved and **not automatically
retried**. The three untouched candidates (134/322/tenant second slots) are
queued separately. Explicit lock waiting revalidates their exact source
bindings before work starts.

Additional prepared corrections pass 20 backend checks for incident 55's
raw cohort-support annotation and eight for incident 5's MySQL join-scope
defect. Both require fresh independent review and preserve completed
students; incident 55's recorded native failure is not resampled or
retrospectively credited. Latest verified totals are **22 attempts,
17 source-ready candidates and nine admissions**, with independent repairs
and untouched candidates continuing under the same serialized batch lock.

The three selector repairs then passed fresh quality and their first source
solves (36: 15 calls; 39: 12; 166: 17), bringing source readiness to **19/22**
with **nine admissions**. A second contract-reviewer request timed out for
incident 36. Both failures are HTTP read timeouts at approximately 300.3
seconds, not SQL failures; their missing-response boundaries remain blocked
without retry. The repaired incident-39/166 downstream roles were untouched
and are queued separately, while independent work continues. The configured
timeout and all original student outcomes remain unchanged.

The user subsequently approved **900-second HTTP timeouts for reviewer
calls only**, with explicitly audited recovery of interrupted review contexts.
[review_transport.py](review_transport.py) routes only exact, recorded
reviewer roles/result schemas to the approved override; students, authors and
curators retain their original client. It records per-call effective
settings and request hashes. Student HTTP (300 seconds), student SQL
(30 seconds), private grading SQL (120 seconds), model, reasoning effort and
token budgets remain unchanged.

An eligible recovery must have an explicit timeout, an unanswered request,
consistent preceding messages/tool results and no accepted/completed outcome.
It appends a new call from the exact retained context; it never replaces
the original unanswered call, error or student trace. Original source
validators and independently required inspections still apply. An uncertain
recovery is not retried automatically.

[review_execution.py](review_execution.py) is an opt-in owned-snapshot runner
that delegates to the unchanged candidate pipeline. The separate owner is
intentional: historical source/pipeline producers and their bindings are
frozen, so the transport change does not rewrite them. The approved policy
and new producer are archived separately. Twenty-nine transport/source-quality
tests and an actual owned native lifecycle check pass. Five interrupted
review contexts are entering audited recovery; unaffected unstarted work
will continue under the same approved reviewer policy.

All five interrupted reviews subsequently completed without another
transport failure. Their substantive outcomes remain gated: identity wording
and checkpoint proof defects require correction, an ancestry answer has a
formatting-only strict-contract mismatch, and incident 34 needs one canonical
event-property reference. Completed students are not rerolled.

An alleged MySQL syntax defect from incident 134's reviewers was independently
disproved: ROLE is nonreserved in the actual MySQL 8.4 keyword catalog, and
all four original programs execute and match DuckDB. The task and SQL remain
unchanged. A materially new native-evidence reconsideration requires
full-snapshot validation plus fresh independent review/reflection; it does
not silently waive the original hold or repeat the same review for a pass.
That reconsideration and incident 34's canonical-only correction are queued
behind the ongoing approved-policy work.

Incident 34's canonical-only correction subsequently passed and became the
**tenth admission**, with **43.33 medium (B1/P2/R1/A1)**. The source/native
students and all passed earlier stages were preserved.

A robustness-author call then hit its original 300-second limit; that role
was intentionally outside the reviewer-only override. The user explicitly
approved the versioned **non-student V2 policy**: scouts, authors/repair
authors, robustness authors, fact/difficulty curators and reviewers now use
900-second HTTP limits. GPT-6-Sol, student HTTP (300 seconds), student SQL
(30 seconds), private grading SQL (120 seconds), reasoning/token budgets
and completed outcomes remain unchanged.

V2 retains the original V1 policy/execution bytes and appends a separately
bound transition. Exact role/schema routing excludes blind/native-blind
students. Author recovery preserves the original context/tool interface and
the same source/claim/probe validators; no accepted outcome or uncertain
recovery is automatically repeated. Thirty-three focused transport and
source-quality tests pass. The V2 recovery/remaining-work batch is active
under the same serialized lock.

An additional, explicitly approved policy supports **validation-only recovery
of already-received non-student JSON results** through
[`recover_json_result`](json_result_recovery.py). It accepts no model client.
The role must declare its exact trusted result schema and have a complete
response containing one JSON object or one unambiguous `json` code block.
Students, accepted finishes, closed stages, refusals, truncations, ambiguous
objects and unresolved earlier boundaries are rejected.

Recorded token-rate waits are not unresolved model responses: a response-less
slot may be retained only with its exact `retry_wait` role/index, no executed
tools, and the unchanged next request. Inspection restoration uses only the
verified completed-response prefix, and completion counts retain every original
request, including waits. Unknown send states still require separate recovery.

Callers must provide the original bound role validator and the original
source-tool interface. Fact inspections are restored solely from recorded
successful queries; unrecorded additional observations cannot be supplied.
Schema validity alone is insufficient. A validation failure publishes no
result, completion or recovery certificate and does not trigger inference.

On success, the original response/history remains byte-identical. The
publisher adds a hash-bound recovery certificate, an exact producer snapshot,
the validated result and completion metadata explicitly identifying received
JSON recovery. It records an empty tool-result list for the response's actual
zero tool calls; it does not invent a `finish` call. Interrupted publication is
idempotently resumable, but changed artifacts are rejected. Ordinary source
inspection replay and cached role loading then work without another model
sample; independent reviews, measurements and admission gates remain required.
The JSON-recovery policy is separate from HTTP recovery and does not change
model, transport, student or SQL settings. Forty-seven focused JSON-recovery,
transport and source-quality tests pass.

Incident 134's unchanged SQL passed native reconsideration, but a subsequent
raw-measurement annotation correction is still pending fresh independent
review. It passes 28 backend checks plus four real claim-verifier controls
rejecting unsupported original gold. Current milestone: **ten admissions,
19 source-ready candidates, 22 attempts**; packaging and source readiness
still do not authorize release or replace final gates.

The seven-job V2 batch completed without a new timeout and added three
admissions: incident 39 second slot (**36.67 medium**), incident 322 second
slot (**63.33 hard**) and incident 55 second slot (**70.0 hard**). The latter's
original native failure remains recorded; question validity is not a
requirement that every student succeeds. The completed milestone is
**13 admissions from 22 attempts**, with 19 source-ready candidates.

The new immutable private packet contains **60 questions: 47 development
plus 13 admitted preproduction**, keeping **36 train / 11 test / 13
unassigned** and all five grading policies. All 4,843 artifacts passed actual
ZIP relocation with original-data access forbidden. The prior 56-question
packet remains unchanged.

A bounded eleven-attempt third-slot source wave is running under V2.
Tenant question two's canonical event-property repair is queued. Incident
134's stale rationale correction plus a substantive missing-IP boundary
passes 32 backend checks and six original-gold rejection controls, but still
requires fresh review and subsequent gates. Checkpoint/proof/identity holds
remain explicit; no completed student is rerolled or a failed question
silently dropped.

[preproduction_revisions.py](preproduction_revisions.py) preserves explicit
same-attempt source repairs under numbered immutable revision receipts.
Original holds and traces remain intact; current-source resolution follows
the bound parent/outcome chain. Revisions add no logical attempt, and their
model calls and compile repairs remain separately accounted. Scope and declared
goals are preserved by default. A started or completed blind student requires
supervised equivalence/recovery rather than automatic resampling.
Compiled revisions are now checked for preserved goals before the next
reviewer/student inference, not only after the pilot returns. Typed task
fingerprints remain bound even on operational errors. Legacy errors without a
task fingerprint require an explicit recovery request bound to their unchanged
task artifact; the original error is never rewritten. Retained-source-student
certificates also block automatic resampling.
Source and revision reports are compared in their JSON representation, so a
Python tuple and its serialized array are not falsely treated as different
results. Actual report-content differences still produce retained errors.
The affected incident-38 result was reconciled without changing its task or
10-call source student; its actual evidence hold remains in place. The two
source slots then completed with pre-blind public-selector holds, rather than
rerunning that completed student. Six logical attempts are now allocated and
two questions admitted. Prepared incident-39/55 public-context repairs are
being checked with private gold and checkpoint objectives unchanged. Incident
39's source review and first 13-call blind solve passed. Incident 55's
schema-constant correction and first 13-call blind solve also passed. Both are
proceeding through downstream validation; neither source pass alone is admission.

An orchestration-only runtime amendment may enable these lifecycle features
without rewriting the original plan. It requires an exact archived copy of
the previous implementation and a continuous fingerprint-bound amendment
chain. Changes outside the explicitly named pre-production orchestration
modules are rejected: this mechanism cannot change source, model, SQL, grading
or curation kernels. The first readiness question was held before any student
because its exact alert-title filter was not quoted publicly. Its wording-only
revision passed source and actual native checks. Independent grading review
then corrected unnecessary downstream checkpoint records and creation-time
predicates; a width-free MySQL extraction passed actual equivalence checks.
The final r5 revision retains both completed students with zero new student
calls during private repairs. Source-reviewed optional context never replaces
the complete five-record final or three-record checkpoint proof.

All 100 baseline/counterfactual backend checks and 36 supporting-context controls
passed. Canonical and objective reviews passed, and independent source-only
difficulty curation assigned **53.33 hard (B2/P2/R2/A0)**. Native SecRL/ACE replay
still yields grounded final success and zero checkpoint progress. Three source
revisions consume only the original logical attempt; original holds, traces
and the approved 47-question development cohort remain unchanged.
The bounded launcher has also passed read-only post-amendment continuation
checks: it loads the original plan, validates current settings separately and
rejects unamended runtime changes without starting any new attempt.

### Observed-pool capacity curves

The latest pooled diagnostic covers the 47 approved development questions plus
two admitted new questions: 90 within-scope pairs, all measurable. Exact summed
capacities across independent scopes are **36 / 46 / 49 / 49** at the four
approved thresholds. These are descriptive subset counts, not source ceilings
or admission limits; no question or split was changed.

[capacity.py](capacity.py) reports per-incident and tenant capacity curves at
the approved diagnostic overlap thresholds 0.25, 0.50, 0.75 and 0.90. Every
example subset satisfies **pairwise aggregate overlap <= the threshold**;
equality is allowed. The aggregate uses the unchanged quarter weights and
the exact current native/canonical bindings. Pair results are streamed to CSV;
the search retains compact per-threshold conflict graphs rather than a full
matrix of rich pair objects.

The deterministic search provides a verified compatible subset as a lower
bound and a graph-coloring upper bound. An observed-pool maximum is labeled
exact only when those bounds meet. The request must specify a positive
`search_budget_states` per bucket/threshold; exhausted searches keep honest
bounds. Missing overlap components make the bucket unscorable, not
zero-overlap or zero-capacity. These curves never reject questions, force
groups, alter train/test assignments or establish source exhaustion.

```bash
# Example request: {"search_budget_states": 10000}
python -m secgym.qagen.agentic capacity-curves \
  --inputs private-inputs.json --request capacity-request.json \
  --output observed-capacity
```

Outputs are `capacity-report.json`, `capacity.csv` and
`within-scope-pairs.csv`, including source/artifact hashes and example-subset
certificates. Cross-scope overlap remains in the separate full overlap audit.
The CLI returns nonzero for unscorable source comparisons. An empty or small
observed pool is not an estimate of every question the source could support.

### Difficulty profiling

[difficulty.py](difficulty.py) implements the provisional four-axis formula
and strict measurement/sidecar contracts. Reviewed plans identify one complete
evidence alternative per final/checkpoint and a logical dependency DAG.
Breadth, dependency depth and operation counts are calculated from that plan;
semantic necessity and the completeness of the decision points still require
review. Raw overlap-edge count is descriptive, not a score input.

Ambiguity probes retrieve source-attributed candidate rows and count distinct
observations or qualified identity fields. Repeated joined rows do not inflate
counts. Exact probes cannot use LIMIT/OFFSET/sampling; empty, incomplete or
unattributed results and query failures do not become difficulty evidence.
A missing ambiguity plan yields no score; an explicitly reviewed empty plan
declares no additional choice point.

For populations larger than one result page, `PartitionedAmbiguityProbe` adds
the explicit `retrieval_policy="exhaustive-record-ranges-v1"`. The original
candidate query remains unchanged inside every partition, including its
joins, time bounds, windows and semantic selection. A whole-scope census
checks non-null source locators and exact row count. The server retrieves
contiguous, disjoint locator ranges under the unchanged per-query limits and
verifies every row's source attribution before deduplicating candidate
identities across pages. A zero-row header query is schema inspection only,
not candidate evidence or sampling.

The private result includes all verified citations and a count-matched
partition audit with query/result digests. Null/invalid locators, unsplittable
oversized locator blocks, missing rows, query errors, more than 4,096 partition
queries or more than 64 MiB of retained result data are explicit measurement
errors: partial pages never produce a score. Existing single-result probes
keep their serialized shape and still fail when their declared query exceeds
its limits; pagination is opt-in, not a silent fallback.

```bash
python -m secgym.qagen.agentic schema difficulty-plan
python -m secgym.qagen.agentic schema difficulty-review
python -m secgym.qagen.agentic schema difficulty-inputs
python -m secgym.qagen.agentic schema difficulty-sidecar

# Descriptors only: no guessed reasoning depth, ambiguity or difficulty label.
python -m secgym.qagen.agentic difficulty-profile \
  --inputs private-inputs.json --output difficulty-inventory

# Actual source measurements for the explicitly reviewed plans.
python -m secgym.qagen.agentic difficulty-profile \
  --inputs private-inputs.json --plans difficulty-inputs.json \
  --serving-bundle /private/public-view --limits query-limits.json \
  --output difficulty-measurements
```

The plans manifest has `entries`, each containing `task_id`, `plan` and an
optional `review` path, relative to that manifest. An absent/failed review is
reported as `needs_review`, never scored. The CLI writes one private sidecar
per question, `difficulty.csv` and `summary.json`; requested incomplete
measurements return a nonzero exit status. No task, native validation,
canonical annotation or public prompt is rewritten.

The frozen development prototype has 47 descriptor profiles. Two source-
measured examples have provisional scores: incident 166 Q2 is 26.666667
(medium), and incident 133 Q2 is 70 (hard). The remaining 45 are explicitly
unmeasured, not easy by default. These manually source/program-reviewed
controls exercise the measurement/scoring pipeline; they are not empirical
model calibration. All 106 focused difficulty/split/CLI/canonical tests pass,
and the approved development split and source bindings remain unchanged.

### Source-inspecting feature curation

[difficulty_curation.py](difficulty_curation.py) provides `curate_difficulty`
for a private feature curator followed by a separate reviewer. Neither role
receives student outcomes or numerical difficulty scores. Both must retrieve
the selected proof records through source-attributed SQL results. Proposals
are checked against the frozen claims, and ambiguity probes cannot select
private witness IDs as an oracle.

The reviewer sees the source measurements and reasoning plan, not a requested
easy/hard tier. Source counts are not themselves proof that the probe's scope
or identity definition is correct; those remain explicit review obligations.
Only a passing plan-bound review enables deterministic scoring. A suspected
question/rubric defect is held separately from a feature-annotation defect.

Fresh revisions preserve prior outputs and keep earlier feedback out of the
new reviewer's context. `resume=True` verifies input/runtime bindings,
restores captured source inspections and retains completed roles, including
when only a reviewer was interrupted. The initial automation rollout is a
three-question source-feature pilot before the rest of the development
cohort. It does not run model-ability evaluations or generate new QA.

The first pilot surfaced two issues before wider rollout. Initial ambiguity
annotations that dropped resolved identity/path bindings were held for
feature-only correction; v0.2 clarifies candidate scope/identity and uses a
smaller property-reference context while retaining mandatory source
inspection. Original model reviews and scores are preserved, not relabeled
as new reviews.

Current curation v0.3 supports exhaustive retrieval and explicitly retains
public semantic roles when measuring ambiguity: a compiler is not a competing
Notepad child, a non-LDAP observation is not an alternative LDAP request, and
other artifact types are not competing executables when executable type is
given. Genuine within-role ranking/temporal/eligibility alternatives may
still count. For paged populations, reviewers receive the full census and
partition audit plus a citation-inventory count/digest; the full attributed
inventory remains in the private measurement artifact. Neither context
contains a desired numerical score or student performance.

Separately, a read-only proof-fixture audit reproduced incomplete collection
witness alternatives in incident-5 Q1/Q5 and tenant Q6: 18 of 30 alternatives
across all 17 multi-valued development claims lost answer members. These are
question/rubric proof defects, not missing difficulty features. Fresh QA
revisions are in progress, and the original development approval remains
historical rather than reusable proof for changed task fingerprints.
The remaining feature queue and pre-production generation are not used to
bypass these checks.

Subsequent source-preserving selector audits are recorded in design Sections
17.43-17.45. They distinguish actual question/program defects from feature
holds, retain historical approvals/outcomes, and require fresh source/native
and downstream bindings for changed questions. No pre-production generation
or model-ability evaluation is authorized by a successful feature review.

## I4: private discovery pilot

[pilot.py](pilot.py) implements separate scout, author/repair, blind-solver and
refuter contexts. [generation.py](generation.py) provides the schema-validated
tool loop and binds executable witness groups to actual private source
provenance. [discovery_context.py](discovery_context.py) provides current-incident
or tenant starting contexts and bounded generation-only graph pivots.
The blind solver receives only the public task and SQL/schema tools, never
author answers, queries, checkpoints, scout history or graph tools.

Generator `discovery-pilot-v1.3` statically validates every answer and witness
program in both SQL dialects before compiling a draft, including literals,
public sources, source-derived answers and ordered-answer sorting. Actual
backend execution and parity remain separate gates. Source-record counts are
allowed; direct literal record-ID selectors, including predicates nested inside
counts, remain forbidden. Use a fresh output/revision when changing runtime
policy so prior failure traces and role inputs remain intact.
`discovery-pilot-v1.4` additionally states the SQL tool's actual dialect and
separates DuckDB testing during discovery from later actual MySQL validation;
an unavailable native tool during discovery is not evidence that a source task
is unsupported.

[azure_generation.py](azure_generation.py) reads only the configured endpoint
and API version from the explicitly supplied environment file. It uses Entra
CLI credentials, not its stored API key. The approved `gpt-6-sol` deployment
requires Responses API for reasoning with function tools; replay retains
encrypted reasoning state but excludes response-only fields incompatible with
the Azure preview input schema. Responses are not stored server-side by this
client. Local request/response traces are private build artifacts.

Every call, tool result, usage record and error is retained. Rate limits
respect server retry timing and resume the same context. There is no aggregate
model-spend or model-call ceiling, as requested; per-query resource bounds,
per-response output bounds and request timeouts remain explicit.
`--resume` preserves prior failed attempts and rejects changed role inputs.
`--revision-from` with concrete feedback creates a new task revision and fresh
blind/refuter runs rather than reusing an old validation result.
Roles can explicitly abstain when evidence is insufficient. Structured result
citations are checked before completion rather than accepted as invented IDs.

For private pair calibration, `--related-from` takes a validated seed,
`--task-id` supplies a new logical identity, and `--relation` selects either
`shared_evidence` (a different investigative objective) or `paraphrase`
(an explicit same-objective control, not a second release item). Related
questions retain the source episode's lineage group, while revisions preserve
the logical task ID. Seed fingerprints and resolved task identity are pinned
before roles run; resume rejects changed seed/lineage bindings instead of
silently reusing model outputs under a new task identity.

```bash
PYTHONPATH="$PWD" /path/to/aces-env/bin/python -m secgym.qagen.agentic.pilot \
  --serving-bundle /path/to/public-view --graph-bundle /path/to/graph \
  --endpoint-env /path/to/approved-endpoint.env --deployment gpt-6-sol \
  --mode incident --incident-id 34 --checkpoint-cap 0.5 \
  --max-result-rows 500 --max-result-bytes 65536 --query-timeout-ms 30000 \
  --model-timeout-seconds 180 --max-completion-tokens 12000 \
  --output /path/to/new-private-pilot
```

The first incident-34 candidate passed executable DuckDB checks, an independent
blind answer/evidence check and refutation. The initial tenant candidate had
correct final bytes but a two-output wording problem and a witness mismatch;
it was revised, not admitted by relaxing the scorer. Its second revision passed
fresh blind/refutation checks with a source-ID-bound application/service
principal/grant/request chain.

Both initial tasks have now completed private MySQL validation and native
adapter replay, not dataset release:

| Task | Correct answer | Grounded final submission | SecRL / ACE reward |
|---|---|---|---|
| Incident 34, revised initial task-creation fields | Yes | No: omitted required alert citation | 0.0 / 0.0 |
| Tenant, reported Graph response bytes | Yes | Yes | 1.0 / 1.0 |

Both independent MySQL runs retrieved complete source-witness alternatives.
Candidate verification is separate from the student's final citation score.
The same recorded student trajectories are replayed, not resampled until they
earn full credit. Neither initial blind run emitted explicit checkpoint
findings; their zero checkpoint credit is not a claim that no intermediate
discovery occurred. Real checkpoint-discovery calibration remains an I5 task.

[pilot_evaluation.py](pilot_evaluation.py) adds actual source/MySQL parity,
a fresh MySQL blind solve, and replay through the native SecRL and ACE adapters.
Explicit `private_pilot` environment admission may defer only *missing*
split/release reviews for `v1-private-pilot` tasks. It never bypasses failed
reviews or missing source/identity/independence/parity gates; logs keep
`release_approved=false`. Default release admission remains unchanged.

The full MySQL load uses prepared parameter batches so stored script/SQL-like
payloads are never interpreted as batch SQL. DOUBLE values use round-trip
decimal representations to avoid connector FLOAT32 binding. Opt-in
`load_mysql_view(..., resume=True)` first verifies every existing row and schema
against the immutable public snapshot, rejects tampering, skips only complete
verified tables, and never overwrites an existing row. Full final verification
is still mandatory; a partial load never receives a completion report.
Native `?` placeholders and cached prepared-statement objects avoid the
connector's quadratic `%s` rewrite. Source-generic, non-unique indexes support
identity/action/time and exact process-parent lookups without changing any
public row, answer, or query timeout. The `mysql-access-indexes-v6` policy also
covers telemetry initiator identities, host/action time ranges, file hashes,
current/previous registry keys and value names, sign-in identities, Office
activity, cloud-event time and composite file/device/process-name lookups. Installation
verifies each index definition and is idempotent; an index is not evidence that
a previously blocked query or task now passes validation.

## I5: current calibration inputs

All ten public incident contexts resolve with the incident-5 missing-alert and
incident-322 missing-SquidProxy exclusions intact. The incident-133 candidate
was revised for an ambiguous linked-alert selection and an unspecified
domain/account delimiter. Its current version passes independent checks and
actual MySQL answer/witness parity.

Both expanded candidates have completed actual MySQL and dual-adapter
validation. Incident 133's baseline final answer was correct but under-cited
(reward 0.0 in both adapters). Incident 322's revised query uses the same public
incident-window scalar bounds to make its timestamp index usable; its baseline
answer and citations were correct (reward 1.0 in both adapters). The proxy
exclusion and no-inferred-cloud-request-causation limits remain intact.

[footprints.py](footprints.py) builds source-bound unit-weight audit footprints
only for validated evidence. The four tasks have 5/6/12/8 observations and
77/27/183/111 deduplicated typed edges, with two fact targets each. All four
overlap components are zero for all six pairs. Unit weights and claim hashes are an explicit initial
baseline, not semantic-paraphrase certification or calibrated production
weights. No aggregate coefficient choice, redundancy action or split is
silently applied.

### Observable finding calibration

Every admitted task requires **at least one relevant, evidence-backed
checkpoint**. An irrelevant or erroneous checkpoint triggers rework of the
question and rubric together, followed by fresh validation. Do not admit an
empty rubric, add an unrelated replacement, or preserve a legacy error for
compatibility. If no sound intermediate discovery can be established, the
question must be reworked or rejected.

The `record_finding` tool now lets a blind solver report intermediate typed
facts and citations without seeing the private rubric. Its `semantic_kind`
is a descriptive label, not a secret checkpoint ID. The rubric still controls
value shape, units, comparison policy and complete source-witness requirements;
renaming a label cannot relax those checks. A set invalid under the rubric's
case policy receives no credit rather than causing a scorer exception.
This behavior is versioned as `source-witness-v1.1`; earlier results are retained.

In a fixed four-task development run, solvers made **12 finding attempts**:
ten had valid shapes and two timestamp findings omitted required units and were
rejected. None of the ten valid findings matched an authored checkpoint target,
so checkpoint progress remained zero. Final grounded rewards were 0/1/1/1
for incident 34, tenant, 133 and 322, with identical results in both adapters.
This is evidence about rubric coverage, not a reason to award credit to
unmatched facts or tune a cap against these four runs.

The calibration driver now replays incorrect/uncertain final submissions as
measured student outcomes too. A valid task is not automatically rewritten
because a student fails; correct intermediate evidence can still earn capped
credit. Independent task validation, student correctness, submitted grounding
and source observations remain separately recorded.

Positive/negative gold-informed controls are evaluated separately from blind
discovery. They use unchanged real source rows to test credited facts, wrong
values, missing citations, unobserved evidence and duplicate findings. All
**16 scenarios passed in both adapters (32 evaluations)**: a correct observed,
cited checkpoint earned 0.5 without a final answer; each negative case earned
zero, and duplicate findings did not add credit. First-completion steps were
retained. These controls must not be reported as spontaneous model discoveries
or a benchmark score.

There is not yet enough data to freeze production checkpoint targets/weights or
split thresholds: each task has only one checkpoint, and the pilot pairs have
no positive-overlap examples. Existing reward weights, task truth, and splits
have not been changed to improve the measured outcomes.
The two identified defects have now been corrected through versioned
question/rubric rework:

- The tenant r3 question follows the specific service principal into its grant
  window; the required checkpoint resolves that principal's object ID from
  application creation. The unrelated role-assignee evidence and selectors
  were removed.
- Incident 133 r4 asks for the account contexts of actual `net.exe` to
  `net1.exe` pairs, grouped and ordered by their `cmd.exe` parents. Its required
  checkpoint resolves those parents, rather than an ancillary PowerShell
  ancestry investigation.

Both revisions passed fresh independent source/blind/refutation checks, real
MySQL answer/witness parity, and native SecRL/ACE replay. Both final student
submissions were grounded and earned 1.0; their submitted intermediate
findings did not satisfy the exact checkpoints, so no checkpoint credit was
invented. No checkpoint-free task was generated or admitted.

The prior defective versions and their calibration outcomes remain audit
history, not current release candidates. Updated audit footprints contain
5/5/10/8 observations and 77/23/154/111 edges across the four current tasks;
no split/threshold or release decision has been made.

### Overlap-positive development slice

The private pool now includes three additional validated instances: two
same-objective paraphrase controls and one distinct tenant question sharing
the application/grant-window evidence. All retain relevant checkpoints and
passed source, MySQL and native SecRL/ACE checks. The paraphrase controls are
diagnostic duplicates, not additional release questions.

Across seven validated instances there are 21 pairs:

| Pair category | Count | Edge / observation / fact Jaccard | Decisive containment |
|---|---:|---|---:|
| Same-objective paraphrase | 2 | 1 / 1 / 1 | 1 |
| Different tenant objectives sharing evidence | 2 | 0.5926 / 0.6667 / 0 | 0.5714 |
| Disjoint evidence | 17 | 0 / 0 / 0 | 0 |

The distinct tenant question asks who performed an observed credential-list
reduction inside the grant window, rather than asking for Graph response bytes.
Its removal-time checkpoint is relevant because a competing reduction occurs
after removal. Shared evidence alone is therefore not a sufficient reason to
delete a question.

One incident-34 companion remains held outside this matrix: its blind solver
found the correct registry value using alert-info/evidence records but did not
retrieve the currently required creation-command and SecurityAlert proof.
The alternative route needs separate adjudication; no required proof was
silently waived and the candidate was not counted as validated.

These are only two overlap-positive episode families. Components and task
lineage are retained, but no production coefficients, feature weights,
deduplication thresholds, split assignments or deletions are selected.

### Approved broader development batch

[batch.py](batch.py) now plans and records the approved **60 discovery attempts**:
five for each of the ten incident scopes, plus ten tenant-wide attempts.
These are attempts, not an accepted-item quota. Missing evidence, abstentions,
errors and questions requiring revision remain explicit outcomes.

Attempts run sequentially with distinct task IDs. Prior question text from the
same scope helps scout/author roles seek different objectives; private gold is
not shared with blind solvers. Every resulting task still needs a relevant
checkpoint and the same source checks. Completed attempts are not rerun on
resume, and a changed manifest or task fingerprint is rejected.

The private batch manifest, per-attempt traces and progress are persistent.
Progress is written when work finishes, not by a monitoring timer. Discovery
completion does not claim MySQL validation, a split, or release approval;
candidate repair and backend validation follow the discovery inventory.

The approved 60-attempt discovery batch has finished:

| Initial outcome | Count |
|---|---:|
| Passed discovery; awaiting MySQL validation | 21 |
| Needs revision or further proof review | 36 |
| Execution error | 3 |

Triage separates 29 independent-review defects, two unstated exact-answer
serialization requirements, five incomplete blind proof traces and the three
execution failures. The 31 question/format defects are being reworked as new
revisions with mandatory relevant checkpoints and fresh independent checks.
Incomplete proof is not silently waived; original attempts remain available.

Two execution failures exposed invented/shortened scout citations. Scout
`finish` results now receive the same source-resolution check as later role
outputs before an author sees the lead. One refuter exceeded its output-token
bound. Explicit resume can retry that unchanged request with a recorded
larger response allowance; it never executes or accepts the truncated output.

Named JSON-array extraction is now available through reviewed read-only
DuckDB `json_each` and MySQL `JSON_TABLE` sources. This supports matching
parameters by name rather than relying on case-specific array positions.
Nested external/private table readers remain rejected, and both dialects are
tested against reordered parameter arrays.

Per-candidate MySQL failures retain their validation report and a separate
failure outcome. Completing the discovery batch is not evidence that 60
questions were accepted, and no dataset release or split has occurred.

## Legacy versions and preservation

[legacy.py](legacy.py) provides explicit, read-only aliases:

| Generator | Dataset alias | Existing files |
|---|---|---|
| v0 | v0.1 | Corrected current `secgym/questions/o1/v1/`: 589 test / 418 train |
| v0 | v0.2 | Current `secgym/questions/opus5/`: 599 test / 418 train |
| v1 | Not released | This new framework; no legacy files renamed or regenerated |

The old folder name `o1/v1` denotes the legacy email correction, **not** the new
QA-generation framework v1. Original o1 and o3 artifacts remain unchanged.

[legacy_baseline.json](legacy_baseline.json) pins content hashes for 109 existing
legacy question/graph/code files, including all 32 aliased release files.
`check-legacy` compares the current checkout with that baseline and exits
nonzero on a mismatch or missing input. It never rewrites legacy data.

To inspect a fresh inventory without replacing the baseline:

```bash
python -m secgym.qagen.agentic legacy-baseline --repo .
```

Do not silently regenerate the pinned baseline to make a regression pass.
Later opt-in integration may intentionally edit legacy-adjacent source modules;
review those changes and preserve legacy behavior with regression tests. Dataset
and old graph artifacts must remain unchanged.

## Stage boundary

I0 validates data shapes and freezes the legacy baseline. I1 implements the
incident/alert state and source catalog below. Neither stage builds a graph,
certifies capture completeness, runs a scorer/judge, computes question evidence
footprints, splits a dataset, or exports executable ACESEvals tasks.

## I1: read-only source preparation

[sources.py](sources.py) reads the imported tenant DuckDB and incident-export
CSVs. Supply explicit input and **new output** paths:

```bash
python -m secgym.qagen.agentic reconcile-sources \
  --tenant-db secgym/database/duckdb_data/tenant.duckdb \
  --incident-root secgym/database/data_anonymized/incidents \
  --output /path/outside/the/source/directories/v1-source-snapshot
```

The command never overwrites an output directory or writes to an input. DuckDB
uses read-only access, one thread and a 512 MB engine memory limit. Files are
SHA256-inventoried and checked for changes during the run. Source IDs use logical
relative paths and content hashes; snapshot identity also includes the
normalization version and implementation digest. `report.json` is written last as the completion marker;
do not consume a partial directory lacking that marker.

### State and provenance

- Reconcile the source updates before selecting the **latest complete incident
  row**. No superseded incident payloads are exported as active state.
- Deduplicate equivalent observations while retaining all source locators.
  CSV locators are logical record ordinals, not physical line numbers.
- Block conflicting latest records rather than choose a source or row ID.
  Historical conflicts remain explicit and suppress unreliable membership
  inferences for the affected history.
- Preserve latest alert observations even when no incident currently references
  them. Conflicting alert records are excluded explicitly, not silently chosen.
- Derive historical removed links with last-present/first-absent bounds, other
  current parents and a not-current/relevance caveat. Missing membership is not
  an empty list; re-added links follow the latest state.
- Preserve source classifications separately from the ten approved TP scenario
  designations and their exclusions.

Canonicalization excludes technical `_rid`/`rn` from content identity, parses
declared types/JSON, represents empty source values as unavailable, and represents
timestamps in UTC at Python/DuckDB microsecond precision. The original values
remain retrievable through the immutable source locators. Invalid casts/JSON do
not silently become successful nulls.

**Explicit approved exception:** for `SecurityAlert.CompromisedEntity` only,
literal `"N/A"` and empty values both mean unavailable. Each applied `"N/A"`
normalization is recorded. `"N/A"` in other columns is not rewritten; different
real entity values still conflict. This rule is included in
`source-normalization-v1.1`.

### Output bundle (private build data)

| File | Purpose |
|---|---|
| `snapshot.json` | Input hashes, IDs, logical paths and provenance limitations |
| `incidents.jsonl` / `alerts.jsonl` | One resolved latest record per incident/alert |
| `observation_references.jsonl` | Canonical IDs and source locators, including membership-transition inputs; no historical incident payloads |
| `historical_memberships.jsonl` | Removed links that are absent from latest membership |
| `membership_transitions.jsonl` | Observed removal intervals, including whether later re-added |
| `cases.jsonl` | Ten selected-case manifests, exclusions, unresolved alert IDs and source-readiness status |
| `issues.jsonl` | Conflicts, invalid input records and explicit normalization warnings |
| `tables.jsonl` | Baseline table/time inventory plus original CSV source references |
| `report.json` | Completion status, counts, case-window coverage, limitations and output checksums |

Exit status is `0` for a completed source run with no blocked entities/cases,
`1` when unaffected results were produced but some entities/cases are blocked,
and nonzero on an ingestion or output error. Warnings and blocked reasons are
retained; an error is not a successful empty inventory.

### Coverage boundary

The verified supplied-input run resolves **914 incidents / 1,069 alerts**,
**155 historical removed links**, and all ten case manifests. Its 760 source
files comprise the tenant DuckDB, 394 incident CSVs and 365 metadata files.
Cases 5 and 322 are source-ready with their existing exclusions; that does not
certify complete telemetry or any particular QA claim.

I1 fully reconciles the incident/alert records. In the I1 bundle alone, other CSV
telemetry tables are hashed, cataloged and exposed through the bounded table-row
reader, but are **not yet deduplicated or merged against the baseline**.
Coverage counts explicitly describe the already merged imported DuckDB's
62 tables / 13,339,265 rows. Graph-building source adapters must resolve the
remaining telemetry overlap/schema issues before claiming an all-source graph.
These outputs are private: final classifications, source paths and raw metadata
must not be served directly to evaluated agents.

## I2 source preparation: canonical diagnostic columns

The seven reviewed AzureDiagnostics name pairs now have one canonical field
per pair. This is an explicit allowlist, not a blanket case-insensitive merge:

| Canonical field | Original field names |
|---|---|
| `clientIp_s` | `clientIP_s`, `clientIp_s` |
| `socketIp_s` | `socketIP_s`, `socketIp_s` |
| `errorInfo_s` | `errorInfo_s`, `ErrorInfo_s` |
| `hostName_s` | `hostName_s`, `hostname_s` |
| `originIp_s` | `originIp_s`, `originIP_s` |
| `pop_s` | `pop_s`, `POP_s` |
| `probeUrl_s` | `probeUrl_s`, `probeURL_s` |

[columns.py](columns.py) maps the imported database's known `_1` storage names
back to their original names before applying the same policy used for CSVs.
Only empty strings/nulls mean absent. One nonempty value is retained; equal
nonempty values become one value; different nonempty values raise an explicit
conflict identifying the field and source records. Values are not trimmed,
case-folded or otherwise rewritten to manufacture equality.

Create derived data without changing the original tables/files:

```bash
python -m secgym.qagen.agentic normalize-diagnostic-columns \
  --source-bundle /path/to/completed-i1-bundle \
  --output /path/to/new-canonical-diagnostics
```

The new `diagnostics.duckdb` contains:

- `imported.AzureDiagnostics`: normalized columns for the supplied baseline.
- `csv_exports.AzureDiagnostics`: normalized columns for original CSV rows.
- `alias_origins`: the original field(s) contributing each populated canonical
  field, indexed by source ID and source record.

Every normalized row carries `_source_id` and `_source_record`. The sidecar
`column_maps.json` records original, physical storage and canonical names.
`column_report.json` is written only after row/value preservation checks and
input-integrity checks pass; it records policy/implementation versions and
output checksums. Existing output directories are never overwritten.

**The two source streams intentionally remain separate.** They overlap; their
row counts must not be added as unique events. Column consolidation is complete
independently of the remaining telemetry row-deduplication and graph work.
Other baseline columns keep their types; original CSV values remain text until
the later typed telemetry reconciliation step.

### CSV parsing fidelity

The source auditor and normalizer now parse CSV with the standard-library
reader, preserving case-sensitive header identities and record ordinals.
A bounded, lossless JSON-lines transfer stages values into DuckDB without
reinterpreting CSV quotes. This corrects the observed CloudAppEvents reader
discrepancy that dropped a closing `]`; it is not a repair to source data.

Dynamic-field repair is separate from column consolidation and is available
through the explicitly approved normalizer below. Neither operation rewrites
ordinary commands, paths or unrelated `"N/A"` values.

## I2 source preparation: lossless dynamic JSON repair

[dynamic.py](dynamic.py) implements the approved `dynamic-json-v1` policy:

- Only fields declared `dynamic` by source metadata are eligible.
- Already-valid, unambiguous JSON remains byte-for-byte unchanged.
- Malformed JSON is repaired only if it consists of literal JSON-compatible data:
  string-keyed dictionaries, lists, strings, booleans, nulls and supported
  numbers. Parsing traverses a restricted AST; it never executes expressions
  or calls, and does not perform global quote replacement.
- A repaired value must round-trip through JSON with the same value and types.
  Duplicate keys, nonfinite or precision-losing numbers, tuples/sets/bytes,
  executable syntax and values beyond explicit size/depth limits are quarantined.
- Raw source files remain immutable. A decision record retains the original
  value, normalized value, reason, content hash and affected-row count; every
  affected field also has its own source-record reference.

```bash
python -m secgym.qagen.agentic normalize-dynamic-fields \
  --source-bundle /path/to/completed-i1-bundle \
  --output /path/to/new-dynamic-normalization
```

The output is private build data:

| Output | Purpose |
|---|---|
| `dynamic_fields.duckdb` / `dynamic_decisions` | Original/normalized values, repair/quarantine statuses and reasons, grouped by source/table/field/value |
| `dynamic_fields.duckdb` / `field_changes` | Source ID, table, row locator, field and decision hash for every affected occurrence |
| `imported.*` / `csv_exports.*` tables in that database | Copies of changed streams only; unaffected fields and source row counts are checked for preservation |
| `dynamic_report.json` | Completion status, checked stream inventory, outcomes, policy/implementation versions, resource limits and database checksum |

Unchanged streams stay at their pinned sources rather than being copied merely
to claim normalization. Baseline and CSV observations are still overlapping
source streams, not a deduplicated event inventory.

A quarantined field has no usable normalized value. Its row and other fields
remain available, but dependent graph extraction and gold claims must consult
`field_changes` and be blocked. The null placeholder is **not evidence that the
source lacked data**. Quarantines produce `complete_with_quarantines` and a
nonzero CLI exit; parse/build failures do not produce a success completion
report. Existing output directories are never overwritten.

### Verified source result

The real run checked 230 baseline/CSV streams with declared dynamic columns:

- **10,104,440 nonempty field occurrences unchanged.**
- **11,472 repaired occurrences**, all in the incident-34
  `DeviceFileEvents.AdditionalFields` export, covering eight distinct values.
- **Zero quarantined occurrences.**
- Only that one changed stream was materialized; all its other fields and row
  locators were preserved. Every repaired record passed an independent
  literal-data versus JSON comparison.
- CloudAppEvents values required no repair; the earlier truncated `]` was a
  reader bug already corrected by the lossless CSV transfer.

These are field counts across overlapping sources, not counts of unique events.
No original database/CSV, classifications, old graph or legacy dataset changed.
Core incident/alert state remains managed by I1. The separate observation-ledger
step below performs full telemetry reconciliation; graph construction and
runtime QA generation remain later work.

## I2 observation ledger: exact telemetry reconciliation

[ledger.py](ledger.py) combines the pinned I1 source bundle and approved dynamic
normalization into a new, private DuckDB observation layer:

```bash
python -m secgym.qagen.agentic build-observation-ledger \
  --source-bundle /path/to/completed-i1-bundle \
  --dynamic-bundle /path/to/completed-dynamic-normalization \
  --output /path/to/new-observation-ledger
```

### Equality and identity

- Canonicalize the seven approved AzureDiagnostics aliases before comparison.
- Apply declared types with explicit failure on invalid casts. Integer values
  must not be rounded; numbers must be finite. Timestamps use the baseline's
  UTC microsecond precision.
- Canonicalize dynamic-JSON key order and formatting for comparison, while
  preserving numeric tokens and array order. Ordinary string values retain
  their case, spaces and quote characters. Empty source fields mean unavailable.
- Merge only observations whose full typed payload, source-field availability
  and quarantine state agree. Compare payloads for matching content IDs;
  a hash collision must not silently discard data.
- Missing columns are not assumed to be known null values. Partial schemas
  receive distinct availability signatures.
- Keep different commands, dates, field values and ambiguous variants separate.
  There is no global quote replacement, filename-only identity or
  time-proximity deduplication.

Non-core observation IDs are content-derived and bound to the row policy and
canonical source-schema variant. The report pins the DuckDB serializer/runtime
version and implementation hashes; identity is not assumed portable across
unreviewed normalization/serialization changes.

### Provenance and active state

Each typed source table gains `_observation_id`, `_source_schema_id` and
`_field_quality`. All source rows, including duplicates, retain entries in
`_origins` with their source ID and original record locator.

The ledger also contains:

- `_stream_schemas` and `_column_aliases`: original field availability and
  canonical-column mappings.
- `_field_changes` and `_dynamic_decisions`: exact repair/quarantine provenance.
- `_core_source_references`: I1 source references for incident/alert evidence.
- `_historical_memberships`: explicitly historical removed links.
- `_cases`: the ten source-readiness manifests and exclusions.

Only I1's latest resolved incident and alert payloads enter the active
`SecurityIncident` and `SecurityAlert` tables. Their I1 observation IDs remain
unchanged; superseded incident payloads are not reintroduced.

A row with a quarantined field cannot merge with a genuinely missing value:
its identity includes the affected field and original-value hash. Consumers
must enforce `_field_quality` and the field-level exclusions before using
that evidence. Source-origin counts and distinct-observation counts are not
certified counts of independent real-world events.

### Completion and limits

Inputs and completed repair bundles are verified before use. A fresh output
directory is required. The builder uses one thread, a 1 GB engine memory limit
and bounded spill storage; it publishes `ledger_report.json` only after count,
provenance, input-stability and checksum checks pass.

The ledger is **not** a graph, student-visible database or QA release.
The clean graph builder below consumes it without modifying it.

### Verified full-source result

The completed real-data ledger contains:

- **62 typed source tables / 13,276,306 canonical observations**.
- **16,051,309 retained source-origin references**, including origins of
  duplicate observations.
- **8,778 additional non-core telemetry observations from the CSV exports**:
  5,548 file events, 2,841 registry events, 387 sign-ins and two device records.
- **914 latest incidents, 1,069 latest alerts, 155 historical removed links and
  ten case manifests**.
- Provenance for all **11,472 repaired dynamic-field occurrences**.

The origin total covers all non-core input rows plus the source copies of active
latest incident/alert records. Superseded core records are represented separately
by `_core_source_references`, not counted as active source-table observations.

Spot checks of retained file/registry variants found differences in initiating
process command text; sign-in examples differ in ASN fields. These are retained
source-content variants, **not automatically new real-world events**. No broad
quote, whitespace or numeric-looking-string heuristic was used to collapse them.

All per-table row/unique-ID/origin counts, the database checksum, historical
evidence references and repair references passed independent verification.
The full focused suite passes **137 tests**, and all 109 pinned legacy files
remain unchanged. Wide-table payload checks use column batches and duplicate
representatives; core JSON records are loaded in bounded batches. No memory
failure or incomplete build is published as a completed ledger.

## I2 clean evidence graph

[graph.py](graph.py) builds fresh relationships from the verified observation
ledger using the explicit [field/JSON rules](graph_rules.py) and
[entity normalization](graph_entities.py). It never imports edges from an old
graph as evidence:

```bash
python -m secgym.qagen.agentic build-evidence-graph \
  --ledger-bundle /path/to/completed-observation-ledger \
  --output /path/to/new-evidence-graph
```

### Representation and provenance

The graph is observation-centered: an observation links to its actors, targets,
devices, file content, processes, addresses, applications and other participants.
Two participants in one observation can be traversed through that observation;
they are not arbitrarily connected by a causal attack edge.

- `observations`: source observation ID, table, tenant, event time, action,
  evidence lineage and quarantine state. All ledger observations remain
  inventoried, even when no entity-extraction rule applies.
- `nodes`: tenant-scoped, typed entity IDs and normalized values. Application
  IDs, cloud-application IDs, directory-object IDs and display labels are
  distinct; accounts are not merged merely by a display name or UPN prefix.
- `edges`: participant/relationship role, exact observation ID, rule ID,
  source field/JSON path and interpretation class.
- `exclusions`: invalid identifiers, unsupported entity types/references, and
  incomplete/future process identities. These are visible diagnostics, not
  successful empty extraction.
- `rule_runs`: per-rule output/rejection/quarantine counts.
- `historical_evidence` and `case_manifests`: membership provenance and selected
  scenario metadata, separate from current incident membership.

The event time and evidence lineage are attached to the observation and shared
by its participant edges. `OtherAlertRelatedActivity` remains detector-derived;
signatures and inventory are context, not authorization. Current membership and
historical removed membership use different roles/semantics. A removed link
records both before and after supporting observations.

### Implemented extraction

The initial rules cover endpoint/identity/network/mail/cloud participants,
exact source process identities, scoped account labels, content hashes, host
file/registry references, current incident/alert identity, and nested alert
entities including `$ref` resolution. Non-shared alert entities are retained.

Enrichment includes:

- All audit target resources and actor fields, not only the first target.
- All cloud activity objects that carry usable identity, retaining source role.
- Click message, user, IP, URL and every redirect-chain member.
- GUID resource targets in supported Microsoft Graph API URI collections.
- Graph activity `SignInActivityId` references linked in the token namespace,
  matching sign-in `UniqueTokenIdentifier`, not incorrectly treated as request
  GUIDs.
- Intune actor/target/enrollment identifiers and provisioning source/target IDs.
- Device IP inventory and sign-in device IDs.
- Filename/script/URL references from complete command text, with character
  offsets and **lexical-reference** semantics, never inferred execution.

Fields remain queryable in the ledger when they do not have a reviewed graph
rule. A `source_only` table disposition is not a claim that the table is empty,
irrelevant or missing.

### Intentional limits and next acceptance checks

Exact host/PID/start-time process identities are supported. Missing process
creation times are not filled from nearest events; recovered-process linking
needs separately justified identity/conflict rules. Full hostnames are not
blindly merged by short name, and generic account labels do not establish
strong identity. Hash aliases can be investigated through observations carrying
both hashes rather than an unconditional global merge.

Raw presence of an identity in a field establishes reported participation,
not proof of actor intent, successful action, or causation. Paths through
contextual/metadata/lexical links require explicit validation before gold use.
This initial graph is not a certified replacement for every old relationship.

### Old/new comparison

```bash
python -m secgym.qagen.agentic compare-evidence-graphs \
  --graph-bundle /path/to/new-evidence-graph \
  --old-graph secgym/database/duckdb_data/graph.duckdb \
  --legacy-graphs secgym/qagen/graph_files \
  --output /path/to/new-comparison
```

[graph_compare.py](graph_compare.py) reports old source-row mapping into the
ledger, presence of new participant edges, and old alert/entity identifier
relationships. It distinguishes missing identifiers, identifiers elsewhere,
and compound identities requiring contextual mapping. It reports
`compared_not_certified`: source-row coverage is not semantic path equivalence.
The separate semantic check below validates legacy alert/entity mappings
against source fields and actual graph paths. Neither command certifies every
possible investigation path. No edge-count equality is required.

```bash
python -m secgym.qagen.agentic check-graph-semantics \
  --graph-bundle /path/to/new-evidence-graph \
  --legacy-graphs secgym/qagen/graph_files \
  --output /path/to/new-semantic-check
```

[graph_semantics.py](graph_semantics.py) verifies graph/ledger checksums and writes
a private, immutable `semantic_report.json` containing per-edge dispositions,
source observations, fields, graph identities and supporting paths. Unresolved
links produce `needs_review` and exit status 1; explained exclusions are separate
from preserved identities. `legacy_edges_accounted` means the supplied legacy
links have been accounted for, not that the whole graph is certified or a QA
task is admissible.

### Initial real-data graph checkpoint

The completed `evidence-graph-v1.2` rule revision contains **13,276,306 observation
nodes**, **6,191,517 entity nodes**, and **64,134,168 edges**, including 155
historical removed memberships. All edge provenance references and destination
nodes resolve; graph/ledger checksums and current/history counts were verified.
This uses 332 rule executions across the 62 inventoried source tables, with
explicit source-only dispositions for tables without supported participants.

This is an observation-centered graph, so its edge/node/depth counts are **not
directly comparable** to the old graph's compressed relationships.

The comparison resolves all **186 original alert nodes**. Of 6,357,495 distinct
source rows cited by the old graph, 6,357,361 map to the active ledger and
all 6,357,361 have new participant edges. The remaining 134 are older incident
versions excluded from active state. The earlier missing file-hash TI rule is
implemented, with 408,790 source-backed contextual indicator-content links.

The initial identifier-only comparison classified the original 1,603
alert/entity edges as follows (superseded by the source-semantic check below):

| Comparison status | Count |
|---|---:|
| Reported entity identifier retained on the same alert | 810 |
| Same-alert weak/lexical reference preserved | 400 |
| Compound identity requiring contextual mapping | 268 |
| Case-variant filename requiring platform context | 68 |
| Identifier exists elsewhere, not matched on the same alert | 19 |
| Invalid or unsupported legacy identifier form | 35 |
| Basename found inside a source path, requiring context | 1 |
| Identifier not represented by the current exact matcher | 2 |

The completed source-semantic check accounts for **all 1,603 links**, with zero
unresolved links:

| Semantic disposition | Links |
|---|---:|
| Same-alert source-reported identifier | 788 |
| Supported weak/lexical/contextual reference | 515 |
| Same-alert host/PID/start-time identity and legacy command projection verified | 261 |
| Old synthesized email corrected to the same source account's authoritative UPN | 35 |
| Exact message/recipient-linked alternative evidence path | 3 |
| Intentionally excluded unqualified legacy process identity | 1 |

The three alternative paths belong to incident 134: sender address and IP are
present in the exact message/recipient's `EmailEvents` record, and the HTTPS URL
is explicitly present in that message/recipient's `UrlClickEvents.UrlChain`.
The alert-to-message, raw-observation-to-message and raw-observation-to-target
graph edges all exist. No generic HTTP/HTTPS equivalence was introduced.

The excluded incident-322 PID 4256 tuple uses timezone-free `CreatedTimeUtc`,
not `CreationTimeUtc`. A unique same-host/PID/full-command raw process record
has an explicitly qualified start time, `2024-08-01T12:25:23.612698+00:00`,
and its own graph process node. The report preserves that evidence but does
**not** alias it to the old `2024-08-01T13:42:52.04` label or create a recovery
edge. Similarly, lexical filename/case checks do not establish physical file
identity, and old lowercased URL projections do not rewrite current URLs.

This closes the scoped **legacy alert/entity semantic check**, not all I2
acceptance or tenant-wide ontology coverage. Source-only tables and unsupported
entity types remain explicit coverage limits; their raw ledger data is retained.
Task-specific evidence/path validation is still required before model-driven
QA admission.

**201 focused v1 tests pass**, including 29 semantic-check tests; Pylance and
Python 3.10 grammar checks are clean (not a Python 3.10 runtime-matrix test).
The 109 legacy-file baseline remains unchanged. No QA generation, external model
calls, graph/source mutation, or full semantic-parity certification occurred.

### Coverage follow-up: evidence-graph-v1.3

The source-only/type audit found **implementation gaps**, not a justification
to discard the available evidence. The completed fresh revision adds 42,585
participant edges and 144 entity nodes:

| Current graph artifact | Count |
|---|---:|
| Observation nodes | 13,276,306 |
| Entity nodes | 6,191,661 |
| Source-linked edges | 64,176,753 |
| Rule executions | 341 |
| Historical removed memberships | 155 |

The new rules retain:

- IoT IDs scoped by the explicitly referenced hub/resource; device names remain
  references, without MDE/Entra equivalence.
- NIC MAC references and existing nested IP evidence, without physical-device
  identity or authorization claims.
- Kubernetes namespace/service/pod/container names scoped by their explicit
  cluster resource and parent names. Without UIDs these are named references,
  not runtime-incarnation identities. Container image names are not hashes.
- Blob-container names scoped by the explicit storage resource.
- Reported resource metadata from `Alert`, `SentinelAudit`, `SentinelHealth`
  and `Usage`; a separately namespaced `Operation.SourceComputerId`; and
  contextual `HuntingBookmark` entities.

All 32,071 valid entity mentions replayed from current alert/anomaly/bookmark
sources have exact graph participants. No currently observed alert entity type
remains unmapped, and no incomplete new scoped reference was emitted. Replay
checks implementation/output consistency, not independent source truth.
All 1,603 legacy semantic dispositions remain unchanged.
The old telemetry-graph comparison also preserves all 6,357,361 active mapped
source rows and their participant coverage; the same 134 superseded incident
rows remain excluded from active state.

Six formerly source-only tables now have participants. This does not mean every
row is linked: `Alert` adds three links across ten rows and `Operation` one
across 36. `Watchlist` remains source-only: all 790 rows have empty
`EntityMapping` objects, so generic search keys are not automatically identities
or authorization evidence.

All 20 `SentinelAudit` rows have a top-level reported resource different from
the ID in their updated resource state. Both source values remain intact.
The graph role is **reported metadata**, not an assertion that the top-level
resource was the modified target. Gold claims must inspect the actual state
and resolve that distinction.

The scoped I2 graph-build/coverage/legacy acceptance gate is complete with these
documented limits. Existing process exclusions remain: 24 incomplete/ambiguous
alert traversal mentions and 1,095,747 missing/invalid/future telemetry process
identity mentions; those source observations and other valid participants
remain available. This is not a complete-acquisition or universal-ontology
certificate, and no task bypasses I3 evidence/serving validation.

The full **223-test** v1 suite passes, including eight new graph tests and
14 scoring tests. Pylance and Python 3.10 grammar checks pass; all 109 legacy
hashes remain unchanged. Original input data and older graph bundles are
unchanged.

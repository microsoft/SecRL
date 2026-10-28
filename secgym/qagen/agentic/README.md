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

The **329-test full suite passes with optional MySQL and ACE tests enabled**.
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

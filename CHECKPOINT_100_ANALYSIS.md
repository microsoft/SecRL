# First Astra QA checkpoint: outcome and analysis

**Cohort:** `astra100-01`, the original 100 logical questions  
**Analysis date:** 2026-11-02  
**Implementation checkpoint:** `97a1eaea6ce122903a2edfdcfb2b4f666490e1fc`

## Executive summary

The first checkpoint is reconciled: **92 questions are admitted with current
validation, eight are genuine scoped-objective duplicates, and no blocking
pipeline or grading hold remains.** All 15 originally admitted questions have
fresh clearances. No original question was replaced and no completed student
episode was rerolled. [A1, A3]

The initial 15% admission rate was not an 85% question-invalidity rate. Of the
85 initially unadmitted questions, **77 were subsequently admitted (90.6%)**;
the other eight were independently verified duplicates. Repairs addressed both
workflow defects and actual SQL/proof contracts, rather than simply relaxing
acceptance. [A1-A4]

Two qualifications matter:

- **Admission is not student success.** On the 92 admitted questions, the
  retained native student answered correctly in all 92 cases, but only
  **76/92 (82.6%)** achieved grounded final success.
- **Admission is not complete difficulty measurement.** Ninety admitted
  questions have numerical difficulty scores; two retain explicit, nonblocking
  ambiguity-measurement gaps. Neither gap is treated as zero difficulty.

The next checkpoint, `astra100-02`, was separately authorized and started after
closure. Its questions and results are excluded from every metric below.

## 1. Scope, denominators and verification

The fixed cohort contains 50 incident questions and 50 tenant questions.
Incident coverage is five questions each for incidents **5, 34, 36, 38, 39, 55,
133, 134, 166 and 322**. The development cohort is not included.

The original generation batch used **102 allocated slots to produce 100
draft-ready questions**; two operational generation failures are outside the
fixed 100. Thus draft production was 100/102, while final admission was 92/100
of the fixed cohort. These are different denominators.

| Measure | Result |
|---|---:|
| Original logical questions | 100 |
| Initially source-ready | 92 |
| Initially admitted | 15 |
| Final current clearances / historical admissions in this cohort | 92 / 92 |
| Genuine duplicate exclusions | 8 |
| Blocking pipeline or grading holds | 0 |
| Original admissions with fresh clearance | 15 / 15 |
| Historical admissions without current clearance | 0 |
| Replacement questions | 0 |
| Source-student role directories | Exactly one per question |
| Native-student role directories | Exactly one per question |
| Campaign historical admissions at first-checkpoint closure | 106 |

The campaign count includes 14 admissions outside this checkpoint; it is not
the size of this analysis.

Metrics were extracted from the fixed disposition inventory and each admitted
question's **current certificate**, not whichever admission or directory was
first encountered. Native evaluation, difficulty and canonical-fact inputs
were checked against certificate artifact hashes. Original inventories,
revalidation certificates, duplicate reviews and target admission receipts
remain linked through the closure records. [A1-A4]

Three incomplete historical pipeline directories remain as preserved failure
history. They are not three unresolved current questions.

## 2. What the initial holds actually meant

The original audit records the following first stopping points. These counts
are mutually exclusive **gate locations**, not mutually exclusive root causes:
a question could reveal another defect after its first blocker was repaired.

| Initial stopping point | Questions |
|---|---:|
| Already admitted | 15 |
| Robustness | 34 |
| Native validation / native preflight | 23 |
| Grading-contract review | 14 |
| Source review | 8 |
| Difficulty annotation | 3 |
| Canonical annotation | 1 |
| Objective novelty | 1 |
| Other operational error | 1 |
| **Total** | **100** |

Initial source outcomes were 92 source-ready, seven needing revision and one
operational error. The initial source-ready count and final admitted count
happen to be equal; they do not identify the same acceptance event. [A2]

Repair burden was substantial:

- **52/100 task fingerprints changed**, including 46 of the 92 admitted tasks.
- The cohort records **73 append-only source revisions**: 48 questions have
  zero, 39 have one, seven have two, five have three, and one has five.
- Annotation-only and operational continuations are additional work; they do
  not necessarily change a task fingerprint or create a source revision.

This supports the original diagnosis of pipeline and grading-contract
problems, but not the stronger claim that every initial draft was already
correct. Some contracts genuinely required repair.

## 3. Repairs and why they were necessary

| Area | Problem exposed | Correction and invariant |
|---|---|---|
| Orchestration | Finalization could reacquire its own lock; metadata contention and interrupted stages could look like question failures. | Short queued metadata transactions, audited continuations and separate fresh-validation certificates; completed students remain immutable. |
| SQL portability | JSON_TABLE input typing, JSON null versus the string `"null"`, timestamp rendering and collection NULLs differed across engines. | Source/native execution and counterfactual controls established the required SQL behavior. An empty collection is not a NULL-containing collection. |
| SQL access paths | Redundant binary casts could defeat indexes, while generic case-insensitive-default assumptions rejected already exact physical columns. | Preserve verified binary/NO PAD column semantics and index access; handle computed/JSON_TABLE values separately. |
| Qualified proofs | Candidate SQL returned only cited fragments or hid incomplete comparison candidates; reviewers sometimes required representative containment in addition to qualified support. | Return complete source-required candidate bundles. The qualified solver checks obligations, coherent bindings and actual availability; raw witness rows, relevance and support remain separate measurements. |
| Counterfactuals | Expected raw witnesses/support and explanatory text could be stale; smaller representatives could drop records needed by original controls. | Preserve original fixture records and interventions, then separately validate typed answers, raw witness groups and citation-availability support on both engines. |
| Canonical facts | Material action/identity/comparison fields were omitted; empty arrays could not be represented as scalar leaves. | Reinspect source properties and add the narrow `json_array_empty_v1` structural observation. Do not invent counts or select whole containers. |
| Difficulty | Given-key lookups, singleton DISTINCT operations, missing smaller routes and observation-level counts could inflate or misdescribe reasoning. | Score necessary work, expose materially different validated representatives, and measure candidates at the actual decision unit. |
| Recovery | Token-rate waits were confused with missing responses; a complete received JSON verdict could lack a `finish` tool call. | Reconstruct exact retained request histories and run the original validator. Unknown send states remain errors; no model output or finish call is fabricated. |

Representative examples:

- `incident-36-09`: preserve exact distinctness without destroying native
  process-identity index access.
- `incident-55-07`: distinguish JSON null from a real string value when counting.
- `incident-38-07`: represent a missing interval as a typed empty list.
- `incident-322-08`: use verified native collation facts and a case-only path
  control, rather than assume generic MySQL defaults.
- `incident-166-04` and `incident-322-04`: source-observed empty-array facts
  resolve a genuine annotation capability gap.
- `incident-322-06`: expose the already accepted **22-record** recipient proof
  alongside the **35-record** comparison proof. Then distinguish full recipient
  identities from repeated delivery observations and a supplied message key
  from a discovered binding.
- `tenant-51`: publish the already received assessment through its original
  validator with zero additional model calls, then resume remaining gates.

The relevant implementation is in
[checkpoint drafting](secgym/qagen/agentic/checkpoint_batches.py),
[pipeline orchestration](secgym/qagen/agentic/preproduction_pipeline.py),
[qualified proofs](secgym/qagen/agentic/qualified_witnesses.py),
[canonical facts](secgym/qagen/agentic/canonical_facts.py),
[difficulty curation](secgym/qagen/agentic/difficulty_curation.py) and
[received-JSON recovery](secgym/qagen/agentic/json_result_recovery.py).

## 4. Final yield and genuine exclusions

| Scope | Original | Admitted | Excluded | Admission rate |
|---|---:|---:|---:|---:|
| Incident | 50 | 50 | 0 | 100% |
| Tenant | 50 | 42 | 8 | 84% |
| **Total** | **100** | **92** | **8** | **92%** |

Every exclusion is a scoped-objective duplicate, not an unresolved SQL,
infrastructure, proof or annotation failure. Variations in wording, equivalent
selectors, output representation or a wider window did not establish a new
observed investigative target. [A4]

Task names in the tables omit the common `preprod-v1-` prefix.

| Excluded task | Retained target | Duplicate objective |
|---|---|---|
| tenant-05 | tenant-04 | Latest recipient click timestamp in the same message/quarantine interval |
| tenant-07 | tenant-06 | Recipient click count over the same observed message interval |
| tenant-13 | tenant-12 | Same creator/computer logon count through equivalent source selectors |
| tenant-19 | tenant-18 | Same subsequent policy assignments, represented as IDs rather than names |
| tenant-20 | tenant-18 | Same subsequent policy-name set with a nondistinguishing success filter |
| tenant-21 | tenant-18 | Same policy-assignment scope and requested policy-name set |
| tenant-25 | tenant-27 | Same provisioning lifecycle update count despite broader/linkage qualifiers |
| tenant-26 | tenant-27 | Same provisioning lifecycle update count with equivalent boundary filters |

Do not reword these eight into artificial novelty or retrospectively replace
them inside this fixed cohort. Future planning should track **admitted**
incident/tenant totals: balanced draft generation did not yield a balanced
admitted set.

## 5. Question and evidence characteristics

All 92 admitted questions have **one checkpoint**.

| Final answer type | Questions |
|---|---:|
| Set | 42 |
| Number | 35 |
| Timestamp | 5 |
| Ordered list | 5 |
| Entity | 5 |

The admitted cohort uses **37 source tables**. SecurityIncident and
SecurityAlert each occur in 50 questions; prominent other tables include
DeviceProcessEvents (29), DeviceEvents (24), DeviceFileEvents (9), SigninLogs
(7) and IdentityDirectoryEvents (7). Counts are questions containing a table,
not independent events or evidence strength.

| Evidence feature | Result |
|---|---:|
| Source evidence records per question: median / mean / range | 5 / 6.23 / 2-35 |
| Smallest represented final proof: median / mean / range | 5 / 5.65 / 2-22 |
| Questions using qualified final proofs | 24 |
| Questions with multiple final representative groups | 8 |
| Canonical fact occurrences across questions | 3,174 |
| Distinct canonical source-fact IDs | 2,753 |
| Canonical facts per question: median / mean / range | 29 / 34.5 / 11-107 |

A smallest *represented* group is not a proven global minimum over all
qualified alternatives. Graph adjacency and alert membership support
discovery/navigation; neither establishes causation or substitutes for
behavioral/security-control evidence.

### Source-fact reuse

Unit-weight Jaccard comparison of the canonical fact sets gives:

- 4,186 admitted-question pairs.
- 110 pairs share at least one canonical fact.
- Three pairs have Jaccard overlap at least 0.5; none has identical fact sets.
- Median overlap is 0; mean overlap is approximately 0.00289.

The largest overlaps are tenant-48/tenant-49 (0.7703), tenant-04/tenant-06
(0.7273), and incident-36-05/incident-36-08 (0.6250).

These are **fact-set reuse statistics, not semantic duplicate rates or split
guarantees**. Most global pairs involve different scopes, making a low global
mean unsurprising. Shared source facts can support distinct legitimate
objectives; novelty still requires independent objective review.

## 6. Difficulty: predominantly hard, with two explicit gaps

Difficulty uses the existing source-only heuristic and reviewed reasoning
routes, not student outcomes or a desired band distribution.

| Difficulty band | Admitted questions |
|---|---:|
| Easy | 0 |
| Medium | 25 |
| Hard | 52 |
| Very hard | 13 |
| Unmeasured | 2 |
| **Total** | **92** |

Among the **90 measured questions**, the mean is 57.22, median 56.67 and range
26.67-93.33. Sixty-five of 90 measured questions (72.2%) are hard or very hard.

The two unmeasured questions are:

| Task | Explicit limitation |
|---|---|
| incident-134-04 | Ambiguity was not measured; score and band are null. |
| incident-38-06 | Ambiguity was not measured; score and band are null. |

Both have reviewed annotations with no task-defect reasons or measurement
errors. The current [admission policy](secgym/qagen/agentic/preproduction_admission.py)
allows an explicitly incomplete difficulty sidecar when the required semantic
review passes. Thus **zero blocking holds does not mean zero measurement
limitations**. Exclude these two from numerical difficulty summaries until
their missing axes are measured; never assign them an easy/zero value.

Forty-eight annotations use curation-context v0.3 and 44 use v0.4, under the
same `difficulty-heuristic-v0.1` definition. They are not a uniformly
reauthored, empirically calibrated difficulty benchmark.

## 7. Retained native-student performance

These results use the current validated contracts and the **original retained
native episodes**, on the 92 admitted questions only.

| Measure | Result |
|---|---:|
| Correct final answer | 92 / 92 (100%) |
| Grounded final success | 76 / 92 (82.6%) |
| Correct answer without accepted complete final grounding | 16 / 92 (17.4%) |
| Incorrect final answers | 0 |
| Student abstentions | 0 |
| Any positive checkpoint progress | 14 |
| Reward 1.0 | 76 |
| Reward 0.5 | 2 |
| Reward 0.0 | 14 |
| Mean reward | 0.8370 |

The two checkpoint-only positive rewards belong to tenant-23 and tenant-40.
The scoring rule remains `max(F, 0.5 * P)`, where `F` is grounded final success
and `P` is checkpoint progress. A correct answer alone is not `F = 1`.

| Scope | Grounded success |
|---|---:|
| Incident | 44 / 50 (88.0%) |
| Tenant | 32 / 42 (76.2%) |

| Difficulty band | Grounded success |
|---|---:|
| Medium | 23 / 25 (92.0%) |
| Hard | 41 / 52 (78.8%) |
| Very hard | 10 / 13 (76.9%) |
| Unmeasured | 2 / 2 |

The current contracts turn five originally ungrounded native episodes into
grounded successes: incident-133-08, tenant-32, tenant-38, tenant-44 and
tenant-54. Seventy-one remain successful, 16 remain unsuccessful, and none
changes from successful to unsuccessful. **This is contract/evaluation repair,
not a model capability gain or an additional student attempt.**

Do not interpret the 100% answer rate as independent benchmark accuracy.
Source readiness is itself conditioned on a successful source-student check,
the cohort was curated through repeated contract review, and this is one
source snapshot. The grounding gap is useful evidence of why citation/proof
validation matters, not a population-level estimate of solver ability.

## 8. Performance and operational lessons

The long repair campaign is not comparable to a clean generation benchmark:
it included diagnosis, contract revisions, counterfactual verification and
fresh source/annotation review while preserving earlier student episodes.
No aggregate wall-clock speedup or monetary cost is established here.

Verified improvements include:

1. **One persistent read-only native snapshot**, with four bounded candidate
   slots and independent grader/student sessions. Source-only reviews do not
   hold a native student slot; mutations use isolated fixtures.
2. **Index-preserving exactness.** Incident-36-09's corrected full parity check
   took 1.109 seconds. Tenant-35's earlier four concurrent parity checks had a
   slowest completion of 4.544 seconds. These are task-specific measurements,
   not whole-checkpoint throughput claims.
3. **Batched immutable metadata lookup.** Three source probes with 495, 765 and
   33 rows reproduced their persisted measurements exactly in 49.88 seconds
   using the corrected read-only metadata adapter. The earlier finish-
   validation callback took 988.31 seconds. The aggregate SQL itself was
   inexpensive; repeated source-record attribution/lookup was the bottleneck.
   The two timings cover closely related but not identical entry points.
4. **Evidence-bound recovery**, including zero-inference publication of a
   complete received verdict, avoids rerunning already completed work.

The metadata adapter is verified in private repair execution; this report does
not claim every default command uses it. An initial adapter cursor-interface
failure was preserved, corrected and tested against a real native lease before
an explicit exact-input empty-stage continuation.

The native index amendment reverified **1,238,201 affected rows**, not every
row of the full snapshot anew. Untouched tables retain their original
verification. The final repair's compatibility audit also preserved 137 legacy
canonical bundles, 4,483 historical fact IDs and the 11 pinned native-kernel
files. This kernel-freeze statement is relative to that repair baseline, not
to the earlier Git branch base.

## 9. Recommendations for subsequent checkpoints

- **Maintain the distinction between drafting, question admission, grounded
  student success, difficulty completeness and release approval.** Publish
  all five dimensions rather than one blended pass rate.
- **Check objective novelty earlier**, especially for tenant variants whose
  wording or selectors change without changing the observed target.
- **Expose materially different proof representatives at drafting time.**
  The difficulty interface binds evidence-set fingerprints; a valid smaller
  qualified route must not become unrepresentable to annotation.
- **Retain complete comparison obligations and original controls.** Do not
  remove inconvenient rows or change typed answers to clear a review.
- **Measure the real decision unit.** Given unique-key lookups are not
  discovered bindings; repeated observations are not necessarily different
  recipient/request/process candidates; singleton DISTINCT is not always
  substantive aggregation.
- **Track the two difficulty gaps explicitly.** Complete their ambiguity axes
  before using the full 92 in difficulty-stratified analysis.
- **Reuse verified infrastructure without hiding failures.** Preserve exact
  source/native bindings, independent sessions, row hashes, original errors
  and student histories; propagate metadata batching only with matching
  interface and parity tests.
- **Continue checkpoint review, not blind scaling.** The first cohort is ready
  to inform subsequent generation, but admission is not release approval,
  and sparse overlap does not establish leakage-free evaluation splits.

## 10. Evidence and reproducibility

The implementation and test/documentation work was committed first as
`97a1eaea6ce122903a2edfdcfb2b4f666490e1fc` (62 files). Validation covered all
**711 discovered agentic tests**: 697 passed in the standard run and the
14 environment-gated native tests passed in a separate isolated-MySQL run.
The existing second-batch runtime binding and SQL service remained valid.

Raw QA questions, gold answers, telemetry, model transcripts, credentials and
run-specific recovery scripts remain private, outside this report's Git
payload. Only aggregate results and task identifiers are reproduced here.

`RUN` below denotes the private preproduction run directory; `FILES` denotes
its containing session artifact collection. These are evidence locators, not
publicly distributed datasets.

| ID | Evidence locator | SHA-256 |
|---|---|---|
| A1 | `RUN/checkpoint-repairs/astra100-01/repair09/fixed-cohort-disposition.json` | `cf50e1f193027751b4b6b7da8b02d1043a7fc251590b2e906b4c00ddc6b2a828` |
| A2 | `FILES/checkpoint-investigation01/inventory.json` | `bbdf25144ac335b6f3eee68a541083377ae190bc0f3382121fed4c8a1b51a47f` |
| A3 | `RUN/checkpoint-repairs/astra100-01/repair09/final-reconciliation.json` | `0b60bdf7d32c514aec8e0e1648d7dc3596b128ef4d804a1e0b8fdc149058342a` |
| A4 | `RUN/checkpoint-repairs/astra100-01/repair07/fixed-cohort-exclusions02.json` | `54abe49a522e4bc0464b4e38493b15dd1c406c8bf536e59c5dc158ff03f9daf7` |

For each admitted entry in A1, resolve its current certificate and
`latest_pipeline/admission-files.json`. The certificate binds the native
evaluation report, difficulty report/sidecar and canonical-fact bundle used
for this analysis. Source-fact overlap is unit-weight Jaccard of the resolved
canonical fact IDs, over all `92 choose 2` pairs.

The extraction script and derived summaries are retained privately as
`FILES/checkpoint100-analysis/build_metrics.py`, `metrics.json` and
`overlap-metrics.json`. Every appendix row was checked against those
certificate-verified metrics.

Performance/compatibility evidence is retained under
`RUN/checkpoint-repairs/astra100-01/repair09/` in
`metadata-cache-verification.json`, `metadata-cache-verification02.json`,
`metadata-cache-native-parity.json` and `compatibility-verification.json`.
The second-batch authorization supersedes the closure's historical
generation-block state; it does not change the first-cohort results.

## Appendix: complete fixed-cohort inventory

The common task prefix is `preprod-v1-`. Source revisions are append-only
source-revision counts, not student attempts. Grounded/reward columns describe
the retained native episode under the current admitted contract; excluded
questions are not included in these performance summaries. Displayed scores
are rounded to one decimal, without changing stored values.

<details>
<summary>All 100 original questions</summary>

| Task | Disposition | Source revs | Difficulty | Score | Native grounded | Reward |
|---|---|---:|---|---:|---|---:|
| incident-133-04 | Admitted | 0 | hard | 56.7 | Yes | 1 |
| incident-133-05 | Admitted | 0 | hard | 63.3 | Yes | 1 |
| incident-133-06 | Admitted | 0 | medium | 26.7 | Yes | 1 |
| incident-133-07 | Admitted | 1 | hard | 50.0 | Yes | 1 |
| incident-133-08 | Admitted | 2 | hard | 50.0 | Yes | 1 |
| incident-134-04 | Admitted | 2 | Unmeasured | - | Yes | 1 |
| incident-134-05 | Admitted | 0 | hard | 56.7 | Yes | 1 |
| incident-134-06 | Admitted | 0 | hard | 70.0 | No | 0 |
| incident-134-07 | Admitted | 0 | medium | 26.7 | Yes | 1 |
| incident-134-08 | Admitted | 0 | hard | 56.7 | Yes | 1 |
| incident-166-04 | Admitted | 1 | medium | 43.3 | Yes | 1 |
| incident-166-05 | Admitted | 1 | hard | 73.3 | Yes | 1 |
| incident-166-06 | Admitted | 1 | hard | 73.3 | Yes | 1 |
| incident-166-07 | Admitted | 0 | medium | 33.3 | Yes | 1 |
| incident-166-08 | Admitted | 0 | very_hard | 76.7 | Yes | 1 |
| incident-322-04 | Admitted | 1 | hard | 53.3 | Yes | 1 |
| incident-322-05 | Admitted | 1 | hard | 60.0 | No | 0 |
| incident-322-06 | Admitted | 5 | hard | 60.0 | Yes | 1 |
| incident-322-07 | Admitted | 0 | hard | 60.0 | No | 0 |
| incident-322-08 | Admitted | 2 | hard | 63.3 | Yes | 1 |
| incident-34-04 | Admitted | 1 | hard | 63.3 | No | 0 |
| incident-34-05 | Admitted | 1 | medium | 36.7 | Yes | 1 |
| incident-34-06 | Admitted | 1 | hard | 53.3 | Yes | 1 |
| incident-34-07 | Admitted | 0 | hard | 70.0 | Yes | 1 |
| incident-34-08 | Admitted | 0 | hard | 53.3 | Yes | 1 |
| incident-36-04 | Admitted | 0 | medium | 36.7 | Yes | 1 |
| incident-36-05 | Admitted | 0 | medium | 26.7 | Yes | 1 |
| incident-36-06 | Admitted | 0 | hard | 53.3 | No | 0 |
| incident-36-08 | Admitted | 1 | medium | 40.0 | Yes | 1 |
| incident-36-09 | Admitted | 2 | medium | 46.7 | Yes | 1 |
| incident-38-04 | Admitted | 0 | hard | 63.3 | Yes | 1 |
| incident-38-05 | Admitted | 0 | medium | 36.7 | Yes | 1 |
| incident-38-06 | Admitted | 3 | Unmeasured | - | Yes | 1 |
| incident-38-07 | Admitted | 1 | hard | 63.3 | Yes | 1 |
| incident-38-08 | Admitted | 1 | hard | 63.3 | Yes | 1 |
| incident-39-04 | Admitted | 1 | hard | 63.3 | Yes | 1 |
| incident-39-05 | Admitted | 1 | hard | 66.7 | Yes | 1 |
| incident-39-06 | Admitted | 1 | hard | 66.7 | Yes | 1 |
| incident-39-07 | Admitted | 1 | hard | 70.0 | Yes | 1 |
| incident-39-08 | Admitted | 1 | hard | 53.3 | Yes | 1 |
| incident-5-04 | Admitted | 0 | very_hard | 76.7 | Yes | 1 |
| incident-5-05 | Admitted | 0 | hard | 63.3 | Yes | 1 |
| incident-5-06 | Admitted | 0 | hard | 70.0 | Yes | 1 |
| incident-5-07 | Admitted | 1 | hard | 66.7 | Yes | 1 |
| incident-5-08 | Admitted | 0 | very_hard | 76.7 | No | 0 |
| incident-55-04 | Admitted | 0 | hard | 53.3 | Yes | 1 |
| incident-55-05 | Admitted | 1 | medium | 36.7 | Yes | 1 |
| incident-55-06 | Admitted | 1 | medium | 46.7 | Yes | 1 |
| incident-55-07 | Admitted | 3 | hard | 56.7 | Yes | 1 |
| incident-55-08 | Admitted | 1 | hard | 56.7 | Yes | 1 |
| tenant-04 | Admitted | 0 | hard | 60.0 | Yes | 1 |
| tenant-05 | Duplicate -> tenant-04 | 1 | - | - | - | - |
| tenant-06 | Admitted | 0 | hard | 53.3 | Yes | 1 |
| tenant-07 | Duplicate -> tenant-06 | 0 | - | - | - | - |
| tenant-08 | Admitted | 2 | medium | 26.7 | Yes | 1 |
| tenant-09 | Admitted | 0 | hard | 50.0 | Yes | 1 |
| tenant-10 | Admitted | 0 | medium | 33.3 | No | 0 |
| tenant-12 | Admitted | 0 | medium | 46.7 | Yes | 1 |
| tenant-13 | Duplicate -> tenant-12 | 1 | - | - | - | - |
| tenant-14 | Admitted | 0 | hard | 63.3 | No | 0 |
| tenant-15 | Admitted | 0 | hard | 53.3 | No | 0 |
| tenant-16 | Admitted | 0 | very_hard | 80.0 | No | 0 |
| tenant-17 | Admitted | 0 | medium | 46.7 | Yes | 1 |
| tenant-18 | Admitted | 0 | medium | 46.7 | Yes | 1 |
| tenant-19 | Duplicate -> tenant-18 | 0 | - | - | - | - |
| tenant-20 | Duplicate -> tenant-18 | 1 | - | - | - | - |
| tenant-21 | Duplicate -> tenant-18 | 1 | - | - | - | - |
| tenant-22 | Admitted | 0 | hard | 53.3 | Yes | 1 |
| tenant-23 | Admitted | 0 | hard | 53.3 | No | 0.5 |
| tenant-24 | Admitted | 3 | very_hard | 86.7 | Yes | 1 |
| tenant-25 | Duplicate -> tenant-27 | 1 | - | - | - | - |
| tenant-26 | Duplicate -> tenant-27 | 1 | - | - | - | - |
| tenant-27 | Admitted | 1 | medium | 46.7 | Yes | 1 |
| tenant-28 | Admitted | 1 | very_hard | 76.7 | No | 0 |
| tenant-29 | Admitted | 0 | medium | 43.3 | Yes | 1 |
| tenant-30 | Admitted | 0 | hard | 53.3 | Yes | 1 |
| tenant-31 | Admitted | 1 | very_hard | 76.7 | Yes | 1 |
| tenant-32 | Admitted | 1 | very_hard | 76.7 | Yes | 1 |
| tenant-33 | Admitted | 1 | medium | 36.7 | Yes | 1 |
| tenant-34 | Admitted | 2 | medium | 43.3 | No | 0 |
| tenant-35 | Admitted | 1 | hard | 63.3 | Yes | 1 |
| tenant-36 | Admitted | 0 | medium | 46.7 | Yes | 1 |
| tenant-37 | Admitted | 0 | hard | 63.3 | Yes | 1 |
| tenant-38 | Admitted | 3 | hard | 66.7 | Yes | 1 |
| tenant-39 | Admitted | 1 | very_hard | 76.7 | Yes | 1 |
| tenant-40 | Admitted | 1 | hard | 60.0 | No | 0.5 |
| tenant-41 | Admitted | 0 | hard | 63.3 | Yes | 1 |
| tenant-42 | Admitted | 0 | hard | 66.7 | No | 0 |
| tenant-43 | Admitted | 0 | hard | 53.3 | Yes | 1 |
| tenant-44 | Admitted | 1 | very_hard | 93.3 | Yes | 1 |
| tenant-45 | Admitted | 0 | medium | 46.7 | Yes | 1 |
| tenant-46 | Admitted | 0 | hard | 53.3 | Yes | 1 |
| tenant-47 | Admitted | 2 | hard | 66.7 | Yes | 1 |
| tenant-48 | Admitted | 1 | very_hard | 76.7 | Yes | 1 |
| tenant-49 | Admitted | 1 | very_hard | 83.3 | Yes | 1 |
| tenant-50 | Admitted | 0 | medium | 26.7 | Yes | 1 |
| tenant-51 | Admitted | 3 | hard | 70.0 | Yes | 1 |
| tenant-52 | Admitted | 0 | medium | 46.7 | Yes | 1 |
| tenant-53 | Admitted | 0 | hard | 60.0 | No | 0 |
| tenant-54 | Admitted | 1 | very_hard | 76.7 | Yes | 1 |

</details>

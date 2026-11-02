# First 100 QA: scope, difficulty and overlap

**Cohort:** `astra100-01` | **Date:** 2026-11-02

## Executive summary

This report covers the original 100 questions, including eight duplicates
excluded from the retained set of 92. Other batches are not included.

- **Scope:** all questions use **one tenant dataset**. The original 50
  incident-scoped / 50 tenant-scoped questions become **50 / 42** after
  exclusions. There are no cross-tenant comparisons.
- **Difficulty:** 70 of 98 measured questions are hard or very hard. The mean
  is **56.87/100**; reasoning and dependency depth drive the scores more than
  ambiguity.
- **Overlap:** mean diagnostic overlap is **0.00739 globally**, but
  **0.18073 within the same incident**. Low global overlap hides concentrated
  reuse; the highest retained pair scores **0.93894**.

## 1. Scope: tenant and incidents

**Tenant:** `e34d562e-ef12-4c4e-9bc0-7c6ae357c015`, the single supplied
SecRL tenant dataset, identified by `SecurityIncident.TenantId`. All ten
selected incidents belong to this tenant.

- **Incident-scoped questions** start from a selected incident. They may use
  relevant supporting evidence from elsewhere in the same tenant.
- **Tenant-scoped questions** investigate entities or workloads anywhere in
  this same dataset; they are not restricted to the ten selected incidents.
- **Overlap compares questions, not tenants.** Two tenant-scoped questions
  are two investigations within the same tenant. The 50 such questions yield
  `50 * 49 / 2 = 1,225` unordered pairs.

### Selected incidents

| Incident | Source incident title | Questions |
|---|---|---:|
| 5 | Human-operated ransomware attack was launched from a compromised asset (attack disruption) | 5 |
| 34 | Multi-stage incident involving Execution & Discovery on one endpoint | 5 |
| 36 | Multi-stage incident involving Execution & Discovery on one endpoint | 5 |
| 38 | Multi-stage incident involving Defense evasion & Discovery on one endpoint | 5 |
| 39 | Multi-stage incident involving Privilege escalation on multiple endpoints reported by multiple sources | 5 |
| 55 | Multi-stage incident involving Initial access & Lateral movement on multiple endpoints reported by multiple sources | 5 |
| 133 | Hands-on keyboard attack was launched from a compromised account (attack disruption) | 5 |
| 134 | BEC financial fraud attack was launched from a compromised account (attack disruption) | 5 |
| 166 | SAP financial process manipulation (attack disruption) | 5 |
| 322 | Multi-stage incident involving Initial access & Collection on multiple endpoints reported by multiple sources | 5 |
| **Total incident-scoped** | **Ten incidents in one tenant** | **50** |

### Scope breadth

| Characteristic | Incident-scoped questions | Tenant-scoped questions |
|---|---:|---:|
| Original questions | 50 | 50 |
| Retained questions | 50 | 42 |
| Median declared answer window | 24.66 minutes | 2 hours |
| Windows over 24 hours | 2/50 | 9/50 |
| Median reviewed-route proof observations | 6 | 4 |
| Median reviewed-route raw-table count | 1 | 2 |
| Questions with a discovered cross-domain binding | 0/50 | 3/50 |

The batch uses **37 evidence tables**, but most selected routes involve only
one or two raw tables. A declared answer window, the supporting evidence
footprint and the selected reasoning route are different boundaries.
Broader temporal or tenant-wide scope does not automatically mean greater
difficulty or cross-domain reasoning.

## 2. Difficulty

Difficulty is a **source-only reasoning heuristic**, not student accuracy.
Four axes, each scored from 0 to 3, describe the least demanding supplied,
reviewed complete reasoning route:

| Axis | What it measures |
|---|---|
| B: breadth | Proof observations, raw tables and discovered cross-domain bindings |
| P: dependency | Necessary binding depth and reconvergence |
| R: reasoning | Distinct necessary operations, such as ranking, aggregation and temporal alignment |
| A: ambiguity | Candidate populations at the actual decision unit, not repeated observations |

```text
Difficulty = (20*B + 30*P + 30*R + 20*A) / 3
```

| Band | Score interval | Full 100 | Retained 92 |
|---|---|---:|---:|
| Easy | `[0,25)` | 0 | 0 |
| Medium | `[25,50)` | 28 | 25 |
| Hard | `[50,75)` | 57 | 52 |
| Very hard | `[75,100]` | 13 | 13 |
| Unmeasured | Not scored | 2 | 2 |

The full-batch mean is **56.87** across 98 measured questions; the retained
mean is **57.22** across 90. Both medians are **56.67**, with scores ranging
from **26.67 to 93.33**.

**Interpretation:** 55 questions reach the maximum reasoning axis, 68 have
dependency level 2, and 50 have zero additional ambiguity. The batch is
primarily reasoning/dependency-heavy rather than uniformly search-heavy.
Tenant questions account for ten very-hard cases, versus three incident cases.

**Limitations:** incident-134-04 and incident-38-06 have unmeasured ambiguity;
their scores are unknown, not zero. Scores are heuristic, and the selected
route is not a proven global minimum over every possible proof.

## 3. Overlap metric and analysis

Overlap measures **shared question evidence**, including final-answer and
checkpoint support—not wording similarity or student citations.

| Component | Compared features |
|---|---|
| J_E | Source-backed, typed and directed graph-edge occurrences |
| J_O | Canonical source-observation IDs |
| J_F | Event-bound canonical source properties, including role and time context |
| C | Containment of the smaller observation-and-fact footprint |

For each of E, O and F, weighted Jaccard is:

```text
J(X,Y) = shared feature weight / union feature weight

D(q) = namespaced union of observation and fact features
C(a,b) = weight(D(a) intersect D(b)) / min(weight(D(a)), weight(D(b)))

Overlap score (equal weights) = (J_E + J_O + J_F + C) / 4
```

This analysis uses **unit feature weights** and **diagnostic equal-quarter
coefficients**. They are not calibrated production weights or duplicate
thresholds. Matching answer strings alone do not establish shared facts.
The earlier label **S25** meant **25% weight per component**. Scores range
from 0 to 1; they are not percentages of duplicate questions.

### Where overlap is concentrated

**Mean overlap** is the arithmetic average of the scorable question-pair
scores in that row. For example, **0.014341** averages **1,176 pairs of
tenant-scoped questions**, all from the same tenant. Missing scores are
excluded from the mean, not counted as zero.

| Question-pair category (same tenant throughout) | Total pairs | Scorable | Mean overlap (equal weights) | Maximum overlap |
|---|---:|---:|---:|---:|
| **All pairs** | **4,950** | **4,851** | **0.007394** | **1.000000** |
| Two questions from the same incident | 100 | 100 | **0.180732** | 0.785071 |
| Questions from different incidents | 1,125 | 1,125 | 0 | 0 |
| Two tenant-scoped questions | 1,225 | 1,176 | 0.014341 | 1.000000 |
| One tenant-scoped and one incident-scoped question | 2,500 | 2,450 | 0.000381 | 0.384153 |

All 100 same-incident pairs have positive overlap. By contrast, most global
pairs compare unrelated scopes. The median **nearest-neighbor** score is
**0.24575** across 99 scorable questions, despite a global pair median of zero.
Global sparsity therefore does not imply that every question is independent.

After the eight duplicate exclusions, mean overlap is **0.005302** over 4,095
scorable retained pairs. The retained fact-only mean, **0.002893**, is just
J_F—not the full overlap metric.

### Highest-overlap retained pairs

Task names omit the common `preprod-v1-` prefix.

| Pair | J_E | J_O | J_F | C | Overlap score |
|---|---:|---:|---:|---:|---:|
| tenant-48 / tenant-49 | 1.0000 | 1.0000 | 0.7703 | 0.9855 | **0.9389** |
| tenant-04 / tenant-06 | 1.0000 | 1.0000 | 0.7273 | 0.9091 | **0.9091** |
| incident-36-05 / incident-36-08 | 0.7922 | 0.8000 | 0.6250 | 0.9231 | **0.7851** |

**Interpretation:** high overlap can support distinct objectives—for example,
click timing versus click count. It should disclose reuse and guide inspection,
not automatically classify duplicates. Zero cross-incident overlap means no
shared included event-bound features, not necessarily different hosts/accounts.

**Availability:** tenant-51 has no graph-edge footprint, making its 99 full-batch
pair scores unscorable; 91 such pairs remain in the retained set. Its other
components are available. Missing scores are **NA, not zero**, and weights
are not silently renormalized.

**Detailed data:** [100-question inventory](CHECKPOINT_100_INVENTORY.csv);
[4,950 pairwise overlap records](CHECKPOINT_100_OVERLAP.csv).
**Definitions:** [difficulty](secgym/qagen/agentic/difficulty.py);
[overlap](secgym/qagen/agentic/similarity.py).

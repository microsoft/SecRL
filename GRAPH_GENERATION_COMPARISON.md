# SecRL and ExCyTIn 2.0: Graph Generation and Relation Coverage

**Review date:** 2026-10-19  
**Last updated:** 2026-10-24, recording the fresh v1 graph and source-coverage comparison.  
**Status:** Historical audits plus v1 implementation findings; scoped graph/legacy acceptance complete for the supplied snapshot with documented coverage limits.

**Scope correction:** the earlier counts of 306 incidents and 1,039 alerts
describe the supplied **post-cleanup DuckDB snapshot**, not every available
source export. The [cleanup-impact audit](#15-preprocessing-provenance-and-impact-on-the-audits)
found skipped incident history and excluded alerts in the local incident CSVs.
The snapshot results remain reproducible, but claims about all available inputs
must use the broader inventory and its explicit history/coverage limitations.

**Project decision (2026-10-21):** treat all ten selected incidents
**5, 34, 36, 38, 39, 55, 133, 134, 166, and 322** as TP benchmark scenarios.
The original eight and incident 133 have explicit user approval; incident 36
also has an exported TP classification. Project designations do not overwrite
the source labels. The evidence exclusions for 5 and 322 still apply.

**Current scope (2026-10-22):** defer FP/BP-targeted investigation and QA generation
at incident, alert, and event levels. The agreed implementation direction is documented in
[Agentic QA Generation for SecRL](QA_GENERATION_DESIGN.md):

- **Tenant-wide generation**, not restricted to the ten cases.
- **Incident-specific generation** for those ten cases, with full tenant access
  when needed but mandatory anchoring to the incident.
- **SecRL-first integration**, agent discovery, and strict validation.
- **FP/BP-targeted work deferred** at all three levels; retain the completed
  research for reference, not as an active generation workstream.

The incident, alert, and event investigations remain supporting research, not
active generation or data-recovery workstreams. The separate rule-analysis
candidate remains out of scope. Underlying tenant data remains unchanged,
including contextual and FP/BP records; the deferral does not blanket-filter
alert labels inside the ten selected TP scenarios. No research candidates are
automatically promoted to QA.

## Executive summary

Both systems build graphs through code-defined rules, not LLM extraction. The main
difference is what those rules represent:

```text
SecRL:
Incident alerts -> listed entity identifiers -> alerts sharing an identifier

ExCyTIn 2.0:
Raw telemetry -> typed activity relationships -> resolved entity identities
               -> cross-table investigation paths
```

ExCyTIn 2.0 also retains alert-to-entity edges. It is not necessary to choose between
an alert graph and a telemetry graph.

The coverage scan found:

- **2,039 of 2,087 original direct alert-pair links remain: 97.7%.**
- **163 additional direct alert-pair links** appear in the supplied 2.0 graph.
- All **48 lost direct links are filename-based**. Of these, 44 have a short
  alternative through raw telemetry; the other four share a filename but have
  different executable hashes.
- More substantial information loss occurs in **multi-target audit events,
  multi-object cloud activity, email-click context, and Graph API resource targets**.
- The supplied graph contains **four relationship types absent from the checked-in
  builder**. Rebuilding from that checkout would not reproduce those relations.
- The additional [node-and-edge audit](#9-complete-original-node-and-edge-mapping)
  accounts for **all 554 original nodes and 1,603 edges**, distinguishing direct
  mappings, typed expansions, missing references, intentional exclusions, and
  identifier metadata loss.
- The subsequent [raw-table-first investigation](#11-raw-alert-entity-json-investigation)
  inventories **2,547 typed JSON records and 963 field-only mentions** in 190
  available alerts, including four alerts absent from the saved graphs.
  The original graphs already contain **117 non-shared entity nodes**; neither
  graph absence nor non-shared status is a false-positive label.
- The [tenant-wide audit](#12-tenant-wide-incidents-classifications-and-telemetry-coverage)
  expands beyond those eight incidents: **306 latest incidents, 1,039 distinct
  raw alerts, and 62 tables containing 13,339,265 rows**. The graph represents
  301 incidents, including 43 whose latest incident row has no alert members.
  Source-specific gaps prevent treating graph presence or time overlap as proof
  of complete telemetry.
- The [FP/BP evidence audit](#13-fpbp-evidence-admissibility-audit) examines all
  47 labeled FP and four BP incidents. **None currently qualifies as an
  evidence-grounded negative incident graph**, including under the near-complete
  criterion defined there. One shared FP analytic has a demonstrable logic flaw
  that can support a separate rule-analysis task, not 47 reconstructed traffic
  investigations.

**Recommended direction:** retain the typed telemetry graph, improve extraction of
event participants and their roles, and preserve useful filename/attribute
similarities as a separate weak-correlation layer rather than as entity identity.

### Consolidated results at a glance

| Audit level | Original inventory | Result |
|---|---:|---|
| Shared-entity alert pairs | 2,087 | 2,039 retained directly; 48 lose a direct shared neighbor; 163 new pairs appear |
| Alert nodes | 186 | All map to existing 2.0 alert nodes |
| Entity-identifier nodes | 368 | 343 single-target and 14 one-to-many mappings; 11 exclusion, reference/component-only, or unresolved cases |
| Alert-to-entity edges | 1,603 | 1,528 direct; 12 message-path and 21 filename-activity expansions; 32 filename references; 7 policy exclusions; 2 hierarchy components; 1 unresolved process |
| Raw alert JSON, expanded source scope | 190 available alerts / 6,499 stored versions | 2,547 typed records plus 963 field-only mentions; counts are not unique physical entities |
| Supplied DuckDB snapshot | 306 latest incidents / 1,039 raw alert IDs / 62 tables | Latest stored classifications: 5 TP, 47 FP, 4 benign positive, 183 undetermined, 67 unclassified; not the union of all available exports (Section 15) |
| FP/BP evidence admission | 47 FP + 4 BP incidents | 0 admitted negative incident graphs; 52 retains partial metric evidence; one deduplicated rule-analysis candidate |

Successful node/edge mapping does not imply complete identifier preservation:
**nine application-related nodes / 15 edges** lose ID or instance indexing.
**Ten email nodes / 35 edges** use existing corrections to fabricated legacy
values. These are subsets of the mapping totals, not additional missing items.

### Review guide

- [Graph construction differences](#2-graph-construction-differences)
- [Original alert-pair preservation](#3-preservation-of-original-alert-pair-links)
- [Confirmed telemetry extraction gaps](#4-confirmed-telemetry-extraction-gaps)
- [Graph/code version differences](#6-supplied-graph-versus-checked-in-builder)
- [Consolidated design recommendations](#7-recommended-design-changes-for-review)
- [Every original node and edge, with rule-level causes](#9-complete-original-node-and-edge-mapping)
- [All available raw alert entities, context, and classifications](#11-raw-alert-entity-json-investigation)
- [Whole-tenant incident classifications and source coverage](#12-tenant-wide-incidents-classifications-and-telemetry-coverage)
- [Evidence admission decisions for every FP/BP case](#13-fpbp-evidence-admissibility-audit)
- [New alert-level negative investigation baseline](#14-alert-level-benignfp-investigation-baseline)
- [Supporting mapping files and reproducible scanners](#10-supporting-audit-artifacts)

## 1. Scope and evidence

### Inputs reviewed

| Input | Version or scope |
|---|---|
| SecRL source | Commit `a1b234f`; branch `feature/excytin-qa-redesign` |
| ExCyTIn 2.0 source | Commit `b32f7ad` |
| Original graphs | Eight [incident GraphML files](secgym/qagen/graph_files), containing 186 distinct alerts |
| Supplied data | [DuckDB data directory](secgym/database/duckdb_data): tenant data, core graph, extra pivots, and graph context |
| Stored core graph | 9,759,190 edges; 77 edge types; 45 source tables |
| Checked-in core rule catalogue | 78 extraction specifications; 73 distinct edge types; 41 source tables |

The scan attached the supplied databases read-only. It did not regenerate QA,
call models, or modify source databases or repository code.

Evidence references such as `AuditLogs#163` mean the row with `_rid = 163` in that
table in the supplied tenant database. These internal row IDs are specific to the
data snapshot; they are not universal event identifiers.

Links to ExCyTIn 2.0 source below assume the sibling checkout is named
`Excytin_2_0`.

## 2. Graph construction differences

| Dimension | Original SecRL | ExCyTIn 2.0 | Consequence |
|---|---|---|---|
| Construction scope | One graph per selected incident | Shared graph over available tenant telemetry | Investigation can extend beyond the entities named in an incident's alerts |
| Primary source | `SecurityAlert.Entities`, grouped by incident | Explicit mappings from endpoint, identity, email, network, cloud, and detection tables | Raw activity becomes part of the graph, not just searchable background data |
| Basic edge meaning | An alert contains an identifier | A row supports a typed relationship between endpoints | Relations convey more than co-occurrence |
| Node identity | Primarily identifier field plus value | Typed keys, canonical aliases, and process-instance keys | Different representations of one identity can join across tables |
| Edge direction | Undirected | Stored source/destination direction | Direction expresses the extraction rule's semantics; traversal can still be undirected |
| Time | Alert timestamps stored in alert data | Event timestamp attached to each relationship | Temporal constraints can be applied during investigation |
| Provenance | Original alert entry | Source table and row reference, plus selected attributes | Individual extracted relationships can be checked against telemetry |
| Multiple relationships per row | Mostly alert-to-identifier memberships | One row can emit several relationship types | A process event can connect parent, child, account, host, file, and session |
| Alert connections | Central structure | Retained through `ALERT_ENTITY` and `ALERT_EVIDENCE` | Existing alert associations can coexist with deeper telemetry paths |
| Component handling | Keep the largest connected incident component | Keep the wider graph, with specific hub/self-edge exclusions | Disconnected or less-alerted activity remains available for exploration |
| Rarity and novelty | No equivalent tenant-wide layer | Behavior frequency, first-seen observations, and attribute pivots | Supports prioritization, but does not establish maliciousness |
| Incident map | The incident graph is the starting object | A later windowed view around selected incident alerts | The default 48-hour pre-window and 24-hour post-window do not limit the initial tenant graph build |

The 2.0 graph is not a complete causal model. Some relationships are inferred,
normalized, or aggregated. A row-backed edge can support an observation without
proving that two events belong to the same attack.

**Source:** [SecRL graph builder](secgym/qagen/alert_graph.py),
[SecRL entity extraction](secgym/utils/utils.py),
[2.0 core extraction rules](../Excytin_2_0/src/excytin2/graph/build_edges.py),
[entity resolution](../Excytin_2_0/src/excytin2/entities/resolve.py), and
[extra pivots](../Excytin_2_0/src/excytin2/graph/build_extra.py).

## 3. Preservation of original alert-pair links

### Method

1. Read the eight original graphs and the alert entries stored in them.
2. Enumerate unordered pairs of distinct alerts sharing at least one entity.
   Multiple shared identifiers count as one pair.
3. Compare those pairs with shared neighbors in the supplied graph's
   `ALERT_ENTITY` and `ALERT_EVIDENCE` relationships.
4. Replay the current 2.0 `ALERT_ENTITY` extractor on the exact original alert
   snapshots, using the supplied alias/hash mappings, to distinguish extraction
   changes from alert-version differences.
5. For lost direct pairs, search for one intervening raw-telemetry edge between
   their new alert-linked entities within the default incident window. This
   search excludes detection edges and `ON_HOST`.

A "direct pair" means:

```text
Alert A -- shared entity -- Alert B
```

It does not mean that the database stores a direct alert-to-alert edge. These
counts are also not QA counts or counts of all shortest paths.

### Results by incident

| Incident | Alerts | Original pairs | Retained pairs | Lost direct pairs | New pairs | Total 2.0 pairs |
|---|---:|---:|---:|---:|---:|---:|
| 5 | 68 | 1,272 | 1,268 | 4 | 28 | 1,296 |
| 34 | 11 | 55 | 55 | 0 | 0 | 55 |
| 38 | 4 | 6 | 6 | 0 | 0 | 6 |
| 39 | 47 | 494 | 481 | 13 | 119 | 600 |
| 55 | 27 | 154 | 123 | 31 | 12 | 135 |
| 134 | 9 | 36 | 36 | 0 | 0 | 36 |
| 166 | 11 | 55 | 55 | 0 | 0 | 55 |
| 322 | 9 | 15 | 15 | 0 | 4 | 19 |
| **Total** | **186** | **2,087** | **2,039** | **48** | **163** | **2,202** |

The exact-original-snapshot replay loses the same 48 pairs. This supports an
extraction/identity explanation rather than merely different alert snapshots.

### Interpretation of the 48 losses

| Original connection | Lost pairs | Interpretation |
|---|---:|---|
| `process.ExtractedFileName` | 46 | Shared filename tokens from process command lines no longer necessarily identify a shared graph entity |
| `file.Name` | 2 | Shared basenames no longer necessarily identify a shared file when stronger identifiers are available |

Names involved include `powershell.exe`, `rubeus.exe`, `adminticket.txt`,
`browsercore.exe`, and `psexesvc.exe`.

For **44 of the 48**, a short alternative exists:

```text
Alert A -- entity X -- raw telemetry relationship -- entity Y -- Alert B
```

The raw relationships include `LOGON`, `AUTH_FROM`, `CONNECTED`, and `INBOUND`.
Their existence proves connectivity, not that the connection is incident-specific
or causal.

The remaining four pairs are in incident 5:
`36-71`, `36-82`, `36-113`, and `36-118`, using the original graph's alert node IDs.
All share `browsercore.exe`, but the process instances run on different hosts and
the executable SHA256 sets on opposite sides do not overlap.

**Recommendation:** preserve "same filename" as a useful hunting association when
appropriate, but do not equate it with "same executable identity." The scan did not
attempt to prove these four pairs disconnected at every possible path length.

## 4. Confirmed telemetry extraction gaps

This is a supplementary **rule-inspection-led audit**, verified against raw rows
and stored edges. These findings were not derived from the 1.0-to-2.0 graph
comparison and are not automatically regressions from 1.0. Sections 3 and 9 use
the original graphs as their baseline; section 11 starts from the raw alert JSON.

The counts below describe source rows exhibiting a structure, not an equal number
of unique missing edges, malicious events, or affected QA items.

### G1. Audit events: only the first target is modeled

**Current behavior:** the `AUDIT` rule extracts its destination from
`TargetResources[0]`.

**Observed data:**

- 36,086 of 56,822 audit rows contain more than one target.
- 6,129 "Add member to group" rows have a group target after the first entry.
- `AuditLogs#163` contains a user as the first target and a group as the second.
  The stored edge is:

```text
app:microsoft teams services -- AUDIT --> acct:dp5hn
```

The group involved in that event is absent from the edge endpoints.

**Investigative information lost:** which group received the member, which
additional principal/resource was affected, and relationships among the targets.

**Proposed change:** expand all relevant targets and retain their roles. Derive
operation-specific relationships, such as a user being added to a group, with the
source event as provenance. Do not turn every multi-target event into arbitrary
pairwise causal links.

**Source:** [AUDIT extraction rule](../Excytin_2_0/src/excytin2/graph/build_edges.py).

### G2. Cloud activity: nested participants are not expanded

**Current behavior:** `CLOUD_ACT` uses scalar `ObjectName`, falling back to an
application. It does not expand the participants in `ActivityObjects`.

**Observed data:**

- 79,981 rows contain multiple activity objects.
- Examples include 6,438 "Add member to group." rows and 10,470
  `MailItemsAccessed` rows with multiple objects.
- `CloudAppEvents#366` identifies a group with role `To`, an actor, and a target
  user. Its stored relationship instead connects the actor to `app:microsoft 365`.

The target user and group IDs in this example also appear in `AuditLogs#163`,
illustrating a potential cross-source connection that endpoint extraction misses.

**Investigative information lost:** actor/target distinctions, group membership,
affected users, and object-specific activity that is collapsed into an application.

**Proposed change:** extract supported entity types from `ActivityObjects` with
their `Role`, `Id`, and namespace. Preserve event participation separately from
inferred activity relationships.

**Source:** [CLOUD_ACT extraction rule](../Excytin_2_0/src/excytin2/graph/build_edges.py).

### G3. Email clicks: message, source, and redirect context remain outside the graph

**Current behavior:** `CLICKED` links an account to a URL/domain. The source IP and
message ID are stored as attributes, not endpoints. `UrlChain` is not expanded.

**Observed data:**

- All 15 click rows contain a `NetworkMessageId` and an `IPAddress`.
- None emits a message or IP endpoint for its click event.
- Three rows contain a two-URL chain.
- `UrlClickEvents#1` is a verified example: the stored edge has account/domain
  endpoints despite the richer source record.

**Investigative information lost:** direct linkage to the clicked message, the
click's source address, and the relationship between the initial and subsequent
URLs. Joining through a commonly reused URL alone can be ambiguous.

**Proposed change:** retain click-event participation for account, message, source
IP, and URL chain. Use explicit redirect relationships only where the source
semantics support the chain's order.

**Source:** [CLICKED and URL_DOMAIN rules](../Excytin_2_0/src/excytin2/graph/build_edges.py).

### G4. Graph API activity: requester is modeled, requested resource is not

**Current behavior:** `GRAPH_API` links the source IP to the requesting
account/application. The resource in `RequestUri` remains text in an attribute
rather than a typed target endpoint.

The scan identified these URI paths containing a concrete GUID or UPN target,
excluding action names such as `delta()`:

| Resource path | Rows | Distinct target identifiers |
|---|---:|---:|
| `users/<id>` | 176,692 | 2,173 |
| `groups/<id>` | 25,056 | 128 |
| `servicePrincipals/<id>` | 55,239 | 208 |
| `applications/<id>` | 165 | 10 |

**Verified examples:**

- `MicrosoftGraphActivityLogs#13` addresses a specific user through
  `users/<id>/microsoft.graph.getMemberGroups`; the stored edges identify the
  requester and token usage, not that user target.
- `MicrosoftGraphActivityLogs#183` requests `groups/<id>/members`; the stored
  edge identifies the requesting application, not the group.

These counts do not imply every target requires a new identity node; some may
already exist elsewhere. The missing piece is the request-to-target relationship.

**Proposed change:** parse supported resource paths into typed target identifiers.
Keep object IDs and application IDs in distinct namespaces, and use request
method/path semantics when assigning the relationship type.

**Source:** [GRAPH_API extraction rule](../Excytin_2_0/src/excytin2/graph/build_edges.py).

## 5. Additional alert-identifier opportunities

The original alert snapshots also contain:

| Entity type | Count | Current 2.0 behavior |
|---|---:|---|
| `cloud-logon-session` | 3 | Parsed by the flattener, but not emitted by the alert-edge builder |
| `cloud-logon-request` | 6 | Unsupported by the flattener |

These contain session/request identifiers that could support more precise sign-in
pivots. They did not establish the original shared-entity links either, so these
are improvement opportunities rather than regressions.

Matching these identifiers to the appropriate raw sign-in fields still needs
validation before adding relationships.

**Source:** [alert entity flattening](../Excytin_2_0/src/excytin2/cases/seeds.py)
and [alert-edge construction](../Excytin_2_0/src/excytin2/graph/build_edges.py).

## 6. Supplied graph versus checked-in builder

The supplied graph contains the following relationships absent from the reviewed
source rule catalogue:

| Stored relationship | Source table |
|---|---|
| `PROVISIONED` | `AADProvisioningLogs` |
| `INTUNE_ADMIN` | `IntuneAuditLogs` |
| `DEVICE_USER` | `IntuneDeviceComplianceOrg` |
| `ANOMALY_ENTITY` | `Anomalies` |

These are **not missing relationships in the supplied graph**. They are
source/artifact reproducibility differences.

Before rebuilding or porting the graph, obtain the matching builder revision or
recover and validate the missing rule definitions. Record the builder revision,
data snapshot, schema, and extraction-rule version together.

A table without stored edges is not automatically a coverage defect. Some tables
contain metrics or operational metadata rather than useful entity relationships.
Likewise, a defined rule may legitimately emit zero edges for a given snapshot.

## 7. Recommended design changes for review

This is the consolidated review list for both the alert-pair and individual
node/edge audits. These are proposals, not implemented changes.

| Recommendation | Rationale | Suggested priority |
|---|---|---|
| Align graph artifacts with their builder revision | Prevent accidental loss of existing relations during regeneration | First |
| Expand audit targets and cloud activity participants | Confirmed loss of actor/target/resource information in populated fields | High |
| Add click context and API resource-target relationships | Recover concrete cross-table pivots already present in raw rows | High |
| Add typed filename references and preserve weak affinity separately | 32 original filename edges remain reference-only; do not merge distinct files solely by name | High |
| Add namespace-aware application aliases and instance metadata | Nine original nodes / 15 edges map by name without full identifier indexing | High |
| Validate process-identity recovery and conflicting timestamps | One process lacks the expected time field, and its legacy timestamp conflicts with matching raw telemetry; no blind fallback | High |
| Represent Azure resource hierarchy explicitly | Two original subscription/group nodes remain only as components of resource URI strings | Medium |
| Derive reference features before truncating display text | Three filename references occur beyond the stored 400-character command attribute, although file-activity alternatives exist | Medium |
| Retain intentional exclusions and known data corrections | Five system-identity nodes / seven edges are policy exclusions; ten fabricated email nodes already have corrections | Preserve and document |
| Investigate cloud session/request IDs | Potentially improve precise identity/session pivots; joins still need verification | Follow-up |
| Add extraction-coverage regression checks | Track the 554-node / 1,603-edge baseline, typed participant coverage, and intentional exclusions | Foundational |

### Proposed layers

1. **Observed event participation**
   - Preserve relevant entities and their roles from each source row.
   - Include supported nested arrays and structured references.
   - Keep source provenance even when no higher-level activity rule exists.

2. **Typed activity relationships**
   - Derive process creation, logon, membership, access, and similar relationships.
   - Preserve direction, time, identity namespace, and derivation information.
   - Distinguish explicit observations from recovered or inferred associations.

3. **Weak correlation**
   - Retain shared filenames, command-line tokens, and other useful affinities.
   - Do not treat these as entity equivalence or confirmed causal relationships.
   - Decide separately whether they may count toward QA difficulty or only guide
     candidate discovery.

### Suggested regression checks

- Compare original alert-pair preservation against a frozen baseline.
- Account for each relevant typed participant: emitted, retained as an attribute,
  or explicitly excluded with a reason.
- Test multi-target arrays and actor/target roles, not only scalar fields.
- Verify emitted relationships against their exact source rows.
- Include same-name/different-hash and conflicting-identity fixtures.
- Check that incident membership, temporal proximity, and shared infrastructure
  are not silently promoted into causal claims.
- Rebuild a small reference dataset from the pinned code and compare it with the
  expected graph artifact.

## 8. Limits of the findings

- The pair-preservation analysis in section 3 measures shared alert neighbors, not
  complete preservation of every identifier, attribute, relationship meaning, or
  QA path. Section 9 adds an individual node-and-edge audit.
- The alternative-path check is bounded to one intervening raw edge within the
  incident window. It does not establish the absence of longer paths.
- Connected events are not necessarily related attack steps.
- Source-row counts are not counts of unique missing edges or malicious behavior.
- The eight original graphs were compared completely; telemetry checks focused
  on the structures described above. This is not an exhaustive certification of
  every extraction rule or every possible telemetry scenario.
- No QA regeneration or downstream score comparison was performed.

The companion machine-readable audit and changed-pair CSV retain the detailed
counts, original alert IDs, old shared values, alternative raw-row references,
and representative source-versus-edge examples for further review.

## 9. Complete original node and edge mapping

### 9.1 Method and mapping semantics

This follow-up accounts for every node and edge in the eight original graphs:

- **186 alert nodes**
- **368 entity-identifier nodes**
- **1,603 alert-to-entity edges**

An original identifier node is not necessarily one real-world entity. Several
account identifiers can map to one account, while one filename can refer to
several different file hashes. Consequently, this is not a one-to-one graph
isomorphism.

The scan:

1. Runs SecRL's existing entity extractor to identify the exact source entity
   behind every original edge.
2. Retains both original and corrected values from the existing
   [corrected graphs](secgym/qagen/graph_files_fixed). Ten fabricated email
   identifiers are explicitly marked as legacy corrections.
3. Uses the actual 2.0 normalization rules, stored alias tables, and source entity
   fields to construct candidate node mappings.
4. Checks candidate existence and direct `ALERT_ENTITY`/`ALERT_EVIDENCE` edges in
   the supplied graph, recording their exact source-row references.
5. Checks specific typed expansions: message-to-sender/source-IP relationships,
   process-image relationships, and same-source-process file/child-process
   activity. These are not arbitrary reachability searches.
6. Records identifier metadata loss separately from successful mapping to an
   entity's name or canonical key.

Every original node has a mapping row; every original edge has a mapping row,
including unsuccessful or intentionally excluded cases. Source entity indices in
the machine-readable output refer to the original alert's `Entities` array.

A pair can remain connected through an account even when a filename edge
disappears. This is why the entity-edge counts below differ from the 48 lost
alert-pair links in section 3.

### 9.2 Node mapping results

All **186 alert nodes** map to existing `alert:<SystemAlertId>` nodes.

| Outcome for original entity nodes | Count | Interpretation |
|---|---:|---|
| Maps to one existing 2.0 node | 343 | Includes alias normalization, source-backed name mappings, and the marked email corrections |
| Maps to multiple existing 2.0 nodes | 14 | Filename/basename families split into distinct file identities |
| Intentionally excluded system identities | 5 | System/service-account identifiers removed by policy |
| Filename retained as a label on a global file candidate | 1 | File exists, but the original alert reference is not resolved to it |
| Filename present only as text, without a resolved file node | 2 | Command-line references are not standalone file identities |
| Unresolved process identity | 1 | Missing expected creation-time field and inconsistent legacy timestamp |
| Resource hierarchy component only | 2 | Subscription/group values remain inside resource IDs, not as separate nodes |
| **Total entity nodes** | **368** | |

The **357 source-backed mappings** reference **251 distinct 2.0 node keys**.
Fourteen one-to-many mappings consist of five `file.Name` nodes and nine
`process.ExtractedFileName` nodes.

Two qualifications apply to those 357 mappings:

- **Ten email nodes** use the already-corrected identifiers, not the invalid
  original literals.
- **Nine application-related nodes** reach an application by name, but their
  original ID or instance metadata is not fully indexed. These are partial
  information-preservation cases, detailed below.

### 9.3 Edge mapping results

| Outcome for original edges | Count |
|---|---:|
| Direct edge to the normalized/source-resolved target | 1,528 |
| Preserved through a typed message relationship | 12 |
| Filename association supported by same-process file/child-process activity | 21 |
| Filename reference remains without an explicit mapped relationship | 32 |
| Intentionally excluded system identity | 7 |
| Resource hierarchy component, without an explicit hierarchy edge | 2 |
| Unresolved process identity | 1 |
| **Total** | **1,603** |

The 12 message expansions comprise six sender and six sender-IP associations,
using the same `NetworkMessageId` and `EMAIL_SENT`/`EMAIL_FROM_IP` relationships.

For the 21 filename activity expansions, the alert links to its source-declared
process, and that process has a `FILE` or `SPAWNED` relationship involving the
filename within the incident window. This is stronger evidence of activity than
an arbitrary same-name match, but it still does not make a filename a unique
identity.

The direct-edge count includes **35 corrected-email edges** and **15 edges with
application identifier/instance metadata gaps**. These annotations are retained
in the mapping output rather than hidden behind the direct-match count.

### 9.4 Coverage by every original entity field

| Original entity field | Nodes | Edges | Edge outcome |
|---|---:|---:|---|
| `account.AadUserId` | 14 | 169 | All direct |
| `account.Email` | 12 | 38 | All direct; 10 nodes / 35 edges use legacy corrections |
| `account.Name` | 25 | 173 | 168 direct; 5 intentionally excluded |
| `account.Sid` | 19 | 186 | 184 direct; 2 intentionally excluded |
| `host.HostName` | 20 | 158 | All direct |
| `host.AadDeviceId` | 11 | 126 | All direct |
| `ip.Address` | 26 | 94 | All direct |
| `url.Url` | 13 | 26 | All direct, including URL/domain normalization |
| `file.Name` | 40 | 103 | All direct to source-resolved file identities |
| `process.ProcessId__CreatedTimeUtc__CommandLine` | 104 | 262 | 261 direct; 1 unresolved |
| `process.ExtractedFileName` | 40 | 208 | 155 direct; 21 activity expansions; 32 reference-only |
| `mailbox.MailboxPrimaryAddress` | 8 | 11 | All direct |
| `mailmessage.Recipient` | 7 | 11 | All direct |
| `mailmessage.Sender` | 7 | 8 | 2 direct; 6 through message relationships |
| `mailmessage.SenderIP` | 7 | 8 | 2 direct; 6 through message relationships |
| `cloud-application.AppId` | 5 | 9 | Application-name mappings; ID indexing gap |
| `cloud-application.Name__InstanceName` | 3 | 4 | Application-name mappings; instance information gap |
| `oauth-application.OAuthAppId` | 1 | 2 | Direct, backed by the application-ID lookup |
| `oauth-application.OAuthObjectId` | 1 | 2 | Application-name mapping; object-ID indexing gap |
| `azure-resource.ResourceId` | 3 | 3 | All direct |
| `azure-resource.SubscriptionId` | 1 | 1 | Component of resource IDs, not a separate node/edge |
| `azure-resource.ResourceGroup` | 1 | 1 | Component of resource IDs, not a separate node/edge |
| **Total** | **368** | **1,603** | |

### 9.5 Causes of the additional gaps

#### E1. Filename mentions are not extracted as references

SecRL extracts filename tokens from the full `CommandLine`. The 2.0 alert builder
instead emits process instances and `ImageFile` identities. Its raw `MENTIONS`
rule extracts IP/URL/host indicators, not general file/script-name references.

Of the **53 filename edges without a direct mapping**, 21 have the activity
expansions above and 32 remain reference-only.

Three original filename nodes have no source-resolved file identity:

| Original node | Filename | Verified representation |
|---|---|---|
| `incident_39:8` | `adminticket.txt` | Present in raw and graph command text; no matching `DeviceFileEvents.FileName` rows found |
| `incident_5:59` | `get-userprttoken.ps1` | A global file hash exists; four raw file-event rows were found, but the original alert references are not linked to that file |
| `incident_55:66` | `ldaprequest.ps1` | Present in raw and graph command text; no matching `DeviceFileEvents.FileName` rows found |

This is not evidence that every mentioned file was created or executed. A future
rule should emit a typed **reference/mention**, not invent file activity from a
string.

**Rule locations:** [original filename extraction](secgym/utils/utils.py),
[2.0 alert entities and MENTIONS](../Excytin_2_0/src/excytin2/graph/build_edges.py).

#### E2. Graph display attributes truncate some filename evidence

For **50 of those 53 edges**, the relevant source process's `SPAWNED.a2` retains
the filename in command text. Three references to `winatp-intro-backdoor.exe` do
not:

- Original command length: **11,282 characters**.
- Filename begins at zero-based offset **10,828**.
- Stored `SPAWNED.a2`: **400 characters**.
- Raw source reference: `DeviceProcessEvents#91226`.

The cause is the `sb_short(ProcessCommandLine, 400)` expression. This is a loss
from the graph's displayed attribute, not deletion from the underlying raw log.
All three cases also have a `FILE` activity alternative. The attribute and
activity-path results overlap and must not be added together.

**Proposed change:** derive reference entities from the untruncated source text
before applying display limits; keep the raw-row reference for full inspection.

#### E3. A process cannot safely be mapped by timestamp fallback alone

Original node `incident_322:36`, attached to alert node `33`, describes PID 4256
on `vnevado-win11h`.

- The alert entity has `CreatedTimeUtc` but no `CreationTimeUtc`.
- The 2.0 flattener reads only `CreationTimeUtc`, so `sb_proc` receives no start
  time and emits no process key.
- The legacy timestamp is `2024-08-01 13:42:52.040000`.
- The alert itself occurs at approximately `2024-08-01 12:26:33`.
- `DeviceProcessEvents#763911` matches the host, PID, and complete command line,
  but gives process creation time `2024-08-01 12:25:23.612698`.
- No corresponding graph process start was found at the legacy 13:42 timestamp.

This exposes both a narrow field-handling rule and inconsistent source identity
information. The raw process is recorded as a **diagnostic candidate**, not an
accepted automatic mapping.

**Proposed change:** reconcile against authoritative process telemetry with
explicit confidence and conflict handling. Do not blindly substitute
`CreatedTimeUtc` for `CreationTimeUtc`.

**Rule locations:** [process flattening](../Excytin_2_0/src/excytin2/cases/seeds.py)
and [process-key construction](../Excytin_2_0/src/excytin2/graph/build_edges.py).

#### E4. Application identity survives by name, but identifier dimensions are lost

Nine original nodes, spanning 15 edges, have this limitation:

- Five numeric cloud-application `AppId` nodes.
- Three `Name__InstanceName` nodes.
- One OAuth `OAuthObjectId` node.

For example, cloud `AppId = 20893` reaches `app:microsoft exchange online`
through the original entity's name, but the numeric ID is not in the
application-ID lookup. The existing lookup is built from Entra sign-in app IDs;
numeric cloud-application IDs are a different namespace.

Similarly, the `SimulandApp` OAuth application ID is indexed, but its separate
OAuth object ID is not. The flattener does not retain `OAuthObjectId`, and the
alert-edge builder emits the application name.

**Proposed change:** introduce namespace-aware application aliases and retain
instance/object identifiers. Do not merge applications solely because their
display names match or treat an application ID as a service-principal object ID.

**Rule locations:** [application flattening](../Excytin_2_0/src/excytin2/cases/seeds.py)
and [app lookup / alert emission](../Excytin_2_0/src/excytin2/graph/build_edges.py).

#### E5. Azure hierarchy exists only inside resource URI strings

Original nodes `incident_322:26` and `incident_322:27` represent a subscription
and resource group. The full resource nodes remain, and their URI strings contain
both values, but 2.0 emits neither separate hierarchy nodes nor membership edges.

**Proposed change:** add explicit resource-to-group-to-subscription relationships
when that hierarchy is relevant to investigation, rather than relying on substring
search over complete resource IDs.

#### E6. System identities and fabricated emails should not be restored blindly

Five original identifier nodes and seven edges represent `LocalSystem`, `SYSTEM`,
or the explicitly excluded `S-2-2-78` SID. They are deliberately removed by the
2.0 hub policy.

Separately, ten original email-node values were already identified as fabricated
and corrected in SecRL. The scan maps their corrected values and preserves the
original values as audit metadata.

These are intentional policy/data-quality changes, not evidence that 2.0 needs
to recreate every old node literally.

### 9.6 Deliverables and remaining limits

The node/edge companion audit contains:

- One record for each of the 554 original nodes.
- One record for each of the 1,603 original edges.
- Original and corrected identifiers, candidate and existing 2.0 node keys,
  direct 2.0 edge references, and typed-path evidence.
- Mapping semantics, source entity indices, identifier-indexing flags, rule
  locations, and unresolved cases.

The corresponding node CSV, edge CSV, and JSON audit are linked in
[Supporting audit artifacts](#10-supporting-audit-artifacts). This is a complete
inventory mapping under the stated rules, not proof of a semantics-preserving
graph isomorphism or a search over every possible path.

The highest-priority additions exposed by this audit are **typed filename
references, namespace-aware application aliases, explicit resource hierarchy,
and validated process-identity recovery**. These complement the multi-target and
multi-object telemetry gaps in section 4.

## 10. Supporting audit artifacts

The conclusions, counts, examples, and recommendations are consolidated in this
document. The files below provide the full row-level mappings and reproducible
scan implementations.

These links point to **local review artifacts in the current Copilot session**,
not files committed to SecRL. To share the detailed audit outside this checkout,
include the companion files and adjust their links.

| Artifact | Contents |
|---|---|
| [Original-to-2.0 node mapping CSV][node-mapping] | All 554 original nodes, target keys, mapping semantics, and missing/partial cases |
| [Original-to-2.0 edge mapping CSV][edge-mapping] | All 1,603 original edges, direct edge evidence, typed paths, and rule-level causes |
| [Complete node/edge audit JSON][entity-audit] | Summary totals, every original field, node/edge records, provenance, and diagnostic candidates |
| [Changed direct alert-pair CSV][pair-mapping] | The 48 lost direct pair links, old shared identifiers, and short raw-telemetry alternatives |
| [Alert-pair and telemetry coverage audit JSON][relation-audit] | Pair counts, extraction replay, source-row examples, and stored-graph/code differences |
| [Node/edge scanner][entity-scanner] | Reproduces the individual mapping audit; reuses the relation scanner's graph reader |
| [Relation coverage scanner][relation-scanner] | Reproduces the alert-pair comparison and focused telemetry checks |
| [Raw alert entity audit JSON][raw-audit] | Source-first census, graph visibility, classifications, history, and omitted-alert evidence |
| [Typed JSON entity inventory][raw-typed] | All 2,547 latest-snapshot typed definitions, their exact JSON paths, annotations, and representations |
| [Field-only entity mentions][raw-fields] | 278 host-IP strings, 67 logged-on-user entries, and 618 message-ID references |
| [Complete alert inventory][raw-alerts] | All 190 available alerts linked to the original eight incidents, including four absent from the saved graphs |
| [Historical alert versions][raw-versions] | All 6,499 inspected source rows with entity-JSON hashes, counts, and classifications |
| [Historical-only identifier descriptors][raw-history] | Twelve source descriptor variants, with spelling/metadata differences distinguished from new identities |
| [Raw SecurityAlert scanner][raw-scanner] | Enumerates the SQL source first; graphs are secondary comparison targets |
| [Tenant-wide coverage audit JSON][tenant-audit] | Latest incident classifications/reasons, graph membership, source coverage, and all 306 incident assessments |
| [All incident coverage profiles][tenant-incidents] | One row per incident: alerts, entity counts/types, source gaps, collection-window evidence, and graph-backed raw support |
| [Latest classification and reason totals][tenant-classification] | Raw-table versus graph incident counts, with undetermined and unclassified kept separate |
| [Coverage by classification][tenant-class-coverage] | Full cross-tabulation of coverage assessments against TP/FP/benign/undetermined/unclassified outcomes |
| [Incident update history][tenant-updates] | All 833 source update rows with labels, reasons, and alert lists, allowing review of the latest-row selection |
| [All latest raw alerts][tenant-alerts] | All 1,039 raw alert IDs, including unassigned alerts and analytic source dependencies |
| [All tenant typed alert entities][tenant-entities] | All 8,689 typed JSON records, including types not supported by the graph builder |
| [All terminal alert JSON fields][tenant-fields] | Gzipped JSONL with 69,690 terminal field/container/absence records and RFC 6901 pointers |
| [All AlertEvidence entity rows][tenant-evidence] | All 5,538 rows, with alert-ID namespace mappings and current incident membership |
| [Raw-table inventory][tenant-tables] | All 62 tables, exact row counts, event-time extents, undated rows, and graph-reference coverage |
| [Per-incident, per-table coverage][tenant-table-coverage] | All 18,972 incident/table combinations, including zero-row combinations |
| [Daily source coverage][tenant-daily] | Source-specific date coverage; does not interpolate across empty dates |
| [Hourly source coverage][tenant-hourly] | Hour-level availability used for the incident-window checks |
| [Historical graph links not current][tenant-stale] | Seventy incident-alert links retained by the graph but absent from latest incident membership |
| [Named analytic source checks][tenant-query-sources] | Available/missing named sources and declared query-window/log-stream checks |
| [Reference export footprints][tenant-reference-windows] | Observed process-export time bounds for the eight reference incidents versus the documented collector windows |
| [Tenant-wide scanner][tenant-scanner] | Reproduces the latest-row census, all-alert field inventory, and coverage profiles |
| [FP/BP evidence audit JSON][negative-audit] | All 51 admission decisions, source alerts, label history, raw/context searches, and analytic-logic checks |
| [FP/BP case readiness CSV][negative-readiness] | One record per labeled negative case with blocking gaps and permitted uses |
| [BP source-window coverage][negative-bp-coverage] | All 248 BP incident/table combinations, including zero-row observations |
| [Project TP designations][reference-tp-policy] | The original eight TP assumptions alongside unchanged exported SIEM labels and scope exclusions |
| [FP/BP audit scanner][negative-scanner] | Reproduces raw-source checks; synthetic arithmetic fixtures are explicitly separated from incident evidence |
| [Alert-level negative candidate inventory][alert-negative-candidates] | All 111 annotation-selected alerts, parent memberships, raw-support screening, and unresolved verdict status |
| [Alert-level negative screen JSON][alert-negative-evidence] | Whole-tenant selection criteria, counts, label conflicts, source examples, and raw probes |
| [Implementation design](QA_GENERATION_DESIGN.md) | Agreed scopes, agentic workflow, strict gates, SecRL integration, and implementation milestones |

All scanners attach the supplied databases read-only. The node/edge scan was
independently checked for complete original-ID coverage, CSV/JSON agreement,
5,135 distinct direct-edge evidence records, and 43 path evidence checks.
The raw-source inventory was independently checked against the exact SQL JSON
paths of all 2,547 typed definitions and 963 field-only mentions.

## 11. Raw alert entity JSON investigation

### 11.1 Source-first scope and the non-shared-entity distinction

This investigation starts with the log tables, not the graph:

```text
SecurityIncident.AlertIds for the original eight incidents, across stored versions
    -> 191 linked alert IDs
    -> 190 IDs present in SecurityAlert, across 6,499 stored rows
    -> full Entities JSON: definitions, nested objects, references, context fields
    -> only then compare with the saved 1.0 and supplied 2.0 graphs
```

One referenced alert, `46f3d4b8-060c-4022-c190-4d88954a6a2e`, has no
`SecurityAlert` row in the supplied data. Its entities cannot be reconstructed
from an incident reference alone.

The primary census uses the latest available `Entities` per `SystemAlertId`,
matching the 2.0 builder's `arg_max(TimeGenerated)` policy. The historical check
also examines all 6,499 rows. No conflicting entity JSON was found at a tied
latest timestamp.

**The original graphs are not limited to shared entities.** Their 368 entity
nodes include:

- **251 shared nodes**, adjacent to more than one alert.
- **117 leaf/non-shared nodes**, adjacent to one alert.

Section 3 used shared entities to measure alert-pair connectivity, while section
9 already included the leaf nodes. The new investigation goes beyond both by
examining what extraction, reference handling, input availability, and component
pruning may leave out of the raw source.

### 11.2 Complete latest-snapshot census

The root `Entities` arrays contain 992 inline typed definitions and 1,538
reference entries. Resolving those references identifies 2,530 typed definitions.
Recursive inspection adds **17 typed definitions that are neither listed nor
referenced at the root**, giving **2,547 typed entity records**.

Definitions are identified by local `$id`, scoped to one alert, or by JSON path
when no `$id` exists. A `$ref` is not counted as another definition. The same
real-world entity appearing in several alerts is still several source records.

| Typed record category | Records |
|---|---:|
| File hashes | 1,069 |
| Processes | 444 |
| Files | 428 |
| Accounts | 207 |
| Hosts | 162 |
| IP addresses | 106 |
| Mail clusters | 45 |
| URLs | 31 |
| Mail messages | 14 |
| Mailboxes | 12 |
| Cloud / OAuth applications | 11 |
| Cloud logon sessions / requests | 9 |
| Registry keys / values | 6 |
| Azure resources | 3 |
| **Total typed records** | **2,547** |

Looking only for objects with a `Type` field is also insufficient. Relevant
identifiers occur in ordinary fields and lists:

| Field-only representation | Mentions | Interpretation |
|---|---:|---|
| Host `LastIpAddress` / `LastExternalIpAddress` strings | 278 | Address observations, not additional typed IP definitions |
| Untyped `LoggedOnUsers` entries | 67 | Account-name/domain objects without an explicit entity `Type` |
| `mailCluster.NetworkMessageIds` members | 618 | Message references, comprising 239 distinct ID values |
| **Total field-only mentions** | **963** | Not 963 additional unique entities |

These counts must not be added together and reported as a physical-entity count.
A process, its file, three hashes, and several references may describe related
aspects of the same underlying activity.

### 11.3 Four available alerts absent from the original graphs

| Incident | Source reference | Alert | Why it was absent from the saved graph |
|---|---|---|---|
| 5 | `SecurityAlert#4429` | Network mapping reconnaissance (DNS) | Belongs to a disconnected component under the original identifier matching |
| 5 | `SecurityAlert#4430` | Suspected overpass-the-hash attack (Kerberos) | Shares uppercase host identifiers with the DNS alert; a hostname case difference prevents connection to the retained component |
| 39 | `SecurityAlert#8860` | Suspected SID-History injection | Its extracted account identifiers do not overlap the retained component |
| 55 | `SecurityAlert#10488` | Mail.Read Permissions Granted to Application | Not present in the original extracted-alert CSV; later included through the incident-55 data merge |

The original extracted CSV matches the stored `Entities` and `TimeGenerated`
of all 186 retained alerts exactly, providing a control for this investigation.
The first three omitted alerts are present in that CSV. Their extracted
identifiers have no exact overlap with the corresponding retained component,
and the builder keeps only the largest connected component.

The two incident-5 alerts share `VNEVADO-DC`. The overpass-the-hash alert also
contains `VNEVADO-Win10V`, whereas the retained graph contains
`vnevado-win10v`. Case normalization would connect that small component through
the latter host. This is an identity-normalization issue, not evidence that the
omitted alerts were false positives.

The fourth alert is a different case: `_merged_rows` records its provenance as
`inc_55`. It should not be attributed to component pruning because it was absent
from the original extraction input.

All four available omitted alerts have detection-linked entities in the supplied
2.0 graph.

### 11.4 What the deeper JSON inspection exposes

The 17 nested-only typed records comprise ten IPs, four hashes, one file, one
account, and one parent process. They are **not 17 missing graph entities**:
several already have representations through a parent or another source.

Notable findings:

- **A valid address exists in raw alert context but not the core graph.**
  `40.84.21.196` appears at
  `SecurityAlert#10089`, `$[0].LastExternalIpAddress`, and in seven host-IP string
  mentions. No `ip:40.84.21.196` node occurs in the core graph. Its presence in
  metadata does not establish malicious communication.
- **Eight other nested IP records have nodes elsewhere but no direct alert link.**
  Missing an alert membership is different from missing the address entirely.
- **Logged-on-user context is substantially represented elsewhere.**
  All 67 untyped user references resolve to existing account nodes and compatible
  host-to-account `LOGGED_ON` relationships somewhere in the available history;
  33 are also direct alert neighbors.
- **Most scalar host-IP context is also represented elsewhere.**
  Of 278 references, 271 have matching host-IP relationships in the graph.
  The remaining seven all refer to `40.84.21.196`. Only three are direct alert
  neighbors.
- **All 618 mail-cluster member references have alert-linked message nodes.**
  These need to be enumerated even though they are strings inside a collection,
  not separately typed objects.
- **The 354 MD5 records are represented through their parent files, not as
  indexed MD5 identities.** The other 715 hash records are SHA1/SHA256 records
  that map to graph file identities. Absence of standalone hash nodes is not the
  same as absence of the files.
- **Three cloud-session and six cloud-request records still lack native
  emission/support**, consistent with section 5.
- **Some unmatched records are placeholders.** Four process records and one IP
  record have `IsValid=false` and lack usable identifiers. They should not be
  counted as five established entities that a graph builder ought to invent.
- **Two process records use the alternate creation-time field.** Both occur in
  `SecurityAlert#10343`: the PID-4256 case described in section 9, and its nested
  PID-8100 parent. The parent has a corroborating raw start in
  `DeviceProcessEvents#763903`; the child's legacy time conflicts with the raw
  process start. Recovery must preserve this distinction.

Host-context checks above span the available graph history. They are not proof
that a user was logged on, or an IP belonged to a host, at the incident's exact
time. Metadata freshness and event-time relevance need separate validation.

A matching graph neighbor also does not establish which JSON field emitted it:
the same identity can appear in multiple fields or in `AlertEvidence`.

### 11.5 What can be said about false positives

The latest alert-level `ExtendedProperties.Classification` values, normalized
for case and unset values, are:

| Stored classification | Alerts |
|---|---:|
| `InformationalExpectedActivity` | 81 |
| `TruePositive` | 35 |
| Unset / `None` / absent | 74 |
| **Total** | **190** |

**79 of the 81 expected/informational alerts are already in the original graphs.**
The graphs therefore should not be interpreted as a malicious-only selection.

No explicit `FalsePositive` classification was found in the latest snapshots or
the inspected historical rows. This does **not** prove that false positives are
absent. Expected activity, unset classification, and false positive are not
interchangeable labels.

At the entity-record level:

- `LastVerdict`: 12 `Malicious`, 81 `Suspicious`, 95 `Unknown`, and 2,359 absent.
- 55 records carry role annotations; 11 include `Contextual`.
- Nine records have `IsValid=false`.

These annotations are not a complete, independently verified per-entity
true/false-positive label set. `IsValid=false` concerns the entity record; it is
not a false-positive alert classification. Likewise:

- Non-shared does not mean benign.
- Missing from a graph does not mean false positive.
- Included in a true-positive incident does not mean every entity is malicious.
- A contextual or observed entity should not automatically become a gold attack
  participant in QA.

### 11.6 Historical versions and the meaning of "all"

The audit also inspected all 6,499 stored alert rows. Of the 190 available alerts,
154 have more than one distinct `Entities` JSON representation.

Comparing selected identity-bearing fields found 12 historical descriptor
variants absent from the latest snapshots, across three alerts:

- Nine IP-address descriptors.
- Two URL spellings that normalize to the same current graph targets.
- One version of an already-known message: its `NetworkMessageId` is unchanged,
  but the older record includes sender, sender-IP, and Internet-message-ID details
  missing or empty in the latest representation.

This is **not a finding of 12 additional real-world entities**. The projection
compares selected identifier fields, not every metadata field or fully resolved
identity. The source-row references and version hashes are retained so the
underlying observations can be revisited.

### 11.7 Implications for the new QA approach

The raw JSON is the appropriate starting point for a complete candidate
inventory. It is broader than the output of either graph builder, but it is not
itself a clean attack graph.

A useful separation is:

1. **Observed in the logs:** retain every source entity/reference with its alert,
   JSON path, source version, timestamps, roles, and verdict annotations.
2. **Represented in the graph:** resolve identities and add relationships with
   explicit reasons for omissions, aliases, placeholders, or weak context.
3. **Relevant and supported for QA:** validate incident-time relevance and the
   investigative claim separately; do not derive maliciousness from graph
   membership or detector context alone.

This source-first ledger would preserve non-shared and contextual observations
without forcing every record into the causal graph or treating it as an attacker
entity.

## 12. Tenant-wide incidents, classifications, and telemetry coverage

### 12.1 Scope and latest-update policy

This audit covers the entire supplied post-cleanup tenant DuckDB, not only the
eight reference incidents. It does **not** include source records omitted by
ingestion/merge policy; Section 15 identifies those exclusions. It inventories:

- **833 `SecurityIncident` update rows**, corresponding to **306 incidents** in
  one workspace.
- **10,427 `SecurityAlert` rows**, corresponding to **1,039 distinct alert IDs**.
- **5,538 `AlertEvidence` entity rows**.
- **62 source tables and 13,339,265 source rows**.
- The supplied core graph, extra-pivot graph, and graph-context node snapshot.

All latest incident metadata comes from the **same complete row available in
that DuckDB snapshot**, not necessarily the latest row across all local exports:

```sql
SELECT *
FROM SecurityIncident
QUALIFY row_number() OVER (
    PARTITION BY TenantId, IncidentNumber
    ORDER BY TimeGenerated DESC, _rid DESC
) = 1;
```

`_rid` breaks timestamp ties. Incident 81 has two rows at its latest timestamp;
their classification, reason, and alert list agree. Incident numbers do not
collide across different incident GUIDs in this dataset.

It is important not to use an independent `arg_max(Classification, TimeGenerated)`
for classification: null-skipping aggregate behavior can retain an older
non-null label instead of the latest row's unset value. The audit retains the
latest `Classification`, `ClassificationReason`, `ClassificationComment`, status,
alert membership, and source-row reference together.

### 12.2 Incident classifications and reasons

| Latest classification | Latest reason | Incidents in SQL | Incidents represented in graph |
|---|---|---:|---:|
| `TruePositive` | `SuspiciousActivity` | 5 | 5 |
| `FalsePositive` | `IncorrectAlertLogic` | 47 | 47 |
| `BenignPositive` | `SuspiciousButExpected` | 4 | 4 |
| `Undetermined` | Unset | 183 | 178 |
| Unclassified / null | Unset | 67 | 67 |
| **Total** | | **306** | **301** |

Thus, **250 SQL incidents have no conclusive TP/FP/benign-positive outcome**:
183 explicitly undetermined plus 67 with no classification. These should remain
separate categories, not all be relabeled false positive or true positive.

The five labeled true positives are **34, 36, 55, 83, and 123**. The four benign
positives are **52, 173, 189, and 226**.

These are the stored incident classifications, not independently adjudicated
ground truth. Some classification comments contain test-oriented text. The full
comments and classification history are retained for review rather than used to
override the latest label.

For benchmark design, the user subsequently designated the original eight SecRL
incidents and additional incident 133 as TP scenarios; incident 36 already has an
exported TP label. All ten selected cases therefore have a positive project
designation. This does not change the source classification table: incident 133's
exported classification remains `Undetermined`.

The absence of explicit FP labels in section 11 was limited to the eight-incident
scope and alert-level annotations. The 47 incident-level false positives here
come from the expanded tenant-wide scope; there is no contradiction.

### 12.3 Graph membership is historical, not necessarily current

The 2.0 `INCIDENT_ALERT` construction unions membership across incident updates.
Consequently:

- **258** latest incidents have at least one alert ID.
- **48** latest incidents have an empty alert list.
- **43 of those 48** still appear as graph incident nodes through historical
  memberships.
- The five incidents with no graph node are **61, 65, 72, 73, and 74**.
- There are **716 current incident-alert memberships**, versus **786 historical
  memberships** represented by the graph: **70 graph links are not current**.

The current memberships refer to 715 distinct alert IDs. One is missing from
the source data: the previously identified incident-5 alert. Therefore 714
distinct current-linked alerts have source rows.

One alert is shared by two current incidents, **322 and 340**. Counting incident
records does not necessarily count independent attacks or campaigns.

The supplied graph has 1,143 alert-shaped node keys, which should not be confused
with 1,143 raw `SecurityAlert` records:

- 1,039 correspond to raw `SecurityAlert` IDs.
- 103 are evidence-linked alert keys without matching `SecurityAlert` rows.
- One is the incident-referenced alert whose source record is missing.

`AlertEvidence` contains 396 alert-ID groups; 291 resolve to raw `SecurityAlert`
IDs and 105 do not. Those raw evidence groups and their namespace mappings are
included separately in the audit.

### 12.4 All alerts and entity data, including unassigned alerts

**325 raw alerts are not associated with any incident in the exported
`SecurityIncident` memberships**, current or historical:

- 221 from Azure Security Center for IoT.
- 104 from Azure Active Directory Identity Protection.

They are retained in the inventory, not silently dropped because an incident
record is unavailable.

Across the latest rows of all 1,039 raw alerts:

- **8,689 typed entity records**, including **172 nested-only definitions**.
- **2,803 recognized field-only mentions**.
- **69,690 terminal JSON field/container/absence records**, exported with exact
  JSON pointers to avoid limiting the source inventory to currently supported
  entity types.
- **60 alerts with absent entity JSON**; 979 with populated, successfully parsed
  arrays.
- No entity-JSON parse or reference-resolution errors in this census.

The broader source includes types barely represented or absent in the original
eight-incident scope: 431 IoT-device records, 558 NIC records, Kubernetes
clusters/namespaces/services/pods, containers/images, and a blob container.
These are preserved as source observations even when a native graph extraction
rule is unavailable.

`AlertEvidence` contributes another **5,538 entity rows**, including processes,
users, machines, mail clusters, cloud sessions/requests, and other evidence
types. These are a separate representation and must not simply be added to the
typed JSON count as distinct physical entities.

The supplied graph-context snapshot contains 1,822,870 node keys. The core graph
has 9,759,190 edges of 77 types; the extra graph has 79,219 edges of five types.
These are different counting units from source records and raw entities.

### 12.5 Raw-event coverage is not uniform across the date range

Every source table was counted directly, with its event-time column, earliest and
latest event, daily/hourly row counts, undated rows, and graph-cited row count.
The total includes activity, inventory, alerts, metrics, and threat intelligence:

| Table category used by this audit | Source rows |
|---|---:|
| Operational activity, 38 tables | 7,882,956 |
| Monitoring / metrics / usage | 2,993,305 |
| Threat intelligence / context | 2,273,513 |
| Inventory | 172,052 |
| Detection / incident records | 17,439 |
| **Total** | **13,339,265** |

The classification is an audit convention, not a claim that only operational
tables can provide evidence. All categories remain in the per-table reports.

Key gaps:

- Major process, network, logon, sign-in, email, audit, and cloud-activity tables
  have **no rows on July 23-31 or August 2**.
- August 1 has a **limited collection around 11:00-14:00 UTC**, not full-day
  operational coverage.
- `DeviceEvents` has additional internal gaps, including July 8-16 and
  July 18-21.
- `AzureDiagnostics` has substantially narrower coverage, concentrated around
  June 20-July 1 and additional July 17/22 slices.
- A few inventory/risk timestamps extend before the main collection period.
  Those isolated historical values do not establish continuous early coverage.

The documentation and current download script describe different tenant end
dates, so the audit uses actual row distributions rather than assuming either
documented range was fully acquired.

### 12.6 Incident-specific missing sources and log streams

| Cases | Missing dependency | Evidence |
|---|---|---|
| All 47 incident-level FPs | `NetworkPatterns_CL` | Every case is "Firewall: Anomaly in transferred bytes"; its saved analytic query names this unavailable source, and every associated alert has no entity JSON |
| 117 | `SAPAuditLog` and its SAP query environment | The saved query uses the unavailable named source plus SAP functions/watchlists; the export cannot execute it as supplied |
| 118, 135, 201, 322 | `SquidProxy` | Proxy-alert queries use this named source and join available TI/device tables; the proxy source or its function definition is absent |
| 131, 132, 161 | `AzureDiagnostics` DDoS mitigation flow stream | Queries require `ResourceType=PUBLICIPADDRESSES` and `Category=DDoSMitigationFlowLogs`; no matching stream rows exist, and the declared query windows contain no `AzureDiagnostics` rows |

A bare KQL name can be a table or a function. For `SAPAuditLog` and `SquidProxy`,
the finding is an **unavailable query dependency**, not a verified claim about
which physical source table or function implementation should exist.

Query-source detection is deliberately conservative and was checked against
actual examples. Projected column names and local `let` aliases are not treated
as missing sources. It is not a complete KQL dependency parser.

These gaps mean that stored labels and alert results may be present even when
the evidence necessary to independently replay their detection is not.

### 12.7 What "fully present" can and cannot mean

There is no per-source acquisition manifest or expected event-count baseline
that proves lossless capture for an incident. Therefore this audit does **not**
certify a count of fully complete incidents.

It does establish several separate levels:

1. **Current incident record:** latest metadata and membership are available.
2. **Alert completeness:** all alert IDs in that latest membership resolve to
   source rows. This holds for **257 of the 258 incidents with current alerts**.
3. **Observed temporal coverage:** activity rows occur across the incident's
   audit-window hours.
4. **Entity-linked raw support:** current alert-linked entities occur on
   operational graph edges within that window.
5. **Source-specific replayability:** the sources and streams actually required
   by the investigation are available. This needs more than steps 2-4.

The audit window rounds to hours and adds context: floor the first-activity hour
minus one hour, through floor the last-activity hour plus one hour, exclusive.
This avoids equating an instantaneous alert timestamp with a zero-length
telemetry search. Coverage in that context window is reported separately from
the incident's exact first/last activity.

Hourly occupancy means **at least one operational source has rows in that hour**.
It does not imply every required table, host, or sensor is covered.

### 12.8 The eight reference incidents are useful baselines, not perfect captures

| Reference incident | Latest classification | Available / referenced alerts | Typed alert JSON records | Graph-backed operational rows in audit window | Important qualification |
|---|---|---:|---:|---:|---|
| 5 | Unclassified | 70 / 71 | 1,121 | 7,035 | One referenced alert has no source row |
| 34 | TruePositive | 11 / 11 | 157 | 4,828 | Observed support; no identified named-query dependency gap |
| 38 | Undetermined | 4 / 4 | 58 | 2,544 | Observed support; no identified named-query dependency gap |
| 39 | Undetermined | 48 / 48 | 675 | 7,811 | Observed support; no identified named-query dependency gap |
| 55 | TruePositive | 28 / 28 | 386 | 59,444 | Observed support; source-specific holes still require task-level checks |
| 134 | Unclassified | 9 / 9 | 40 | 863 | Observed support; no identified named-query dependency gap |
| 166 | Unclassified | 11 / 11 | 38 | 1,969 | Observed support; no identified named-query dependency gap |
| 322 | Unclassified | 9 / 9 | 72 | 3,173 | Proxy alert depends on unavailable `SquidProxy` |

These entity counts use latest complete raw alert records, not only the alerts
or identifiers retained in the original graphs. Graph-backed row counts
deduplicate `(table, rid)` within each incident; they can include contextual or
benign activity and can overlap between incidents.

Thus, even the known eight should not be described as universally complete for
every possible question. Six pass this audit's observed-support/no-identified-
dependency-gap screen; incident 5 has a missing alert and incident 322 has an
unavailable proxy dependency. All eight have substantial raw support.

The original incident exports were also inspected directly. Their observed
process-export hour envelopes mostly match the downloader's padding rules.
Incident 322 extends to 14:00 UTC in the actual export, while the current script
would request only through 13:00. Observed envelopes are used for candidate
selection, not treated as an all-table acquisition guarantee.

### 12.9 Additional incidents with useful coverage

More than eight incidents have useful raw telemetry:

- **24 additional current incidents** have their entire stated activity interval
  inside the observed reference-export hour envelopes.
- Of these, **22** pass the additional observed-support screen: current alert
  records present, no identified missing named source/stream, activity in every
  audit-window hour, and graph-backed operational support.
- The other two are **52**, which needs metric/resource-specific validation, and
  **135**, which has an unavailable proxy dependency.
- **60 other non-reference incidents** pass the same temporal/support screen
  outside those contained reference envelopes. That does not make them fully
  captured.

The 22 contained candidates are:

```text
36, 68, 70, 71, 133, 168, 305, 311, 312, 313, 314,
315, 316, 317, 318, 319, 320, 321, 325, 326, 330, 340
```

Their classifications are one TP (36), one unclassified (70), and 20
undetermined. The list is a shortlist for task-level validation, not 22 new
independent attack scenarios. Incident 340 shares an alert with reference 322.

The additional labeled TP cases merit particular attention:

| Incident | Alerts | Typed alert JSON records | Graph-backed operational rows | Coverage interpretation |
|---|---:|---:|---:|---|
| 36 | 12 | 230 | 3,195 | Contained within the combined June 26 reference-export envelopes; strongest additional TP candidate |
| 83 | 17 | 127 | 5,365 | Observed support outside the reference envelopes; `DeviceEvents` and `AzureDiagnostics` have no rows in its audit window |
| 123 | 6 | 101 | 1,466 | Observed support outside the reference envelopes; the same two source-table gaps require scrutiny |

The latter two demonstrate why "the incident has telemetry" is weaker than
"every source needed to answer every question is available."

### 12.10 Mutually exclusive coverage profiles

The following profiles account for all 306 latest incidents. They are assigned
in a fixed order: missing current membership, missing alert source, missing named
source/stream, temporal availability, and finally graph-backed support/reference
scope. A case can have additional flags beyond its primary profile.

| Primary assessment | Incidents | Interpretation |
|---|---:|---|
| No current alert membership | 48 | Latest alert list empty; 43 still have historical graph nodes |
| Missing alert source | 1 | Reference incident 5 |
| Missing named telemetry source | 52 | 47 firewall FPs, SAP case 117, and four proxy-dependent cases |
| Missing named telemetry stream | 3 | DDoS mitigation-flow cases 131, 132, 161 |
| No operational rows in audit window | 102 | Current alerts exist, but the operational table set has no window rows |
| Partial operational hourly occupancy | 2 | Cases 297 and 348 straddle the limited August 1 collection; both are unclassified compliance alerts |
| Time overlap without graph-backed operational corroboration | 10 | Includes metric-backed/contextual cases; not automatically missing telemetry |
| Reference with observed support | 6 | Six of the eight reference cases; not a full-capture certificate |
| Additional contained reference-scope candidate | 22 | Promising additional cases requiring source/task validation |
| Observed support outside reference scope | 60 | Useful activity exists, but capture completeness is unproven |
| **Total** | **306** | |

The companion coverage-by-classification CSV retains the full TP/FP/benign/
undetermined/unclassified cross-tabulation.

### 12.11 Why graph-zero does not mean evidence-zero

Incident **52**, a benign-positive DDoS case, has no graph-backed operational
rows under this audit's seed/window test. However:

- `AzureMetrics` contains **2,186 DDoS-related rows** in its audit window with the
  matching `SubscriptionId` column.
- There are **34 positive `IfUnderDDoSAttack` records** among them.
- The rows span four metric resource IDs.

This is potentially relevant metric evidence that the operational graph does
not represent. It is not yet a verified target-IP match: the metric `ResourceId`
strings contain a different subscription value from the `SubscriptionId` column,
and an IP-to-resource attribution has not been established.
The follow-up audit in section 13 also finds no independent benign rationale and
therefore excludes incident 52 from negative-verdict QA under the current data.

The other benign-positive incidents, **173, 189, and 226**, have no operational
rows in their audit windows. Their stored classifications alone do not provide
complete negative/benign examples for QA.

### 12.12 Consequences for enrichment and QA selection

This work inventories the tenant; it does **not** mutate or enrich the production
graph yet.

Recommended next steps:

1. Keep all source incidents, alerts, entity records, and raw-table inventories,
   including orphans and graph-unsupported types, in the enrichment ledger.
2. Represent **current** and **historical** incident membership separately; do not
   silently use historical graph unions as current case membership.
3. Use the eight reference incidents plus the 22 contained candidates as a
   validation pool, not a pre-certified complete set.
4. Validate each question's evidence closure against its required tables,
   log categories, timestamps, and entity identities. Missing source dependencies
   must be explicit.
5. Do not construct a fully replayable FP benchmark from the 47 firewall labels
   without the missing network-pattern source or an independently validated
   alternative evidence set.
6. Recover source manifests or acquisition counts where possible. Only those,
   together with source/task validation, can justify a stronger completeness
   claim than the observed-support profiles here.

## 13. FP/BP evidence-admissibility audit

### 13.1 Decision rule

The user requires evidence that explains benign behavior or refutes the alert's
claim. A stored FP/BP label is not enough.

A negative incident is admissible only if the proposed question can be answered
from case-attributable evidence, including:

1. The relevant event or detection claim and its actual participants.
2. Reliable time, identity, and resource attribution.
3. Independent benign/authorization evidence or evidence refuting the claim.
4. Sufficient source coverage to distinguish a negative finding from missing data.
5. A defensible verdict without exposing final adjudication labels as the answer.

For this review, **near complete** means the core event identity and benign or
refuting evidence are present, leaving only a bounded verification task. A case
missing the primary activity, target attribution, or benign explanation does not
meet that threshold merely because some surrounding telemetry exists.

The audit examined all **51 latest FP/BP incidents**, their **54 latest source
alerts**, incident classification history, preserved analytic queries, query/audit
logs, and relevant raw/context tables. All supplied databases were read-only.

### 13.2 Admission results

| Pool / incident | What is available | What prevents evidence-grounded negative QA | Decision |
|---|---|---|---|
| 47 FP firewall incidents | Alert/query metadata, a common analytic logic defect, query execution counts, and rule change logs | Missing traffic tuples/byte values, missing source relation, and no alert entities identifying the flagged flows | Exclude as negative incident graphs |
| BP 52 | DDoS metrics in the time/subscription context | Unresolved target-IP attribution, inconsistent resource identifiers, no independent legitimate-test explanation, conflicting adjudication metadata | Partial evidence; not near enough to admit |
| BP 173 | Three elevation alerts and `securityTesting` annotations | No operational rows in the incident window and no independent execution/authorization record | Exclude |
| BP 189 | Two elevation alerts and `confirmedActivity` annotations | No operational rows in the incident window and no independent authorization evidence | Exclude |
| BP 226 | Malware alert, file/hash/path details, and a `Benign` investigation annotation | No operational rows in the incident window; same-hash observations on other dates do not establish this event's benignness | Exclude |

**Current admissible negative incident graphs: 0 FP and 0 BP.**
No case meets the near-complete negative-verdict criterion above.

This is a finding about the supplied evidence, not a claim that these incidents
were actually malicious or that the missing evidence never existed.

### 13.3 False positives: one grounded analytic flaw, but missing incident evidence

All 47 FP incidents are classified `IncorrectAlertLogic` and contain the same
"Firewall: Anomaly in transferred bytes" analytic body after removing the
scheduled `query_now` timestamp. Each has one source alert, with no entity JSON.

The saved query:

1. Computes `avg(NoofByesTransferred + NoofBytesReceived)` per flow group.
2. Computes the sum of that same quantity for the same source/group.
3. Flags the group when the sum exceeds 2.5 times its average.

For a group with `n` non-null byte totals and positive mean `mu`:

```text
total = n * mu
total > 2.5 * mu  <=>  n > 2.5
```

Under those conditions, the threshold is effectively driven by observation
count, not a comparison against an independent normal-traffic baseline.

SQL-equivalent arithmetic fixtures confirmed:

| Synthetic group | Sum | Mean | Fires? |
|---|---:|---:|---|
| Two identical 100-byte observations | 200 | 100 | No |
| Three identical 100-byte observations | 300 | 100 | Yes |
| One 1,000,000-byte observation | 1,000,000 | 1,000,000 | No |
| Three zero-byte observations | 0 | 0 | No |

**These are synthetic regression fixtures, not reconstructed incident traffic.**
They demonstrate the query's arithmetic behavior without asserting that any
specific historical flow was benign.

The audit searched for recoverable source/results:

- `NetworkPatterns_CL` is absent from the exported relations.
- The source-specific traffic field names do not occur as columns in another
  exported table.
- **26 `LAQueryLogs` records** mention the source, including two successful
  direct source queries reporting 7,462 returned rows. The log stores response
  counts, not the actual returned tuples.
- **`SentinelAudit#16` and `#17`** preserve analytic configuration changes.
  The schedule changes from daily to five-minute execution and the query period
  from 25 hours to 24 hours; the query body remains unchanged.
- No matching source query/result was recovered from the inspected hunting
  bookmarks, and no matching source content was found in the inspected watchlist.

The variable per-alert "Search Query Results Overall Count" is the number of
query result groups, not their source/destination addresses or byte observations.
It cannot reconstruct the absent traffic.

**Potential future use, outside the current scope:** one deduplicated detection-rule analysis candidate,
such as explaining why this threshold produces false-alarm risk. This is not
equivalent to a grounded question requiring the agent to conclude that a
particular observed flow or actor was benign. The 47 alert instances must not be
counted as 47 independent, evidence-complete negative investigations.

### 13.4 BP 52: metrics do not establish the benign explanation

The alert at `SecurityAlert#4693` names public IP `60.78.13.245` and reports DDoS
activity being mitigated.

The audit found:

- 2,186 DDoS metric rows and 34 positive `IfUnderDDoSAttack` records in the
  July 1 19:00-21:00 UTC context window.
- Metric examples include `AzureMetrics#798605`, `#798785`, and `#798832`.
- All 2,186 rows have a discrepancy between the subscription embedded in
  `ResourceId` and the separate `SubscriptionId` column.
- No literal target-IP match in the checked fields of metrics, diagnostics,
  device/network inventory, endpoint network events, firewall NAT/network/flow
  logs, sign-in logs, or cloud activity across their available histories.
- No independent approved-test or expected-activity record in the inspected
  watchlist/bookmark context.

The metric rows support activity in the time/subscription context. They do not
prove that the activity belongs to the alerted public IP or that it was an
authorized test.

The annotations also require caution:

- Incident history moves from `FalsePositive / InaccurateData` to
  `BenignPositive / SuspiciousButExpected`.
- Its comments explicitly discuss editing comments and classifications.
- The latest alert's classification annotation remains `falsePositive`.

This is not a basis for picking one label as unquestionable ground truth. Event
attribution and the actual benign rationale must be recovered or independently
adjudicated before admitting a BP verdict question.

### 13.5 BP 173 and 189: annotations without the event-time evidence

**Incident 173** concerns three global-admin elevation alerts for `u118` on
July 23:

- Source alerts: `SecurityAlert#6229`, `#6230`, and `#6231`.
- Alert annotations: `informationalExpectedActivity`, `securityTesting`.
- Latest incident comment: `tests`.
- Audit window: July 23 08:00-11:00 UTC.

**Incident 189** concerns elevation activity for `u101` on July 25:

- Source alerts: `SecurityAlert#7263` and `#7264`.
- Alert annotations: `informationalExpectedActivity`, `confirmedActivity`.
- Audit window: July 25 12:00-17:00 UTC.

Every operational table in the audited export has zero rows in these respective
windows. Account activity on other dates establishes that the accounts exist,
not that these elevation events were authorized.

There is no independent change/approval/test-execution record in the inspected
context that can replace those missing observations. Asking the agent to infer
the expected verdict from `securityTesting`, `confirmedActivity`, or the incident
classification would be adjudication-label lookup rather than investigation.

### 13.6 BP 226: other-date file matches do not establish this event

`SecurityAlert#8226` reports a Kekeo detection on July 30, naming `test.exe` under
an Azure Run Command extension directory on `vnevado-dc`. The alert has a
`Benign` investigation-state annotation.

No operational rows exist in the July 30 07:00-09:00 UTC audit window.

The exact SHA256 does appear elsewhere:

- `DeviceFileEvents#346772`: July 9, in a Custom Script Extension directory.
- `DeviceFileEvents#683830`: August 1, in a Run Command extension directory.
- Additional detection/event evidence occurs on those other dates.

Neither an administrative extension path nor the filename `test.exe` proves
authorization. Those other-date records cannot be silently substituted for the
July 30 event. The execution context and an independent legitimate-testing
explanation are still missing.

### 13.7 Minimum evidence needed to reconsider the excluded cases

| Case family | Required recovery / verification |
|---|---|
| FP firewall analytic | Actual `NetworkPatterns_CL` rows or authentic saved result tuples for the alert windows, source/function definition, endpoint attribution, and sufficient traffic context to assess the flagged behavior |
| BP 52 | Valid IP-to-resource mapping, consistent metric/resource identities, and independent evidence of an authorized test or other benign explanation; adjudication conflict resolved |
| BP 173 / 189 | Event-time identity/cloud audit and sign-in activity, the elevation operation, and authorization/change/test context |
| BP 226 | July 30 endpoint activity plus the administrative deployment/execution context and approved-testing evidence |

The project decision is to **leave dedicated FP/BP incident sets out of this work**. Retain this
audit and the recovery requirements for future reference; do not create FP/BP
incident QA sets or start data recovery for them under the current feature.
Section 14 records the subsequently approved alert/event research, which did not
assume that the entire parent incident qualified as a negative benchmark. That
work is also deferred under the 2026-10-22 project decision.

The original eight TP assumptions remain valid as project decisions, independently
of this negative-case audit. They do not make unavailable evidence available, and
they do not justify inferring benignness elsewhere from a lack of logs.

## 14. Alert-level benign/FP investigation baseline (research; now deferred)

The user previously approved a finer-grained investigation after excluding
dedicated FP/BP incident sets. Candidate selection examined the latest raw alert records
across the full tenant, not only incidents labeled FP or BP.

This was an **initial screen, not a completed semantic adjudication**. It selected
alerts having a false-positive/expected-activity classification annotation or a
`Benign` automated-investigation state, then assessed whether raw activity existed
to investigate the claim. Section 14.1 summarizes the consolidated study findings;
no further FP/BP-targeted investigation is currently planned.

| Candidate signal | Alerts |
|---|---:|
| `InformationalExpectedActivity` classification | 87 |
| `FalsePositive` classification | 1 |
| `Benign` automated-investigation state | 26 |
| **Distinct union** | **111** |

The counts overlap. The candidate set includes 11 alerts whose own classification
is `TruePositive` while their investigation state is `Benign`; these are not
automatically false positives.

| Initial evidence screen | Candidates |
|---|---:|
| Some graph-linked operational raw evidence in the context window | 91 |
| No operational rows in the context window | 17 |
| Window context but no graph-linked operational support | 3 |
| **Total** | **111** |

Eighty-seven candidates belong to the ten selected TP scenarios and 24 belong
elsewhere. Eight are manual-investigation-start notices, which should not be
mistaken for independently established benign behaviors.

The screen confirms an investigation pool richer than the incident-level
negative sets, but **admits zero new negative QA items**. Graph-linked activity
shows that an event can be investigated; it does not establish its authorization,
legitimacy, or detection error.

A concrete lead is the August 1 Kekeo alert `SecurityAlert#9685`, linked to
incident 330. Unlike the July 30 BP incident 226, it has same-window evidence in
`DeviceFileEvents#683830` and `DeviceEvents#307461`. Those observations establish
artifact/detection context, not authorized testing. Its `Benign` investigation
state must not be promoted to gold without the independent rationale.

The [design document](QA_GENERATION_DESIGN.md) retains a future protocol for claim
scoping, raw identity/time binding, counterevidence and authorization checks,
coverage assessment, and reviewer approval. It applies only if this scope is
explicitly reopened; no FP/BP-targeted QA is currently eligible.

### 14.1 Consolidated tenant study

The [benign/FP QA research report](BENIGN_FP_QA_RESEARCH.md) combines source
collection, stratified review, detailed case analysis, and answer verification
into one study. It covers all 111 annotation-selected leads, with 79 reviewed
packets across all 47 detection-title families. Six detailed alerts are a subset
of those 79, not additional cases. Raw-source discovery also examines 27 latest
dismissed/confirmed-safe identity-risk events (28 historical rows, 24 request IDs,
12 additional alert anchors) and three Azure Guest Agent ASR block events.

The result is **zero verified benign/FP verdicts** and three locally SQL-verified
negative factual/configuration QA candidates about signing, prior artifact
presence, and initial task configuration. No research question is
release-approved, and the study does not establish that the entire tenant
contains no qualifying negative behavior. Raw activity often
corroborates suspicious operations without explaining authorization. Risk-review
actions record dismissal/confirmation without substantive benign rationale.
Platform-agent content/signature/service context is promising but does not
explain the particular blocked operation.

Validation lessons include separating detector-description echoes such as
`DeviceEvents.OtherAlertRelatedActivity` from independent evidence, preserving
sign-in substeps/history rather than assuming request-ID uniqueness, separating
enforcement facts from benignness, and distinguishing exact entity binding from
claim-specific causal evidence.
The original 17 no-window / 3 context-only / 91 graph-supported candidate
coverage counts are unchanged; narrower endpoint extraction is a different
measurement. No FP/BP incident set or negative gold task has been reinstated.

## 15. Preprocessing provenance and impact on the audits

### 15.1 What the cleanup actually changes

The investigation traced [Database Problems and How We Fixed Them](../Excytin_2_0/docs/design/problem_Database.md)
through the checked-in code and the exact databases used in our audits.
The document mixes ingestion, post-ingestion repair, and derived-graph changes:

| Layer | Implemented behavior | Effect on our analysis |
|---|---|---|
| [CSV ingestion](../Excytin_2_0/src/excytin2/ingest/build_db.py) | Load typed columns from metadata; strip header BOM/whitespace; empty strings become null; numeric/time conversion uses `try_cast`; assign `_rid` | This is already the input to our SQL audits. Failed casts can become null, so byte-for-byte source fidelity is not established merely by successful loading. |
| [Incident-export merge](../Excytin_2_0/src/excytin2/ingest/merge_incidents.py) | Append content-key-missing telemetry; record `_merged_rows`; do not merge `SecurityIncident`; add only absent alert IDs referenced by a tenant incident | Improves event coverage but deliberately omits incident history and some alerts. This materially limits an all-source incident/alert census. |
| JSON repair in the same module | Convert fixable Python-literal dynamic values to compact JSON | Changes representation, not an independently established behavioral verdict. The checked fields are valid JSON in our snapshot. |
| [Identity resolution](../Excytin_2_0/src/excytin2/entities/resolve.py) and [graph normalization](../Excytin_2_0/src/excytin2/graph/build_edges.py) | Account/host aliases, hub-edge exclusions, file-hash mapping, process-time recovery/snapping, alert-evidence mapping | These operate in the derived graph database while the tenant database is attached read-only. They do not rewrite raw incident labels or raw process timestamps. |

The merge key normalizes text for matching, excludes `_rid`/`rn`, and compares
shared columns after type conversion. It is not a general proof that source
rows are semantically interchangeable. Extra source columns, cast failures, and
potential normalization collisions require explicit ingestion-quality controls.

### 15.2 The supplied snapshot already includes the merge

Runtime checks reconcile every source table:

- `_ingest_report`: **61 tables / 13,174,822 rows**.
- `_merged_rows`: **164,443 retained appended rows**.
- Current source tables: **62 / 13,339,265 rows**; the added table is
  `LASummaryLogs`.
- Every recorded merge reference exists; every table's row count equals its
  recorded ingestion count plus retained merged rows.
- Recorded merge origins: incident folders 55 (34,934 rows), 134 (13,266),
  166 (20,898), 322 (95,330), and 39 (15). These are export origins, not proof
  that each row belongs exclusively to that incident.
- `SecurityIncident`: **833 original rows, zero merged rows**.
- `SecurityAlert`: **10,426 ingestion rows plus one retained merged row**,
  `SecurityAlert#10488`, "Mail.Read Permissions Granted to Application."

The document's 164,509 figure includes the subsequently removed 66 alert rows:
164,509 - 66 = 164,443. Its earlier description of missing alerts in incidents
5/34/55 is not a current snapshot manifest; the actual provenance records only
one retained added alert row.

Database sizes and modification times match all five prior audit artifacts
checked. Thus the earlier analyses were **already post-merge**; rerunning this
cleanup is not a new way to fill their known evidence gaps.

### 15.3 Material correction: incident history was not fully imported

The eight available incident-export `SecurityIncident.csv` files contain
**1,147 rows covering 715 distinct incident IDs**. Of these IDs, **608 are absent
from the 306-incident DuckDB**. All are in the same workspace; the checked
incident-number/GUID mappings do not conflict.

The union contains **914 observed incident IDs**. This is a historical/source
inventory, **not 914 independent attacks, currently active incidents, or
evidence-complete graphs**:

- Some are older incident records around subsequently consolidated cases.
- 572 source-only IDs come from the incident-322 export, whose incident updates
  extend to August 22; those 572 have activity on or after August 3.
- The merge excludes the whole incident table, not just demonstrably redundant
  old versions. Consequently it also excludes later updates.

One later classification changes an existing incident: **175** is unclassified
in DuckDB at its August 2 update, but a source row on August 22 marks it
`TruePositive / SuspiciousActivity`. Its July 23-27 activity window still has no
operational rows in the supplied snapshot; a later TP label does not make it a
complete benchmark case.

**Source-label baseline (unchanged):**

| Latest source classification | Supplied DuckDB | Latest available rows across DuckDB + incident CSVs |
|---|---:|---:|
| True positive | 5 | 6 |
| False positive | 47 | 48 |
| Benign positive | 4 | 4 |
| Undetermined | 183 | 245 |
| Unclassified | 67 | 611 |
| **Observed incident IDs** | **306** | **914** |

**Project-adjusted breakdown, including the ten selected TP scenarios:**

Apply the approved TP designations to **5, 34, 36, 38, 39, 55, 133, 134, 166,
and 322**, while preserving source-labeled TPs outside that selected set.
This includes the assumption that the original eight are TP, the approved
designation for 133, and the source TP label for 36.

| Project classification | DuckDB inventory with project designations | Combined available sources with project designations |
|---|---:|---:|
| TP - selected benchmark scenarios | **10** | **10** |
| TP - other source-labeled incidents | 2 | 3 |
| False positive | 47 | 48 |
| Benign positive | 4 | 4 |
| Undetermined | 180 | 242 |
| Unclassified | 63 | 607 |
| **Total distinct incident IDs** | **306** | **914** |

The project-adjusted **total TP count is 12 / 13**, not 10: incidents **83 and
123** are additional source-labeled TPs in both inventories, and **175** is an
additional source-labeled TP in the combined inventory. These other TPs are not
automatically added to the ten selected benchmark scenarios or certified as
evidence-complete.

Three selected cases (34, 36, 55) were already source-labeled TP. The overlay
therefore moves **three** cases from Undetermined (38, 39, 133) and **four** from
Unclassified (5, 134, 166, 322) into TP. It does not change FP/BP counts or rewrite
raw classifications; the source-label table remains the provenance baseline.

The 608 source-only IDs comprise 545 unclassified, 62 undetermined, and one FP.
That extra FP is **471**, "Custom Incident," reason `InaccurateData`, with an
empty alert list in its latest exported row. It is not another evidence-complete
negative graph. Of the 608 source-only incidents, 579 have nonempty alert lists,
but only incident 20 has any of those alerts in the current DuckDB; its 17
present alerts are not 17 newly discovered observations.

The 306-case breakdown and latest-row SQL remain correct **within DuckDB**.
They must no longer be described as the latest incident state across every
available input. Ordering DuckDB rows by `LastModifiedTime` instead of
`TimeGenerated` selected the same rows; the missing later history, not the
within-snapshot ordering, is the issue.

### 15.4 Material correction: 30 source alerts were excluded

The incident CSVs contain **66 rows / 30 alert IDs absent from DuckDB**, matching
the documented removal cohort. None of these IDs is referenced by any retained
tenant incident version. However, **28 are referenced by incident rows in the
source CSVs**. "Not in a retained tenant incident" is therefore not the same as
"never part of an incident."

The filter is based on incident membership, **not FP/BP classification**.
Nevertheless, checking every excluded alert version found two additional
negative-investigation leads:

| Excluded alert | Source | Candidate signal |
|---|---|---|
| `525f886a-6cf3-2891-4950-803b5aa0a068`, "Suspicious scheduled task" | Incident-34 folder; source incident references 34/35 | `InformationalExpectedActivity / ConfirmedActivity` |
| `1c458044-578b-3503-99a5-845c27c2f412`, "Attempt to hide use of dual-purpose tool" | Incident-55 folder; source incident reference 77 | `Benign` investigation state |

Combining available alert records gives **1,069 alert IDs and 113 latest
annotation-selected candidates**, versus 1,039 and 111 in DuckDB. These are
identifier counts, not proof of distinct behaviors; original and re-exported
alerts can describe related activity.

Those two leads were **not reviewed in the 79-alert study**. Their annotations
do not establish benignness, but their omission means the study cannot claim
to exhaust even the annotation-selected pool across all available exports.
The zero-verified-negative result remains a result for the evidence actually
examined, not a negative finding for those omitted cases.

### 15.5 What still holds about coverage and FP/BP evidence

Recomputing operational-window counts reproduced the earlier results for all
audited incident and candidate-alert windows. The merge had already improved
coverage in 79 incident windows and four of the 111 candidate-alert windows:

| Candidate alert | Retained base operational rows in window | Appended rows in window |
|---|---:|---:|
| `SecurityAlert#10057`, dual-purpose tool, incident 55 | 6,223 | 561 |
| `SecurityAlert#4693`, DDoS, incident 52 | 23,465 | 946 |
| `SecurityAlert#5975`, manual notice, incident 168 | 62,019 | 14,393 |
| `SecurityAlert#9685`, Kekeo, incident 330 | 0 | 57,289 |

These are **window-wide** rows, not counts of claim-specific corroboration.
For example, the August 1 file record `DeviceFileEvents#683830` and detector echo
`DeviceEvents#307461` were imported through the incident-322 export and were
already considered in the research. That evidence did not establish authorized
use.

- The 17 candidate-alert windows with no operational data remain empty.
- BP incidents 173, 189, and 226 still have no operational rows in their audited
  windows; BP52's target attribution and benign-rationale limitations remain.
- `NetworkPatterns_CL`, `SquidProxy`, and `SAPAuditLog` are absent both from
  DuckDB and as named tables in the available incident exports.
- The known missing incident-5 alert remains absent.
- The ten chosen TP scenarios and their explicit exclusions remain the current
  project scope. The additional source IDs have not undergone the earlier
  near-complete-case screen and must not be automatically added.

Subtracting tracked merged rows provides a count-based sensitivity check, not an
exact pre-cleanup database reconstruction. It does not undo JSON repairs or any
earlier untracked transformation.

### 15.6 Graph cleanup is not raw-data correction or verdict evidence

The stored graph confirms **571,333 recovered initiating-process times** for
`DeviceFileEvents` and **251,888 snapped times** for `DeviceProcessEvents`.
The former remain null in the raw table; the graph stores them separately in
`r_DeviceFileEvents` with `_ipct_src='asof'`. Snapped values likewise remain
derived. Some ASOF matches are more than seven days old, including 30,279 file
event associations; these require confidence/identity checks, not automatic
causal acceptance.

Account cannot-link rules and host/hash normalization can improve navigation,
but do not retroactively repair all anonymization inconsistencies in raw rows.
Hub-edge exclusions remove graph relationships, not the raw System activity.
Our direct SQL evidence checks therefore do not become invalid merely because
the graph omitted a hub or normalized an alias. Conversely, a clean-looking
graph match is not sufficient proof of a raw identity or benign explanation.

Alert export time also remains distinct from activity time: 391 latest alerts
have `TimeGenerated` more than a day after `EndTime`. The prior alert-window
screen used `StartTime`/`EndTime`, and operational coverage preferred event-time
columns. That part of the analysis does not need shifting to the re-ingestion
date.

### 15.7 Implications and provenance limits

**Correct the scope, not the observed evidence:** keep snapshot results
reproducible, distinguish them from the all-available-input inventory, and
explicitly retain omitted history and candidate records in the planned ledger.
Before freezing a new QA dataset:

1. Reconcile all source updates, then keep only the latest whole incident row
   per incident as active QA state, with its source provenance.
2. Derive historical removed-membership links from those input updates, with
   before/after references and not-current status, rather than serving all old
   incident rows or unioning their alert lists into current membership.
3. Preserve unassigned/unreferenced alerts as observations; use generation scope
   to select tasks, not irreversible source deletion.
4. Record original values, transformations, cast failures, and derived-identity
   confidence; keep source IDs and provenance portable across rebuilds.
5. Recompute inventory, memberships, classifications, and coverage for the chosen
   source manifest before making all-source claims.

This is a material M0 data-provenance prerequisite, not a reason to resume
FP/BP-targeted QA. The present deferral remains unchanged.

The original full-tenant CSV export, staged incident DuckDB, pre-merge backups,
and merge reports are not present locally. This audit used the supplied
post-cleanup databases, merge/ingestion metadata, checked-in code, and available
incident CSVs; it is not a byte-level certification of every cleanup operation.
No input database, CSV, graph, or production code was changed.

Supporting results: [cleanup audit][cleanup-audit], [source-only incidents][cleanup-incidents],
[excluded alerts][cleanup-alerts], [newer classifications][cleanup-labels],
[coverage sensitivity][cleanup-coverage], and [read-only audit program][cleanup-code].

### 15.8 Latest incident state and removed memberships

The user confirmed on 2026-10-23 that only the latest incident row is needed as
active incident state. Original source files remain unchanged and can be read
to derive removed-membership metadata; retaining old full incident rows in the
active QA dataset is not required.

A bounded [removed-membership investigation](BENIGN_FP_QA_RESEARCH.md#35-removed-incident-memberships)
reconciled 1,980 update rows across the 914 incident IDs:

- **155 historical-only incident-alert links**, representing 150 alert IDs
  across 79 incidents; every alert still has a latest membership elsewhere.
- 137 links were removed from incidents marked `Redirected` and left empty;
  124 links have Defender alert correlation as modifier of their first-absent
  update. These are link counts, not counts of distinct update rows.
- Among selected cases: 5 lost eight links now in 25; 34 lost six now in 35;
  36 lost four now in 38. Current member counts for all ten scenarios are unchanged.
- Twenty-seven distinct removed alerts have negative-investigation signals:
  26 overlap the original candidate pool, and one scheduled-task alert received
  a new targeted evidence check. No verified benign/FP verdict was established.

Historical membership is a source-backed observation, not proof of current
relevance or benignness. Preserve last-present/first-absent bounds and source
references; do not infer exact removal time, a consolidation mechanism, or
negative classification solely from disappearance from an alert list.
The negative-QA deferral remains in force outside this completed diagnostic.

## 16. Fresh SecRL v1 evidence graph

The v1 implementation now builds a fresh graph from the reconciled observation
ledger, not by importing old edges. The initial `evidence-graph-v1.2` rule revision
contains 13,276,306 observation nodes, 6,191,517 typed entity nodes and 64,134,168
source-linked edges. These graph-rule revision labels do not change the legacy
dataset aliases v0.1/v0.2.

The representation is observation-centered: a source observation links to its
participants with roles, source paths, rule IDs and interpretation classes.
Traversing two participants through an observation is not an assertion of a
causal relationship. Existing counts in Sections 1-15 describe their historical
snapshots and are not numerically comparable to this new edge representation.

Verified enrichments include every usable audit target and cloud activity
object, message/account/IP/redirect click context, Graph API resource targets,
Intune and provisioning participants, full-command lexical references and
typed TI file-hash references. Token references were corrected against raw
sign-in data; filename/account/application-name references remain explicitly
weak rather than being promoted to identity for compatibility.

The [initial coverage comparison][v1-graph-comparison] accounts for all 186
original alert nodes and classifies all 1,603 original alert/entity edges:

| Link comparison status | Count |
|---|---:|
| Same-alert reported entity identifier | 810 |
| Same-alert weak/lexical reference | 400 |
| Compound identity requiring contextual validation | 268 |
| Filename case variant requiring platform context | 68 |
| Identifier elsewhere rather than matched on the same alert | 19 |
| Invalid/unsupported legacy identifier form | 35 |
| Basename inside a path requiring context | 1 |
| Exact legacy identifier not represented | 2 |

The two unmatched exact strings are the earlier case-specific fileless-script
URL in incident 38; the retained source contains a different schemeless/case
variant. It must not be rewritten to match the old node by assumption.
A targeted screen found exact same-alert PID/start-time representation for 261
of 262 compound-process links, but that does not validate every command and
host/context association.

At the source-row level, all **6,357,361 old graph source rows mapped to active
ledger observations** have new participant links. The remaining 134 of the old
6,357,495 rows are superseded incident versions excluded by the approved
latest-row policy. Source-row coverage is not proof that all old graph paths
have equivalent meaning.

The new build preserves 1,383 current incident-alert links and 155 separate
historical removed links, with all 914 incident identities, 1,069 active alert
records and ten case manifests. Real incident 34/55 process pivots and incident
330 content-hash pivots were checked against raw observation identities.
Graph/ledger checksums, endpoint/source references and membership counts pass;
172 focused regression tests pass and the 109-file legacy baseline is unchanged.

The [graph build report][v1-graph-report] is a completed build artifact.
The coverage comparison remains explicitly `compared_not_certified`; the
source-semantic follow-up below is a separate, narrower acceptance result.
No model-driven QA generation or runtime evaluation has started.

### 16.1 Completed legacy alert/entity semantic checks

The [source-semantic report][v1-semantic-report] accounts for all **1,603 links**
with zero unresolved mappings. It replaces the initial identifier-only
classifications above for purposes of legacy alert/entity acceptance:

| Final semantic disposition | Count |
|---|---:|
| Same-alert source-reported identifier | 788 |
| Source-supported weak/lexical/contextual reference | 515 |
| Source/graph process identity and command projection verified | 261 |
| Old synthesized email corrected using authoritative same-account UPN | 35 |
| Exact message/recipient-linked alternative path | 3 |
| Intentionally excluded unqualified legacy process identity | 1 |

Checks use the latest raw alert entity fields and actual graph mentions.
Compound process checks include host, PID, qualified creation time and full
legacy command projection, rather than merely finding a matching PID/time.
Application/resource components and filename/URL projections remain references,
not new globally merged identities.

Current graph process keys normalize timezone-qualified creation times to UTC
microseconds, consistent with the typed telemetry columns. The original dynamic
JSON fields retain any additional fractional digits. Matching these normalized
keys is not a claim that the original timestamps are equal at submicrosecond
precision, and is not permission to add a wider timing tolerance. Timestamp
**answer** comparison separately retains all supplied fractional digits.

The three alternative paths belong to incident 134 alert
`842de14d-27aa-d006-296c-239987d60a6e`. Its direct mail-message ID
`2dbfc9f0-951f-4dd2-692b-08dca64b9909` and recipient bind the raw sender/IP
record and click redirect chain. The raw click explicitly contains both the
HTTP and HTTPS URLs. All graph bridge/target roles are verified; the check
does not infer scheme equivalence or borrow fields from another message.

Incident 322 alert `a2fb174d-cdd1-4484-436a-f3cb4c2713bb` has the one excluded
PID-4256 legacy identity. Its old `CreatedTimeUtc=2024-08-01T13:42:52.04`
is timezone-free and not the source's qualified process-creation field.
The unique raw same-host/PID/full-command candidate starts at
`2024-08-01T12:25:23.612698+00:00` and already has a graph process node.
That candidate is recorded separately, **not** used to declare the old timestamp
equivalent or invent an alert-to-process recovery edge.

All **201 v1 regression tests pass**, including 29 semantic tests with negative
binding/path/checksum cases and CLI round-trips. The 109-file legacy baseline
and input graph/ledger checksums remain unchanged.

This is scoped legacy-link accounting, not certification of complete tenant
ontology coverage or causal meaning for every graph path. Source-only tables
and unsupported entity types remain explicit limitations, not evidence of
benignness or data corruption. Task-level evidence validation and the remaining
graph-coverage dispositions are still required before model-driven QA admission.

### 16.2 Source-backed coverage closure in evidence-graph-v1.3

The follow-up resolved real extraction omissions: explicit IoT/hub IDs, NIC
MAC references, cluster/namespace/pod-scoped Kubernetes names, container-image
references and storage-scoped blob-container names. Named references do not
identify a physical device or runtime incarnation.

Six previously source-only tables now have participants: reported resource
metadata in `Alert`, `SentinelAudit`, `SentinelHealth` and `Usage`, a separate
monitoring-computer namespace in `Operation`, and contextual entities in
`HuntingBookmark`. These are not independent proof of referenced activity.
`Watchlist` remains source-only because all 790 supplied entity mappings are
empty; raw rows remain queryable.

The [new build][v13-graph-report] has **13,276,306 observation nodes**,
**6,191,661 entity nodes** and **64,176,753 edges**: 42,585 additional links,
with no per-table participant-count losses. It preserves all 155 removed
memberships. The [coverage check][v13-coverage-report] verifies all 32,071
valid entity-extraction replay mentions against their exact output source paths
and identities, with zero missing mentions or remaining unmapped alert types.
Repeated `$ref` traversal mentions are not additional physical entities.
The [semantic rerun][v13-semantic-report] retains all 1,603 legacy dispositions.
The [source comparison rerun][v13-source-comparison] preserves all 6,357,361
active mapped old source rows and their participant coverage, with only the
same 134 superseded incident rows outside active state.

A specific limitation remains explicit: all 20 `SentinelAudit` records report
a top-level resource different from the updated-state resource ID. The graph
does not claim that the reported metadata resource is the modified target.
Configuration-change claims must examine and reconcile the state evidence.

The **scoped I2 acceptance gate is complete** for this source snapshot, with
223 passing v1 tests and all 109 legacy hashes unchanged. This does not certify
complete tenant coverage, remove conservative process-time exclusions, admit
any QA, or substitute for task-specific evidence and public-serving validation.

[v13-graph-report]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i2/evidence-graph-v1.3/graph_report.json
[v13-coverage-report]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i2/coverage-verification-v1.3.json
[v13-semantic-report]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i2/semantic-check-v1.3/semantic_report.json
[v13-source-comparison]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i2/graph-comparison-v1.3/comparison_report.json
[v1-graph-report]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i2/evidence-graph-v1.2/graph_report.json
[v1-graph-comparison]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i2/graph-comparison-v1.2/comparison_report.json
[v1-semantic-report]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/v1-i2/semantic-check-accepted/semantic_report.json
[node-mapping]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/entity-scan/node_mapping.csv
[edge-mapping]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/entity-scan/edge_mapping.csv
[entity-audit]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/entity-scan/entity_coverage.json
[pair-mapping]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/relation-scan/lost_alert_pairs.csv
[relation-audit]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/relation-scan/relation_coverage.json
[entity-scanner]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/entity_coverage_scan.py
[relation-scanner]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/relation_coverage_scan.py
[raw-audit]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/raw-entity-scan/raw_entity_audit.json
[raw-typed]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/raw-entity-scan/typed_entity_inventory.csv
[raw-fields]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/raw-entity-scan/field_only_entity_mentions.csv
[raw-alerts]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/raw-entity-scan/alert_inventory.csv
[raw-versions]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/raw-entity-scan/alert_versions.csv
[raw-history]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/raw-entity-scan/historical_only_identifier_records.csv
[raw-scanner]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/security_alert_entity_audit.py
[tenant-audit]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/tenant_coverage_audit.json
[tenant-incidents]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/incident_inventory.csv
[tenant-classification]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/classification_reason_summary.csv
[tenant-class-coverage]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/coverage_by_classification.csv
[tenant-updates]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/incident_update_history.csv
[tenant-alerts]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/all_alerts.csv
[tenant-entities]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/all_typed_entity_records.csv
[tenant-fields]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/all_alert_entity_fields.jsonl.gz
[tenant-evidence]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/all_alert_evidence_entities.csv
[tenant-tables]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/raw_table_inventory.csv
[tenant-table-coverage]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/incident_raw_table_coverage.csv
[tenant-daily]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/raw_table_daily_coverage.csv
[tenant-hourly]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/raw_table_hourly_coverage.csv
[tenant-stale]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/historical_graph_links_not_current.csv
[tenant-query-sources]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/named_query_source_availability.csv
[tenant-reference-windows]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant-coverage/reference_export_footprints.csv
[tenant-scanner]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/tenant_coverage_audit.py
[negative-audit]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/negative-evidence/negative_evidence_audit.json
[negative-readiness]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/negative-evidence/negative_case_readiness.csv
[negative-bp-coverage]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/negative-evidence/bp_source_window_coverage.csv
[reference-tp-policy]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/negative-evidence/reference_tp_designations.csv
[negative-scanner]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/negative_evidence_audit.py
[alert-negative-candidates]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/alert-negative-screen/alert_negative_candidates.csv
[alert-negative-evidence]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/alert-negative-screen/alert_negative_screen.json
[cleanup-audit]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/cleanup-impact/cleanup_impact_audit.json
[cleanup-incidents]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/cleanup-impact/source_only_incidents.csv
[cleanup-alerts]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/cleanup-impact/excluded_alert_inventory.csv
[cleanup-labels]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/cleanup-impact/newer_incident_classifications.csv
[cleanup-coverage]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/cleanup-impact/merge_coverage_sensitivity.csv
[cleanup-code]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/cleanup_impact_audit.py

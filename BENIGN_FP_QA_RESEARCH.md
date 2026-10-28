# Tenant Study: Evidence-Backed Benign/FP QA Feasibility

**Research date:** 2026-10-21  
**Consolidated:** 2026-10-22  
**Last updated:** 2026-10-23, with the requested removed-membership diagnostic.  
**Status:** Retained research; FP/BP-targeted work deferred, no release-approved QA.  
**Design:** [Agentic QA generation](QA_GENERATION_DESIGN.md).  
**Source inventory:** [Graph and evidence audits](GRAPH_GENERATION_COMPARISON.md).

**Project decision (2026-10-22):** hold off on FP/BP-targeted investigation and QA
at incident, alert, and event levels. Preserve these findings and artifacts as
reference only; do not continue this workstream or automatically promote its
candidates. Tenant-wide and ten-TP-incident generation remain active design
scopes. Raw tenant records remain available as context.

**Narrow research exception (2026-10-23):** the user requested a check of alerts
removed from incident membership as potential FP/BP leads. Section 3.5 records
that completed diagnostic; it does not reopen general negative-QA generation
or change the original 79-packet review denominator.

## 1. Tenant-wide study: scope and overall outcome

**Study scope: 1,039 latest alerts in the supplied post-cleanup DuckDB screened,
111 annotation-selected leads
with evidence collection, and 79 alert packets reviewed across all 47
detection-title families.** Raw-source investigation also covered 27 resolved
identity-risk records linked to 12 additional alerts, and three Azure Guest
Agent protection events.

**Source-provenance qualification (2026-10-22):** these are snapshot counts, not
all available pre-merge inputs. The cleanup-impact audit found 30 excluded alert
IDs in the incident CSVs, including two additional annotation-selected leads
outside the original packet review. See Section 2.5. One of those leads is
examined in Section 3.5; the recorded findings must not be generalized to
unexamined records.

Can tenant alert and raw-event leads produce questions whose benign or
false-positive conclusions are supported by attributable evidence, rather than
by classification labels, investigation states, or missing telemetry?

**The study established zero verified benign/FP verdicts.** It did produce three
locally SQL-verified factual/configuration QA candidates. A negative answer to a
factual question is not a benign/FP classification: these candidates challenge
specific assumptions without justifying dismissal of the underlying alerts.

| Study coverage or result | Count |
|---|---:|
| Latest raw tenant alerts screened | 1,039 |
| Annotation-selected alerts with source/evidence collection | 111 |
| Stratified alert packets reviewed | 79, spanning all 47 detection-title families |
| Additional latest dismissed/confirmed-safe identity risks | 27 risk IDs across 24 request IDs |
| Additional alerts linked to that risk cohort | 12 alerts across 11 alert-linked request IDs |
| Additional Azure Guest Agent protection events | 3 |
| Locally SQL-verified negative factual/configuration QA candidates | **3** |
| Verified benign/FP verdicts | **0** |
| Release-approved QA | **0** |

The 79 reviewed alert packets yielded **61 cases missing a benign/refuting
premise, 11 missing event-window evidence, and seven manual investigation
notices rather than threat detections**. The additional identity-risk and
platform-event investigations also established no verified benign/FP verdict.

The risk-event and platform-event cohorts use different selection rules and
units; they are not added to the alert-review denominator. Detailed case examples
support the study findings but do not define its scope.

This is a targeted feasibility study, not a random sample, prevalence estimate,
or conclusion that no qualifying negative behavior exists anywhere in the tenant.

## 2. Tenant-snapshot screening, sampling, and method

### 2.1 Annotation-selected alert cohort

The screen of 1,039 latest raw alerts selected records with false-positive or
expected-activity classification annotations, or a benign investigation state:

| Candidate signal | Alerts |
|---|---:|
| `InformationalExpectedActivity` classification | 87 |
| `FalsePositive` classification | 1 |
| `Benign` automated-investigation state | 26 |
| **Distinct union, accounting for overlap** | **111** |

The cohort spans 47 detection-title families, five products, and 19
incident-membership groups. Of the 111 alerts, 87 fall inside selected TP
scenarios; 11 have both a TP alert classification and a benign investigation
state. Eight are manual-investigation-start notices, not necessarily threat
detections. These signals identify leads, not independently verified negatives.

| Source-coverage screen | Alerts |
|---|---:|
| Some graph-linked operational raw support in the context window | 91 |
| No operational rows in the context window | 17 |
| Window context exists but no graph-linked operational support | 3 |
| **Total** | **111** |

The endpoint collector found identity-bound, non-echo rows for **82** of these
alerts. That uses narrower selectors than the coverage screen: it is not a
replacement census and does not imply that the remaining 29 have no evidence.

### 2.2 Review of 79 alerts across 47 detection families

Review selection used 63 title / incident / annotation / coverage strata:
one evidence-rich representative per stratum, plus a second host where
available. The resulting **79 packets cover all 47 detection-title families**.
Review considered source claims, entity identities, coverage, extracted activity,
and possible benign/refuting premises. The remaining 32 cohort alerts have
collection results but were not individually adjudicated.

Review depth varied with evidence availability and the claim being tested.
It would be incorrect to describe the study as 111 equally deep investigations
or to count repeated alerts as independent behaviors.

### 2.3 Raw-source leads outside the annotation filter

To avoid relying exclusively on alert labels, the study also investigated:

- **27 latest dismissed/confirmed-safe identity-risk records**, represented by
  28 historical rows and 24 distinct request IDs. Typed request entities link
  them to 12 alerts outside the 111-alert cohort.
- **Three Azure Guest Agent ASR block events**, selected from raw protection
  telemetry. These remain raw-event leads, not three established alert anchors.

The identity-risk cohort includes records with automated clearance and recorded
account-review actions. MFA-driven remediation signals were inventoried during
discovery but were not treated as proof of an original false alarm.

### 2.4 Investigation and verification workflow

The study applied the proposed QA workflow at research scale:

1. Collect source/evidence packets and select diverse review cases.
2. Freeze the actual alert/event claim and identify its subjects.
3. Retrieve raw activity; check identity, time, source lineage, and coverage.
4. Seek legitimate-use or refuting evidence and investigate competing readings.
5. Draft a precise question only where the evidence supports its premise.
6. For the three factual QA candidates, compute answers through two alternative
   local SQL derivations, repeat execution, and test missing-input controls.
7. Record unsupported interpretations, review dispositions, and release blockers.

This was **assistant-led local SQL research**, not execution of the proposed
production multi-agent pipeline. The two derivations were authored in the same
investigation; their agreement is not independent blind-model verification.

Annotations were discovery signals, not inputs to the factual answer queries.
Those queries do not inspect `Classification`, `Determination`, or investigation
verdicts, and do not filter on hidden target row IDs. Source references such as
`Table#rid` below identify evidence in the pinned database; they are not public
question clues or portable identifiers across rebuilds.

### 2.5 Source-cleanup effects on the study boundary

The [cleanup-impact audit](GRAPH_GENERATION_COMPARISON.md#15-preprocessing-provenance-and-impact-on-the-audits)
verified that the databases used throughout this study already include the
incident-export merge and graph cleanup. It also identified source exclusions:

- The merge skipped incident-folder `SecurityIncident` history. Across DuckDB
  and the available CSVs there are 914 observed historical incident IDs, not
  only the 306 in DuckDB. These are not 914 independent or complete cases.
- It excluded 66 alert rows / 30 alert IDs not referenced by retained tenant
  incident records. Twenty-eight of those IDs are referenced by source incident
  history that was itself omitted.
- Two excluded alerts meet the annotation screen:
  `525f886a-6cf3-2891-4950-803b5aa0a068` ("Suspicious scheduled task," expected
  activity) and `1c458044-578b-3503-99a5-845c27c2f412` ("Attempt to hide use of
  dual-purpose tool," benign investigation state). The all-available-input
  inventory therefore has 1,069 alert IDs and 113 latest candidate signals.

The 111-alert collection, 79-packet review, and zero verified benign/FP results
are unchanged **for the studied snapshot and cases**. Neither extra lead was
part of those 79 packets. The scheduled-task lead subsequently received the
targeted check in Section 3.5; the other is not assigned a verdict here.

The cleanup did not filter on FP/BP labels, but its membership-based exclusions
still limit source completeness. An extra source-only FP incident, 471, has no
alerts in its latest exported row. A newer source update labels incident 175 TP;
its event window still lacks operational evidence. Neither establishes a usable
new negative graph or reverses the decision to defer this work.

Operational-window checks reproduced the study's existing counts, including all
17 empty windows. Imported evidence already contributed to four candidate-alert
windows; the August 1 Kekeo window depends entirely on appended operational
rows. Graph-only process-time and identity normalization do not supply
authorization or change raw classifications. This provenance check did not
reopen FP/BP discovery or generate new QA.

## 3. Findings and benign/FP admission outcomes

### 3.1 Review dispositions

| Disposition for reviewed alert packets | Count | Interpretation |
|---|---:|---|
| Missing benign/refuting premise; needs review | 61 | Neither an accepted negative nor an automatic malicious verdict |
| Missing event-window evidence | 11 | Cannot resolve the claim from the available collection |
| Manual investigation notice, not a threat detection | 7 | Not an FP simply because the resulting investigation is benign |
| **Total reviewed** | **79** | **No verified benign/FP verdicts** |

The disposition categories are mutually exclusive. Two of the seven manual
notices also fall in unavailable telemetry windows. A notice reports that a user
started an investigation; it does not necessarily assert a malicious event that
can be adjudicated false, and a benign investigation state does not prove a host
clean. The additional risk/platform leads also failed to establish a benign or
refuting premise; they are not included in this 79-alert disposition table.

### 3.2 Endpoint and related identity activity

| Investigated behavior | Representative evidence | Why it does not establish a negative verdict |
|---|---|---|
| Credential-tool and LSASS activity | `DeviceProcessEvents#6166`, `#6197`, `#6235`; matching file/activity records | Credential-access commands are observed. The records do not establish approved testing or refute the detection premise. |
| Recovery tampering and remote WMI execution | `DeviceProcessEvents#6302`, `#6311`, `#6478`, `#6486` | Recovery-disabling / shadow-copy-deletion commands are observed; legitimate administrative purpose is not independently established. Execution alone also does not prove every requested change succeeded. |
| Document-to-PowerShell persistence chain | `DeviceProcessEvents#91226`, `#91228`, `#92183`; `DeviceRegistryEvents#132209` | Task creation and the RunOnce value are corroborated. Simulation-oriented names/wording are not a blanket authorization record. |
| Renamed dual-use tools | `DeviceProcessEvents#181305` and `#6270`; associated file/network records | Signed PowerShell and renamed PsExec remain dual-use. Authenticity is not legitimate-use evidence. |
| Remote service installation | `DeviceFileEvents#131675`; `DeviceProcessEvents#107666`; `DeviceRegistryEvents#157174` | PsExec service creation is corroborated, but its approval and purpose are not. |
| Ransomware-like and lateral-movement alerts | Related file, network and enforcement rows across several hosts | Some bindings involve a long-lived System process or shared context. They do not prove encryption, disprove encryption, or establish benign intent. |
| DNS reconnaissance | `IdentityQueryEvents#22849`, matched to the source/destination pair and alert time | An AXFR query is recorded; no legitimate zone-transfer rationale was established. |
| Kerberos/overpass-the-hash lead | `IdentityLogonEvents#502`, `#503`, matching account SID and hosts near the alert | Authentication success is recorded; it does not determine whether the credential use was legitimate. |
| Elevation, July malware and repeated July attack-chain leads | Unavailable event windows in the supplied data | Earlier/later activity and annotation text cannot substitute for missing event evidence. |

The selected ten TP scenario designations remain unchanged. Expected-activity
annotations and test filenames are not silently converted into negative gold
for scenarios the project treats as positive attack examples.

**Enforcement is a separate claim.** Four
`ExploitGuardNetworkProtectionBlocked` records (`DeviceEvents#8351`, `#8388`,
`#8715`, `#8915`) report actual, non-audit protection actions. A nearby
`ConnectionSuccess` does not by itself prove successful application-level C2 or
invalidate the protection record. Preventing an operation also does not make
the attempted behavior benign.

### 3.3 Identity-risk clearance versus authentication and authorization

Latest whole-row selection by `TenantId, Id` produces 27 resolved risk events:

- 14 with literal detail `aiConfirmedSigninSafe`;
- 10 with literal detail `blatempDismissedAllRiskForUser`;
- 3 with literal detail `blatempConfirmedAccountSafe`.

The raw `blatemp...` strings are preserved, not silently normalized. These are
candidate signals, not ground-truth explanations. All 24 request IDs have
matching sign-in rows with consistent user ID and IP. Twelve latest alerts carry
exact matching `cloud-logon-request.RequestId` entities, covering **11 distinct
alert-linked requests**, not 12 independent authentication attempts.

**Confirmed-safe risk with unsuccessful sign-in.** `SecurityAlert#1892`,
`#1893`, and `#1894` map to two June 12/19 requests. `SigninLogs#40244` and
`#40242` record result `50076`: the password step succeeded, but MFA was required
and not completed in those records. `AuditLogs#27757` records a successful
`ConfirmAccountSafe` action on July 10, with the same user ID as actor and target.
Its reason/details document the operation's success, not why the original
activity was legitimate. This supports a narrow authentication-outcome finding,
not the assertion that the detector was wrong or the password user was benign.

**Bulk dismissal with successful risky sign-ins.** Nine anonymous-IP alert
requests have result `0` in all matching exported sign-in rows.
`AuditLogs#49351` records a successful `DismissUser` operation targeting the same
account. Its additional details contain the operation, target ID and action
time, not a benign-use rationale. Account-level dismissal is a workflow fact,
not independent proof that every underlying sign-in was authorized.

The 14 AI-cleared risk events likewise supply no independent explanation merely
by having that state. Neither clearance nor remediation establishes an original
false alarm.

**Join limitation:** the 27 risk events produce 110 join associations to 97
distinct exported sign-in rows. Eight of the 24 request IDs have multiple
`CreatedDateTime` values and differing authentication substeps/outcomes. Do not
count these as 110 independent events, select the first result, or silently use
one latest row per request for every question. Preserve history/substeps and
define the question's attempt or outcome scope explicitly. For the 11
alert-linked requests, observed result codes are consistent per request:
nine succeed and two require MFA.

### 3.4 Azure Guest Agent: stronger provenance, incomplete explanation

Three raw `AsrLsassCredentialTheftBlocked` events identify `WaAppAgent.exe`:

- `DeviceEvents#4709`: vnevado-srv2016, June 20;
- `DeviceEvents#7079`: mb-adfs, June 20;
- `DeviceEvents#126914`: avoriaz-sql1, June 27.

The identity has more support than a filename alone:

- identical SHA1/SHA256 across the three event records;
- WindowsAzure GuestAgent paths and `services.exe` / System context;
- 45 same-content process observations across eight hosts and nine days, all
  started by `services.exe` as System, with Microsoft company metadata;
- six matching signed/trusted Microsoft certificate observations.

This is a **plausible benign-product interaction lead**, but not a verified
benign operation:

- No exact host/PID/creation-time process-created row was found for the three
  blocked instances, including a sub-second tolerance check.
- Signature observations are elsewhere in the tenant, not proof of the affected
  host's exact trust decision at that time.
- The evidence does not explain why the particular memory-access attempts were
  expected and authorized, or rule out misuse of the process.
- No latest alert entity explicitly names this executable or its matching hash;
  these remain raw-event leads rather than three verified FP alert nodes.

The missing ingredient is behavioral/deployment rationale tied to these
instances, not another signature observation or a larger prevalence count.

### 3.5 Removed incident memberships

This diagnostic tests a specific hypothesis: alerts removed from an incident
may have been dismissed as false or benign positives. It uses source update
history to derive transitions, not to replace the latest incident state.

Across DuckDB and the eight original incident exports, 1,980 incident-update
rows cover 914 incident IDs. After collapsing 204 repeated same-time snapshots,
there were no conflicting same-time membership sets. Missing/malformed lists
would be an error, not interpreted as an empty incident.

| Membership finding | Count |
|---|---:|
| Incident-alert links observed previously but absent from the latest incident row | 155 |
| Distinct alert IDs in those links | 150 |
| Incidents with such removed links | 79 |
| Removed links whose alert is present in another incident's latest available row | **155 / 155** |
| Removed links from incidents marked `Redirected` at removal and empty in their latest row | 137 |
| Removed links with `ModifiedBy = Microsoft Defender XDR - alert correlation` at the first absent snapshot | 124 |
| Removed links with an available alert record | 136 |
| Removed links with only incident references, no available alert record | 19 |

The counts of 137 and 124 overlap; they are not separate case totals.
No observed removal was later re-added to the same incident in the available
snapshots. A removal interval is bounded by the last-present and first-absent
exported updates; it is not an exact administrative action timestamp.

**All removed links retain another latest parent.** Combined with the
`Redirected` and alert-correlation metadata, this is primarily a regrouping/
reassignment signal, not independent evidence of benign dismissal. The data
does not prove a specific transfer mechanism for every link.

For the selected TP scenarios:

| Historical source incident | Removed links | Other latest parent |
|---|---:|---|
| 5 | 8 | 25 |
| 34 | 6 | 35 |
| 36 | 4 | 38 |

The latest current alert counts for all ten selected scenarios agree with the
previous DuckDB-based counts. These removed links must not be unioned back into
current membership.

#### Negative signals and the additional scheduled-task lead

Twenty-seven distinct removed alerts meet the negative-annotation screen:
23 have expected-activity annotations and four have TP annotations with benign
investigation states. Of these, 26 were already in the 111-alert pool and 16
were among the 79 reviewed packets. These are overlapping cohorts, not 27 new
independently investigated negatives.

The one lead outside that original pool is
`525f886a-6cf3-2891-4950-803b5aa0a068`, **"Suspicious scheduled task"**, from the
incident-34 CSV. It is no longer in incident 34 but is in incident 35's latest
exported alert list. It has `InformationalExpectedActivity / ConfirmedActivity`.
The first absent incident-34 update is attributed to Defender alert correlation;
the latest incident-35 row is `Undetermined` and contains only a `config` comment.
These fields do not provide an independent authorization rationale.

Targeted raw checks establish:

- `DeviceEvents#111669` records a boot-triggered task,
  `\(Attack) UpdateOrchestrator`, on vnevado-win10s at
  2024-06-26 11:03:48.377789 UTC. Its PowerShell action downloads
  `Orchestrator.ps1` from a demo-named blob endpoint.
- `DeviceRegistryEvents#126052` independently records the corresponding task
  cache key on the same host near that time.
- `DeviceProcessEvents#89431` matches the alert's WMI process by host, PID and
  creation time.
- `DeviceEvents#111668` is a detector-description echo. The task-created event
  lacks an initiating-process ID, so the echo cannot independently prove that
  the matched WMI process created the task.

The task's demo-oriented naming makes authorized simulation plausible, but no
independent approval or refutation of the actual detection premise was
established. **This diagnostic adds zero verified benign/FP verdicts and no QA.**
It validates the task-registration facts and explains why removed membership
cannot serve as a negative label; it is not exhaustive adjudication of all 150
alert IDs.

The design therefore uses latest-row-only incident state and separate
`historical_removed` links. Such a link can be a reliable record of past
membership while remaining weak evidence of current incident relevance.
Removal does not make the alert benign, false, or unrelated to all incidents.
See the [membership audit][membership-audit] and
[derived historical links][membership-links] for source references and checks.

## 4. Supporting case examples and factual QA

The following cases illustrate the tenant-wide findings; they are not a separate
study or an additional sample. Six alerts within the **79 already reviewed**
received detailed case analysis:

| Investigative lead group | Source alerts | Reason for detailed analysis |
|---|---|---|
| PowerShell drop and scheduled task, incident 34 | `SecurityAlert#7530`, `#7454` | Expected/benign annotations with detailed process/file/task evidence |
| Renamed executable, incident 55 | `SecurityAlert#10009` | TP detection and benign investigation state coexist; content/signature evidence can challenge superficial interpretation |
| Kekeo detection, incident 330 | `SecurityAlert#9685` | Same-window telemetry exists, unlike the excluded July 30 BP incident |
| Manual investigation notices, incidents 81/168 | `SecurityAlert#1541`, `#5975` | Benign investigation states that might otherwise be mistaken for false-positive threat detections |

These four investigative groupings are not additional detection-title families.
They are retained here for concrete evidence and reproducible answer derivations,
not as the basis for the study's overall coverage counts.

The three candidates below establish narrower facts, not benign/FP verdicts.
Signing and task configuration are incident-anchored to 55 and 34 respectively;
artifact novelty is tenant-scoped and originates from incident 330 outside the
ten selected cases. Full-tenant evidence access is retained in both scopes.
All candidates remain `release_accepted=false`.

### 4.1 The renamed executable is not unsigned

#### Public briefing

> In the Alpine Ski House tenant on 2 July 2024, Defender raised "System executable
> renamed and launched" on mb-adfs.

#### Question

> Do the available tenant certificate records identify the executable launched
> under the changed name as unsigned? Answer yes or no and support the answer with
> the executable identity and certificate evidence.

#### Verified factual answer

**No.** The renamed image is identified as PowerShell content, and all ten
matching certificate observations mark it signed and trusted, with signer
`Microsoft Windows`.

#### Evidence and derivation

- `DeviceFileEvents#230109`: the differently named file is created.
- `DeviceProcessEvents#181305`: that image launches; its original-file metadata
  identifies `PowerShell.EXE`.
- The process and certificate records join by content hash, not by the changed
  filename.
- `DeviceFileCertificateInfo#11457` is an earlier matching certificate observation
  on another host. The first matching mb-adfs observations occur on July 14,
  including `DeviceFileCertificateInfo#89853`.

Derivation A follows the renamed process identity to the certificate inventory.
Derivation B starts with the file-created event and confirms its subsequent
process identity before checking certificate variants. Both resolve one target
and answer `false` to the unsigned claim.

#### What this does not establish

- Signed Microsoft content can be used maliciously.
- The encoded-command execution remains suspicious context.
- The question concerns the available tenant certificate inventory, not a
  reconstruction of this host's exact trust decision at execution time.
- This is not an FP/BP classification of the alert.

**Analyst value:** distinguish artifact authenticity from execution legitimacy;
avoid treating a changed filename as proof of unsigned/new malware or a valid
signature as proof of benign behavior.

**Release concern:** the answer may be guessable from the alert family. Require
the actual identity/evidence and run a blind shortcut probe before inclusion.

### 4.2 The flagged content was not newly created on the alert day

#### Public briefing

> In the Alpine Ski House tenant on 1 August 2024, Defender raised a "Kekeo" malware
> detection on vnevado-dc.

#### Question

> Was that day the first recorded file creation on this device for the content
> identified by the alert? Answer yes or no and cite the earliest matching creation
> record in the supplied logs.

#### Verified factual answer

**No.** The earliest matching `FileCreated` record in the supplied logs is
**2024-07-09 15:03:17.949569 UTC**, before the August 1 alert.

#### Evidence and derivation

- `DeviceFileEvents#346772`: July 9 creation on the same device.
- `DeviceFileEvents#683830`: August 1 creation on the same device.
- Both identify the same file content by SHA256 and SHA1, rather than merely
  matching the generic filename `test.exe`.
- Derivation A uses the alert's SHA256; derivation B separately follows its
  SHA1. Both return the same earliest observed creation.

#### What this does not establish

- An earlier observation is not a legitimate-use approval.
- This is the earliest recorded file creation in the supplied data, not proof of
  the file's first existence in the real environment.
- The July 9 observation cannot be substituted for missing July 30 activity in
  the separate excluded BP incident.
- This is not a benign or false-positive verdict.

**Analyst value:** test novelty and prior exposure using stable content identity,
without treating recurring malware or old artifacts as benign.

### 4.3 The initial task action did not preserve the requested path

#### Public briefing

> In the Alpine Ski House tenant on 26 June 2024, Defender raised "An anomalous
> scheduled task was created" on vnevado-win10e.

#### Question

> Did the task's initial recorded executable setting contain the complete payload
> path requested when the task was created? Answer yes or no and identify the
> requested path and the recorded executable setting.

#### Verified factual answer

**No.** The task creation request supplied the full payload path, but the initial
recorded action split it into:

```text
Requested executable:
C:\Users\samuelf\OneDrive - (new) AlpineSkiHouse\Desktop\WinATP-Intro-Backdoor.exe

Recorded executable field:
C:\Users\samuelf\OneDrive

Recorded arguments:
- (new) AlpineSkiHouse\Desktop\WinATP-Intro-Backdoor.exe
```

#### Evidence and derivation

- The task name and requested path are discovered from the alert-associated
  creation process, not supplied as hidden gold-query literals.
- `DeviceEvents#113282`: initial `ScheduledTaskCreated` record.
- `DeviceEvents#113286`: early update retaining the same split action.
- `DeviceEvents#114681`: later update at approximately 13:17:15 UTC, with a full
  executable path under the user's Desktop.
- `DeviceProcessEvents#92176`: the payload has a process-creation record at
  approximately 13:17:17 UTC.

Derivation A obtains the request from the source alert's process data.
Derivation B obtains it from the matching raw process-creation record. Both compare
it with the initial task registration and return `false`.

#### Counterevidence and limits

The task was later reconfigured and the payload was observed running. Therefore:

- Do not classify the persistence detection as FP because the initial action was
  malformed.
- Do not infer that the payload never executed.
- Do not claim that this configuration defect alone caused the observed delay;
  task execution results and clock semantics would be needed for that explanation.

**Analyst value:** distinguish intended persistence, recorded configuration, later
repair, and observed execution instead of collapsing them into one outcome.

## 5. Evidence independence and binding limits

### 5.1 Detector echoes are not independent corroboration

The study identified **440 distinct detector-description echoes** matched across
78 alerts in the annotation-selected cohort. One concrete example appears among
the supposed raw corroboration for the Kekeo alert:

```text
DeviceEvents#307461
ActionType = OtherAlertRelatedActivity
AdditionalFields.Description = Defender detected the named threat in the file
```

This row repeats a detector description. It is not independent evidence of
execution, remediation, authorization, or benign behavior.

Consequences for the QA design:

- "It is in a raw table" is not sufficient to establish independent corroboration.
- Two table names do not necessarily mean two independent observations.
- A detector-derived row may support a question about what the detector reported,
  but cannot independently validate the detector's own correctness.
- Track source lineage and the role of each row in the proof, including
  `detector_derived` versus behavior observations.

The file-created record is independent activity evidence; the detector echo
was not used to justify the factual answer or a benign verdict.

### 5.2 Entity matching is not claim-level proof

Exact entity binding is not automatically exact claim binding. A shared ancestor
or System process can connect many unrelated observations. Likewise, control
telemetry can prove an enforcement action without independently proving the
detector's complete interpretation.

The endpoint evidence inventory contains 2,599 non-echo alert-to-row associations
representing **546 distinct rows**: 468 behavior observations and 78
security-control observations. Association counts must not be presented as
independent observation counts or as proof of authorization.

## 6. Validation performed and remaining limitations

### 6.1 Executed source and answer checks

For the study evidence inventory:

- Existence checks covered all **1,137 distinct endpoint/control/context
  source-row references** emitted by the collector.
- Risk/sign-in joins passed exact request/user/IP consistency checks.
- Repeated public-title/date authentication checks for June 12 and June 19 were
  stable; a missing-anchor control raises an error rather than answering "No."
- Input database sizes and modification times remained unchanged.

For all three factual QA candidates:

- Public anchors are only the date, host, and alert title.
- Hidden target `_rid` filters and adjudication fields are absent from answer
  derivations.
- Both local derivations resolve exactly one target.
- Repeated execution returns the same answer and required supporting facts.
- Missing-anchor controls reject the input rather than produce a successful "No."
- Certificate absence or incomplete certificate metadata is not accepted as
  evidence for the signing claim.
- Cited source rows exist in the pinned data.

The [QA audit][qa-audit] and [study validation][study-validation] retain the
programs, checks, evidence references, and results. These checks validate
observations and factual answers, not a benign/FP gold verdict; no such verdict
passed the premise review.

### 6.2 Coverage and interpretation limits

The endpoint collector uses supported flattened alert entities; it is not an
exhaustive replay of every nested/field-only entity or every possible source
join. Separate identity probes address selected non-endpoint families. The study
does not establish that authorization evidence cannot exist anywhere else, or
that no unlabeled tenant event could qualify.

The packet-review dispositions are research assessments, not independent human
adjudications. Missing evidence does not prove benignness; corroborated suspicious
activity does not alone prove malicious intent. The differing review depths and
cohort selection rules prevent a tenant-wide negative-yield estimate.

### 6.3 Validation not performed

- Independent blind solver execution.
- Human assessment of question clarity, usefulness, and benign/FP rationale.
- Gold-query parity in the sanitized SecRL MySQL serving database.
- Measured difficulty or shortcut resistance.
- Balanced evaluation against affirmative and competing outcomes.

No external model calls or production multi-agent generation were performed,
and no production generator or input database was modified.

All three selected QA answers are "No" because this research deliberately sought
negative claims. This is **not a balanced benchmark**; an always-No submission
must not receive evidence-grounded credit. Related variants must remain in one
split lineage. Authentication-outcome and enforcement findings suggest other
task types, but are not additional release-approved questions.

## 7. Conclusion and project disposition

**The study yielded zero verified benign/FP verdicts under the agreed evidence
requirement.** It yielded three locally verified negative factual/configuration
QA candidates, which remain separate from benign/FP classification tasks.

Across the cohorts, the recurring missing premise is an independent explanation
of legitimate behavior or evidence directly refuting the detection:

- Raw activity can corroborate a suspicious operation without establishing
  whether it was authorized.
- Signatures, service provenance, prior artifact presence, and repetitive
  baselines do not establish legitimate use.
- Risk clearance, successful authentication, and recorded protection actions
  answer different questions from whether the original behavior was benign.
- Missing event windows and detector echoes cannot supply the missing premise.

The project therefore **defers FP/BP-targeted investigation and QA at incident,
alert, and event levels**, including further lead investigation or evidence
acquisition. Retain the findings and three factual candidates as research only;
do not automatically promote them, create a negative quota, or reopen the
excluded FP/BP incident dataset.

The explicitly authorized removed-membership diagnostic in Section 3.5 is a
completed, bounded exception. It does not change that general deferral.

Tenant-wide and ten-TP-incident factual QA remain the active design scopes.
The general lessons about source lineage, identity, claim relevance, history,
coverage, and executable validation apply to that work. Raw tenant context and
source labels remain intact.

If explicitly reopened, useful new evidence would be claim-specific
approval/test/deployment context, substantive investigation rationale, or
evidence falsifying a detection/correlation premise. More cleared labels alone
are unlikely to resolve the missing premise.

## 8. Supporting artifacts

| Artifact | Purpose |
|---|---|
| [Study evidence inventory][study-audit] | All 111 alert inventories, 47 family packets, and additional risk/platform evidence |
| [Alert review dispositions][study-dispositions] | Outcomes and evidence references for the 79 reviewed packets |
| [Matched evidence][study-matches] | Identity-bound row associations with separate behavior/control/echo lineage |
| [Study validation][study-validation] | Reference checks, authentication results, risk cardinality, platform baseline and identity probes |
| [Factual QA audit][qa-audit] | Three questions, answers, both derivations, source evidence, limits, and detailed-case dispositions |
| [Factual QA candidates][qa-candidates] | Three local-SQL-verified candidates, explicitly not release accepted |
| [QA verification queries][qa-sql] | Executable DuckDB derivations with public named parameters |
| [Detailed-case interpretations][qa-leads] | Broad benign/FP interpretations and why they were not admitted |
| [Evidence collector][study-code] / [validator][study-validator] | Read-only research programs; depend on the existing local audit helpers |
| [Factual QA verification runner][qa-code] | Read-only runner for the three candidate derivations and controls |
| [Removed-membership audit][membership-audit] | Membership transition counts, overlapping candidate cohorts, and targeted scheduled-task evidence |
| [Historical removed links][membership-links] | All 155 links with status, time bounds, source references, and other current parent incidents |
| [Membership audit program][membership-code] | Read-only source-history reconciliation and targeted evidence checks |

These are local session artifacts rather than committed datasets. Existing
artifact filenames and source references are retained for reproducibility;
consolidating the report does not regenerate or merge the underlying data.

[qa-audit]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/negative-qa-pilot/negative_qa_pilot.json
[qa-candidates]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/negative-qa-pilot/research_qa_candidates.jsonl
[qa-sql]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/negative-qa-pilot/verification_queries.sql
[qa-leads]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/negative-qa-pilot/lead_dispositions.csv
[qa-code]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/benign_fp_qa_pilot.py
[study-audit]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/expanded-negative-audit/expanded_negative_audit.json
[study-dispositions]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/expanded-negative-audit/review_dispositions.csv
[study-matches]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/expanded-negative-audit/matched_raw_evidence.csv
[study-validation]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/expanded-negative-audit/expanded_validation.json
[study-code]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/expanded_negative_audit.py
[study-validator]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/expanded_negative_validation.py
[membership-audit]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/removed-memberships/removed_membership_audit.json
[membership-links]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/removed-memberships/historical_removed_memberships.csv
[membership-code]: ../../.copilot/session-state/8eb9a4db-66e9-4a79-9209-5bcb11ed058a/files/removed_membership_audit.py

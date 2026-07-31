# Excytin entity-email fix — audit & remediation

This directory documents and remediates a data-quality bug in the ExCyTIn
question-generation pipeline where an **account entity's email was synthesized
from its display name** instead of its real UserPrincipalName (UPN).

## The bug

`secgym/utils/utils.py :: process_entity_identifiers()` built the account
`Email` entity as:

```python
final_entities_list.append([type_value, "Email",
    entity_dict["Name"] + "@" + entity_dict['UPNSuffix'], ...])
```

The Microsoft Sentinel *Account* entity `Name` field is provider-dependent and
frequently holds the **display name** (e.g. `"Jordan P"`), not the UPN prefix.
So the synthesized "email" became `Jordan P@vnevado.alpineskihouse.co` — an
address that contains a space, is invalid, and **exists nowhere in the logs**.
The real address (`laylaw@vnevado.alpineskihouse.co`) was present in the very
same entity object under `UserPrincipalName` / `AccountName` + `DomainName`.

This fabricated email then propagated into generated Q/A as answers (graded
scoring targets), contexts, and solutions.

## The fix (pipeline)

`process_entity_identifiers()` now prefers authoritative fields:

1. `UserPrincipalName` if present,
2. else `AccountName` + `@` + (`DomainName` or `UPNSuffix`),
3. else the legacy `Name` + `@` + `UPNSuffix` (fallback only).

The misleading few-shot examples in `qa_gen_prompts.py` (which used
`Megan Bower@vnevado.alpineskihouse.co` as an `Email` value) were also corrected
to a realistic UPN (`meganb@vnevado.alpineskihouse.co`).

## Files

| File | Purpose |
|------|---------|
| `fabricated_email_map.json` | Authoritative map of every fabricated `<DisplayName>@domain` → real UPN, extracted from the incident databases. Includes provenance. |
| `build_map_from_db.py` | Regenerates `fabricated_email_map.json` from the running excytin incident MySQL containers. |
| `audit_qa.py` | Scans QA JSON datasets for fabricated account emails and reports occurrences (answer / context / other). |
| `remediate.py` | Applies `fabricated_email_map.json` to QA JSON or task YAML files (dry-run by default; `--apply` to write). |

## Scope of impact (full excytin audit)

14 distinct fabricated identities across 6 of 8 incidents (34 and 38 clean).
In the source QA (o1 + o3, test + train): 64 scoring-critical answers, plus
~290 context/solution occurrences.

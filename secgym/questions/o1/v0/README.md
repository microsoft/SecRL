# ExCyTIn QA — o1 dataset, **v0** (original, unmodified)

- **Generator model:** OpenAI **o1** (`o1-ga`), config `c42`.
- **Status:** Historical record — this is the raw Q/A exactly as generated. **Do
  not edit.** Kept for provenance and reproducibility.
- **Contents:** 8 incidents × {`test`, `train`} of `incident_<id>_qa_incident_o1-ga_c42.json`.

## Known issue in this version

This version contains the **account-email synthesis bug**: an account entity's
email was built from its *display name* (`Name + "@" + UPNSuffix`) instead of the
real `UserPrincipalName`. As a result some answers/contexts contain fabricated
addresses such as `Jordan P@vnevado.alpineskihouse.co` (the real address is
`laylaw@vnevado.alpineskihouse.co`).

Audit of this version: **64 scoring-critical answers** plus ~290 context/solution
occurrences across 6 of 8 incidents (incidents 34 and 38 are clean).

➡️ For a corrected copy see **`../v1/`**. The pipeline root cause is fixed in
`secgym/utils/utils.py :: process_entity_identifiers()` (see
`secgym/qagen/entity_email_fix/`).

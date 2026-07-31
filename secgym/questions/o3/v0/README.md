# ExCyTIn QA — o3 dataset, **v0** (original, unmodified)

- **Generator model:** OpenAI **o3**, configs `c100` (test) / `c101` (train).
- **Status:** Historical record — raw Q/A exactly as generated. **Do not edit.**
  Kept for provenance and reproducibility.
- **Contents:** 8 incidents × {`test`, `train`}
  (`incident_<id>_qa_incident_o3_c100.json`,
  `incident_<id>_qa_incident_o3_c101_train.json`).

## Known issue in this version

Contains the **account-email synthesis bug**: account emails were built from the
*display name* (`Name + "@" + UPNSuffix`) rather than the real
`UserPrincipalName`, yielding fabricated addresses such as
`Jordan P@vnevado.alpineskihouse.co` (real: `laylaw@vnevado.alpineskihouse.co`).

➡️ For a corrected copy see **`../v1/`**. The pipeline root cause is fixed in
`secgym/utils/utils.py :: process_entity_identifiers()` (see
`secgym/qagen/entity_email_fix/`).

# ExCyTIn QA — Opus 5 `latest_cleaned` dataset

- **Generator model:** Anthropic **`claude-opus-5`**.
- **Purpose:** A corrected regeneration of the ExCyTIn QA that is free of the
  account-email synthesis bug (see `secgym/qagen/entity_email_fix/`). Maps to the
  oss_saber `latest_cleaned_{test,train}_set` benchmark.
- **Contents:** 8 incidents × {`test`, `train`}
  (`incident_<id>_qa_opus5_cleaned.json`), 1017 questions total (599 test / 418
  train).

## How it was generated

1. **Fixed parser:** `process_entity_identifiers()` now emits the real
   `UserPrincipalName` for account Email entities (not `DisplayName@UPNSuffix`).
2. **Fixed graphs:** the account Email entity node values in the alert graphs
   were corrected in place (`secgym/qagen/graph_files_fixed/`), so the QA-gen
   prompts receive the real email. Node IDs/structure are preserved, so paths
   still align with the o3 dataset.
3. **Path mirroring:** each question reuses the exact alert path
   (`start/end_alert`, entities, `shortest_alert_path`) from the o3 (`latest`)
   dataset, so `latest_cleaned` aligns **1:1** with `latest`.
4. **Driver:** `secgym/qagen/entity_email_fix/regenerate_opus5.py`
   (resumable, parallel).

## Verification

- Audit (`entity_email_fix/audit_qa.py`): **0** fabricated emails in answers,
  contexts, or solutions — the graph fix eliminated them at the source, so no
  post-hoc remediation was required.
- All 16 JSON files valid.

## Reproduce

```bash
# 1. patch graphs (already committed as graph_files_fixed/)
python secgym/qagen/entity_email_fix/remediate.py \
    --glob "secgym/qagen/graph_files_fixed/*.graphml" --apply
# 2. regenerate (needs ANTHROPIC_API_KEY; see secgym/myconfig.py)
python secgym/qagen/entity_email_fix/regenerate_opus5.py --workers 8
# 3. audit -> expect 0
python secgym/qagen/entity_email_fix/audit_qa.py --glob "secgym/questions/opus5/**/*.json"
```

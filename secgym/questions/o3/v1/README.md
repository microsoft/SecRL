# ExCyTIn QA — o3 dataset, **v1** (fabricated emails corrected)

- **Generator model:** OpenAI **o3**, configs `c100` (test) / `c101` (train) —
  same generation as `../v0/`.
- **Post-processing:** fabricated account emails deterministically replaced with
  the real UPN. Nothing else was changed.

## What changed vs v0

Account emails built from the display name (e.g.
`Jordan P@vnevado.alpineskihouse.co`) were replaced with the account's real
`UserPrincipalName` (e.g. `laylaw@vnevado.alpineskihouse.co`) using
`secgym/qagen/entity_email_fix/fabricated_email_map.json`.

- **359** email tokens corrected across **22** files (o1 + o3 v1 combined; see
  per-run output).
- Bare display names left unchanged — only `<name>@<domain>` tokens rewritten.
- Post-remediation audit: **0** fabricated emails remain.

## Reproduce

```bash
cd secgym/qagen/entity_email_fix
python remediate.py --glob "../../questions/o3/v1/**/*.json" --apply
python audit_qa.py --glob "../../questions/o3/v1/**/*.json"   # expect 0
```

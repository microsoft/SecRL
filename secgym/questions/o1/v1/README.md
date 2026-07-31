# ExCyTIn QA — o1 dataset, **v1** (fabricated emails corrected)

- **Generator model:** OpenAI **o1** (`o1-ga`), config `c42` — same generation as
  `../v0/`.
- **Post-processing:** fabricated account emails deterministically replaced with
  the real UPN. No questions, answers (other than the corrected email strings),
  contexts, or structure were otherwise changed.

## What changed vs v0

The account-email synthesis bug produced addresses built from the display name
(e.g. `Jordan P@vnevado.alpineskihouse.co`). Every such fabricated address was
replaced with the account's real `UserPrincipalName`
(e.g. `laylaw@vnevado.alpineskihouse.co`), using the authoritative mapping in
`secgym/qagen/entity_email_fix/fabricated_email_map.json`.

- **359** email tokens corrected across **22** files (with-space, no-space, and
  lowercase variants).
- Bare display names (e.g. an answer of `Jordan P`) were intentionally left
  unchanged — only `<name>@<domain>` email tokens were rewritten.
- Post-remediation audit: **0** fabricated emails remain.

## Reproduce

```bash
cd secgym/qagen/entity_email_fix
python remediate.py --glob "../../questions/o1/v1/**/*.json" --apply
python audit_qa.py --glob "../../questions/o1/v1/**/*.json"   # expect 0
```

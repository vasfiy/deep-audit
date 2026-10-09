# deep-audit

A **read-only** web-infrastructure security audit methodology, packaged as a
[Claude Code / Agent skill](https://docs.claude.com). It walks through passive
recon, subdomain mapping, origin discovery, and safe (non-destructive) checks for
common stacks (Odoo, Laravel, status pages, APIs, object storage), with evidence
collection and reporting.

> ⚠️ **Authorized use only.** Run this methodology **only** against systems you own
> or have explicit written permission (scope / rules of engagement) to test.
> Unauthorized scanning and testing is illegal in many jurisdictions. Never go
> outside the agreed scope.

## Design principles

- **Read-only by default** — GET/HEAD/OPTIONS plus tightly-bounded tests only. No
  write operations (POST/restore/duplicate/drop/wake/register). No brute force.
- **Control tests for every finding** — re-run each probe with wrong/empty values
  to avoid false positives (e.g. an unauthenticated enumeration endpoint looking
  like "default password works").
- **Evidence preserved** — copy (`cp`) artifacts, never move; log every action.
- **Transparent reporting** — map → findings (with severity) → fixes → action log
  → remediation plan → scope limits.

## Install

Copy the folder into your skills directory:

```bash
git clone https://github.com/<you>/deep-audit.git ~/.claude/skills/deep-audit
```

Then invoke it from Claude Code with `/deep-audit` (or let it trigger by description).

## Contents

- `SKILL.md` — the methodology (10 sections, in Uzbek).

## License

MIT — see [LICENSE](LICENSE).

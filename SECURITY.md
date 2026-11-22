# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub's "Report a vulnerability"
(Security → Advisories) on this repository, or to the maintainers' security contact. Include:
- the affected version (`insight --version`) and deployment (Docker or local);
- steps to reproduce, or a proof of concept using only documentation addresses and synthetic data;
- the impact as you understand it.

Never include real intelligence, credentials or TLP:AMBER/RED material in a report.

You will get an acknowledgement within 5 working days. Fixes ship through the normal release gates (signed
images, changelog entry). Credit is given unless you prefer otherwise.

## Supported versions

Only the latest release receives fixes. Upgrade using [docs/RUNBOOK.md](docs/RUNBOOK.md) §6.

## Optional infrastructure providers

crt.sh is off by default and receives only a reviewed domain from a current CLEAR report after explicit
approval for each uncached lookup. Its fixed HTTPS endpoint, metadata limits, audit, cache rules and terms
references are documented in [Infrastructure pivots](docs/INFRASTRUCTURE_PIVOTS.md). Public certificate
metadata is context, not a verdict or a blanket grant to redistribute provider data.

## Scope and posture

Insight is a single-operator workbench. By default it listens on loopback only; it can be published behind a TLS
reverse proxy. What it protects against, what it does not, and what to do before exposing it to a network is
documented in [docs/SECURITY.md](docs/SECURITY.md). API keys start with `insk_`: if you find one in a public
place, report it as above so it can be revoked.
Operational incident handling is in [docs/RUNBOOK.md](docs/RUNBOOK.md) §12.

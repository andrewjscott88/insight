# ADR 0013: An instance TLP limit; TLP:RED refused by default

Status: Accepted

## Context
TLP:RED is for named recipients only. The instance is heading for an internet-facing deployment, where a
breach would expose such material beyond the people it was entrusted to. TLP labels in Insight are metadata, not
access control: the operator's session and the API key can read every report. ADR 0009 already raises a
report's label to any more restrictive `TLP:` marking in its text.

## Decision
`INSIGHT_MAX_TLP` (default `AMBER+STRICT`) is the most restrictive label the instance stores. `services.ingest`
refuses a manual submission (workspace or API) whose label **after** ADR 0009's raising is above it, before
anything is stored: a RED marking cannot slip through under an AMBER label, and an existing RED duplicate is not
returned. The default is fail-safe, like ADR 0009's AMBER default. Operators who deliberately keep RED set
`INSIGHT_MAX_TLP=RED`. Curated connectors and the synthetic demo are exempt: their content is public or
synthetic, so a RED label there comes from a public text mentioning RED, not from entrusted material.

## Consequences
By default, RED material never reaches the server. A report that merely *discusses* TLP:RED is refused as well
(ADR 0009's fail-safe raising); the message explains why and asks the analyst to reword the marking. Reports
stored before the limit stay readable; start-up logs their count and the RUNBOOK's deletion procedure applies.
Tests and the browser gate that exercise RED handling opt in explicitly. A per-reader limit (e.g. an API key
capped at GREEN) remains future work.

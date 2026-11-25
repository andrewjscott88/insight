# ADR 0044: Sector and industry Intel Briefs

Status: Accepted (1.0.0)

## Context

Readers need an Intel Brief for the sector they work in, as well as for an actor or technical indicator.
The existing industry threat profiles already use cited catalog mappings and explicit analyst decisions.
The landing page should open with the last 30 days, while retaining the seven-day choice.

## Decision

- Add **Sector / Industry** to Intel Brief search. Both words refer to the existing 15 industry categories;
  no competing taxonomy or new source is introduced. Search uses the category name, scope and source aliases.
  Choosing this type with an empty query lists the categories. All-types search includes sector matches.
- Reuse the industry-profile candidate selection, including visible analyst additions and removals.
  Show up to five cited groups, with groups having recent explicit report links first and names breaking ties.
  This is historical background rather than an attack ranking. Methods are documented for those groups,
  without asserting that a given method was used against the chosen sector.
- Read at most the latest 500 current reports inside the selected reporting window and caller's TLP limit.
  A report matches if the existing reviewed industry phrases occur in its title or text, or if an analyst
  explicitly linked it to a group with a visible target mapping. These reasons are displayed separately.
  A literal mention establishes relevance only, not attribution or a confirmed attack. It creates no link.
- Return metadata only, never publisher body text or excerpts. Keep up to 100 matching report references
  and show the latest five. Deduplicate reports that match both routes. Disclose scan and result limits.
- Keep the strictest label of contributing reports, group links, target mappings and removal decisions.
  Hidden decisions and reports are absent. The scan-limit signal also retains contributing labels.
  Future-dated and superseded reports are excluded. Dates mean when reports were added, not attack dates.
- Default new workspace pages and focused briefs to 30 days. General HTTP API defaults stay unchanged.
  Threat Hunt shares the same categories through [ADR 0045](0045-sector-threat-hunt-guides.md).

No schema migration, network lookup, model call, dependency, new HTTP route or write is needed.

## Validation

Focused regressions cover sector aliases, no-query browsing, default and changed periods, direct sector
mentions versus explicit group links, date boundaries, restricted reports and mappings, publisher-body
exclusion, target removals, and visible scan/result caps. Full release checks remain due when the workspace
iteration is frozen.

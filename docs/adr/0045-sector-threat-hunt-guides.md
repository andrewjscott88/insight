# ADR 0045: Sector and industry threat hunt guides

Status: Accepted (1.0.0)

## Context

The sector focus in Intel Brief should also start a Threat Hunt guide. Readers need to choose an industry,
review a sourced plan, download Markdown or PDF, and save a draft package from the same selection.

## Decision

- Share the exact **Sector / Industry** label in both focus selectors. Use the existing 15 categories,
  names, scopes and source aliases, with blank-query browsing. The API kind is `industry` and its reference
  is the canonical category key. No second taxonomy or new external source is introduced.
- Reuse visible industry-profile candidates and analyst additions/removals. Show up to five source-backed
  groups, ordered by recent explicit report links, then name and ID. This is background selection, not an
  attack ranking. Cite the mapping source and reference without copying private analyst notes.
- Share the sector report selector with Intel Brief: inspect at most the latest 500 current, visible
  reports added in the last 30 days, excluding future dates. Retain at most 100 matching references and
  use the latest 20 in the guide. State scan and result limits. This fixed hunt window is independent of
  the Intel Brief period toggle; report dates are not attack dates.
- Keep direct sector-phrase matches separate from explicit links to a group in the full visible sector
  profile. Reports linked to a group outside the five shown may still qualify; state that scope. A report
  matching both routes is attached once. Neither route attributes its indicators to an actor or proves
  an attack on the sector.
- Use tagged techniques on the included reports first, then catalog techniques from the displayed groups.
  Preserve deterministic order and the existing 12-technique display/package cap. A method recorded for
  a group is not evidence of its use against the sector. Reuse the fixed planning guidance and source links.
- Reuse the reviewed-indicator sweep, including safe, warning-list and expired-verdict exclusions and the
  100-indicator cap. Preserve the strictest contributing label, including mappings, removals, report links,
  excluded verdicts and limit metadata. Hidden evidence stays absent for lower-ceiling readers.
- Use the existing guide preview/download routes and audited draft-save service. Markdown/PDF retain
  metadata and guidance, never publisher bodies or analyst notes. Saving rebuilds current evidence and
  creates a draft with the same structured evidence bounds. A sector package has no single actor reference;
  publishing remains a separate operator action.

No dependency, migration, new route, external lookup, model call or telemetry execution is needed.
Existing actor-attributed guide and package audit entries cover the actions.

## Validation

Focused service, real-middleware API and NiceGUI regressions cover category browsing and aliases, guide
building, both downloads, audited draft saving, report match reasons, current/date boundaries, target
removals, hidden AMBER evidence and retained aggregate labels. Full QA remains due when the local workspace
iteration is frozen for GitHub review.

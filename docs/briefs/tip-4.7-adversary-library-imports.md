# Brief: TIP 4.7 Adversary library imports

Required for 1.0. ADR number reserved: **0038**. Read [AGENTS.md](../../AGENTS.md) first.

## Goal

Make the threat library cover what adversaries *use* as well as who they are: MITRE ATT&CK software (malware
and tools) as first-class items analysts can link reports to, MISP threat-actor galaxy aliases so more reports
are recognised as naming a group, an activity timeline per actor, and ATT&CK Navigator layers for software.

## What already exists (reuse it; do not rebuild it)

- **The library pipeline** ([ADR 0025](../adr/0025-threat-guides.md), [THREAT_GUIDES.md](../THREAT_GUIDES.md)):
  `threat_library_build.py` turns a pinned ATT&CK Enterprise bundle and the MISP galaxy `threat-actor` cluster
  into Insight's library (pure functions, no network). `scripts/update_actors.py` builds the bundled edition
  (`src/insight/data/actors.json`); `insight threat-library-sync` fetches the full edition from pinned URLs and
  checks each file's SHA-256. MISP is used today only for industry labels, with an exact-name rule.
- **Groups already list their software IDs**, and the library keeps each software's name and type.
- **Navigator layers** exist per actor (`GET /api/actors/{ref}/navigator`) and for the landscape
  (`GET /api/attack/navigator`).
- **Analyst data:** actors, campaigns, report links to groups (`ActorDocument`), threat links
  (`ThreatLink`), threat guides (`threat_guide.py`, `threat_guide_markdown.py`), the Threat groups panel in
  Investigate (`ui/threats.py` and friends), and stable STIX IDs for TAXII ([ADR 0026](../adr/0026-taxii-server.md)).

## Build

1. **Software in the library.** Every ATT&CK `malware` and `tool`: ID (`S0154`), name, type, aliases, a short
   description, platforms, the techniques it uses and the groups that use it, in both editions (the bundled
   one trimmed like groups). If the library format changes, bump `insight-threat-library-1` and keep reading
   the old format.
2. **MISP aliases for groups.** Add the synonyms of the MISP `threat-actor` entry whose name exactly matches a
   group's name or ATT&CK alias, only when that name points to one group (the rule industries already use).
   Record where each alias came from. Never merge groups, and never use MISP's "similar" links. Aliases must
   then work wherever group names are matched (search, reports that name a group, requirement criteria).
3. **Software pages and links.** `GET /api/software` (search) and `GET /api/software/{id}`; software in the
   workspace (a Software tab in Investigate, or inside Threat groups). An analyst can link a report to a piece
   of software, as an audited decision with a TLP label, like linking a report to a group. Reports that only
   *name* the software (name or alias, whole words) are shown as candidates; nothing is linked automatically.
4. **STIX.** Linked software goes out as `malware` (`is_family: true`) or `tool`, with `uses` relationships from
   the analyst's actors and campaigns where they are linked, in the STIX export and the Reviewed indicators
   TAXII collection, under each link's label, with stable IDs as for techniques.
5. **Activity timeline per actor.** Dated events within the reader's TLP limit: ATT&CK campaigns (first and last
   seen), the analyst's campaigns, reports linked to or naming the group (date added), hunt packages for the
   group (published, retired) and sightings of indicators from its linked reports. `GET
   /api/actors/{ref}/timeline`, and a timeline section in the threat guide and its Markdown and JSON exports.
6. **Navigator.** A layer per software (`GET /api/software/{id}/navigator`). In the actor layer, mark the
   techniques that come only from the group's software, in a comment, without changing existing scores.

## Not in scope

Sources other than the pinned ATT&CK release and the MISP galaxy; attribution inferred from indicators,
techniques or co-occurrence (never); automatic links of any kind.

## Constraints

- Licences: keep the ATT&CK terms notice; MISP galaxy data is dual-licensed CC0-1.0 or BSD-2-Clause
  (`MISP_LICENCE` in `threat_library_build.py`). Update the pins and the library section of THREAT_GUIDES.md.
- Catalog data is TLP:CLEAR; analyst links carry their own labels; every new read filters by the caller's limit.
- Keep the bundled edition small: check the tests that cover `actors.json` before adding fields to it.

## Suggested parts

1. Library: software and MISP aliases (no database change).
2. Software API, links, workspace and STIX (a migration if links need a table; follow `ActorDocument`).
3. Timeline and Navigator layers.

## Done when

Every item in the AGENTS.md checklist is met for each part; THREAT_GUIDES.md, API.md, API_GUIDE.md, TAXII.md
(if TAXII output changes), CHANGELOG.md, README.md, ROADMAP.md and ROADMAP-TIP.md are updated; and ADR 0038
records the decisions.

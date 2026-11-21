# ADR 0025: Industry threat profiles and actor threat guides from a sourced, pinned threat-group library

Status: accepted (unreleased)

## Context
Analysts are asked two questions again and again: "who targets our industry?" and "what do we do about group X?".
Premium platforms answer both with curated adversary profiles written by in-house analysts (premium-TIP plan,
`docs/ROADMAP-TIP.md`, item 2.10). Insight has no analyst team, so it cannot write such profiles, and it must not
pretend to: the README says it never infers attribution, and extraction is precision-first (ADR 0007).

What Insight can do honestly is put together what public, licensable catalogs say, with the analyst's own reports
and decisions, and say exactly where each statement comes from. Constraints:

- **No fabricated mappings.** ATT&CK has no structured "industries targeted" field; its group descriptions say
  it in prose. MISP's threat-actor galaxy has sector labels for some groups, often under different names.
- **Offline and reproducible.** Insight works without internet access, goes online only when asked (ADR 0018),
  and its tests run offline.
- **Small repository.** The full ATT&CK bundle is about 55 MB.
- **TLP everywhere** (ADR 0009, 0013, 0014), including exports.
- TIP 2.5 (actors) and 2.7 (rules) were not built yet; a guide needs a minimum of both.

## Decision
1. **A threat-group library built from two pinned public sources.** `scripts/update_actors.py` builds
   `src/insight/data/actors.json` (about 600 KB) from MITRE ATT&CK Enterprise 20.1 and the MISP galaxy
   threat-actor cluster (version 359), each fetched from a URL naming an exact commit and checked against a
   pinned SHA-256 (`insight.threat_library_sync.PINNED`). It holds every current ATT&CK group with aliases,
   campaigns, techniques, software, and for each technique its mitigations and detection strategies (data
   components and log sources). Descriptions are shortened and procedure examples and analytics left out.
   `insight threat-library-sync` (or `make threat-library-sync`) downloads the same two pinned files through the
   connector download path (HTTPS, curated host allowlist, no redirects, size limits of 80 MB and 8 MB) and
   writes a full edition to `<INSIGHT_DATA_DIR>/threat-library.json`, used instead when present and valid.
2. **Every industry claim names its source.** An ATT&CK claim exists only when a sentence of the group's
   ATT&CK description says the group targeted that industry; the sentence is kept as evidence with its
   citations, and a test checks it is in the pinned description. Sentences that name a sponsor ("on behalf of
   the ... government") do not count, and reviewed false matches are listed in `REVIEWED_EXCLUSIONS`. A MISP
   claim exists only when a MISP entry has *exactly* the name of the group or an alias and that name points to
   one group; MISP "similar" links are not followed. Labels too vague to map ("Private sector") are dropped.
   The fixed list of 15 industries and the words that count for each live in `insight.industries`.
3. **The analyst corrects the library, with a citation.** An analyst may add an industry (with an HTTPS citation
   or a report) or remove one (with a reason). Decisions are rows with their own TLP label, audited, and
   override the library for that instance only.
4. **The top ten is ranked, not scored.** Candidates for an industry are the groups a source names for it.
   They are ordered by how many of the analyst's current, visible reports *name* the group (name or alias,
   whole words; a one-word name such as `Tick` only as written), then by the group's latest public campaign activity in
   ATT&CK, then by its number of techniques. The page states this order and shows the evidence for each group.
   Naming is not attribution: nothing is inferred from indicators, techniques or co-occurrence, and only
   reports an analyst *links* to a group feed its techniques into the guide.
5. **Actors and rules at their minimum (TIP 2.5 and 2.7).** `threat_actors` holds actors the analyst creates
   (optionally the same as an ATT&CK group); `actor_documents` holds report links. `detection_rules` stores YARA
   and Sigma rules as text with source, licence and SHA-256, linked to groups, techniques or reports through
   `rule_links`. Insight never compiles or runs a rule; a light shape check only catches pasting mistakes.
6. **Hunt material is labelled as a starting point.** Each technique gets a hypothesis built from ATT&CK's
   detection strategies and data components (falling back to the parent technique), with log sources, ranked
   by recent reports, then linked reports, then ATT&CK. The guide says these are starting hypotheses, not
   detections. The indicator sweep list holds accepted indicators from reports an analyst **linked** to the
   group, without private or documentation addresses, benign verdicts or expired verdicts. Reports that only
   *name* the group add their indicators only on explicit request (`linked_only=false`, `--include-named`):
   a sweep CSV is the artifact most likely to end up in a SIEM or blocklist, and a name-drop ("unlike APT29
   ...") is not evidence about indicators. Exports record which choice was made. A hunt record keeps, per
   technique, what was checked, over which dates, and the result.
7. **TLP on guides and exports.** A guide's label is the most restrictive label of anything in it, counted
   items included: every sweep row (whose label also covers the indicator's verdict), every listed or counted
   report, and the reports behind the hypotheses' recent-report counts. Every read
   takes the caller's limit; exports take an optional stricter `max_tlp`; labelled writes are capped by the
   instance limit too. JSON, Markdown, Navigator and CSV exports carry the label (Markdown first and last,
   CSV on its first line) and are audited (`actor.guide`). CLI files are created 0600 and never overwritten.
8. **Retention.** Deleting a report removes its group links and rule links, and analyst industry claims that
   rested only on it; claims that also cite a URL keep the URL.
9. **No AI in the loop.** Nothing calls a model; an opt-in, reviewed model could later suggest links
   (`docs/LLM_EXTENSION.md`).

## Consequences
- An analyst can pick an industry, see up to ten groups with the evidence for each, open a guide with aliases,
  industries, techniques (and a Navigator layer), software, mitigations, their own reports, sources and the TLP,
  then plan and record a hunt with linked rules and an indicator sweep list.
- Coverage is limited by the sources: ATT&CK describes about 180 groups, and many descriptions name no industry,
  so some groups are missing from industries they target. The page says so, and analysts can add claims.
- The industry vocabulary is Insight's own; a new source or a change to the words is a reviewed code change.
- Moving to a new ATT&CK or MISP release means updating `PINNED`, rerunning `scripts/update_actors.py` and
  `scripts/update_attack.py`, and reading the diff of claims; the tests check every quoted sentence.
- Seven new tables (migration `0014_threat_guides`, reversible); no change to existing tables.

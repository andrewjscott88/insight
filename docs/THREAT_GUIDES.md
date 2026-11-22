# Industry threats and threat guides

Insight's **Investigate › Threat groups** tab answers two questions: *which groups target my industry?* and *what do I do
about this group?* It is TIP roadmap item 2.10 ([ADR 0025](adr/0025-threat-guides.md)); it also brings the
minimum of item 2.5 (actors you track) and item 2.7 (YARA and Sigma rules as linked artifacts).

Insight has no analyst team writing adversary profiles. It puts together what two public catalogs say, your own
reports and your own decisions, and shows **where every statement comes from**. Read the limits at the end.

## Using it

1. Open **Investigate › Threat groups** and pick an industry (15 fixed industries; `insight industries` lists them).
2. You see up to ten groups. For each: its names, how many of your reports name it in the last 90 days, its
   latest public activity, its number of ATT&CK techniques, and under **Why it is listed** the evidence: the
   sentence ATT&CK wrote, or the MISP galaxy sector label, with a link to the source.
3. **Open guide** shows the threat guide. **Find any group by name** opens any group in the library;
   **Track your own actor** creates one that is not in ATT&CK (or your own name for one).
4. In a report, **Threat groups** lets you link the report to a group. Only linked reports add techniques and
   indicators to a guide; reports that merely *name* a group are listed separately as "names it".

### The order of the top ten

Candidates are the groups a source names for the industry (plus your additions, minus your removals). They are
sorted by:

1. how many of your current reports, within your TLP limit, name the group (its name or an alias, as whole
   words; a one-word name such as `Tick` only as written) in the period;
2. then the most recent `last seen` date of its ATT&CK campaigns;
3. then how many ATT&CK techniques it has.

It is an order, not a likelihood score. Naming is not attribution: a report that says "unlike APT29, this actor
..." counts as naming APT29. Insight never decides that a group is behind activity from indicators, techniques
or co-occurrence.

## Track actors and campaigns

Open **Industry threats → Actors and campaigns you track**. Use **New campaign** to record a campaign
name, aliases, description and TLP. **Track your own actor** creates an actor. Search for the record by
name and open it. Choose **Report**, **Indicator** or **Technique**, search by title, value or technique
ID, set the link’s sharing label and select the matching item. Use **Remove link** to retract a decision.
A shared name, indicator or technique between two reports creates no link.

Each link inherits the strictest label of the record, target and analyst’s chosen link label. An indicator
is visible only while a report within the reader’s limit mentions it. The label on a saved link can be
raised by saving it again. A more restricted link stays out of the lists and guides of limited readers.
A report belongs to a specific revision. Deleting a report removes its links. Deleting the last report
that mentions an indicator also removes links to that indicator.

STIX exports can carry local actors, campaigns and links for targets already selected for export.
Each relationship carries its own sharing label. See the [STIX export guide](IOC_EXPORT.md#stix-21-export).

## What a guide contains

| Section | Source |
| --- | --- |
| Names, description | ATT&CK group (aliases from ATT&CK; MISP names are not merged) |
| Who it targets | Industry claims with evidence (below); countries from MISP `cfr-suspected-victims`; latest ATT&CK campaign |
| How it works | ATT&CK techniques by tactic, plus techniques tagged in reports **you linked** (ADR 0019); download as an ATT&CK Navigator layer |
| Tools and malware | ATT&CK software the group uses |
| Ways to defend | ATT&CK mitigations for its techniques |
| Your reports | Linked reports and reports that name the group (up to 50), within your TLP limit |
| Hunt plan | One starting hypothesis per technique, from ATT&CK detection strategies and data components, with log sources |
| Indicators to search for | The sweep list (below) |
| Detection rules | YARA, Sigma, Suricata and Snort rules linked to the group, its techniques or its reports |
| Hunt records | What was checked for each hypothesis, over which dates, with what result (kept as they are; see below) |
| Sources | Library edition, pinned versions and SHA-256, ATT&CK references, the MITRE notice |

Downloads: the guide as Markdown or JSON (`insight-threat-guide-1`), the Navigator layer (format 4.5) and the
sweep list as CSV or JSON (`insight-sweep-v1`). The API equivalents are in [API.md](API.md#industry-threats-and-threat-guides).

### Industry claims: how they are sourced

* **MITRE ATT&CK.** ATT&CK has no structured industry field. A claim exists only when one sentence of the
  group's ATT&CK description both names an industry (a reviewed word list in `insight.industries`) and says the
  group targeted, attacked or compromised someone. Phrases naming a sponsor ("on behalf of the ... government")
  are removed first. The sentence is kept as evidence with ATT&CK's citations, and a test checks that every
  quoted sentence is in the pinned ATT&CK release. Matches a person read and rejected are in
  `REVIEWED_EXCLUSIONS` (`insight.threat_library_build`). Every claim in the bundled edition was read against its
  sentence before release; the word list was tightened where it misread one ("social engineering" is not the
  engineering industry, "industrial verticals" means any industry, aviation is transport and the "gaming
  industry" is video games), and those cases are regression tests.
* **MISP galaxy.** The `cfr-target-category` and `targeted-sector` labels of the MISP threat-actor entry whose
  name is *exactly* the group's name or one of its ATT&CK aliases, when that name points to only one group.
  MISP's "similar" links are not followed. Vague labels ("Private sector") are dropped.
* **You.** Add an industry with an HTTPS citation or a report you can see, or remove one with a reason. Your
  decisions carry a TLP label, are audited (`actor.industry`) and apply to your instance only.

### Hunt hypotheses

Each hypothesis says: *if this group is active here, it may use technique X; look in these data components and
log sources*. It comes from ATT&CK's detection strategies for the technique (or for its parent technique, which
the guide says). They are **starting hypotheses**, not detections: check each against your own data. They are
ordered by techniques in your recent reports, then in reports you linked, then the rest of ATT&CK.

### Indicator sweep list

Accepted IPs, domains, URLs and hashes from reports **linked** to the group. Reports that only *name* the group
are listed in the guide but add nothing to the sweep list unless you ask: `linked_only=false` in the API,
`--include-named` on the command line, or **Download the sweep list with reports that only name it** in the
guide. Rows from such reports say `via: named`. Every export records which choice was made (`linked_only` in the
JSON and the audit event, the CSV's first line, a sentence in the Markdown).

Indicators flagged as private, reserved or documentation values, indicators with a `benign` verdict and
verdicts past their `valid until` date are left out. Every row says which report it came from. It is a list of
things to search for, not a list of things the group used.

### Rules

Open **Detection rules** in a report to attach a saved rule or add new YARA, Sigma, Suricata or Snort text. You can also
add a rule from a group guide. The guide includes rules attached to that group, its techniques, and reports
explicitly linked to the group. Insight displays the text without running it.

Use `insight rule-add FILE --kind sigma --link G0016 --link T1059.001` to import a local file.
Additional links accept `document:REPORT_ID`, `cve:CVE-2024-1234`, or `"malware:Example Family"`.
An analyst supplies the CVE and family associations. They carry the rule’s sharing label. CVEs are
normalized to uppercase. Family labels accept up to 36 ASCII letters, digits, spaces, dots, underscores
and hyphens, and are stored lowercase.

**Download rule and manifest** saves a ZIP containing `rule.yar` or `rule.yml` and `manifest.json`.
Keep the two files together. The manifest records the rule’s name, source URL, licence, TLP label and
SHA-256 of the enclosed UTF-8 file (CRLF is converted to LF). Report and actor links stay in Insight.
Check the licence and sharing label before sending the file to another team.

## From a guide to a hunt package

A guide is the background; a **hunt package** is what you hand a hunt tool ([ADR 0034](adr/0034-hunt-packages.md)):
one hypothesis, with the ATT&CK techniques, indicators and rules that test it. Make one in **Share → Hunt
packages**, or with **Add to hunt package** in the reader or the indicator explorer, then publish it to the
*Hunt packages* TAXII collection. Hunt records stay as they are, but get no new features: the hunt tool records
what it ran and found, and reports sightings back.

## TLP

* Library groups are public catalog data: TLP:CLEAR.
* Actors, links, industry decisions, rules and hunts carry their own labels. A reader (API key, CLI
  `--max-tlp`) sees only what is within its limit, and a write is refused above the caller's or the instance
  limit (`INSIGHT_MAX_TLP`).
* A guide is labelled with the most restrictive label of anything in it, at most the reader's limit. That
  includes every sweep row (a row takes the label of its reports *and* of the verdict on the indicator, which
  can be stricter) and the reports behind a hypothesis's "in N of your reports" count. Exports may
  be made at a lower limit (`max_tlp=GREEN`) to share; anything above is left out, not redacted in place.
* A rule's listed report and actor links are limited to visible targets. The exported rule and guide carry
  the highest label of those references. Industry decisions inherit their cited report and actor labels.
  Hunt records inherit their actor's label. Profiles include the labels of counted reports and candidates.
* Guide downloads respect the instance limit and any stricter requested limit. Metadata-only publisher reports
  can contribute a name match, title and report reference. Their publisher text stays in the workspace.
* JSON exports carry `tlp`; Markdown has the label first and last; the Navigator layer has it in its name,
  description and metadata; CSV starts with a `# TLP:` line. Every export is audited as `actor.guide`.

## The threat-group library

| Edition | Where | What |
| --- | --- | --- |
| bundled | `src/insight/data/actors.json` (about 600 KB) | Every current ATT&CK Enterprise group with aliases, campaigns, techniques, software, industry claims; per technique its mitigations and detection strategies. Shortened descriptions; no procedure examples or analytics |
| full | `<INSIGHT_DATA_DIR>/threat-library.json` | The same, with whole descriptions, procedure examples, ATT&CK analytics and every reference. Written by `insight threat-library-sync`; used instead of the bundled one when present and valid |

Both are built from the same pinned releases (`insight.threat_library_sync.PINNED`):

* MITRE ATT&CK Enterprise **20.1**, `attack-stix-data` commit `a8db2f52eb933c9c99060c123e088b3326d3a607`;
* MISP galaxy `threat-actor.json` **version 359**, commit `6d78ff22dd1986ffd1a74bd720e635991a52e91a`.

The sync downloads exactly those two files over HTTPS from `raw.githubusercontent.com` (on the connector
allowlist, no redirects, at most 80 MB and 8 MB), checks each SHA-256 before parsing, and replaces the file
atomically. It runs only when you ask: [RUNBOOK](RUNBOOK.md#threat-library) explains it. Updating the pinned
versions is a code change (`scripts/update_actors.py`, then review the diff of claims).

Attribution and licences are in [NOTICE](../NOTICE): MITRE ATT&CK under MITRE's terms of use; the MISP galaxy
under CC0-1.0.

## Command line

```sh
insight industries                                   # the industries and how many groups each has
insight threat-profile healthcare --days 90          # the top ten, with evidence
insight threat-guide G0016 apt29.md                  # also --format json|navigator|sweep-csv|sweep-json
insight threat-guide G0016 apt29-green.md --max-tlp GREEN
insight threat-guide G0016 apt29-sweep.csv --format sweep-csv --include-named   # also reports naming it
insight rule-add encoded-powershell.yml --kind sigma --name 'Encoded PowerShell' --link G0016 --link T1059.001 \
  --licence DRL-1.1 --source-url https://github.com/SigmaHQ/sigma --tlp CLEAR
insight threat-library-sync                          # make threat-library-sync with Docker
```

Files are created owner-only (0600) and never overwritten; every export and change is audited as `cli`.

## Limits

* **Coverage follows the sources.** ATT&CK describes about 180 groups; many descriptions name no industry, and
  MISP labels exist for only some groups. A group missing from an industry may simply not be described that way.
  The top ten is "the groups our sources name", not "the groups that target you". Add claims you can cite.
* **Word lists can miss or mismatch.** The industry patterns are precision-first and reviewed, but prose is
  prose: read the quoted sentence before relying on a claim, and remove wrong ones with a reason.
* **No vendor intelligence.** No CrowdStrike, Mandiant, Recorded Future or Microsoft data and no closed-source
  attribution. Vendor names for groups appear only where ATT&CK lists them as aliases.
* **Naming is counted, not attribution.** The mention count shows what your reports discuss.
* **Hypotheses are generic.** They come from ATT&CK detection strategies, not from your environment.
* **Rules are not validated or run.** Test them in your own tooling.
* **Only Enterprise ATT&CK.** Mobile and ICS groups are not included.

## Activity timeline and software layers (TIP 4.7, part 3)

The guide's **Activity timeline** uses the same reader-filtered events as its JSON and Markdown downloads.
Dates have explicit meanings: ATT&CK campaign first/last activity; the date a current report entered Insight;
the date an analyst linked a campaign; the package's latest publication or retirement; and an indicator's
reported first/last sighting. A report that only names a group is labelled as a mention, not attribution.
Sightings require an accepted indicator in a current, explicitly linked report. They do not prove the actor
caused the activity. No report excerpts are copied into the timeline.

Use **Link a campaign** in the guide to record evidence for an association. Nothing associates campaigns
from shared reports, indicators, software or techniques. The link label includes the actor, campaign and note
markings. The campaign keeps that label after unlinking. Hidden actors, campaigns and links appear missing.
Group references are exact: catalog groups and separately tracked analyst actors do not silently merge.

The API defaults to ten years and 100 events; `days` accepts 1–36,500 and `limit` accepts 1–200. Results are
newest first with deterministic ties, within the inclusive UTC period. Missing or invalid source dates are
omitted; they are never replaced with today. Report collection is bounded to 200 current linked reports and
50 named reports from the newest 5,000 visible reports. Campaign and package scans stop at 201; sighting
support stops at 5,000 accepted report/indicator associations and sightings at 201. `truncated` means a visible
source or output cap was reached. The timeline label includes every in-period event that influences this
flag, even if the output limit omits it. If a source scan is capped, the flag is conservatively marked at the
reader ceiling (RED for an unlimited reader). The guide label includes its timeline. Hidden events never
influence a limited reader's counts or flags.

Hunt packages retain only the latest publication timestamp and the current retirement timestamp. Republished
packages therefore do not show earlier cycles. This view is not a complete activity or audit history.

`GET /api/software/{software_id}/navigator` exports Navigator layer format 4.5 with explicit ATT&CK software
techniques, source attribution and TLP:CLEAR. Legacy libraries with no software technique context return an
empty layer. The actor layer keeps every existing direct-group/report score. Techniques available only through
catalog group/software links or visible explicit analyst software links have score zero and an explanatory
comment. They never become direct group techniques, change hunt hypotheses or infer attribution.

# Executive brief: behavior and evidence

The landing page helps a reader decide what deserves attention in the intelligence already collected by
Insight. It serves both general readers who need an explanation and IT readers who need the supporting
report, vulnerability identifier or product name. The workspace keeps the **Insight** name and symbol and
uses **Cyber Threat Intelligence Platform** as its tagline. The previous **Collect. Connect. Understand.**
line is removed.

## What the brief answers

The default workspace view covers 30 days, with a seven-day option. There is no separate last-24-hour receipt card or
attention highlight. The `recent_reports` API field remains as compatibility metadata. The brief
explains known exploitation, repeated reporting, serious weaknesses and matches to the operator's watch
terms when those facts exist. Each highlight combines a short explanation, a conditional next step and
links to available, visible evidence. **Exploited now** and **Most severe** remain available below the
summary under **Vulnerabilities to watch**. The separate watch-term, repeated-indicator and vendor detail
panels are not shown on the landing page.

The landing section is **Intel Brief**, with the main heading **Intel brief** and the 7- or 30-day period
chosen beside it ([ADR 0020](adr/0020-threat-landscape.md),
[ADR 0041](adr/0041-guided-threat-hunt-workspace.md)). Its **Executive summary** shows up to three short,
fact-based takeaways: known attacks and affected products, a leading threat trend or critical severity,
and a next step. One short note explains the limits of the collection. Sparse evidence produces fewer
takeaways, without filler or unsupported claims. The summary spans the page; the context sidebar and
**About this brief** expansion are removed. Report/source counts, the UTC reference time and coverage notes
remain part of the API data contract. **What needs attention** contains the highlights and their **Next step**
and **View evidence** controls. **Trending threats** follows, then **Vulnerabilities to watch** with the two
vulnerability sections. The separate **What attackers are doing** section and the four bottom inventory
counters are removed. **Sync all sources** sits beside the main heading. The toolbar's **Import Intel**
button opens the existing intelligence import dialog. Evidence controls reveal
the supporting report or relevant workspace tab on both phones and larger screens; scrolling honors the
reader's reduced-motion preference.

## Focus on a subject

The top search bar looks across **All focus types** by default. It shares nine choices with Threat Hunt:
**Sector / Industry**,
threat type, threat actor, software flaw (CVE), report or advisory, exploit activity, malware or tool,
indicator and campaign. Choose a type to narrow the search, or enter a sector, name, alias, identifier, report title
or source and select **Search**. Select **Choose a match**, then **Show brief**.

The focused view shows the selected subject and period, its sharing label, up to three concise takeaways,
up to two limits or context notes, and at most five supporting reports. Report buttons open the evidence
in Triage. For a focused brief, the 7/30-day window uses the dates current reports were added to Insight.
Catalog information and saved background facts are identified as background, not evidence of activity
during that window. Changing the query or type clears the previous focus; **All intelligence** returns to
the general overview.

Actor briefs also show compact profile sections and catalog source links when available: who the group is,
reported targets, methods in plain English, what to watch for, tools, aliases and catalog update context.
Methods and watch guidance retain their technique references. Missing fields do not produce empty profile
headings. A separate coverage section states when no explicitly linked reports were added in the selected
period; this does not mean the actor has no known background. Industry mappings still respect analyst
additions, removals and sharing labels. Catalog update dates are not last-seen dates.

Sector briefs use the existing 15 industry categories and their source aliases. Select **Sector / Industry**
with an empty query to browse them. The brief shows cited groups known to target that sector, their documented
methods and fixed watch guidance. These are background facts, not a ranking of current attacks. Up to five
groups are shown, with recent explicitly linked reports first and names breaking ties.

Sector evidence has two separate routes: reports that mention a reviewed sector phrase, and reports explicitly
linked to a group with a visible target mapping. The report buttons state why they matched. Mentions establish
relevance only; group links do not prove that a report describes an attack on this sector. Neither route creates
new links or attribution. A report matching both appears once. At most the latest 500 visible current reports
in the period are scanned, with up to 100 matching references retained and five displayed. Scan and result caps
are disclosed. Publisher body text is inspected locally but never copied into the brief. Target additions,
removals, links and reports preserve their sharing labels. [ADR 0044](adr/0044-sector-intel-briefs.md)

Focused briefs review at most 100 matching current reports and show the latest five, with a note when the
review cap is reached. Actor, software and campaign report evidence follows explicit visible links;
a shared name, method or indicator does not establish attribution.

An empty all-types search shows a hint instead of loading every choice; sector and threat-type choices can
be browsed with no query. All-types results show at most
five matches per type; a single type shows up to 50. The interface explains these limits so the reader can
narrow the query. Choices and brief content respect the caller's and instance's sharing limits. The brief
uses saved intelligence and fixed wording; it is not an AI chat and performs no new source fetch.

The focused view is separate from the general API and briefing export. It does not replace their full
summaries or expose a general-brief download as though it described the chosen subject.

## Details retained outside the overview

This is a presentation change. API responses and the downloadable Markdown briefing retain their full
summaries. The brief API also retains all five detail sections and its coverage metadata; the landscape
API retains its tactic data. The Markdown briefing still includes attacker tactics and all five detail
sections. Removing these panels does not delete reports, indicators, watch terms or other stored intelligence.

Sharing badges explain the audience, retaining the standard token: **Public · TLP:CLEAR** for public
disclosure, or a restricted audience for other levels. Copyright and source terms still apply to public
material. Restricted briefs retain their warning. This wording changes no stored label, access limit or
publisher reuse rule. Long labels wrap on phones.

Next steps depend on the reader's situation: check whether the product is used, read the relevant advisory,
then consider the applicable fix or mitigation. Insight does not know the operator's asset inventory,
exposure or patch status. A mentioned product is not automatically an affected asset, and an extracted
indicator is not automatically malicious.

## Where the words come from

The brief is deterministic. It uses stored reports, their extracted indicators, configured watch terms and
the locally stored public CISA Known Exploited Vulnerabilities (KEV) catalogue. It does not send report text
to an AI provider, request a model completion, fetch full articles or start a source sync when rendered.
Manual and scheduled source syncs remain separate, existing operations.

"Collected reports" includes authorized reports pasted by the operator as well as reports imported by
connectors. This is a summary of evidence stored in this workspace, not a claim to cover every public feed.
Synthetic demo reports are excluded. Source counts use connector keys where present, otherwise source names
normalized for case and whitespace. Two source identities must not be assumed to be two independent
investigations.

Database reads remain in `src/insight/services/brief.py`. `src/insight/brief_facts.py` applies the date and
counting rules; `src/insight/brief_highlights.py` supplies explanations and coverage notes; and
`src/insight/brief.py` composes the summary and sections, with shared response types in
`src/insight/brief_types.py`. `src/insight/brief_digest.py` creates the shorter workspace takeaways from the
already-filtered `BriefData`, using the same `_facts` date and counting rules. It selects facts for a concise
display rather than clipping the full summary's text. The API and export summary composition is unchanged.
Focused subject briefs use `services.focused_brief` and the same filtered choice service as Threat Hunt;
the interface renders the returned facts and report references without composing new claims.

Highlights follow a fixed priority: known ransomware use and other known exploitation, the most-mentioned
CVE (or a vendor to check when no CVE repeats), stored attack forecasts, the highest reported severity,
then watch-term relevance. No recent-receipt highlight is generated, including for an empty collection.
Each highlight has at most five evidence items.
The severity explanation translates a small set of explicitly named weaknesses into plain English; when
no precise translation applies, the supporting highlight quotes the source description or directs the
reader to the advisory. The executive summary omits untranslated quotations and sends the reader to the
source. Exact CVE identifiers and numeric severity scores remain in **Most severe**. The brief does not
infer an attack technique from a severity number, or current attacks from a historical CISA listing.

## Time and coverage

| Value | Interpretation |
| --- | --- |
| Seven-day view | The default reporting window. API callers can request 1–30 days. |
| Reference time (`as_of`) | The end of the reporting window, in UTC. It is not proof that every source was synced at that time. |
| Report count | Included current reports after visibility, date and demo filtering. It is not a count of unique incidents. |
| API receipt metadata (`recent_reports`) | Included reports received during the previous 24 hours. Retained for compatibility, not displayed as a separate card or highlight. It does not date the underlying attacks. |
| Source count | Distinct source identities among included reports, not all configured or currently healthy connectors. |

The existing publication-date rules keep historical imports from appearing to be new intelligence. KEV
reports use the date CISA added the vulnerability; CISA advisories use their first release date, not a later
revision date. Where the publisher's date is unavailable, the receipt date is the fallback. A first sync of
an old advisory therefore does not make it a new advisory in the brief. Publisher dates have day-level
precision. Invalid dates and dates after the reference time are excluded rather than treated as fresh
evidence. The API's last-24-hour count is a subset of the reports included after those rules, based on their
received timestamps; an updated report's current version can count as a recent receipt.

The database query considers at most 2,000 current reports received in the requested window, newest first.
Counts and themes describe this bounded selection. Coverage notes disclose when the query limit makes
counts and topic rankings partial. The detail sections show at most five items each.
Stored public KEV additions can appear even when the report count is zero; a public catalogue fact must not
inflate the count of reports or expose a report the caller cannot read.

An empty or quiet brief describes the available collection. It does not prove that no threats exist or
that a source is up to date. Coverage notes report stored source-check history: the last successful check,
a later failed check, no success within 24 hours, or no recorded success. They do not include connector
error details and do not trigger a check. Synchronization remains the way to bring in newer source material.

## Keep the signals distinct

| Signal | What it supports | What it does not establish |
| --- | --- | --- |
| Known exploitation | A vulnerability is on the stored CISA KEV list, including recent additions and older entries discussed in included reports. | Current attack frequency, a new attack wave, or compromise of the operator's systems. |
| Ransomware use | CISA's KEV entry says it knows of ransomware campaigns that use the weakness (**Used in ransomware attacks**). | That the operator is targeted, or that a campaign is active today. |
| Technical severity | A CISA advisory or NIST NVD supplies a CVSS base score of at least 9 for the **Most severe** section. | Proof that the vulnerability is being exploited or is present in the operator's environment. |
| Attack likelihood | FIRST's EPSS estimates a 10% or higher chance of exploitation attempts in the next 30 days (**Forecasts worth checking**). | That the operator uses the product, or that an attempt will reach them. |
| Repeated reporting | A vulnerability, indicator or product appears repeatedly in the selected collection. | More attacks than last week, independent corroboration, or broader prevalence outside the collection. |
| Watch-term match | A configured literal term occurs in an included report. | An asset inventory match, exposure assessment or risk score. |
| API receipt metadata | Insight received an included report in the last 24 hours; no receipt card or highlight is shown. | The event's time, a fresh vulnerability disclosure or a verified current threat. |

`GET /api/brief` has no previous-period comparison. The landing overview (`GET /api/landscape`) compares
reporting with earlier periods. In both cases, "trending" refers to the collected reporting, not a measured
increase in attacks. Publisher deadlines for US federal
agencies, when reported, retain that scope rather than becoming a universal deadline.

## Evidence and access

Highlights carry the same `BriefItem` navigation data used by detail sections: report ID, indicator value
or search term. Readers can open the report, inspect related observations or search the collection to check
the explanation. Report-derived counts, themes and links respect the API key's TLP limit. Restricted reports
must not contribute to a limited caller's explanation, count or evidence list.

The public KEV catalogue is separate from restricted report content. When a caller cannot read a stored KEV
report, the brief may still state a public catalogue fact but must not link to that hidden report. A watch
term is a literal match; reviewing the source and deciding what to do remain operator actions.

## API compatibility and review

`GET /api/brief` retains `days`, `since`, `summary` and `sections`. It adds `as_of`, `recent_reports`,
`report_count`, `source_count`, `highlights` and `coverage`; existing clients may ignore these fields. The
new data is computed on read, so this change needs no database migration. The
[API reference](API.md#executive-brief) defines the JSON types and item fields.

Review the behavior through the focused brief unit tests, API tests and UI/accessibility tests. The useful
checks are factual and behavioral: receipt-time boundaries, exclusion of demo/old reports, TLP visibility,
linked evidence, severity versus exploitation, and wording that does not invent exposure or attack growth.
The UI should keep both themes, larger text, phone layouts and existing evidence navigation usable.
Test results belong in the pull request's validation record; this document describes the behavior
and interpretation rather than certifying a particular deployment.

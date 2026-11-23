# Executive brief: behavior and evidence

The landing page helps a reader decide what deserves attention in the intelligence already collected by
Insight. It serves both general readers who need an explanation and IT readers who need the supporting
report, vulnerability identifier or product name. The workspace keeps the **Insight** name and symbol and
uses **Cyber Threat Intelligence Platform** as its tagline. The previous **Collect. Connect. Understand.**
line is removed.

## What the brief answers

The default view covers seven days and separately highlights reports received in the last 24 hours. It
explains known exploitation, repeated reporting, serious weaknesses and matches to the operator's watch
terms when those facts exist. Each highlight combines a short explanation, a conditional next step and
links to available, visible evidence. **Exploited now** and **Most severe** remain available below the
summary, alongside watch terms, indicators seen in several sources and vendor mentions.

The brief is part of the **Threat landscape** ([ADR 0020](adr/0020-threat-landscape.md)), the page's main
heading and first main content, with the 7- or 30-day period chosen beside it. The landscape's **Executive
summary** (trends compared with earlier periods, then the brief's sentences) sits beside the reporting-window
counts, last-24-hour receipt count and UTC reference time on wide screens; they stack on smaller screens.
**About this brief** expands the coverage notes, including how fresh each source in use is (optional sources
count only once switched on). **What needs attention** contains the highlights and their **Next step** and
**View evidence** controls. The landscape's trending threats and attacker behaviour follow, then **Evidence at
a glance** with the five detail sections, **Exploited now** and **Most severe** emphasized and explained.
**Sync all sources** sits beside the main heading. Analyst actions, inventory counters and the report
workspace follow below, so the overview comes before the working tools. Evidence controls reveal
the supporting report or relevant workspace tab on both phones and larger screens; scrolling honors the
reader's reduced-motion preference.

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
`src/insight/brief_types.py`. The workspace and `GET /api/brief` use the same result. The interface changes its
presentation without creating a second set of intelligence rules.

Highlights follow a fixed priority: known exploitation, the most-mentioned CVE (or a vendor to check when
no CVE repeats), the highest reported severity, watch-term relevance, then recent receipts. The recent
receipt highlight also appears for an empty collection. Each highlight has at most five evidence items.
The severity explanation translates a small set of explicitly named weaknesses into plain English; when
no precise translation applies, it quotes the source description or directs the reader to the advisory.
It does not infer an attack technique from a severity number.

## Time and coverage

| Value | Interpretation |
| --- | --- |
| Seven-day view | The default reporting window. API callers can request 1–30 days. |
| Reference time (`as_of`) | The end of the reporting window, in UTC. It is not proof that every source was synced at that time. |
| Report count | Included current reports after visibility, date and demo filtering. It is not a count of unique incidents. |
| Last 24 hours (`recent_reports`) | Included reports that Insight received during the previous 24 hours. It does not mean the underlying attacks occurred then. |
| Source count | Distinct source identities among included reports, not all configured or currently healthy connectors. |

The existing publication-date rules keep historical imports from appearing to be new intelligence. KEV
reports use the date CISA added the vulnerability; CISA advisories use their first release date, not a later
revision date. Where the publisher's date is unavailable, the receipt date is the fallback. A first sync of
an old advisory therefore does not make it a new advisory in the brief. Publisher dates have day-level
precision. Invalid dates and dates after the reference time are excluded rather than treated as fresh
evidence. The last-24-hour count is a subset of the reports included after those rules, based on their
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
| Attack likelihood | FIRST's EPSS estimates a 10% or higher chance of exploitation attempts in the next 30 days (**Likely to be attacked soon**). | That the operator uses the product, or that an attempt will reach them. |
| Repeated reporting | A vulnerability, indicator or product appears repeatedly in the selected collection. | More attacks than last week, independent corroboration, or broader prevalence outside the collection. |
| Watch-term match | A configured literal term occurs in an included report. | An asset inventory match, exposure assessment or risk score. |
| Recent receipt | Insight received an included report in the last 24 hours. | The event's time, a fresh vulnerability disclosure or a verified current threat. |

There is no previous-period comparison. If a reader calls repeated coverage "trending", it means repeated
reporting within the collected sources, not an increase in attacks. Publisher deadlines for US federal
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

# Build a threat hunt guide

**Threat Hunt** turns intelligence already in Insight into a plan for your own hunting tools. Choose a
focus, review the plan, then download Markdown or PDF or save it as a draft hunt package. The builder uses
the full panel width. Insight does not search your systems, run an exploit or execute detection rules.
It does not use AI to write the guide.

## Choose a starting point

| Start from | API `kind` | What it uses |
| --- | --- | --- |
| Sector / Industry | `industry` | Cited target mappings, documented group methods and related current reports added in the last 30 days. |
| Threat type | `theme` | Fixed threat guidance, plus reports matching the theme's words or tagged techniques. |
| Threat actor | `actor` | Catalog methods and current reports an analyst explicitly linked to the group. |
| Software flaw (CVE) | `cve` | A flaw mentioned in a current, visible report, with saved exploitation context. |
| Report or advisory | `document` | One current, visible report, its tags, flaw references and eligible indicators. |
| Exploit activity | `exploit` | A visible CVE with saved evidence of public exploit code or known exploitation. |
| Malware or tool | `software` | Catalog methods and reports explicitly linked to the selected software. |
| Indicator | `indicator` | A value with a non-rejected mention in a current, visible report. |
| Campaign | `campaign` | The campaign's explicit report and technique links. |

1. Open **Threat Hunt** and choose **Start from**.
2. Use **Search this list**, then **Search**, to find a name, alias, ID or report. Select a match.
3. Choose **Build guide**. Read why it matters, the proposed steps, logs to gather, source links and gaps.
4. To keep the plan in Insight, choose **Save as hunt package**. It creates an editable draft with the
   selected focus, guidance and eligible facts. The draft editor opens; the button then becomes **Open
   saved package** for that built guide. Saving does not publish the package or run a hunt.
5. Choose **Download Markdown** to edit the plan outside Insight, or **Download PDF** to read and share it.
   Each download opens a new tab and rebuilds the guide from the evidence visible at that time.
6. Set the scope and dates in your hunt tool. Check that you have the right logs before running any checks.

Choices are limited to 50 per kind. Search is applied before this cap; use a narrower query to reach a
choice outside the first list. Searches are at most 120 characters. Report searches use the existing title,
source and body search. An FBI bulletin, for example, must first be added as an authorized report or imported
through a configured source. This feature adds no FBI feed and does not fetch a bulletin on demand.

For an industry guide, choose **Sector / Industry** and browse the 15 categories, or search for a sector
name such as healthcare, energy or banking. Select the match and choose **Build guide**. The same guide
can be downloaded or saved as a draft package. It has no single actor assigned: choosing a sector does not
attribute its reports or indicators to a group.

The sector guide separates source-backed targeting history from recent report context. A report can match
because it mentions a reviewed sector term or because an analyst linked it to a group with a visible target
mapping. The guide states the match reason; neither route proves an attack on the sector. Only current,
visible reports added in the last 30 days are considered. This is a report window, not a claim about when
attacks happened. [Sector guide decisions](adr/0045-sector-threat-hunt-guides.md)

Sector plans scan at most 500 recent visible reports, retain up to 100 matches and use the latest 20.
They show up to five cited groups, with recent explicitly linked reports first. Reports may link to other
groups in the full cited sector profile. Tagged methods from included reports precede catalog methods
from the groups shown; the existing 12-technique limit applies. Caps and missing evidence are stated.

## Read the plan as a starting point

The guide is deterministic: fixed advice, the pinned ATT&CK library and saved evidence produce its sections.
It uses up to 20 matching current reports, 100 eligible reviewed indicators and 12 techniques. It explains
when a list is cut short. Campaign plans inspect up to 200 visible explicit links; indicator and software
links are noted for review on the campaign page, rather than silently added to the report-based indicator
list. A report-based plan considers up to 12 CVE references for saved flaw context.

Technique guidance names its source. When a sub-technique has no check but its parent does, the guide says
it uses the parent as a starting point. Missing log guidance stays missing; Insight does not invent a query.
A shared method, name, report or indicator does not establish actor attribution or link two events to a
campaign. Theme matches describe report context, not proof of an attack.

The indicator list requires accepted review and excludes known-safe, warning-listed and expired-verdict
values. These current plans apply the verdict's explicit expiry or, if none is set, the default lifetime:
30 days for IP addresses and 90 days for domains and URLs. File hashes have no default expiry. The older
actor threat-guide sweep remains a retrospective view with its existing explicit-expiry-only policy.
An accepted mention can still have an unknown verdict. Choosing an indicator as the starting point
does not make it accepted or malicious. A match in your logs is a lead to review, and no match does not prove
that your systems are safe. Record the actual work and findings in your hunt or case tool; send sightings
or requests for information back to Insight when needed.

Guide text is bounded: up to 24 source sections, 150 lines per section, 1,200 characters per line and 40,000
characters of section text. A size-limit note is added if text is shortened. The title and summary are also
capped. PDF uses the built-in fonts; a visible note explains any characters rendered as `?`, while Markdown
keeps the text. Network indicators are defanged in downloads to prevent accidental opening.

Saving rebuilds the guide using the evidence visible at that moment; it does not freeze the earlier preview.
The draft stores the guidance in its hypothesis, with a 10,000-character cap and a notice if shortened. Its
title is capped at 200 characters. Up to 12 techniques, 20 current reports and 100 eligible reviewed
indicators become structured package items. Only an actor-based guide sets the package's group reference.
Each new save operation creates a draft; **Open saved package** reopens the draft already saved from the
current built guide.

## Sharing and source rights

Every guide uses the stricter of the reader's limit and the instance limit. Hidden choices are absent from
lists; a hidden or missing subject produces the same `404`. The guide retains the strictest label of its
subject, evidence and metadata used to describe limits. Cutting a list short does not lower that label.
The PDF repeats the TLP label on each page; Markdown and JSON retain it too.

Guides share metadata and fixed guidance, not report bodies, publisher summaries or private analyst notes.
Report titles, source names, dates, identifiers and references let the reader open the original context in
Insight. **Public · TLP:CLEAR** means the sharing label allows public disclosure; copyright and source terms
still apply. A restricted label remains restricted. No stored report is relabelled by this workflow.

Building a preview or requesting a download records `hunt.guide`, with the caller, subject, output format and
sharing label. These actions create no saved package; their audit entry is the only write. **Save as hunt
package** is a separate, explicit write: it creates an audited draft using the selected focus and eligible
evidence, within the caller's and instance's sharing limits. Existing package creation/item audit entries
record the write; `hunt_package.from_guide` records the starting kind and reference. The draft retains its
handling label. Review and edit it before using the existing **Publish** action. Neither building nor saving
makes an outbound request, executes a rule or records hunt findings.

## Where the other workflows went

- **Intel Brief** is the opening section, with a 7/30-day overview. It has no separate last-24-hour receipt
  card or attention highlight. The existing receipt count remains API metadata for compatibility.
- **Threat Hunt → Saved hunt packages** holds drafts and published packages. Save a built guide to start
  with its content, or choose **Start a blank package** for manual authoring. Publishing remains a separate
  action that makes the package available to external tools over TAXII.
- **Threat Hunt → Advanced: intelligence reports** holds the separate written products: assessments,
  alerts, profiles and summaries, with evidence, judgements and immutable published versions. Their
  case/product APIs remain. Saving a hunt guide creates a hunt-package draft, not one of these reports.
- **Settings → Intelligence questions (advanced)** holds requirements and requests for information.
  Existing report links still open the matching question there.
- **Share** retains IOC exports, TAXII connection details, API access and MISP sharing.

See the [API reference](API.md#hunt-guide-previews-and-downloads), [curl examples](API_GUIDE.md#hunt-guide-previews-and-downloads),
[actor threat guides](THREAT_GUIDES.md) and [ADR 0041](adr/0041-guided-threat-hunt-workspace.md).

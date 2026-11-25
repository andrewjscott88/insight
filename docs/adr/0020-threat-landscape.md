# ADR 0020: A threat landscape counted from the reports, compared with the weeks before

Status: Accepted

## Context
The intel brief (0.5.0) told analysts what came in during the last 7 days: new KEV entries, severe advisories,
watch-term matches. It did not say what the reporting *adds up to*: which kinds of threat are growing, what
attackers are doing, and why that matters. The operator asked for exactly that: a digestible executive summary,
in plain English, of what is trending and what it means for analysts' situational awareness.

Premium threat intelligence platforms answer this with analyst-written landscape reports and, increasingly,
generated summaries. Insight's rules shape the answer:

- **No model writes it.** Insight's brief never states anything the reports do not (ROADMAP-TIP section 3.6:
  the deterministic brief stays authoritative). A trend summary must be built the same way.
- **Precision first** (ADR 0007), **no attribution**, **TLP everywhere** (ADR 0014).
- **Readability** (ADR 0017): every sentence at about age 12-14.

## Decision
1. **Kinds of threat are a curated, visible list.** `insight/themes.py` holds 13 themes (ransomware, phishing,
   data theft, password theft, supply chain, zero-days, state-backed spying, wipers, DDoS, botnets,
   hacktivism, cryptomining, insiders). A report counts towards a theme when its text contains one of the
   theme's words (a literal, case- and accent-insensitive match, like a watch term) or when it is tagged with one
   of the theme's ATT&CK techniques (ADR 0019). The words are chosen to almost always mean the threat
   ("denial of service" is left out: most advisories name it as a possible effect). The workspace shows the
   words and techniques under **How Insight spots this**.
2. **What it means is fixed, reviewed text.** Each theme carries *what it is*, *why it matters* and *what to
   check*, written for analysts and checked for reading level like the interface. It is general guidance, not a
   claim about the reports.
3. **Trends compare like with like.** The chosen period (7 or 30 days) is compared with the 4 periods before it.
   *Rising*: in at least 2 reports, at least 1.5 times the usual number plus 1, **and** at least 1.25 times the
   usual share of reports. The share test stops a new or busy source from making everything rise. *New*: in no
   report of the earlier periods. *Quieter*: half the usual number and share or less, from at least 2 a period.
   Reports count on their publication date when Insight knows it, as in the brief; the demo is left out.
4. **No history, no trend.** When Insight has no (non-demo) report from before the period, the landscape says
   it cannot show trends yet rather than calling everything new; partial history is called rough.
5. **Attacker behaviour from ATT&CK tactics**, in plain words ("getting in (Initial Access)"), with the top
   techniques, compared the same way but against the reports that have techniques.
6. **One summary, one TLP.** The executive summary leads with activity, trending and quieter threats and
   attacker behaviour, then the brief's lines (KEV with a comparison to earlier periods, deadlines, the most
   severe weakness, watch terms, a first step). The landscape carries the most restrictive TLP of the reports it
   counted; the workspace and the briefing say to share it no wider.
7. **A briefing to share.** `GET /api/landscape/briefing` returns the same content as Markdown, TLP-marked at the
   top and bottom, with text from reports escaped. Downloads are audited (`landscape.briefing`).
8. **Every count honours the caller's TLP limit**; a report above it adds nothing, not even to a count.

## Consequences
- Analysts open the workspace to a summary of what is changing and why it matters, can follow every line to
  its reports, and can share the result at the right TLP.
- A rise in reporting is not a rise in attacks; the landscape says so every time. Themes reflect the words
  publishers use; a theme the list does not have is invisible until it is added (a release, not a setting).
- Reports without technique IDs say little about behaviour until analysts tag them; the landscape says so.
- Later work can feed it: KEV's ransomware flag (TIP 1.1), EPSS (TIP 1.2), actors and campaigns (TIP 2.5), and
  analyst-defined themes.

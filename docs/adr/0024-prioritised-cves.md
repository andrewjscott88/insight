# ADR 0024: A prioritised CVE view, and a brief that uses KEV ransomware use, NVD CVSS and EPSS

Status: Accepted. Decision 3's groups are extended by [ADR 0028](0028-exploit-availability.md).

## Context
With automatic lookups (ADR 0023), Insight holds NIST NVD's CVSS score and FIRST's EPSS probability for many
CVEs. CISA's Known Exploited Vulnerabilities (KEV) feed also says whether CISA knows of ransomware campaigns that
use a weakness (`knownRansomwareCampaignUse`), but Insight dropped that field, the weakness name, the notes and
the CWEs (TIP 1.1). The brief's *Most severe* section read CVSS only from CISA advisories, and nothing used EPSS
(TIP 1.3). Analysts had no single list of the CVEs in their reports in the order to look at them.

## Decision
1. **Keep more of KEV (TIP 1.1, part).** `kev_records` gains `vulnerability_name`, `ransomware_use` (`Known`,
   `Unknown`, or empty for anything else), `notes` and `cwes` (validated `CWE-n` values, at most 20). Migration
   0013; the next KEV sync fills them. KEV report text is unchanged, so no report gets a new revision. The
   reader shows "CISA knows of ransomware campaigns that use it" and the weakness name beside the CVE. TIP 1.1's
   inbox policy for older KEV entries stays open.
2. **The brief uses the new signals.** *Exploited now* marks and lists first the entries used in ransomware;
   the summary says how many; a finding **Used in ransomware attacks** comes first. *Most severe* takes NVD's
   score for any CVE a new report mentions as well as a CISA advisory's, says where a score comes from, and
   shows NVD's score beside the advisory's when they differ; a rejected CVE's score never counts. A finding
   **Likely to be attacked soon** names CVEs with an EPSS of 10% or more (roughly the top 2% of scored CVEs),
   with the caveat that EPSS says nothing about whether the reader uses the product.
3. **A prioritised CVE view, by stated rules.** `GET /api/cves` and a *Prioritised CVEs* tab list the CVEs that
   current reports (received in the chosen period, the reader may see, a mention the analyst has not rejected,
   demo left out) mention, in groups: used in ransomware (KEV), known exploited (KEV), likely to be attacked
   soon (EPSS 10% or more), critical (CVSS 9 or more, NVD or a CISA advisory), high (CVSS 7 or more), then the
   rest. Within a group: higher EPSS, higher CVSS, more reports, most recently seen. Each row says why it is
   where it is, lists the facts behind it, and opens its newest report or the indicator. There is no weighted
   or hidden score: an analyst can always check the order.
4. **TLP.** Rows and counts come only from reports the caller may see (`cve_signals(max_tlp=...)`, in the
   architecture test's TLP-aware list); KEV entries and provider scores are public facts about a CVE.
   TLP-limited keys may read `GET /api/cves`; the planted-marker sweep covers it.

## Consequences
- The first screen and the CVE tab put ransomware-linked and exploited weaknesses first, then likely and severe
  ones, so triage starts with the strongest evidence of harm.
- Every signal describes the weakness, not exposure: the view and the brief say so, and the next step is
  always conditional ("if you use these products").
- The quality of the order depends on lookups being on (ADR 0023); rows without scores say "Not looked up at
  NIST NVD or FIRST EPSS yet".
- The mention read is bounded (20,000, newest first); the view says when it reached the limit.

# ADR 0033: Confidence, source reliability and report credibility

Status: accepted (unreleased)

## Context
Every indicator in Insight looked equally trustworthy: one blog post and five independent vendor reports gave
the same row. Leading threat-intelligence platforms grade sources and reports on the Admiralty (NATO) scale,
build a confidence score for each indicator from which sources agree, and age indicators so an old IP address
stops looking current (MISP decaying models, ThreatQ scores, ThreatConnect ThreatAssess). TIP 4.2 is required
for 1.0. This ADR covers grades, confidence and source statistics; sightings from hunt tools follow in a second
change and will add to the same score.

Constraints: TLP per reader everywhere (ADR 0013, 0014); one audit log; nothing written by a model; no new
dependency; the score must be explainable to an analyst in one line.

## Decision
1. **Grades** (migration 0025). `source_ratings` holds, per source name, a reliability grade from A (completely
   reliable) to F (cannot be judged), an optional ageing period in days (1–3650) and a note. A source with no
   row is F. `documents.credibility` holds a report's credibility from 1 (confirmed by other sources) to 6
   (cannot be judged); a new report starts at 6. Both are changed only by people and audited
   (`source.rate`, `document.credibility`).
2. **Confidence, computed on read.** For one indicator, each current report the reader may see that mentions it,
   unless review rejected the mention, gives a weight:
   `0.6 × reliability × credibility × age × review`, where reliability A..F is 1.0, 0.85, 0.65, 0.4, 0.15, 0.5
   (F, unknown, sits between C and D, below every positive judgement), credibility 1..6 uses the same scale,
   age is `0.5 ^ (days / half-life)`, and review is 1.0 for an accepted mention and 0.8 for one not yet
   reviewed. Each source counts once, with its best report, so reposts are not agreement. Independent sources
   combine as `1 − Π(1 − weight)`; the score is that × 100, rounded. Bands: 70+ high, 40+ medium, above 0 low,
   0 none. One unrated, unreviewed report scores 12; three agreeing, accepted reports from A, B and F sources
   score high.
3. **Ageing.** Half-lives by kind: IP address and CIDR 30 days, URL 60, domain 90, email 180. File hashes and
   CVEs do not age. A source's own ageing period replaces the default for kinds that age, so a fast-rotating
   feed can age faster; it never makes a hash age.
4. **Source statistics.** Per source, from the current reports the reader may see: reports, last report,
   indicators (distinct, not rejected), indicators only that source reported, and the share of reviewed
   mentions that were rejected. A rated source with no visible reports is listed only for unlimited readers,
   so a grade cannot reveal that a hidden source exists.
5. **TLP.** Confidence and statistics use only reports the caller may see, so two readers can see different
   scores for the same indicator. Setting a source's grade affects reports at every label, so TLP-limited API
   keys may read grades but not set them (`403`). Credibility can be set only on a report the caller may see.
6. **Interfaces.** `GET`/`PUT /api/source-ratings`, `PUT /api/documents/{id}/credibility`,
   `GET /api/entities/{id}/confidence`, and `confidence` in `GET /api/entities/{id}`; report summaries carry
   `credibility`. In the workspace: a confidence line with its sources on each indicator, a credibility select
   in the reader, and **Source reliability** in Settings.
7. **Not built yet.** Sightings (TIP 4.2b), confidence in TAXII and exports, sorting and filtering by
   confidence, and automatic credibility from corroboration.

## Consequences
- Analysts can see why an indicator is trusted, and grading a source changes every indicator it reported.
- The score is computed per request: one query per indicator, capped at 5000 mentions, so it stays cheap for one
  team but is not yet used to sort long lists.
- The weights are a starting point. They are documented constants and can be tuned without a migration.

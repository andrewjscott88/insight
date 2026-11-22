# 0038: Adversary library imports

## Part 2: software links, workspace and sharing

Status: proposed for the part 2 pull request. Library fields and timeline/Navigator work are separate parts.

The software catalog stays in the pinned JSON library. A `SoftwareDocument` records each analyst decision
that a report concerns a software item: software ID, saved name/type, report ID, note, TLP, time and actor.
The existing `ThreatLink` accepts a software target for an analyst's actor or campaign. These are explicit
use decisions; sharing a report, indicator or technique never creates an attribution. Catalog groups remain
public reference data and are not silently turned into analyst actors.

The stored name/type keeps old decisions readable and removable when an entry leaves a later catalog.
Both link models track update times; older threat links start with their original creation time. Raising
a sharing label advances the timestamp, so clients polling TAXII do not miss the newly marked projection.
The existing threat STIX projection also reads this update time, with creation-time fallback for other
link models. A shared subject projection takes the latest contributing change and appears only once per
identity and label, including when the software projection reuses it.
New links require an entry in the current catalog. Search uses public catalog data. Detail and link views
filter both the stored link and its report/subject by the caller's TLP limit; a hidden item looks missing.
Write labels respect the instance and caller limits, and report-link notes can raise their label. Updating
an existing link never lowers it. Duplicate writes are idempotent, and mutations carry the caller's audit
actor. Database uniqueness arbitrates concurrent additions. Migration `0028` follows sightings `0027`;
downgrade deletes the new associations while preserving reports and previous threat links.

Candidates use the existing whole-word name matcher and publisher excerpt rules, checking at most the
newest 5,000 visible current reports. A match is not a link. Detail returns at most 50 report links, 50 use
decisions and 50 candidates; report links also have a paged route. Search pages have at most 200 items.
The detail envelope includes labels from nonmatching scanned reports because they affect scan counts.
Candidate exclusion checks every visible saved link among matching reports, beyond the displayed page.

STIX software objects use saved catalog identity/name/type, with deterministic IDs that include the sharing
label. Malware is a family; tool objects remain tools. No analyst note or publisher text goes into these
objects. A marked `related-to` relationship joins a selected report to its software. A more restricted
association is never added to a lower-label report's `object_refs`. Explicit visible actor/campaign links
emit `uses` when their software or subject is already selected. No traversal or co-occurrence inference
expands the selection. Both endpoints and the relationship receive the appropriate label. The exporter
retains the existing report/indicator selection and publisher reuse policy and validates the final bundle.

TAXII uses the same projection and stable IDs. Software/link dates include the link time, so linking an old
report is visible to a polling client. The export caps software associations at 100,000; it refuses an
oversized snapshot instead of silently truncating it. There is no dependency or outbound network addition.

Validation covers missing/hidden endpoints, higher link labels, note markings, duplicate writes, retirement,
retention deletion, explicit versus inferred use, valid malware/tool output, stable TAXII IDs and dates,
real middleware authentication/CSRF/key limits, the GREEN-key sweep, and the workspace decision flow.

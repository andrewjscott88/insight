# 0038: Adversary library imports

Status: Accepted

Date: 2026-11-22

## Context

TIP 4.7 expands the existing pinned library (ADR 0025) from group guides to software context, richer
name matching, analyst software links and actor activity timelines. The source data
must stay separate from analyst attribution. A public catalog name is not a decision about a report.

## Part 1: catalog software and sourced aliases

Keep the existing pure build and explicit sync paths. Both editions use the same pinned ATT&CK Enterprise
20.1 release and MISP threat-actor cluster 359, with exact commit URLs and SHA-256 in
`threat_library_sync.PINNED`. This change expands extraction from those inputs; it does not add a source,
network request on reads, schedule or dependency. Pin updates still require reviewing and rebuilding both
source-derived catalogs. Inputs are downloaded by `connectors.download`, under its HTTPS host allowlist,
timeouts and size limits, then verified before parsing. A refused request is not retried by another route.

The writer emits `insight-threat-library-2` (schema in `docs/schemas`). The reader accepts formats 1 and 2.
Format 1 software has only name/type, so missing context remains empty rather than being invented. An
operator can resync explicitly to obtain format 2. There is no database migration.

Each current ATT&CK malware/tool is indexed by its stable software ID even when no current group uses it.
It keeps name, type, aliases, plain description, platforms, directly used techniques and groups that use it.
Only current objects and current explicit `uses` relationships are followed; missing, revoked or deprecated
targets are excluded. Software techniques are not copied to the group's direct techniques. Bundled
descriptions are trimmed; full descriptions remain intact. The bundled file must remain below 1 MB.

MISP entry matching uses only original ATT&CK group names and aliases. A primary MISP entry name must
match exactly after case folding and trimming whitespace, and identify one group and one entry. All
qualifying entries may supply `meta.synonyms`; existing industry/region selection remains unchanged.
Imported synonyms cannot seed another match; MISP `similar` links are ignored. If a proposed synonym
also names another group, or multiple groups propose it, omit that imported synonym. Preserve ATT&CK's
own aliases even where the upstream catalog shares a name. This conservative rule trades some recall
for keeping distinct groups apart.

`Group.aliases` remains a flat tuple for existing consumers. `alias_sources` records each alias's source;
MISP evidence also records the entry name, UUID when supplied, and exact ATT&CK name used for the match.
The pinned URL/version/digest identifies the source snapshot without repeating its URL for every alias.
On disk, each group's `alias_sources` maps names to indices in its `alias_references` evidence list, so
synonyms from the same entry share one provenance record. The reader validates indices and exposes full
`AliasSource` records to consumers. This keeps useful descriptions while staying below the bundled size cap.
The stable renderer omits optional spaces inside entries while keeping one catalog entry per line for review.
Old format 1 group aliases receive ATT&CK provenance on read. MITRE's notice and MISP's dual
CC0-1.0/BSD-2-Clause terms remain in the data and `NOTICE` (Insight uses CC0-1.0).

## Matching, privacy and attribution

Aliases flow through existing catalog search and report-name matching. Whole-word boundaries and the
case rule for ordinary one-word names remain unchanged. Report matches are filtered by the reader's
TLP ceiling and current revision. A mere name match never creates a group, report link or STIX relationship.
Requirement term criteria can search alias text. Requirement group criteria still need an explicit,
visible analyst report link; aliases do not weaken that rule.

Catalog data is TLP:CLEAR. This part adds no stored intelligence, service, route or UI control. Existing
API/UI flows use the enriched catalog, with tests through middleware and the NiceGUI user simulation.
New software fields stay in the library; existing guide/STIX export shapes are unchanged.

## Validation

Offline fixtures cover all current software (including unassigned tools), revoked/deprecated relationships,
format 1 compatibility, the format 2 schema, both editions, source evidence, duplicate/ambiguous names,
non-transitive aliases and deterministic builds. The bundled artifact keeps the existing size, pinned-hash
and stable-render checks. API tests plant restricted alias-naming reports and verify they remain invisible;
they also verify that name matching never satisfies an explicit-link group criterion. A UI test opens the
original group via an imported alias without creating an analyst actor.

## Part 2: software links, workspace and sharing

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
actor. Database uniqueness arbitrates concurrent additions. Migration `0029` follows intelligence products `0028`;
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
Creation and modification are separate: a relationship retains its link creation time, and a software
projection takes the earliest contributing creation and latest contributing update. Same-label note updates
and label raises do not rewrite the saved creation time.
These remain current snapshots, as with technique projections. Removing an earliest/latest contributor or
narrowing the selected reports can shift aggregate software dates under the same projection ID. This part
does not add a projection-history store or deletion tombstones; clients needing full history must retain
their received snapshots. Editing a retained link preserves its creation time while modification advances.

Validation covers missing/hidden endpoints, higher link labels, note markings, duplicate writes, retirement,
retention deletion, explicit versus inferred use, valid malware/tool output, stable TAXII IDs and dates,
real middleware authentication/CSRF/key limits, the GREEN-key sweep, and the workspace decision flow.

## Part 3: timeline and Navigator decisions

- Reuse the pinned library, existing reports, packages and sightings. Never infer attribution or
  actor/campaign associations from shared reports, indicators, software or techniques.
- Add explicit `ActorCampaign` decisions with notes, caller/instance TLP enforcement, audit identity and
  deterministic uniqueness. Migration `0030` follows software links `0029`. Raise the campaign's label
  to its association floor and retain it after removal.
  Add `Campaign.updated_at`, backfilled to creation time, so label raises are visible to TAXII polling.
- Timeline event DTOs record source, date meaning, relation and effective label. Every stored read filters
  before aggregation. Existing guides consume the same service; guide format 1 gets an additive timeline.
  Reports use current revisions; sightings require accepted indicators in current explicit report links.
- Use only known current package publication/retirement timestamps. Do not reconstruct earlier cycles from
  unrelated audit records or imply complete historical coverage. Invalid dates are omitted, never invented.
- Bound all source reads and the final result. A conservative truncation flag does not expose hidden counts.
  Catalog/analyst group references are distinct; no name-based identity merge occurs.
- Software Navigator is a pure projection of explicit catalog software techniques. Actor layers add
  software-only techniques at score zero, with source comments, without modifying existing scores, direct
  group techniques or hunt hypotheses. Visible explicit analyst/software links also contribute context and
  their labels enter the guide envelope. Legacy software records remain valid with empty context.
- No new dependency, external fetch, provider job, model call or deployment setting is added.

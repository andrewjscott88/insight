# 0038: Adversary library imports

Status: Proposed for part 1; parts 2 and 3 remain planned

Date: 2026-11-22

## Context

TIP 4.7 expands the existing pinned library (ADR 0025) from group guides to software context, richer
name matching and, in later parts, analyst software links and actor activity timelines. The source data
must stay separate from analyst attribution. A public catalog name is not a decision about a report.

## Decision: part 1

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

## Remaining work

Part 2 will add software search/API/workspace, explicit audited and labelled report links, and stable STIX
software objects and relationships. Part 3 will add reader-scoped actor timelines and software Navigator
layers, plus software context in actor layers without changing existing scores. Those decisions and their
migrations, route protections, export handling and tests belong to their separate pull requests. TIP 4.7
remains incomplete until those parts pass their gates.

## Validation

Offline fixtures cover all current software (including unassigned tools), revoked/deprecated relationships,
format 1 compatibility, the format 2 schema, both editions, source evidence, duplicate/ambiguous names,
non-transitive aliases and deterministic builds. The bundled artifact keeps the existing size, pinned-hash
and stable-render checks. API tests plant restricted alias-naming reports and verify they remain invisible;
they also verify that name matching never satisfies an explicit-link group criterion. A UI test opens the
original group via an imported alias without creating an analyst actor.

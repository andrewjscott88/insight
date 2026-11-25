# ADR 0042: ATT&CK Mobile and industrial-control-system catalogs

Status: Accepted (1.0.0)

## Decision

Extend ADR 0019 with MITRE ATT&CK Mobile and ICS 20.1 alongside Enterprise 20.1. The compact, offline
catalogs contain all current techniques, sub-techniques, names and matrix-ordered tactics: 125 Mobile
techniques and 104 ICS techniques. Revoked and deprecated objects stay excluded. MITRE's copyright and
terms remain in each file and NOTICE. No dependency or database migration is needed.

The sources are the versioned files in MITRE's official `attack-stix-data` repository at tag `v20.1`:

- [Mobile](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v20.1/mobile-attack/mobile-attack-20.1.json),
  SHA-256 `632e2ec40848394f9873a7a3485fc32f92b861a4e7271f7e88e0cb02f11bb6af`.
- [ICS](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v20.1/ics-attack/ics-attack-20.1.json),
  SHA-256 `3f6448369f9135ade84ff6437479441530d0b262f910dca991879a7146b524ff`.

`scripts/update_attack.py` accepts `--domain`, `--source-url` and `--sha256`. It reads local input only,
refuses a hash mismatch or a bundle from the wrong domain, uses that domain's kill-chain name, and writes
the provenance beside the compact data. Refreshes require an intentional source download and review.

The three pinned domains have disjoint technique IDs. Lookups and explicit-ID extraction use their union;
the union refuses a duplicate ID rather than choosing a domain silently. Existing report rows keep their
IDs, review decisions and TLP labels. Reports are never attributed to an actor from a technique. Existing
reports can be reviewed and tagged manually; this change does not silently reprocess stored reports.

Catalog search, report summaries and report Navigator layers accept `enterprise`, `mobile` or `ics`.
Enterprise remains the default for compatibility. The workspace adds a domain selector and a searchable
offline catalog; adding a report tag offers the same domains. Counts and report pivots retain the reader's
TLP ceiling. Navigator layers never mix domains. STIX and TAXII pattern projections cite the correct
catalog and use `mitre-attack`, `mitre-mobile-attack` or `mitre-ics-attack` kill-chain names respectively.
The public external-reference source remains `mitre-attack`, as in MITRE's three source bundles.

Stored tags that no current catalog recognizes remain visible in the default Enterprise summary and its
**No longer in ATT&CK** section. Legacy rows have no saved domain, so these unknown IDs are not assigned
to Mobile or ICS. Navigator exports continue to omit unknown IDs instead of inventing a matrix position.

The threat-group/software library still uses Enterprise. Its actor Navigator layer excludes non-Enterprise
report tags instead of placing them in an Enterprise matrix. Report tags, guides, link-map context and hunt
package STIX can still carry a Mobile or ICS technique by its real catalog ID and name. The general threat
landscape's tactic aggregation remains Enterprise-scoped; it does not invent cross-domain equivalence.

## Validation and limits

Focused tests cover catalog completeness and provenance, explicit-ID extraction, domain API selection,
tagging and pivots, Navigator isolation, STIX/TAXII attribution, hidden AMBER tags for GREEN readers, and
workspace domain selection. Full release QA remains required when the current UI iteration is frozen.
No new outbound connection occurs in the application and no detection rule is executed.

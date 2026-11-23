# 0040. Operator-defined sources

Status: Accepted for RSS and Atom.

## Context

An operator may have permission to read a feed whose publisher limits how its text can be shared. Adding
that feed also authorises Insight to contact a new host. These decisions belong to the operator.

## Decision

Store each source under a generated key distinct from the curated registry. A signed-in operator sets its
name, HTTPS URL, TLP label and reuse rule. Saving a source leaves it switched off. Switching it on permits a
manual sync. A schedule is a separate opt-in. Management writes are audited. API keys can list the sources
visible under their sharing ceiling.

RSS and Atom use the existing feed parser and the DNS-pinned downloader. Each request is limited to the
configured hostname over HTTPS on port 443. Downloads use the existing time and size limits. The operator
can opt in to private network addresses for these sources. Fetch validators and report identities belong to
the source, so two feeds with the same URL can have different handling rules.

Store only the scheme, host and path. Query parameter names are chosen by the publisher, and any one of them
can carry a credential. The form therefore rejects all query strings, as well as embedded credentials and
fragments. A publisher that requires a secret in its feed URL cannot be added through this form.

Apply the source label as a floor on ingest and retain a stricter report marking. The default reuse rule is
`metadata`. Public reuse requires the operator to confirm the publisher permits it. Exporters resolve that
rule when they share a report. A deleted or unknown operator source counts as metadata-only. Removing a
source keeps the reports already collected.

## Consequences

Operators can change a feed's sharing rule for future exports. A copy already distributed remains with its
recipient. TAXII advances affected report versions so polling clients can receive the revised metadata.
The source's generated key keeps its reports identifiable when the operator renames or deletes
the source. RSS and Atom require no new dependency.

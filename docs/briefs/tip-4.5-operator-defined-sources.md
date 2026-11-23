# Brief: TIP 4.5 Operator-defined sources

Required for 1.0. ADR number reserved: **0040**. Read [AGENTS.md](../../AGENTS.md) first.

## Goal

Let the operator add their own sources in Settings: RSS or Atom feeds, and TAXII 2.1 collections. Each one is
switched off until the operator turns it on, and has its own TLP label and redistribution rule (review J3).
Both apply to every report it brings in, exactly as the curated sources' rules apply to theirs.

## What already exists (reuse it; do not rebuild it)

- **Curated sources:** `source_registry.py` (`Source`, `SOURCES`, `metadata_only()`, `in_use()`), synced by
  `connectors.sync_source()` and `sync_all()`. They send conditional requests through `fetch_if_changed()`,
  record every attempt as a `SourceRun` with a bounded message, and parse RSS and Atom in
  `connectors.parse_feed()`. Switches are in the `SourceSwitch` table (`services.source_switches()` and
  `set_source_switch()`). The Sources tab is `ui/sources.py`; the routes are in `web/routes/sources.py`.
- **Schedules:** opt-in, per source (`jobs.py`, [ADR 0018](../adr/0018-opt-in-scheduled-syncs.md)); changing
  one is a browser-session-only write (`SESSION_ONLY_WRITE_PREFIXES` in `web/boundary.py`).
- **Reuse rules:** [ADR 0021](../adr/0021-threat-research-sources.md). `metadata_only(source_key)` decides
  whether a report's text may leave Insight. It is a pure function over the curated registry today, called by
  the report, IOC and threat-profile exports (`services/exports.py`, `services/threat_profiles.py`,
  `web/routes/exports.py`). Every export path must keep honouring it: STIX, MISP, TAXII, briefings, products
  and the MCP tools included.
- **STIX import** (TIP 2.2, `stix_import.py`): atomic, validated imports that keep publisher restrictions.
  TAXII objects go through it.
- **Outbound connections:** `connectors.download()` and `egress.py` (HTTPS, an allowlist per call, addresses
  checked before connecting, size caps). The MISP connector shows how an operator opts in to a host on a
  private network (`misp_remote.py`, `INSIGHT_MISP_PRIVATE_NETWORK`); loopback, link-local and cloud metadata
  addresses stay blocked.
- Insight's TAXII support is a server only (`taxii.py`, [ADR 0026](../adr/0026-taxii-server.md)). There is no
  TAXII client yet.

## Build

1. **A table of operator sources,** in the next migration on `main` when you start (TIP 4.7 takes `0029` and
   `0030`). Each row has a name, a kind (`rss` or `taxii`), the URL (for TAXII, the API root and the collection
   ID), a TLP label, a reuse rule, the times it was created and changed, and the actor. The reuse rule is
   `metadata` unless the operator says the publisher allows `public`. A source starts switched off: use
   `SourceSwitch` with a key that can never equal a curated source's key (for example `op-<id>`). Audit every
   add, change, switch and delete.
2. **Settings.** A "Your sources" section in the Sources tab: add, edit, switch on or off, delete and sync
   now, showing each source's label and reuse rule. Adding, changing or deleting a source is a
   browser-session-only write, like schedules: Insight contacting a new host is the operator's decision.
   API keys may read the list.
3. **RSS and Atom** through `parse_feed()`, with the source's own label. The curated feeds' fixed `CLEAR` must
   not apply to operator feeds.
4. **TAXII 2.1 collections.** Poll `GET {api_root}/collections/{id}/objects/` with
   `Accept: application/taxii+json;version=2.1`. Resume from the last `X-TAXII-Date-Added-Last` as
   `added_after`, follow `more` and `next`, and cap pages, objects and bytes for each sync. Import through the
   STIX import path, with its validation, atomicity and publisher restrictions. A report takes the stricter of
   the source's label and its own markings, never a lower one.
5. **Credentials,** which TAXII servers often need, are never stored in the database or shown. A source may
   name an environment variable (`INSIGHT_SOURCE_` followed by up to 40 of `A-Z`, `0-9` and `_`) that holds a
   bearer token or `user:password`. Insight sends it only as a header, only to that source's host. A source
   whose variable is missing or empty is "not configured" and makes no request.
6. **Reuse in every export.** Reports from operator sources follow their source's rule wherever the curated
   rule applies. A report whose operator source is unknown or deleted counts as metadata-only. Deleting a
   source keeps its reports and their labels.
7. **Egress.** HTTPS on port 443 only. No credentials, query-string secrets or fragments in the stored URL.
   Each request is allowlisted to that source's own host only, so redirects cannot lead anywhere else. Public
   addresses only, unless the operator opts in to a private network with a setting like MISP's (for example
   `INSIGHT_SOURCES_PRIVATE_NETWORK`). Size caps and timeouts as for the curated sources.
8. **Schedules.** Operator sources can be scheduled exactly like curated ones, and are off until someone sets
   a schedule.

## Not in scope

Other kinds of source (e-mail, web pages, paid APIs), TAXII discovery and writes, STIX 2.0, secrets in the
database, and choosing a label from a feed's content.

## Constraints

- Saving a source whose label is above the instance limit is refused (`403`). Reads filter by the caller's
  limit, as everywhere.
- Errors are Insight's own words: never a feed's body, a URL with its query, or a credential. `SourceRun`
  messages stay bounded.
- Offline fixtures for RSS, Atom and TAXII, including malformed, oversized and paginated answers and a `more`
  that never ends, and an opt-in case in `tests/live/`.
- Describe the TAXII client and the rules for operator sources in `docs/SECURITY.md` (outbound connections),
  `docs/TAXII.md` and the README's sources section.

## Suggested parts

1. The table, Settings, RSS and Atom, and the reuse rule in every export.
2. TAXII 2.1 collections, with credentials from the environment.

## Done when

Every item in the AGENTS.md checklist is met for each part. `docs/API.md`, `docs/API_GUIDE.md`,
`docs/SECURITY.md`, `docs/TAXII.md`, `CHANGELOG.md`, `README.md`, `ROADMAP.md` and `docs/ROADMAP-TIP.md` are
updated, and ADR 0040 records the decisions.

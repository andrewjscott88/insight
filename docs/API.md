# HTTP API (0.6.0)

JSON over HTTP on the same origin as the workspace. The API is **unversioned and intended for automation by
the single operator** (scripts, a SIEM), signed in with a browser session or the
[API key](#api-key-scripts-and-siem). Breaking changes are listed in `CHANGELOG.md` under "Upgrade notes".
There is no OpenAPI endpoint (disabled on purpose); this file is the reference.

**New to the API?** Start with the [API guide](API_GUIDE.md): authentication, limits and a tested `curl`
command for every route, plus recipes (SIEM pulls, ingesting files, paging, back-off) and troubleshooting. This
page is the field-by-field reference.

## Authentication and request rules

1. `GET /login` returns a form containing `csrf_token` (also stored in the session cookie `insight_session`,
   HttpOnly, SameSite=Strict).
2. `POST /login` (form fields `csrf_token`, `password`, and `otp` when MFA is on) → `303` to `/` on
   success; `401` wrong password or authentication code (one message for both); `403` bad or missing CSRF
   token; `429` throttled (more than 30 failures per minute; each failure waits ~1 s); `503` MFA is on but no
   authenticator app is paired (sign-in locked). MFA is off by default (`INSIGHT_MFA=on` or `make mfa-enable`
   turns it on); then `otp` is the 6-digit code from the app, and each code works once.
3. `GET /api/session` → `{"csrf_token": "…"}`. Send it as `X-CSRF-Token` on **every non-GET** API request.
4. `POST /logout` (form field `csrf_token`) revokes the session server-side.

Every request is also checked as follows:
- The `Host` header must be in `INSIGHT_ALLOWED_HOSTS`, else `400`.
- An `Origin` header, if present, must equal `scheme://host`, else `403`. `Origin: null` is always refused.
  Behind a TLS-terminating proxy listed in `INSIGHT_TRUSTED_PROXIES`, `scheme` is the browser's
  (`X-Forwarded-Proto`), so `https://host` matches.
- Request bodies are limited to 2 MB, else `413`.

Responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`
and, unless the route sets its own, `Cache-Control: no-store`. With `INSIGHT_SECURE_COOKIES=1` they also carry
`Strict-Transport-Security: max-age=31536000`. Authenticated `/api` responses carry `RateLimit-Policy` and
`RateLimit` ([Rate limits](#rate-limits)).

Errors are JSON `{"detail": "message"}`; request-body validation errors list each problem
(`{"detail": [{"loc": ["body", "title"], "msg": "...", ...}]}`). Status codes across the API: `400` host not
allowed, `401` no valid key or session, `403` forbidden (read-only or TLP-limited key, CSRF, origin,
browser-only route), `404` not found or above the key's TLP limit, `409` conflict, `413` body too large, `422`
invalid or refused input, `429` rate limited (`Retry-After`), `502` external source failed, `503` sign-in locked
(MFA on, no app paired). Details per status: [API guide, section 3](API_GUIDE.md#3-conventions-errors-rate-limits-tlp-paging).

Minimal client:

```python
import re, httpx
c = httpx.Client(base_url='http://127.0.0.1:8080')
token = re.search(r'name="csrf_token" value="([^"]+)"', c.get('/login').text).group(1)
c.post('/login', data={'csrf_token': token, 'password': PASSWORD})
c.headers['X-CSRF-Token'] = c.get('/api/session').json()['csrf_token']
```

All `/api/*` routes return `401` without a valid session and `403` for writes without the CSRF header.

## API key (scripts and SIEM)

Automation should use the API key instead of the sign-in flow above. There is **one active key at a time**,
managed only from the command line on the host (there is no API or UI for it, so a hijacked browser session
cannot create one):

```sh
insight api-key create --name siem                    # read-only, expires in 90 days
insight api-key create --name scripts --access read-write --expires-days 30
insight api-key status                                # key ID, access, expiry, last use; never the key
insight api-key rotate                                # new key, same settings; the old one stops at once
insight api-key revoke
# Docker: docker compose exec insight insight api-key create --name siem
```

The key (`insk_<12-hex key ID>_<43-character secret>`) is printed **once**; only its SHA-256 is stored, so a
lost key cannot be recovered, only rotated. Store it in your secret manager or SIEM credential store, never in
a URL or a repository. Send it on every request:

```python
import httpx
c = httpx.Client(base_url='https://insight.example.org', headers={'Authorization': f'Bearer {API_KEY}'})
iocs = c.get('/api/iocs/export', params={'max_tlp': 'GREEN', 'review_status': 'accepted'}).json()
```

| | Session (browser) | API key |
| --- | --- | --- |
| Credential | `insight_session` cookie | `Authorization: Bearer <key>` |
| CSRF token on writes | Required (`X-CSRF-Token`) | Not used |
| Reads (`GET`) | Yes | Yes |
| Writes (`POST`) | Yes | Only with `--access read-write` |
| `GET /api/session`, the workspace UI | Yes | No (`403`) |
| Reports above a TLP limit | Sees all | With `--max-tlp`, invisible (see below) |

- `401` with `WWW-Authenticate: Bearer error="invalid_token"` and `{"detail": "Invalid or expired API key"}`
  for any unknown, malformed, revoked or expired key (the reason is logged server-side, with the key ID only).
- `403 "This API key is read-only"` for a write with a read-only key.
- When an `Authorization: Bearer` header is present, the key alone decides: a session cookie sent alongside is
  ignored. Other schemes (e.g. `Basic` added by a reverse proxy) are ignored and the session applies.
- Expiry is required (1-365 days, default 90). Rotate before it expires: `insight api-key status` shows the date.
- Revocation and rotation take effect on the next request; no restart is needed.
- **TLP limit** (`insight api-key create --max-tlp GREEN`): the key sees only reports at or below that label.
  Reports above it behave exactly like missing ones: absent from lists, search, entity counts, stats and IOC
  exports (an export's `max_tlp` is lowered to the key's), `404` for detail, export, review and notes, and
  entities mentioned only in such reports are `404` too. The key cannot store a report above its limit (`422`).
  `GET /api/audit` and CVE enrichment are refused (`403 "Not available to TLP-limited API keys"`), because
  they reveal information across all reports. Rotation keeps the limit unless `--max-tlp` is given again;
  `insight api-key rotate --max-tlp RED` removes it.
- Key creation and revocation are audited (`api_key.create`, `api_key.revoke`). Every write made with the key is
  logged by `insight.auth` as `API key <key ID>: POST /api/...`.

## Rate limits

Every authenticated `/api` request counts against a budget **per caller**: the API key and the signed-in
operator have separate budgets, so a runaway script cannot lock the analyst out of the workspace.

| Policy | Requests | Limit |
| --- | --- | --- |
| `read` | `GET`/`HEAD`, except the IOC export | 300 per minute |
| `write` | `POST` (ingest, triage, notes, demo, sync, enrichment) | 60 per minute |
| `ioc-export` | `GET /api/iocs/export`, `GET /api/iocs/blocklist` | 30 per hour |
| (invalid keys) | Requests with a wrong, revoked or expired key, per client address | 10 per minute |

Budgets are token buckets: the full limit is available as a burst, then it refills evenly (`read`: 5 per
second; `ioc-export`: one every 2 minutes). Requests refused with `429` do not use up budget. A valid key is
never refused because of invalid-key attempts. Source sync and enrichment keep their own stricter rules
(one sync at a time, `409`; one lookup per 6.5 s, `429`).

Limited responses carry the IETF draft headers
([draft-ietf-httpapi-ratelimit-headers](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/)):

```
RateLimit-Policy: "read";q=300;w=60      300 requests per 60 s window
RateLimit: "read";r=297;t=1              297 left; full again in 1 s
```

A `429` adds `Retry-After: <seconds>`. Clients should wait at least that long (and back off exponentially on
repeated `429`s). A SIEM polling the IOC export every 5 minutes uses 12 of its 30 exports per hour.

Limits are held in the server's memory: they reset on restart and assume one worker (`insight serve` runs one).

## Documents

### `POST /api/documents`
Body: `title` (1–300 chars), `body` (1–200,000 chars; CRLF/CR normalised to LF), `source_name` (1–160),
`source_url` (optional; http/https only, no credentials), `tlp` (`CLEAR` `GREEN` `AMBER` `AMBER+STRICT` `RED`,
**default `AMBER`**).

Returns the document detail (below) plus:
- `created`: `false` means it is an exact duplicate of title, body, source, URL and TLP.
- `tlp_raised_from`: the submitted label when a more restrictive `TLP:` marking in the title or body raised
  it, else `null`. Labels are never lowered.

Errors:
- `422`: validation failed, or more than 2,000 indicator mentions (split the document);
- `422`: the report's label, after raising, is above the instance's TLP limit (`INSIGHT_MAX_TLP`, default
  `AMBER+STRICT`, so TLP:RED is refused). Nothing is stored. `detail` says whether a marking in the text caused
  it, e.g. `Refused: the text carries a TLP:RED marking, so the report counts as TLP:RED (submitted as
  TLP:AMBER). This instance stores reports up to TLP:AMBER+STRICT (INSIGHT_MAX_TLP). …`;
- `409`: concurrent import (retry).

### `GET /api/documents`
Query parameters:
- `q`: literal substring of title, source and body, folded for case, accents, width and Unicode normal form;
  at most 200 characters.
- `status`: `new` / `reviewing` / `reviewed`.
- `tlp`.
- `include_superseded`: default `false`.
- `offset`, `limit`: at most 200.

Returns summaries, newest first:
`id, title, source_name, source_url, tlp, status, created_at, summary, entity_count, is_current, truncated`.

### `GET /api/documents/{id}`
The summary plus:
- `body`, `content_hash` (SHA-256 of the body), `extractor_version`;
- `source_key`, `external_id`, `supersedes_id`, `revisions` (all revisions of the same source item, oldest
  first);
- `notes`;
- `observations`, each with:

| Field | Meaning |
| --- | --- |
| `id`, `entity_id`, `kind`, `value` | Kinds: `cve url domain ip md5 sha1 sha256 sha512` |
| `evidence` | Source text around the mention |
| `start_offset`, `end_offset` | Code-point offsets into `body` (Python indexing) |
| `start_offset_utf16`, `end_offset_utf16` | The same span for JavaScript (`body.slice(start, end)`) |
| `review_status` | `unreviewed` / `accepted` / `rejected` |
| `kev` | CISA KEV context for CVEs (`date_added`, `due_date`, `required_action`, `vendor`, `product`, `imported_at`) or `null` |

### Other document routes
| Route | Body | Result |
| --- | --- | --- |
| `POST /api/documents/{id}/review` | `{"status": "new"\|"reviewing"\|"reviewed"}` | `{"status": …}`; `404` if missing |
| `POST /api/observations/{id}/review` | `{"status": "unreviewed"\|"accepted"\|"rejected"}` | `{"status": …}` |
| `POST /api/documents/{id}/notes` | `{"body": "…"}` (1–10,000 chars) | `{"id": …}` |
| `GET /api/documents/{id}/export` | - | Detail plus `format: insight-report-v1` and a handling notice, as an attachment; audited |

## IOC export

Task-oriented guide with recipes and troubleshooting: [IOC_EXPORT.md](IOC_EXPORT.md). JSON Schema:
[schemas/insight-ioc-v1.schema.json](schemas/insight-ioc-v1.schema.json). Example file:
[examples/insight-iocs-example.json](examples/insight-iocs-example.json).

### `GET /api/iocs/export`
One JSON file listing every indicator across the selected reports, each **once**, with the reports that mention
it. Returned as an attachment `insight-iocs-<YYYYMMDDTHHMMSSZ>.json`; audited as `ioc.export`. The workspace
(**Export IOCs**) and `insight export-iocs FILE` produce the same file.

Query parameters (all optional; values are **case-sensitive**):

| Parameter | Default | Meaning |
| --- | --- | --- |
| `kind` (repeatable) | all | `cve` `url` `domain` `ip` `md5` `sha1` `sha256` `sha512` |
| `review_status` (repeatable) | `unreviewed`, `accepted` | Review state of each **mention** (`unreviewed` / `accepted` / `rejected`); rejected mentions are left out unless requested |
| `max_tlp` | none | Include only reports labelled at or below this level, e.g. `GREEN` before sharing with a community |
| `defang` | `false` | Defang values, report titles and evidence: `hxxps://evil[.]example/a[.]php`, `evil[.]example`, `192[.]0[.]2[.]8`, `2001[:]db8[:][:]1`, plus e-mail domains, CIDR ranges and file-like names in text (see the guide, §7) |
| `evidence` | `true` | `false` leaves out the report text around each mention (`evidence: null`). Recommended when sharing: excerpts can carry victim details or indicators an analyst rejected |
| `document_id` (repeatable) | all reports | Only these reports. A chosen report is included even if it is a superseded revision |
| `q` | none | Inbox search text (literal, folded like the inbox). At most 200 characters: longer text is rejected with `422`, whereas `GET /api/documents` shortens it |
| `status` | any | The **report's** triage status: `new` / `reviewing` / `reviewed`. Not the mention review state |
| `verdict` (repeatable) | all | Only indicators with this verdict: `unknown` `benign` `suspicious` `malicious` |
| `exclude_flag` (repeatable) | none | Leave out indicators with this warning flag: `non-routable` `documentation` `reserved-name` `common-benign` |
| `tlp` | any | Only reports with **exactly** this label (compare `max_tlp`) |
| `include_superseded` | `false` | Also include superseded revisions of synced items |

Encode `+` in `AMBER+STRICT` as `%2B` (`max_tlp=AMBER%2BSTRICT`): a literal `+` in a query string means a space
and fails validation. HTTP clients that take a parameter list (httpx `params`, `curl --get --data-urlencode`)
encode it for you.

Example (using the client above):

```python
r = c.get('/api/iocs/export', params=[('kind', 'ip'), ('kind', 'domain'), ('max_tlp', 'GREEN'), ('defang', 'true')])
export = r.json()  # export['tlp'], export['counts'], export['iocs']
```

Response (`format: insight-ioc-v1`, **not STIX**):

| Field | Meaning |
| --- | --- |
| `format` | `insight-ioc-v1`. Fields may be added within v1; incompatible changes get a new identifier |
| `export_id` | Also the `object_id` of the `ioc.export` audit event |
| `generated_at`, `generator`, `handling_notice` | Provenance and handling reminder |
| `tlp` | Most restrictive label of every included report (`AMBER` when the export is empty). Handle the whole file at this label |
| `defanged` | Whether values and evidence excerpts are defanged |
| `filters` | The normalised filters that produced the file (defaults filled in), including `document_ids` and `include_evidence` |
| `counts` | `iocs`, `documents`, `mentions` (included mentions only), `by_kind` |
| `iocs` | One entry per indicator, sorted by `kind`, then `value` (as written, so defanged files can order differently) |

Each IOC:

| Field | Meaning |
| --- | --- |
| `kind`, `value`, `entity_id` | Canonical value (defanged if requested); `entity_id` works with `GET /api/entities/{id}` |
| `tlp` | Most restrictive label of this indicator's **included** sources |
| `first_ingested_at`, `last_ingested_at` | When the oldest/newest included source was added to Insight (not publication or sighting dates) |
| `review_statuses` | Number of included mentions per review state, e.g. `{"unreviewed": 1, "accepted": 1}` |
| `kev` | CISA KEV context for CVEs (`date_added`, `due_date`, `required_action`, `vendor`, `product`, `imported_at`) or `null` |
| `verdict` | The analyst's verdict: `unknown` (none, or its own label is above the export's TLP limit), `benign`, `suspicious` or `malicious`. Review says a value was copied correctly; the verdict says what it means |
| `verdict_valid_until` | When the verdict expires, or `null` |
| `flags` | Warning flags: why the value is unsafe to block (`non-routable`, `documentation`, `reserved-name`, `common-benign`); `[]` for most |
| `sources` | Included reports that mention it, oldest first (see below) |

Each source: `document_id`, `title`, `source_name`, `source_url`, `tlp`, `status` (the report's **triage**
status), `created_at`, `is_current` (`false` only for superseded revisions), `extractor_version` (e.g.
`regex-v2`; `regex-v1` for reports ingested before 0.2.0), `mentions` (included mentions in that report) and
`evidence`. `evidence` is the text around the first included mention, up to 90 characters either side, cut at
arbitrary positions; `null` with `evidence=false`.

Defanging applies to values, titles and evidence excerpts. Source URLs (the publisher's link) and source names
are exported as stored. Each defanged **value** refangs to the original; the file as a whole is not meant to be
re-imported.

Errors:
- `422` for an invalid filter or when more than 100,000 mentions match (narrow the filters). `detail` names the
  parameter as you sent it and, for list items, the value: `kind 'IP': Input should be 'cve', …`,
  `max_tlp: Input should be 'CLEAR', …`;
- `401` without a session.

### `GET /api/iocs/blocklist`
Values that are safe to load into a firewall, proxy, DNS filter or SIEM lookup, one `kind` at a time: `ip`,
`domain`, `url`, `md5`, `sha1`, `sha256` or `sha512` (`422` otherwise). A value is listed only when all of
these hold:

- an analyst recorded a **`malicious` verdict** (`POST /api/entities/{id}/assessment`), and it has not
  expired: its own `valid_until`, or else a default lifetime of 30 days for IP addresses and 90 days for
  domains and URLs (file hashes do not expire);
- at least one mention of it is **accepted**, in a report you can see;
- it carries **no warning flag**: no private, reserved or documentation address, special-use name or vendor
  domain, whatever its verdict;
- the verdict's own TLP label is within your limit.

`format=txt` (default): one value per line, sorted, never defanged. `format=csv`: `value,kind,decided_at,
expires_at,tlp` with a header row. Audited as `ioc.blocklist`; shares the `ioc-export` budget.

## Entities

| Route | Parameters | Result |
| --- | --- | --- |
| `GET /api/entities` | `q` | Up to 200 `{id, kind, value, document_count}` sorted by kind and value |
| `GET /api/entities/{id}` | `offset` (0), `limit` (100, at most 200) | `{id, kind, value, flags, assessment, first_seen_at, last_seen_at, document_count, offset, documents: [summaries]}`, newest first, paginated. `assessment` is `null` or `{verdict, reason, tlp, valid_until, decided_at, actor}`; a TLP-limited key sees it only within its limit. `first_seen_at` / `last_seen_at`: when the oldest and newest report **you can see** that mentions it was added |
| `POST /api/entities/{id}/assessment` | JSON `{verdict, reason, tlp, valid_until}`: `verdict` `unknown` (clears) / `benign` / `suspicious` / `malicious`; `reason` up to 2,000 characters; `tlp` (default `AMBER`) labels the reason; `valid_until` a date, today or later, or omitted | The recorded assessment, or `{"verdict": "unknown"}`. Audited as `entity.assess`. `404` if you cannot see the entity; `403` if a TLP-limited key would set, or replace, a verdict above its limit |

## ATT&CK techniques

MITRE ATT&CK® Enterprise techniques on reports ([ADR 0019](adr/0019-attack-techniques.md)). A report is tagged
with every technique ID written in its text (`T1059`, `T1059.001`) that is in the bundled catalog (`source:
report`); analysts add and remove techniques by hand (`source: analyst`). A new revision of a synced item keeps
the analyst's additions and removals. Insight never guesses a technique from prose and never infers an actor.
Summaries and pivots count **current** reports you can see.

| Route | Parameters | Result |
| --- | --- | --- |
| `GET /api/attack/techniques` | `q` (ID prefix or name, up to 100 characters), `limit` (50, at most 200) | `{version, techniques: [{id, name, tactics, url}]}` from the bundled catalog, by ID |
| `GET /api/attack/summary` | `days` (30; `0` for all time, at most 3650) | `{version, period, techniques: [{id, name, tactics, url, reports, last_seen_at}]}`, most reports first |
| `GET /api/attack/techniques/{technique_id}/documents` | `days` (0), `offset` (0), `limit` (25, at most 200) | `{id, name, tactics, url, offset, documents: [summaries]}`, newest first; `404` for an ID not in the catalog |
| `GET /api/attack/navigator` | `days` (30; `0` for all time) | An [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer (format 4.5) of the summary, each technique scored by its number of reports, as an attachment. Audited as `attack.navigator` |
| `GET /api/documents/{id}/techniques` | - | `[{id, name, tactics, url, source, evidence, actor, created_at, in_catalog}]` by ID; `404` if you cannot see the report |
| `POST /api/documents/{id}/techniques` | JSON `{technique_id}` (`T1486` or `T1059.001`) | The tag. Restores a removed one; a tag that already exists is returned unchanged. Audited as `technique.tag`. `422` for an ID not in the catalog, `404` if you cannot see the report |
| `DELETE /api/documents/{id}/techniques/{technique_id}` | - | `{removed}`. Later revisions keep it removed. Audited as `technique.untag`. `404` if it is not tagged or you cannot see the report |

## Industry threats and threat guides

Industry threat profiles and actor threat guides ([ADR 0024](adr/0024-threat-guides.md),
[THREAT_GUIDES.md](THREAT_GUIDES.md)). `{ref}` is an ATT&CK group ID from the bundled threat library (`G0016`)
or the ID of an actor you created. Library groups are public (TLP:CLEAR); an actor you created, its links, your
industry decisions, rules and hunts carry their own labels and are hidden from callers whose limit is lower.
**Every industry claim names its source**: MITRE ATT&CK's own group description (with the sentence quoted), a
MISP galaxy sector label, or your decision with a citation. Insight never infers a group from indicators,
techniques or co-occurrence; "reports naming it" counts reports whose text contains the group's name or an alias,
which is not attribution.

| Route | Parameters | Result |
| --- | --- | --- |
| `GET /api/industries` | - | `{library: {edition, attack, sources}, industries: [{key, name, covers, groups}]}`; `groups` counts groups a cited source names for the industry, including your own decisions you can see |
| `GET /api/industries/{key}/actors` | `days` (90, 1-3650), `top` (10, at most 10) | `{industry, tlp, days, candidates, reports_read, reports_capped, ranking, actors: [{rank, ref, kind, name, aliases, tlp, reports_naming_it, last_named_at, latest_public_activity, attack_techniques, evidence: [{industries, source, evidence, url, citations, match}], reasons}], removed_by_you}`. Ranked by reports naming the group in the period, then latest public campaign activity, then number of ATT&CK techniques. `tlp` is the most restrictive label used. `reports_capped`: more than 5,000 reports in the period; only the newest were read. `404` for an unknown industry |
| `GET /api/actors` | `q` (ID, name or alias, up to 100 characters), `limit` (50, at most 200) | `{library, groups: [{ref, kind, name, aliases, url, industries, techniques}], actors: [{ref, kind, name, aliases, description, attack_group_id, tlp, created_at, created_by}]}` |
| `POST /api/actors` | JSON `{name, aliases, description, attack_group_id, tlp}` (`aliases` up to 20; `attack_group_id` optional, `G` and four digits) | The actor (`201`). Audited as `actor.create`. `422` for an `attack_group_id` not in the library; `403` for a label above your limit or the instance limit |
| `GET /api/actors/{ref}` | - | `{ref, kind, name, aliases, description, tlp, attack_group, industry_claims, your_industry_decisions, linked_reports}`; `404` if unknown or above your limit |
| `POST /api/actors/{ref}/documents` | JSON `{document_id, note}` | `{ref, document_id, note}` (`201`). Links a report to the group: your decision. Linking twice returns the same link. Audited as `actor.link`. `404` if you cannot see the group or the report |
| `DELETE /api/actors/{ref}/documents/{doc_id}` | - | `{unlinked}`. Audited as `actor.unlink` |
| `POST /api/actors/{ref}/industries` | JSON `{industry, decision, citation_url, document_id, reason, tlp}`. `added` needs an HTTPS `citation_url` or a `document_id` you can see; `removed` needs a `reason` | `{ref, industry, decision, tlp}`. One decision per group and industry; a new one replaces it. Audited as `actor.industry`. `422` without a citation or reason, `403` above your limit (also for replacing a decision labelled above it) |
| `GET /api/actors/{ref}/guide` | `format` (`json` or `md`), `max_tlp` (leave out anything above it), `linked_only` (`false`: also reports that name the group) | The threat guide: JSON format `insight-threat-guide-1` `{format, generated, generator, tlp, reader_limit, group, industries, removed_industries, regions, campaigns, techniques, software, mitigations, reports, reports_naming_group, hunt: {label, hypotheses, sweep, rules, records}, sources, notice}`, or a Markdown attachment with the TLP label first and last. Audited as `actor.guide` |
| `GET /api/actors/{ref}/navigator` | `max_tlp` | An ATT&CK Navigator layer (format 4.5) of the group's techniques, scored 1 for each of: in ATT&CK, in a linked report. The label is in the layer's metadata and description. Audited |
| `GET /api/actors/{ref}/sweep` | `format` (`json` or `csv`), `max_tlp`, `linked_only` | The indicator sweep list (format `insight-sweep-v1`): accepted IPs, domains, URLs and hashes from linked reports and reports naming the group, without indicators flagged as private or documentation, benign verdicts or expired verdicts. CSV starts with a `# TLP:` line; cells are protected against spreadsheet formulas. Things to search for, not proof of the group. Audited |
| `GET /api/actors/{ref}/hunts` | - | `[{id, ref, title, status, summary, tlp, created_at, updated_at, created_by, checks: [{technique, result, data_checked, from, to, notes}]}]` you can see, newest first |
| `POST /api/actors/{ref}/hunts` | JSON `{title, tlp}` | The hunt (`201`), `status: open`. Audited as `hunt.start`. `403` above your limit or the instance limit |
| `GET /api/hunts/{hunt_id}` | - | One hunt, as above; `404` if unknown or above your limit |
| `PUT /api/hunts/{hunt_id}` | JSON `{status, summary}` (`open` or `closed`) | The hunt. Audited as `hunt.update` |
| `PUT /api/hunts/{hunt_id}/checks/{technique_id}` | JSON `{result, data_checked, period_start, period_end, notes}`; `result` is `not-checked`, `nothing-found`, `suspicious` or `confirmed`; dates `YYYY-MM-DD` | `{hunt, technique, result}`. One row per technique, replaced by the next save. Audited as `hunt.check`. `422` for a closed hunt, a technique not in the catalog or an end before the start |
| `GET /api/rules` | `kind` (`yara` or `sigma`) | `[{id, kind, name, source_url, licence, sha256, tlp, created_at, created_by, linked_to: [{kind, id}], body}]` you can see |
| `POST /api/rules` | JSON `{kind, name, body, source_url, licence, tlp}`; `body` up to 100,000 characters | The rule (`201`). Rules are stored as text and **never compiled or run**; a basic shape check (YARA `rule name { … condition: … }`, Sigma `title:` and `detection:`) catches pasting mistakes. `422` for a bad shape or the same text twice. Audited as `rule.add` |
| `GET /api/rules/{rule_id}` | - | One rule; `404` if unknown or above your limit |
| `DELETE /api/rules/{rule_id}` | - | `{deleted}`, with its links. Audited as `rule.delete` |
| `POST /api/rules/{rule_id}/links` | JSON `{target_kind, target_id}`: `group` (a `{ref}`), `technique` (`T1059.001`) or `document` (a report ID) | `{rule, kind, id}`. Audited as `rule.link`. `404` if you cannot see the target |
| `DELETE /api/rules/{rule_id}/links` | Same body | `{unlinked}`. Audited as `rule.unlink` |

## Sources and enrichment

| Route | Result |
| --- | --- |
| `GET /api/sources` | Registry entries with the last 5 runs each: `{key, name, url, note, category, optional, reuse, in_use, runs}`. `category` is `vulnerabilities`, `threat research` or `news`; `optional` sources start switched off; `in_use` says whether Insight may contact the source; `reuse` is `public` (the text may be exported) or `metadata` (exports leave the text out; [ADR 0021](adr/0021-threat-research-sources.md)). Sources are switched on and off in the workspace only |
| `POST /api/sources/{key}/sync` | `{"message": …}`. Keys: `cisa-kev`, `cisa-csaf`, `sans-isc`, `ncsc`, and the optional `talos`, `microsoft-ti`, `dfir-report`, `eset`, `securelist`, `the-record`. `404` unknown key, `409` another sync running or the source is switched off (nothing is contacted or recorded), `502` failure (recorded as an error run). |
| `GET /api/schedules` | `[{source_key, interval_minutes, next_run_at, updated_at}]` for every source. `interval_minutes` is `0` (syncs only when asked, the default), `60`, `360` or `1440`. Times are ISO-8601 UTC. |
| `PUT /api/schedules/{key}` | Body `{"interval_minutes": 0 \| 60 \| 360 \| 1440, "at": "HH:MM"}` (`at` optional, UTC: the time of day the syncs start from; every next sync keeps that slot); returns the schedule as above. **Browser session only**: API keys get `403` (how often Insight goes online by itself is the operator's decision; `insight schedule` on the host does the same). `404` unknown source, `409` turning on a schedule for a switched-off source, `422` other intervals. Without `at`, a schedule turned on runs within a minute, then every interval. Audited as `schedule.update`. Scheduled syncs run only in a process with `INSIGHT_RUN_JOBS=on` (the default for `insight serve`). |
| `GET /api/jobs?limit=20` | Recent background jobs (scheduled syncs, alert deliveries, automatic CVE lookups), newest first: `[{id, kind, key, status, attempts, run_after, started_at, finished_at, message, actor, created_at}]`. `status`: `queued`, `running`, `succeeded` or `failed`. A failed sync is tried again after 5, then 10 minutes, then marked `failed`. `limit` 1-100. Finished jobs are kept 30 days. |
| `POST /api/sources/sync-all` | `{"results": [{key, name, status, message}]}`: every source in use, in registry order, one at a time. `status` is `success` or `error`; a failing source does not stop the others and is recorded as an error run. Always `200` once it has run; `409` another sync running. |
| `POST /api/enrichment/{provider}/{cve}` | Provider JSON (`epss`, `nvd`), cached. Only the CVE number is sent. `422` invalid input or unknown CVE (checked first, so it uses no lookup window), `429` with `Retry-After` when the provider's window is taken: one request every 6.5 s at NVD (0.7 s with `INSIGHT_NVD_API_KEY`) and every 1 s at EPSS, shared with every other caller and with automatic lookups, so the wait may come from Insight itself. `502` provider failure, `403` for TLP-limited keys (a lookup can name a CVE from any report to a provider). |
| `GET /api/cves/{cve}/scores` | The cached scores, read without contacting anyone ([ADR 0023](adr/0023-automatic-cve-lookups.md)): `{cve, nvd, epss, nvd_checked_at, epss_checked_at}`. `nvd` is `{score, severity, version, vector, status, published, description, cwes}` or `null` (not looked up, or NVD has no record); `score` is the CVSS base score from the newest version NVD has (4.0, 3.1, 3.0, then 2), `null` when NVD has not scored it (`status` says why, such as `Awaiting Analysis` or `Rejected`). `epss` is `{probability, percentile, date}` (both 0-1; probability of exploitation attempts in the next 30 days) or `null`. A `*_checked_at` time with a `null` score means the provider was asked and has none. `404` unless a current report the caller may see mentions the CVE, so TLP-limited keys can use it for their own reports. |

Sync and enrichment are the only routes that cause outbound network traffic. A schedule makes the same syncs happen by
themselves; an unchanged feed is skipped (conditional requests with `If-None-Match` / `If-Modified-Since`, then a
payload hash), and its run says `Unchanged since the last sync.`

**Automatic CVE lookups** ([ADR 0023](adr/0023-automatic-cve-lookups.md)) are switched on per provider in the
workspace's *Sources* tab (off by default; there is no API for the switches). Then the job runner looks up, by
itself, each CVE that a current TLP:CLEAR or GREEN report mentions and that has no recent answer (EPSS after
7 days, NVD after 30), newest reports first, as `lookup` jobs in `GET /api/jobs` (key `epss` or `nvd`). CVEs
seen only in AMBER or RED reports are never looked up by themselves. The answers fill
`GET /api/cves/{cve}/scores`. This product uses the NVD API but is not endorsed or certified by the NVD.

## Workspace

| Route | Result |
| --- | --- |
| `GET /api/stats` | `{documents, entities, unreviewed, observations_unreviewed}` (current revisions only) |
| `GET /api/brief?days=7` | The intel brief shown on the landing page, built from the data (no AI): `{days, since, summary: [sentence], sections: [{title, items: [{text, document_id, entity, search}], empty}]}`. `days` 1-30 (default 7). `summary` is the executive summary, most important first. Sections: *Exploited now* (CVEs added to CISA KEV in the window, then KEV CVEs that new reports from other sources mention), *Most severe* (CVSS 9 or higher in new CISA advisories), *Your watch terms*, *Seen in several sources* (indicators in new reports from two or more sources), *Most-mentioned vendors*. An item opens `document_id`, looks up the indicator `entity`, or searches reports for `search`. "New" means published in the window: KEV entries by the day CISA added them, CISA advisories by their first release, other reports by the day Insight received them; the synthetic demo is left out. Built only from reports the caller may see (TLP limit). |
| `GET /api/landscape?days=7` | The threat landscape that opens the workspace ([ADR 0020](adr/0020-threat-landscape.md)), built from the data (no AI). `days` 1-30 (default 7); the period is compared with the 4 periods before it. `{days, since, compared_since, compared_periods, tlp, reports, sources, summary: [sentence], caveats: [sentence], threats: [threat], quieter: [threat], tactics: [tactic], brief}`. A threat is `{key, name, change: {label, current, usual}, sources, what, impact, check, reports: [{text, document_id}], words, techniques}`; `label` is `rising`, `new`, `steady`, `quieter` or `no-history` (nothing before the period to compare with); `usual` is reports per period before, `null` without history. A tactic is `{shortname, name, plain, change, techniques: [[id, name, reports]]}`. `brief` is the intel brief below for the same period. `tlp` is the most restrictive label of the reports counted: share no wider. Built only from reports the caller may see (TLP limit) |
| `GET /api/landscape/briefing?days=7` | The same as a Markdown briefing (`text/markdown`, attachment `insight-threat-landscape-7d.md`), marked with its TLP on the first and last lines; text from reports is escaped. Audited as `landscape.briefing` |
| `GET /api/audit` | Latest 200 audit events: `{action, object_id, detail, actor, created_at}`. Not available to TLP-limited keys |
| `GET /api/watch-terms` | `[{id, term}]` |
| `POST /api/demo` | `{"created": n}`; loads the synthetic demo, idempotent |
| `GET /health` | `{"status": "ok", "version": "…"}`, no authentication required |

Audit `actor`: `operator` (browser session or workspace), `api-key:<key ID>`, `cli`, `connector:<source key>`,
`system`, or empty for events recorded before schema revision `0005`.

Audit actions:
- `api_key.create`, `api_key.revoke` (detail: key ID, and the reason `rotated` or `revoked`), `mfa.pair`,
  `mfa.reset` (pairing an authenticator app, or forgetting it);
- `document.ingest`, `document.review`, `document.export`, `document.tlp_raised`;
- `ioc.export` (detail: counts, TLP, defanging and filters as JSON);
- `document.revision.supersede`, `document.revision.reactivate`;
- `observation.review`, `note.add`, `watch_term.create`, `watch_term.remove`;
- `document.delete` (manual procedure, RUNBOOK §9).

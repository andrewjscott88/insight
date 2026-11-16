# HTTP API (0.2.0)

JSON over HTTP on the same origin as the workspace. The API is **unversioned and intended for local automation
by the single operator**. Breaking changes are listed in `CHANGELOG.md` under "Upgrade notes". There is no
OpenAPI endpoint (disabled on purpose); this file is the reference.

## Authentication and request rules

1. `GET /login` returns a form containing `csrf_token` (also stored in the session cookie `insight_session`,
   HttpOnly, SameSite=Strict).
2. `POST /login` (form fields `csrf_token`, `password`) → `303` to `/` on success; `401` wrong password; `403`
   bad or missing CSRF token; `429` throttled (more than 30 failures per minute; each failure waits ~1 s).
3. `GET /api/session` → `{"csrf_token": "…"}`. Send it as `X-CSRF-Token` on **every non-GET** API request.
4. `POST /logout` (form field `csrf_token`) revokes the session server-side.

Every request is also checked as follows:
- The `Host` header must be in `INSIGHT_ALLOWED_HOSTS`, else `400`.
- An `Origin` header, if present, must equal `scheme://host`, else `403`. `Origin: null` is always refused.
- Request bodies are limited to 2 MB, else `413`.

Responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`
and, unless the route sets its own, `Cache-Control: no-store`.

Minimal client:

```python
import re, httpx
c = httpx.Client(base_url='http://127.0.0.1:8080')
token = re.search(r'name="csrf_token" value="([^"]+)"', c.get('/login').text).group(1)
c.post('/login', data={'csrf_token': token, 'password': PASSWORD})
c.headers['X-CSRF-Token'] = c.get('/api/session').json()['csrf_token']
```

All `/api/*` routes return `401` without a valid session and `403` for writes without the CSRF header.

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

## Entities

| Route | Parameters | Result |
| --- | --- | --- |
| `GET /api/entities` | `q` | Up to 200 `{id, kind, value, document_count}` sorted by kind and value |
| `GET /api/entities/{id}` | `offset` (0), `limit` (100, at most 200) | `{id, kind, value, document_count, offset, documents: [summaries]}`, newest first, paginated |

## Sources and enrichment

| Route | Result |
| --- | --- |
| `GET /api/sources` | Registry entries with the last 5 runs each |
| `POST /api/sources/{key}/sync` | `{"message": …}`. Keys: `cisa-kev`, `cisa-advisories`, `sans-isc`, `ncsc`. `404` unknown key, `409` another sync running, `502` failure (recorded as an error run). |
| `POST /api/enrichment/{provider}/{cve}` | Provider JSON (`epss`, `nvd`), cached. `422` invalid input or unknown CVE, `429` within 6.5 s of the last lookup, `502` provider failure. |

Sync and enrichment are the only routes that cause outbound network traffic.

## Workspace

| Route | Result |
| --- | --- |
| `GET /api/stats` | `{documents, entities, unreviewed, observations_unreviewed}` (current revisions only) |
| `GET /api/audit` | Latest 200 audit events |
| `GET /api/watch-terms` | `[{id, term}]` |
| `POST /api/demo` | `{"created": n}`; loads the synthetic demo, idempotent |
| `GET /health` | `{"status": "ok", "version": "…"}`, no authentication required |

Audit actions:
- `document.ingest`, `document.review`, `document.export`, `document.tlp_raised`;
- `ioc.export` (detail: counts, TLP, defanging and filters as JSON);
- `document.revision.supersede`, `document.revision.reactivate`;
- `observation.review`, `note.add`, `watch_term.create`, `watch_term.remove`;
- `document.delete` (manual procedure, RUNBOOK §9).

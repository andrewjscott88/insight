# HTTP API (1.0.0)

## Software

Software catalog entries are public reference data, but these routes require authentication like other API
reads. Analyst report/use links and name-match candidates respect the caller's TLP limit. IDs are ATT&CK
software IDs such as `S0154`; lowercase IDs are accepted. Hidden reports/links look missing (`404`), and a
write above the instance or key limit is refused (`403`). Browser writes require the normal CSRF token.

| Route | Result |
| --- | --- |
| `GET /api/software?q=&offset=0&limit=50` | `{software: [...]}`; catalog ID/name/alias substring search. Query at most 120 characters, nonnegative offset, limit 1–200. |
| `GET /api/software/{ref}` | Catalog context plus `reports`, `uses`, `candidates`, `reports_scanned`, `scan_capped`, and aggregate `tlp`. Missing items return `404`; retired items with a visible saved link retain their saved name/type. |
| `GET /api/software/{ref}/documents?offset=0&limit=50` | `{reports: [...]}`; visible explicit report links, newest link first; limit 1–200. Unknown IDs return an empty list. |
| `POST /api/software/{ref}/documents` | Body `{document_id, note?: "", tlp?: "CLEAR"}`. Note at most 2,000 characters; unknown fields refused. Returns `201` with `{id, software_id, document_id, note, tlp, created_at, created_by}`. Idempotent repeated writes; label never lowered. |
| `DELETE /api/software/{ref}/documents/{document_id}` | Remove a visible link, including a retired catalog link; `{removed: document_id}`. Missing/hidden link `404`. |
| `GET /api/documents/{document_id}/software` | `{software: [...]}` containing saved `{id, name, type, tlp, note, retired}` for up to 200 visible links. Missing/hidden report `404`. |

Catalog fields: `id`, `name`, `type` (`malware` or `tool`), `aliases`, `description`, `platforms`, `techniques`,
`groups`, `url`, `tlp`, `retired`. Context absent from an older library edition uses empty lists/text.
Detail returns at most 50 explicit report links, 50 actor/campaign use decisions and 50 candidates. Report
links contain `document_id`, `title`, report `created_at`, `linked_at`, `note`, effective `tlp`, and saved
`software_id`, `software_name`, `software_type`. Use decisions contain `kind`, subject `ref`, `name`, `tlp`,
`linked_at`, and saved software name/type. Candidates carry `document_id`, `title`, `tlp`, `created_at`,
`source_name`, matched `name`, and `evidence` (empty for metadata-only sources). They check at most the newest
5,000 visible current reports with the existing whole-word matcher; a match never adds a link.

The existing `/api/actors/{ref}/links` and `/api/campaigns/{ref}/links` accept `target_kind: "software"` with
`target_id: "S0154"` and a TLP label. Their GET results and DELETE paths use the same kind. Only explicit
analyst actor/campaign links produce STIX `uses`, never catalog claims or report co-occurrence. Mutations are
audited as `software.link`/`software.unlink` or the existing `actor.link`/`campaign.link` actions.

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
   token; `429` a wrong password after 30 failures in the last minute (each failure waits ~1 s; the right password always signs in); `503` MFA is on but no
   authenticator app is paired (sign-in locked). MFA is off by default (`INSIGHT_MFA=on` or `make mfa-enable`
   turns it on); then `otp` is the 6-digit code from the app, and each code works once.
3. `GET /api/session` returns `{"csrf_token": "…", "version": "…", "role": "admin", "actor": "operator"}` for
   the signed-in session. Send the `csrf_token` value as `X-CSRF-Token` on **every non-GET** API request. The
   `version` field is the running Insight version; `role` and `actor` say what you may do and how the audit log
   names you (see [Roles](#roles)).
4. `POST /logout` (form field `csrf_token`) revokes the session server-side.
5. **Sign-in through the identity provider** ([ADR 0046](adr/0046-sso-sign-in-and-roles.md)), when
   `INSIGHT_OIDC_ISSUER` is set (otherwise these routes answer `404`):
   - `GET /login/sso` stores a fresh state, nonce and PKCE verifier in the session cookie and answers `303`
     to the provider's authorisation endpoint (`502` with the sign-in page if the provider cannot be reached).
   - `GET /login/sso/callback?code=…&state=…` is where the provider sends the browser back. It only answers a
     page that posts the code and state on, because the `SameSite=Strict` cookie is left out of requests that
     come from another site.
   - `POST /login/sso/callback` (form fields `code`, `state`, or `error`) checks that the state matches this
     browser's, at most ten minutes old and used once; exchanges the code with the verifier; checks the ID
     token; then signs the person in (`303` to `/`). A person with no role yet can sign in but has no access
     until an admin gives them one. Refusals answer `400` (`403` for a disabled person), and repeated failures
     from one address get `429`.
   - With `INSIGHT_SSO_ONLY=on`, the password form is gone and `POST /login` answers `403`.

**Temporary password-free mode:** with the explicit default-off `INSIGHT_DEV_NO_AUTH=on`, `GET /login`
creates the normal operator session and CSRF token, then returns a `200` continuation page instead of a
password form. The page checks `/api/session` before navigating to `/`, with a fixed link as a fallback.
Ending the HTTP redirect chain lets the browser send its `SameSite=Strict` cookie after a cross-site entry.
An already authenticated `GET /login` still returns `303` to `/`.
Anyone who can reach the site can obtain this full-access session. Direct API calls without a valid session
or key still return `401`, and session-authenticated writes still require `X-CSRF-Token`; API-key behavior
is unchanged. Enabling MFA and this mode together is rejected. Turning the mode off and restarting with
the changed environment invalidates its sessions and restores password sign-in. See the
[runbook](RUNBOOK.md#temporary-password-free-access) for enable/restore checks and the public-access tradeoff.

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

### Roles

Every request also needs a role that allows its route ([ADR 0046](adr/0046-sso-sign-in-and-roles.md)). There
are three fixed roles; each may do everything the one before it may:

| Role | May |
| --- | --- |
| `viewer` | Every `GET` route, and `POST /mcp` (fixed read-only tools) |
| `analyst` | Also intelligence work: add and import reports; review reports, indicators and verdicts; credibility and source ratings; notes, ATT&CK tags, groups, campaigns and links; products; requirements and RFIs; hunt packages, hunts, rules and sightings; *Sync now*; an approved outside lookup |
| `admin` | Also settings: operator sources, schedules and the demo reports (in the workspace also: switching sources and lookup providers on or off, alert destinations, and people in Settings → People) |

- The password sign-in is the built-in operator, an `admin`, so a single-operator instance works as before.
  People who sign in through the organisation's identity provider (TIP 3.4b) get their role from an admin
  (Settings → People, or `insight users role` on the host) or from provider groups. People are managed only
  there: no API route changes a person, and no key is an `admin`.
- A `read` or `read-feedback` key acts as a `viewer` (`read-feedback` keeps its two writes) and a `read-write`
  key as an `analyst`. No key is ever an `admin`.
- A role below the route's gets `403 {"detail": "Your role does not allow this"}`. Each route's permission is
  listed in `src/insight/web/route_permissions.py`; a route missing from that table is refused to everyone.
- Roles do not change TLP: everyone signed in reads up to the instance limit.
- A visitor to the read-only public view (`INSIGHT_PUBLIC_VIEW=on`) is not signed in: every API route still
  answers `401` without a session or a key.
- `actor` is how audit events name the caller: `operator`, `user:<id>` for a person, `api-key:<key ID>`.

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
| Writes (`POST`) | Yes | Only with `--access read-write`; `--access read-feedback` may send requests for information (`POST /api/rfis`) and sightings (`POST /api/sightings`) and nothing else |
| `GET /api/session`, the workspace UI | Yes | No (`403`) |
| Role ([Roles](#roles)) | The operator is an `admin`; a person has their own | `read`, `read-feedback`: `viewer`; `read-write`: `analyst` |
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
| `ioc-export` | `GET /api/iocs/export`, `GET /api/iocs/stix`, `GET /api/iocs/blocklist` | 30 per hour |
| `taxii` | TAXII collection reads (`objects/`, `manifest/`, single objects and versions) | 240 per hour |
| `mcp` | All `POST /mcp` messages, per API key | 120 per minute |
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
| `id`, `entity_id`, `kind`, `value` | Kinds: `cve url domain ip cidr email md5 sha1 sha256 sha512`. A `cidr` value includes its network prefix length. An `email` value preserves the mailbox case and uses a lower-case domain. |
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

### `GET /api/iocs/stix`

Download a validated STIX 2.1 bundle as `application/stix+json;version=2.1`. Use the same filters as the
IOC export below. The request's `max_tlp`, the instance ceiling and the API key's ceiling all apply.
Use `evidence=false` to omit excerpts. A request with `defang=true` returns 422.
Each included report references its active ATT&CK techniques from the current catalog as `attack-pattern` objects.
Each successful request records `stix.export` with its bundle UUID. Empty selections return a valid empty bundle.
[Object mapping and handling rules](IOC_EXPORT.md#stix-21-export)

### `POST /api/documents/pdf`

Send original PDF bytes as `application/pdf`. A read-write bearer key or signed-in session with
`X-CSRF-Token` is required. Provide the report metadata in the `X-Insight-Document` header as unpadded
base64url-encoded UTF-8 JSON. Required strings are `title` and `source_name`. Optional strings are
`source_url` and `tlp`, which defaults to AMBER. Header encoding keeps the metadata out of URLs and supports
international text. Use HTTPS when accessing a remote instance. [Upload example](API_GUIDE.md#documents-reports)

The workspace accepts the same fields under **Add intelligence**. On the server, run
`insight import-pdf FILE --title "Advisory" --source-name "Publisher" --tlp GREEN`. The CLI defaults to the
file’s name without its extension for the title and **Local PDF** for the publisher. Provide the publisher's
label when submitting a document. Printed or scanned markings depend on the PDF’s available text. Detected
higher TLP markings raise the label as on pasted documents. Both the instance limit and the key limit apply.

A successful response contains `document_id`, `created` and `file_sha256`. Identical file bytes and report
metadata reuse the existing report. Different files with identical extracted text retain separate identities.
`GET /api/documents/{id}` and the single-report JSON export include `attachment.sha256`, `media_type`,
`page_count` and `size_bytes` for a PDF. The original-file SHA-256 is distinct from the existing `content_hash`
of the normalized report text. The reader shows both under **Where this report came from**. Report deletion
removes the attached metadata in the same transaction. The audit entry records the original digest and size.

The Linux worker extracts embedded text. Only the report text and provenance are retained. Text order follows
the PDF and may differ from the printed layout. OCR, encrypted documents and image-only scans are unsupported.
Limits per import are 2,000,000 input bytes, 100 pages, 200,000 extracted characters, 256 MiB worker memory,
five CPU seconds and ten elapsed seconds. Each server process admits two concurrent PDF workers. Invalid PDFs,
empty text, parsing limits or a disallowed label return 400 with no report stored. An oversized HTTP body
returns 413, a different content type returns 415, and an unavailable or busy sandbox returns 503.

### `POST /api/import/stix`

Send a local STIX 2.1 bundle as the request body with `Content-Type: application/json` or
`application/stix+json`. Use a read-write bearer key or an authenticated browser session with
`X-CSRF-Token`. The workspace offers **Import a STIX bundle** in the ingest dialog. On the server, run
`insight import-stix FILE`. All three paths apply the same import and handling rules.

The result contains `bundle_id`, `bundle_sha256` (the submitted bytes), `reports` (the reports processed),
`created` (new report revisions) and `document_ids`. A repeated submission of unchanged reports returns
zero new revisions. Import keeps the original UUID for the first revision of each STIX Report. A changed
version receives a new Insight document ID with a link to the revision it supersedes. A conflicting UUID
from another source is refused. Each accepted report has a source ID and an audit receipt with the bundle
ID and SHA-256. Report text, extracted values and mentions use Insight's existing deletion path.

Import accepts Reports that reference simple Indicator equality patterns, CVE Vulnerabilities and
catalog-backed ATT&CK Attack Patterns by reference. Supported values are IPs, CIDRs, domains, email
addresses, URLs, MD5, SHA-1, SHA-256 and SHA-512 hashes, and CVE IDs. Standalone Indicators and CVEs are
grouped under one report identified by the bundle. Identity objects can supply publisher metadata. The
importer validates data locally and reads no external URLs. Compound patterns, time-limited indicators,
revoked objects, unsupported object types and unresolved report references cause the entire import to fail.

Unmarked data defaults to AMBER. A report inherits the strongest TLP of its own text and markings, linked
observations and publisher identity. The standard TLP 1.0 and 2.0 marking IDs are supported. Unknown or
granular markings are refused. Both `INSIGHT_MAX_TLP` and the API key's ceiling apply. Existing publisher
restrictions and TLP labels are protected across revisions. Metadata-only reports retain their titles,
publisher links and observations. Their excerpts are discarded.

An upload can contain up to 2,000,000 bytes, 2,000 objects, 200 Reports and 10,000 references. Individual
indicator values are capped at 2,000 UTF-8 bytes. A malformed or unsupported bundle returns 400 and stores
zero documents from that request. Oversized HTTP bodies return 413 and unsupported content types return 415.

### `GET /api/iocs/export`
One JSON file listing every indicator across the selected reports, each **once**, with the reports that mention
it. Returned as an attachment `insight-iocs-<YYYYMMDDTHHMMSSZ>.json`; audited as `ioc.export`. The workspace
(**Export IOCs**) and `insight export-iocs FILE` produce the same file.

Query parameters (all optional; values are **case-sensitive**):

| Parameter | Default | Meaning |
| --- | --- | --- |
| `kind` (repeatable) | all | `cve` `url` `domain` `ip` `cidr` `email` `md5` `sha1` `sha256` `sha512` |
| `review_status` (repeatable) | `unreviewed`, `accepted` | Review state of each **mention** (`unreviewed` / `accepted` / `rejected`); rejected mentions are left out unless requested |
| `max_tlp` | none | Include only reports labelled at or below this level, e.g. `GREEN` before sharing with a community |
| `defang` | `false` | Defang values, report titles and evidence: `hxxps://evil[.]example/a[.]php`, `evil[.]example`, `192[.]0[.]2[.]8`, `2001[:]db8[:][:]1`, plus e-mail domains, CIDR ranges and file-like names in text (see the guide, §7) |
| `evidence` | `true` | `false` leaves out the report text around each mention (`evidence: null`). Recommended when sharing: excerpts can carry victim details or indicators an analyst rejected |
| `document_id` (repeatable) | all reports | Only these reports. A chosen report is included even if it is a superseded revision |
| `q` | none | Inbox search text (literal, folded like the inbox). At most 200 characters: longer text is rejected with `422`, whereas `GET /api/documents` shortens it |
| `status` | any | The **report's** triage status: `new` / `reviewing` / `reviewed`. Not the mention review state |
| `verdict` (repeatable) | all | Only indicators with this verdict: `unknown` `benign` `suspicious` `malicious` |
| `exclude_flag` (repeatable) | none | Leave out indicators with this warning flag: `non-routable` `documentation` `reserved-name` `common-benign` `personal-data` |
| `tlp` | any | Only reports with **exactly** this label (compare `max_tlp`) |
| `include_superseded` | `false` | Also include superseded revisions of synced items |

Encode `+` in `AMBER+STRICT` as `%2B` (`max_tlp=AMBER%2BSTRICT`): a literal `+` in a query string means a space
and fails validation. HTTP clients that take a parameter list (httpx `params`, `curl --get --data-urlencode`)
encode it for you.

Example (using the client above):

```python
r = c.get(
    '/api/iocs/export', params=[('kind', 'ip'), ('kind', 'domain'), ('max_tlp', 'GREEN'), ('defang', 'true')]
)
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
| `flags` | Warning flags include `non-routable`, `documentation`, `reserved-name`, `common-benign`, and `personal-data` (every e-mail address) |
| `sources` | Included reports that mention it, oldest first (see below) |

Each source: `document_id`, `title`, `source_name`, `source_url`, `tlp`, `status` (the report's **triage**
status), `created_at`, `is_current` (`false` only for superseded revisions), `extractor_version` (e.g.
`regex-v4` for the extractor that recognizes e-mail addresses), `mentions` (included mentions in that report) and
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

E-mail addresses and network ranges are available through `/api/iocs/export` with `kind=email` or `kind=cidr`. The blocklist excludes both kinds.

`format=txt` (default): one value per line, sorted, never defanged. `format=csv`: `value,kind,decided_at,
expires_at,tlp` with a header row; a cell that would start with `=`, `+`, `-`, `@`, a tab or a carriage return
gets a leading `'` so spreadsheets never run it as a formula (code review N1). Audited as `ioc.blocklist`; shares
the `ioc-export` budget.

For IPs and domains, `format=suricata` or `format=snort` downloads a plain-text `.rules` file. These formats
return 422 when the selection is empty or the kind is unsupported. See [network sensor rules](IOC_EXPORT.md#network-sensor-rules)
for signatures, DNS coverage and local rule IDs.

## MCP (read-only)

`POST /mcp` accepts stateless JSON-RPC 2.0 using protocol `2026-07-28`: `server/discover`, `ping`,
`tools/list` and `tools/call`. Legacy `2025-11-25` also supports `initialize` and
`notifications/initialized`. `GET /mcp` returns `405`.
API keys only; browser sessions are refused. The exact MCP POST accepts all API-key access levels, because
the fixed tools only read. Every intelligence read applies the key's TLP ceiling and publisher reuse rules.

Send `Content-Type: application/json` and `Accept: application/json, text/event-stream`. Modern requests
require matching protocol/method/name headers and per-request `_meta`; legacy requests send
`MCP-Protocol-Version: 2025-11-25` after initialization. Results include identical structured JSON and text,
explicit truncation and a conservative `sharing_tlp`. Tool errors set `isError`; missing and hidden IDs
give the same `status: 404` result. No write
tools, OAuth, transport sessions, STIX, resources, prompts, sampling, elicitation or model calls.

Authentication errors use `401`, Origin errors `403`, unsupported protocol headers `400`, media errors
`406`/`415`, body limits `413`, and the dedicated per-key budget `429`. Protocol errors use JSON-RPC codes
`-32700` (parse), `-32600` (request), `-32601` (method), and `-32602` (parameters/unknown tool).
Modern header mismatches use `400` / `-32020`; unsupported revisions use `400` / `-32022` with supported
versions. Unknown modern methods use `404` / `-32601`.
The request limit is 65,536 bytes. [MCP.md](MCP.md) lists tool arguments, response limits, audit semantics
and client requirements; [API_GUIDE.md](API_GUIDE.md#read-only-mcp) has curl examples.

## TAXII 2.1 (read-only)

API keys only (`Authorization: Bearer <key>`); a signed-in browser gets `403`. Responses use
`application/taxii+json;version=2.1` and TAXII error messages. Full guide: [TAXII.md](TAXII.md).

| Method | Path | Returns |
| --- | --- | --- |
| `GET` | `/taxii2/` | Discovery: the API root |
| `GET` | `/taxii2/insight/` | API root information |
| `GET` | `/taxii2/insight/collections/` | The fixed collections: *Reviewed indicators* (with ATT&CK techniques, actors and campaigns) and *CISA Known Exploited Vulnerabilities* |
| `GET` | `/taxii2/insight/collections/{id}/` | One collection |
| `GET` | `/taxii2/insight/collections/{id}/objects/` | Objects: `added_after`, `limit` (1 to 1,000), `next`, `match[id]`, `match[type]`, `match[version]`, `match[spec_version]`. Audited as `taxii.read` |
| `GET` | `/taxii2/insight/collections/{id}/manifest/` | The same selection as IDs, `date_added` and versions |
| `GET` | `/taxii2/insight/collections/{id}/objects/{object_id}/` | One object |
| `GET` | `/taxii2/insight/collections/{id}/objects/{object_id}/versions/` | Its version (Insight keeps the current one) |

## Ranked search and the link graph

[ADR 0027](adr/0027-ranked-search-and-link-graph.md). Both read only what the caller's TLP limit allows.

| Method | Path | Returns |
| --- | --- | --- |
| `GET` | `/api/search?q=` | Reports matching **every word** of `q` (quotes keep a phrase together; case, accents and width ignored), best first: `terms`, `total`, `capped` (more than 5,000 matched; the newest 5,000 were ranked) and `results`, each a report summary plus `score`, `matched_in_title` and `snippet`. Filters `status`, `tlp`, `include_superseded`; `offset`, `limit` (1 to 200, default 50). |
| `GET` | `/api/graph?node=&depth=1` | Nodes and edges within `depth` (1 or 2) links of `node`: `report:<id>`, `indicator:<entity id>`, `technique:T1059`, `group:G0016`, `actor:<id>` or `campaign:<id>`. Edges are `mentions` (not rejected), `tagged` and `linked` (an analyst's link). At most 25 neighbours per node (`truncated`) and 150 nodes (`capped`). `404` for a node that does not exist or is above the caller's TLP limit. |

`GET /api/documents?q=` keeps its literal substring match, newest first.

## Entities

| Route | Parameters | Result |
| --- | --- | --- |
| `GET /api/entities` | `q` | Up to 200 `{id, kind, value, document_count}` sorted by kind and value |
| `GET /api/entities/{id}` | `offset` (0), `limit` (100, at most 200) | `{id, kind, value, flags, assessment, first_seen_at, last_seen_at, document_count, offset, documents: [summaries]}`, newest first, paginated. `assessment` is `null` or `{verdict, reason, tlp, valid_until, decided_at, actor}`; a TLP-limited key sees it only within its limit. `exploit` is the CVE's exploit context as in `GET /api/cves` (`null` for other kinds, or when nothing is known). `first_seen_at` / `last_seen_at`: when the oldest and newest report **you can see** that mentions it was added. `confidence`: see [Confidence and source reliability](#confidence-and-source-reliability) |
| `POST /api/entities/{id}/assessment` | JSON `{verdict, reason, tlp, valid_until}`: `verdict` `unknown` (clears) / `benign` / `suspicious` / `malicious`; `reason` up to 2,000 characters; `tlp` (default `AMBER`) labels the reason; `valid_until` a date, today or later, or omitted | The recorded assessment, or `{"verdict": "unknown"}`. Audited as `entity.assess`. `404` if you cannot see the entity; `403` if a TLP-limited key would set, or replace, a verdict above its limit |

## Infrastructure pivots (TIP 4.6)

`GET /api/pivots?value=...` returns the fresh cached results for a reviewed indicator in a current
TLP:CLEAR report. Each result names `provider`, `value`, `fetched_at`, `found` and bounded provider metadata.
An eligible subject without a fresh cache returns `[]`; a missing, hidden or ineligible subject returns
`404`. Reads never contact a provider. Results expire after 24 hours and eligibility is rechecked each time.

`POST /api/pivots/{provider}` accepts `{"value":"example.com","approved":true}`. Providers
are `rdap` (domain or public IP), `asn` (public IP), `crtsh` (domain), and `circl` (domain or public IP).
Only `circl` requires credentials configured on the host. Extra fields are refused. An uncached lookup needs
`approved: true`; each provider must be enabled in Settings first. Only an operator session with CSRF or an
unlimited read-write API key may request it. Limited/read-only keys get `403`, disabled providers `503`,
missing/ineligible subjects `404`, invalid/unapproved requests `422`, throttled requests `429` with
`Retry-After`, and failed or unrelated provider answers `502`. A fresh cache is returned without disclosure.

RDAP metadata includes registry status/dates, public registrar IDs and name servers, or network name,
handle, first/last address and country. No contact data is kept. RIPEstat returns prefix and a list of origin
network numbers and holders. `nodes` describes provider context for the link map, never new observations.
`GET /api/graph` can include `domain`, `address`, `as`, `certificate_name` and `name_server` node types, with
provider and fetch date in edge labels. Hidden known indicators are not linked. All graph caps still apply.

A certificate transparency result has `provider`, `value`, `found`, `fetched_at`, `truncated`, `certificates` and `nodes`.
`certificates` contains at most 500 distinct `{name, issuer, not_before, not_after}` records; dates are UTC ISO
strings. `nodes` contains `{type:"certificate_name", value}` graph context. No matches means empty lists and
`found=false`. Renewed names keep their newest validity record. Every provider row must relate to the query.
Settings switches have no API; they are audited workspace controls. Nothing is scheduled.
[Limits and provider conditions](INFRASTRUCTURE_PIVOTS.md).

A passive DNS result has `provider`, `value`, `found`, `fetched_at`, `truncated`, `records` and `nodes`.
`records` holds at most 500 `{name, type, answer, first_seen, last_seen, count}` records; dates are UTC ISO
strings and unknown counts are null. Name and answer preserve provider orientation. Graph nodes contain
validated standalone domain/address values only. No matches means empty lists and `found=false`.
The Settings switch has no API. Credentials stay on the host, outside request bodies and cached metadata.
[Exact merge rules, passive-only behaviour and provider conditions](INFRASTRUCTURE_PIVOTS.md).


## ATT&CK techniques

MITRE ATT&CK® Enterprise, Mobile and industrial-control-system techniques on reports
([ADR 0019](adr/0019-attack-techniques.md), [ADR 0042](adr/0042-mobile-and-ics-attack-catalogs.md)). A report is tagged
with every technique ID written in its text (`T1059`, `T1059.001`) that is in the bundled catalog (`source:
report`); analysts add and remove techniques by hand (`source: analyst`). A new revision of a synced item keeps
the analyst's additions and removals. Insight never guesses a technique from prose and never infers an actor.
Summaries and pivots count **current** reports you can see.

| Route | Parameters | Result |
| --- | --- | --- |
| `GET /api/attack/techniques` | `q` (ID prefix or name, up to 100 characters), `limit` (50, at most 200), `domain` (`enterprise`, `mobile` or `ics`; default `enterprise`) | `{version, domain, techniques: [{id, name, tactics, url, domain}]}` from the selected bundled catalog, by ID |
| `GET /api/attack/summary` | `days` (30; `0` for all time, at most 3650), `domain` (default `enterprise`) | `{version, domain, period, techniques: [{id, name, tactics, url, domain, reports, last_seen_at}]}`, most reports first within the selected domain |
| `GET /api/attack/techniques/{technique_id}/documents` | `days` (0), `offset` (0), `limit` (25, at most 200) | `{id, name, tactics, url, domain, offset, documents: [summaries]}`, newest first; `404` for an ID not in any catalog |
| `GET /api/attack/navigator` | `days` (30; `0` for all time), `domain` (default `enterprise`) | An [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer (format 4.5) of the selected domain, each technique scored by its number of reports, as an attachment. Audited as `attack.navigator`, including the domain |
| `GET /api/documents/{id}/techniques` | - | `[{id, name, tactics, url, domain, source, evidence, actor, created_at, in_catalog}]` by ID; `domain` is null for retired/unknown IDs; `404` if you cannot see the report |
| `POST /api/documents/{id}/techniques` | JSON `{technique_id}` (`T1486` or `T1059.001`) | The tag. Restores a removed one; a tag that already exists is returned unchanged. Audited as `technique.tag`. `422` for an ID not in the catalog, `404` if you cannot see the report |
| `DELETE /api/documents/{id}/techniques/{technique_id}` | - | `{removed}`. Later revisions keep it removed. Audited as `technique.untag`. `404` if it is not tagged or you cannot see the report |

The default Enterprise summary also retains stored IDs absent from every current catalog, with their
ID, report count and last-seen time. These retired/unknown tags have no saved domain; Mobile and ICS
summaries exclude them, and Navigator layers omit them. The report still retains its original tag.

## Industry threats and threat guides

Industry threat profiles and actor threat guides ([ADR 0025](adr/0025-threat-guides.md),
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
| `POST /api/campaigns` | `name`, optional `aliases`, `description`, `tlp` | Creates an analyst campaign and returns its `id` |
| `GET /api/campaigns` or `GET /api/campaigns/{id}` | List accepts `offset` and `limit` (1–200) | Visible campaigns or the selected campaign |
| `GET /api/actors/{id}/links` or `/api/campaigns/{id}/links` | Optional `offset` and `limit` (1–200) | `links` with target kind, target ID, name, and effective TLP |
| `POST /api/actors/{id}/links` or `/api/campaigns/{id}/links` | `target_kind` (`document`, `indicator`, `technique`), `target_id`, optional `tlp` (default AMBER) | Links the report UUID, indicator entity UUID or ATT&CK technique ID to a local record. Saving the same link can raise its label. |
| `DELETE /api/actors/{id}/links/{target_kind}/{target_id}` or `/api/campaigns/{id}/links/{target_kind}/{target_id}` | Both ends and the link must be visible | Removes the analyst’s link |
| `GET /api/actors` | `q` (ID, name or alias, up to 100 characters), `limit` (50, at most 200) | `{library, groups: [{ref, kind, name, aliases, url, industries, techniques}], actors: [{ref, kind, name, aliases, description, attack_group_id, tlp, created_at, created_by}]}` |
| `POST /api/actors` | JSON `{name, aliases, description, attack_group_id, tlp}` (`aliases` up to 20; `attack_group_id` optional, `G` and four digits) | The actor (`201`). Audited as `actor.create`. `422` for an `attack_group_id` not in the library; `403` for a label above your limit or the instance limit |
| `GET /api/actors/{ref}` | - | `{ref, kind, name, aliases, description, tlp, attack_group, industry_claims, your_industry_decisions, linked_reports}`; `404` if unknown or above your limit |
| `POST /api/actors/{ref}/documents` | JSON `{document_id, note}` | `{ref, document_id, note}` (`201`). Links a report to the group: your decision. Linking twice returns the same link. Audited as `actor.link`. `404` if you cannot see the group or the report |
| `DELETE /api/actors/{ref}/documents/{doc_id}` | - | `{unlinked}`. Audited as `actor.unlink` |
| `POST /api/actors/{ref}/industries` | JSON `{industry, decision, citation_url, document_id, reason, tlp}`. `added` needs an HTTPS `citation_url` or a `document_id` you can see; `removed` needs a `reason` | `{ref, industry, decision, tlp}`. One decision per group and industry; a new one replaces it. Audited as `actor.industry`. `422` without a citation or reason, `403` above your limit (also for replacing a decision labelled above it) |
| `GET /api/actors/{ref}/guide` | `format` (`json` or `md`), `max_tlp` (leave out anything above it), `linked_only` (default `true`: the sweep list takes indicators only from reports linked to the group; `false` also takes them from reports that only name it; such reports are listed either way) | The threat guide: JSON format `insight-threat-guide-1` `{format, generated, generator, tlp, reader_limit, group, industries, removed_industries, regions, campaigns, techniques, software, mitigations, reports, reports_naming_group, hunt: {label, hypotheses, sweep, rules, records}, sources, notice}`, or a Markdown attachment with the TLP label first and last. Audited as `actor.guide` |
| `GET /api/actors/{ref}/navigator` | `max_tlp` | An ATT&CK Navigator layer (format 4.5) of the group's techniques, scored 1 for each of: in ATT&CK, in a linked report. The label is in the layer's metadata and description. Audited |
| `GET /api/actors/{ref}/sweep` | `format` (`json` or `csv`), `max_tlp`, `linked_only` (default `true`) | The indicator sweep list (format `insight-sweep-v1`, with `linked_only` saying which reports it used): accepted IPs, domains, URLs and hashes from reports linked to the group (and, with `linked_only=false`, reports that only name it), without indicators flagged as private or documentation, benign verdicts or expired verdicts. CSV starts with a `# TLP:` line; cells are protected against spreadsheet formulas. Things to search for, not proof of the group. Audited |
| `GET /api/actors/{ref}/hunts` | - | `[{id, ref, title, status, summary, tlp, created_at, updated_at, created_by, checks: [{technique, result, data_checked, from, to, notes}]}]` you can see, newest first |
| `POST /api/actors/{ref}/hunts` | JSON `{title, tlp}` | The hunt (`201`), `status: open`. Audited as `hunt.start`. `403` above your limit or the instance limit |
| `GET /api/hunts/{hunt_id}` | - | One hunt, as above; `404` if unknown or above your limit |
| `PUT /api/hunts/{hunt_id}` | JSON `{status, summary}` (`open` or `closed`) | The hunt. Audited as `hunt.update` |
| `PUT /api/hunts/{hunt_id}/checks/{technique_id}` | JSON `{result, data_checked, period_start, period_end, notes}`; `result` is `not-checked`, `nothing-found`, `suspicious` or `confirmed`; dates `YYYY-MM-DD` | `{hunt, technique, result}`. One row per technique, replaced by the next save. Audited as `hunt.check`. `422` for a closed hunt, a technique not in the catalog or an end before the start |
| `GET /api/rules` | Optional `kind` (`yara`, `sigma`, `suricata` or `snort`), optional `target_kind` and `target_id` together | `[{id, kind, name, source_url, licence, sha256, tlp, created_at, created_by, linked_to: [{kind, id}], body}]` you can see |
| `POST /api/rules` | JSON `{kind, name, body, source_url, licence, tlp}`; `body` up to 100,000 characters | The rule (`201`). Rules are stored as text and **never compiled or run**; a basic shape check (YARA `rule name { … condition: … }`, Sigma `title:` and `detection:`, Suricata and Snort an action then options with a numeric `sid`) catches pasting mistakes. `422` for a bad shape or the same text twice. Audited as `rule.add` |
| `GET /api/rules/{rule_id}` | - | One rule; `404` if unknown or above your limit |
| `GET /api/rules/{rule_id}/export` | - | ZIP attachment with the rule file and a JSON manifest containing its source, licence, TLP and SHA-256. Returns `404` above the instance or key limit. Audited as `rule.export` |
| `DELETE /api/rules/{rule_id}` | - | `{deleted}`, with its links. Audited as `rule.delete` |
| `POST /api/rules/{rule_id}/links` | JSON `{target_kind, target_id}`: `group` (a `{ref}`), `technique` (`T1059.001`), `document` (a report ID), `cve` (a CVE ID) or `malware` (a family label) | `{rule, kind, id}`. Audited as `rule.link`. `404` if you cannot see the target |
| `DELETE /api/rules/{rule_id}/links` | Same body | `{unlinked}`. Audited as `rule.unlink` |

## Hunt packages

[ADR 0034](adr/0034-hunt-packages.md). A hunt package is one hypothesis for a hunt tool, with the ATT&CK
techniques, indicators, detection rules and reports behind it. Its `tlp` is the strictest of its text, its
group and every item ever added, and removing an item does not lower it. `draft` packages stay in Insight;
`published` ones are served in the *Hunt packages* TAXII collection ([TAXII](TAXII.md)); `retired` ones are
served as revoked and refuse changes (`409`) until published again. A caller sees and changes only packages
within its limit (the stricter of the instance and key limits), and can only add what it can see. Every change
is audited on the package.

| Route | Input | Returns |
| --- | --- | --- |
| `GET /api/hunt-packages` | `status` (`draft`, `published`, `retired` or `all`; default `all`) | `{hunt_packages: [{id, title, status, tlp, group_ref, techniques, indicators, rules, documents, created_at, updated_at, published_at}]}`, most recently changed first (at most 200); the four counts are items of each kind |
| `POST /api/hunt-packages` | `{title, hypothesis, group?, tlp?, items?: [{kind, target_id}]}` (`group` an ATT&CK group ID or one of your actor IDs; `tlp` default AMBER; at most 100 items here) | `201` and the package `{id, title, hypothesis, group_ref, status, publication, tlp, created_at, updated_at, published_at, created_by}`, as a draft. Audited as `hunt_package.create` |
| `GET /api/hunt-packages/{id}` | - | The package with `group_name` and `items: [{id, kind, target_id, name, tlp, added_at, added_by}]` |
| `PATCH /api/hunt-packages/{id}` | Any of `{title, hypothesis, group, tlp}`; `group: null` removes the group | The package. A lower `tlp` stops at the items, the group and the TLP markings in the text. Audited as `hunt_package.update` |
| `DELETE /api/hunt-packages/{id}` | - | `{deleted}` for a draft or retired package (its items go, what they point to stays); `409` for a published one: retire it first, so hunt tools learn it was withdrawn. Audited as `hunt_package.delete` |
| `POST /api/hunt-packages/{id}/items` | `{kind, target_id}`: `technique` (`T1059.001`), `indicator` (an indicator ID), `rule` (a rule ID) or `document` (a report ID, as context) | `201` and the item; adding it twice changes nothing. Raises the package label to the item's own. At most 500 items. Audited as `hunt_package.item.add` |
| `DELETE /api/hunt-packages/{id}/items/{item_id}` | - | `{removed}`. A published package keeps at least one technique, indicator or rule (`409`). Audited as `hunt_package.item.remove` |
| `POST /api/hunt-packages/{id}/publish` | - | The published package; `409` without a technique, indicator or rule. Publishing a retired package again gives its STIX objects new IDs. Audited as `hunt_package.publish` |
| `POST /api/hunt-packages/{id}/retire` | - | The retired package (served as revoked). Audited as `hunt_package.retire` |
| `GET /api/hunt-packages/{id}/stix` | - | The package as a validated STIX 2.1 bundle attachment, in any status (check a draft before publishing it): a `grouping` (context `suspicious-activity`, description the hypothesis), an `attack-pattern` per technique, an `indicator` or `vulnerability` per indicator, an `indicator` per rule (`pattern_type` `sigma`, `yara`, `suricata` or `snort`, the rule text as `pattern`), `indicates` relationships from rules to the package techniques they are linked to, and the TLP marking. The group and the reports are external references; report text is never included. `422` with nothing huntable in it. Audited as `hunt_package.export` |

## Sightings

[ADR 0035](adr/0035-sightings.md). A hunt tool saw a known indicator in its own data. Sightings are the
strongest confidence signal: each place an indicator was seen counts as one completely reliable source in
`confidence` (`kind: sighting`), ageing from when it was last seen. A sighting's `tlp` defaults to AMBER and
rises with TLP markings in its text and with its hunt package's label. A caller sees a sighting only within its
limit, and only for an indicator a report within its limit mentions.

| Route | Input | Returns |
| --- | --- | --- |
| `POST /api/sightings` | `{value, kind?, first_seen, last_seen?, count?, where?, observer?, note?, external_ref?, hunt_package_id?, tlp?}`: `value` as Insight serves it (`kind` only if the value could be more than one kind); times in ISO 8601 (UTC if no zone), not in the future, `last_seen` (default `first_seen`) not before `first_seen`; `count` 1 or more (default 1); `where` and `observer` up to 120 characters | `201` and `{id, entity_id, hunt_package_id, first_seen, last_seen, count, where, observer, note, external_ref, tlp, created_at, created_by}`. `404` for an indicator Insight does not know or the caller cannot see, or a hidden hunt package; `403` for a label above the caller's limit. One of the two writes a `read-feedback` key may make. Audited as `sighting.add` on the indicator |
| `GET /api/sightings` | `entity_id`, `hunt_package_id`, `limit` (1-500, default 200) | `{sightings: [{id, entity_id, kind, value, hunt_package_id, first_seen, last_seen, count, where, observer, note, external_ref, tlp, created_at, created_by}]}`, most recently seen first |
| `DELETE /api/sightings/{id}` | - | `{deleted}`, for a sighting reported by mistake. Audited as `sighting.delete` on the indicator |

## Products (cases)

[ADR 0029](adr/0029-cases.md), [ADR 0036](adr/0036-intelligence-products.md). The workspace calls a case a
**product**: an intelligence product in progress, with its evidence (items), working notes, and the product
itself: a bottom line up front (`bluf`), key judgements, the analysis (`summary`) and intelligence gaps.
Publishing stores the product exactly as it is as the next numbered version, in the `insight-product-1` shape
the exports render. A case's `tlp` is the strictest of its items, judgements, gaps and text, and removing one
does not lower it. A caller sees and changes only cases within its limit (the stricter of the instance and key
limits), and can only add what it can see. Every change is audited on the case. `404`: unknown or above your
limit; `403`: a label above your limit; `409`: the case is archived (closed), or not ready to publish.

| Route | Input | Returns |
| --- | --- | --- |
| `GET /api/cases` | `status` (`open`, `closed` or `all`; default `open`), `offset`, `limit` (1–200) | `{cases: [{id, title, status, tlp, items, created_at, updated_at, closed_at, product_type, version, published_at}]}`, most recently changed first; `items` counts evidence, not notes |
| `POST /api/cases` | `{title, summary?, tlp?, product_type?, audience?, bluf?}` (`tlp` default AMBER; TLP markings in the text raise it; `product_type` `assessment` (default), `alert`, `profile` or `summary`; `summary` is the analysis, up to 30,000 characters; `bluf` up to 2,000) | `201` and the case `{id, title, summary, status, tlp, created_at, updated_at, closed_at, close_note, created_by, product_type, audience, bluf, version, published_at}`. Audited as `case.open` |
| `GET /api/cases/{id}` | - | The case with `items: [{id, kind, target_id, name, note, tlp, added_at, added_by}]` (`kind` is `document`, `indicator`, `actor`, `campaign` or `note`), `judgements: [{id, position, statement, likelihood, confidence, evidence, tlp, created_at, updated_at, created_by}]` (`evidence` lists item IDs), `gaps: [{id, question, requirement_id, tlp, created_at, created_by}]` and `versions: [{version, tlp, published_at, published_by}]` (newest first, within your limit) |
| `PATCH /api/cases/{id}` | Any of `{title, summary, tlp, product_type, audience, bluf}` | The case. A lower `tlp` stops at the strictest item, judgement, gap or marking. Audited as `case.update` |
| `DELETE /api/cases/{id}` | - | `{deleted}`; items, notes, judgements, gaps and versions go with it, their targets stay. Audited as `case.delete` |
| `POST /api/cases/{id}/items` | `{kind, target_id, tlp?}`: `document` (report ID), `indicator` (entity ID), `actor` (actor ID) or `campaign` (campaign ID) | `201` and the item. Labelled at least like its target; raises the case. Adding it again changes nothing. Audited as `case.item.add` |
| `DELETE /api/cases/{id}/items/{item_id}` | - | `{removed}`. Audited as `case.item.remove` |
| `POST /api/cases/{id}/notes` | `{text, tlp?}` (default: the case's label) | `201` and the note item. Audited as `case.note` |
| `POST /api/cases/{id}/judgements` | `{statement, likelihood, confidence, evidence?, tlp?}`: `statement` up to 1,000 characters; `likelihood` one of ICD 203's expressions, `almost-no-chance` (1-5%), `very-unlikely` (5-20%), `unlikely` (20-45%), `roughly-even-chance` (45-55%), `likely` (55-80%), `very-likely` (80-95%) or `almost-certain` (95-99%); `confidence` `low`, `moderate` or `high`; `evidence` item IDs of this case (not notes), at most 50 | `201` and the judgement, last in order. Labelled like the case unless `tlp` says otherwise; markings in the statement raise it, and the case with it. At most 50. Audited as `case.judgement.add` |
| `PATCH /api/cases/{id}/judgements/{judgement_id}` | Any of `{statement, likelihood, confidence, evidence, position}`; `evidence` replaces the list; `position` moves it (1 is first) | The judgement. Audited as `case.judgement.update` |
| `DELETE /api/cases/{id}/judgements/{judgement_id}` | - | `{removed}`; the case keeps its label. Audited as `case.judgement.remove` |
| `POST /api/cases/{id}/gaps` | `{question, tlp?}`: 5–300 characters | `201` and the gap, labelled like a judgement. At most 50. Audited as `case.gap.add` |
| `DELETE /api/cases/{id}/gaps/{gap_id}` | - | `{removed}` (an RFI asked from it stays). Audited as `case.gap.remove` |
| `POST /api/cases/{id}/gaps/{gap_id}/rfi` | - | `201` and `{id, kind, question, status, tlp}`: the gap filed as a request for information with the gap's label (TIP 4.1), linked to the gap; asking again returns the same one. Audited as `case.gap.rfi` (and `requirement.rfi`) |
| `POST /api/cases/{id}/publish` | - | `{version, tlp, published_at, published_by}`: the product as it is now, stored as the next version. `409` without a bottom line up front, without a key judgement, or with a judgement that cites no evidence, and for an archived case. The case stays open for the next version. Audited as `case.publish` |
| `GET /api/cases/{id}/product` | `version` (optional) | The product in the `insight-product-1` shape: `{format, id, title, product_type, audience, tlp, version, published_at, author, generated_at, bluf, judgements: [{statement, likelihood, confidence, sources}], analysis, gaps: [{question, rfi}], sources: [{n, kind, id, name, tlp, ...}]}`: the draft, or exactly what that version published. `sources` are the evidence numbered in order (reports with `source_name`, `url`, `added_at`, `reliability` and `credibility`; indicators with `indicator_kind`, `confidence` and `band`, scored from the reports within the product's label; actors and campaigns by name); a judgement's `sources` are those numbers. Working notes are never part of a product |
| `GET /api/cases/{id}/export` | `format` (`md`, `stix` or `pdf`; default `md`), `version` (optional) | An attachment `insight-product-{id}-v{n}` (or `-draft`): Markdown with the TLP label first and last; a PDF (`application/pdf`, US Letter) with the label in the header and footer of every page in 12-point type, network indicators defanged, tagged for screen readers, and the same bytes on every export of a version; or a validated STIX 2.1 bundle: a `report` (the title, the bottom line and the analysis; cited reports as external references, never their text), a `note` per key judgement (`confidence` 15, 50 or 85 for low, moderate or high; `x_insight_likelihood`; `object_refs` the report and the cited objects) and per gap, and an object per cited indicator, CVE, actor or campaign. A published version's STIX IDs are the same on every export. `422` for a STIX export with nothing in it. Audited as `case.export` |
| `POST /api/cases/{id}/close` | `{note}` | The archived (closed) case: it refuses changes until reopened. Audited as `case.close` |
| `POST /api/cases/{id}/reopen` | - | The open case. Audited as `case.reopen` |
| `GET /api/cases/{id}/timeline` | - | `{events: [{at, action, actor, detail}]}`, oldest first (at most 1,000) |

## Requirements and requests for information

[ADR 0032](adr/0032-intelligence-requirements.md). `kind` is `pir` (priority intelligence requirement), `ir`
(narrower, under a PIR: needs `parent_id`) or `rfi` (request for information). A requirement's `tlp` is the
strictest of its text, criteria and cited reports, and removing a criterion or citation does not lower it.
Matches and coverage are counted on read from the current reports the caller may see. `404`: unknown or above
your limit; `403`: a label above your limit; `409`: retired, or a PIR with IRs under it (delete);
`422`: invalid input, such as an IR without a PIR or a malformed CVE or technique ID.

| Route | Input | Returns |
| --- | --- | --- |
| `GET /api/requirements` | `status` (`open`, `answered`, `retired` or `all`; default `open`), `kind` | `{requirements: [summary]}`, high priority first, then most recently changed (at most 200). A summary is `{id, kind, parent_id, question, stakeholder, priority, status, tlp, due_at, answered_at, created_at, updated_at, criteria_count, evidence_count, recent_matches, last_match_at, quiet}`: `recent_matches` counts reports in the last 30 days; `quiet` is true for an open requirement with criteria and no match in that time |
| `POST /api/requirements` | `{kind, question, context?, stakeholder?, priority?, tlp?, parent_id?, due?, criteria?: [{kind, value}]}` (`priority` default `medium`, `tlp` default AMBER; `due` a date, today or later; at most 50 criteria) | `201` and the requirement `{id, kind, parent_id, question, context, stakeholder, priority, status, tlp, due_at, answer, answered_at, external_ref, created_at, updated_at, created_by}`. Audited as `requirement.create` |
| `POST /api/rfis` | `{question, context?, requester?, priority?, tlp?, due?, external_ref?}` | `201` and the RFI as above (`requester` is its `stakeholder`). One of the two writes a `read-feedback` key may make. Audited as `requirement.rfi` |
| `GET /api/requirements/{id}` | - | The summary with `context, answer, external_ref, created_by`, `criteria: [{id, kind, value, name, tlp, added_at, added_by}]`, `evidence: [{id, document_id, title, note, tlp, added_at, added_by}]`, `children` (IRs, as summaries) and `matches: [{document_id, title, source_name, tlp, created_at, because}]` (newest 50; `because` lists the criteria each report meets, such as `cve: CVE-2024-3400`) |
| `PATCH /api/requirements/{id}` | Any of `{question, context, stakeholder, priority, tlp, due}` | The requirement. A lower `tlp` stops at the strictest criterion, citation or marking. Audited as `requirement.update` |
| `DELETE /api/requirements/{id}` | - | `{deleted}`; criteria and citations go with it, the reports stay. Audited as `requirement.delete` |
| `POST /api/requirements/{id}/criteria` | `{kind, value}`: `term` (a word or phrase, 2–120 characters), `cve`, `technique` (`T1190`, `T1059.001`), `group` (`G0016` or your actor's ID; the two count as one group when linked) or `campaign` (your campaign's ID) | `201` and the criterion. A restricted actor or campaign raises the requirement's label. Adding it again changes nothing. Audited as `requirement.criterion.add` |
| `DELETE /api/requirements/{id}/criteria/{criterion_id}` | - | `{removed}`. Audited as `requirement.criterion.remove` |
| `POST /api/requirements/{id}/evidence` | `{document_id, note?}` | `201` and the citation; raises the label to the report's. Audited as `requirement.evidence.add` |
| `DELETE /api/requirements/{id}/evidence/{evidence_id}` | - | `{removed}`. Audited as `requirement.evidence.remove` |
| `POST /api/requirements/{id}/answer` | `{answer}` | The requirement: an RFI becomes `answered`; a PIR or IR stays `open` with the answer as its latest assessment. Audited as `requirement.answer` |
| `POST /api/requirements/{id}/retire` | - | The retired requirement (it refuses changes until reopened). Audited as `requirement.retire` |
| `POST /api/requirements/{id}/reopen` | - | The open requirement. Audited as `requirement.reopen` |
| `GET /api/documents/{id}/requirements` | - | `{requirements: [{id, kind, question, priority, because}]}`: the open requirements that report addresses, high priority first. Empty for a report you cannot see |

## Confidence and source reliability

How far each source and report can be trusted, and how well the reports back up an indicator
([ADR 0033](adr/0033-confidence-and-source-reliability.md)). Scores use only reports the caller may see.

| Route | Input | Returns |
| --- | --- | --- |
| `GET /api/source-ratings` | - | `{sources: [{source_name, reliability, reliability_label, half_life_days, note, reports, indicators, unique_indicators, reviewed, rejected, last_report_at}], reliability, credibility}`: one row per source with visible reports (unlimited callers also see rated sources with none). `unique_indicators` counts indicators no other source reported; `reviewed` and `rejected` count reviewed mentions. `reliability` and `credibility` map each grade to its meaning |
| `PUT /api/source-ratings` | `{source_name, reliability, half_life_days?, note?}`: `reliability` `A`–`F`; `half_life_days` 1–3650 or `null` for the default ageing | The rating with `updated_at, updated_by`. `403` for TLP-limited keys. Audited as `source.rate` |
| `PUT /api/documents/{id}/credibility` | `{credibility}`: 1–6 | `{id, credibility}`; `404` for a report the caller may not see. Audited as `document.credibility` |
| `GET /api/entities/{id}/confidence` | - | `{score, band, half_life_days, sources: [{source_name, reliability, reliability_label, reports, newest_at, weight}]}`: `score` 0–100, `band` `high`, `medium`, `low` or `none`, `half_life_days` `null` for kinds that do not age; sources strongest first. The same object is `confidence` in `GET /api/entities/{id}` |

## Sources and enrichment

API keys can read operator-defined feeds up to their sharing ceiling. Creating, editing, switching and
deleting definitions requires a signed-in browser session and its CSRF token. Submitted URLs must use HTTPS
on port 443 and omit credentials, query strings and fragments. Saving a definition makes no network request.
Operator sources may also poll one TAXII 2.1 collection. Send `kind: taxii`, the API root in `url`,
and the collection identifier in `collection_id`. For authenticated collections, `credential_env` names
a host variable matching `INSIGHT_SOURCE_[A-Z0-9_]{1,40}`. A missing or unusable value sets `configured`
to false. An enabled collection then returns `503` on sync or a request to turn on its schedule. An existing
schedule keeps its setting and resumes automatically when the credentials return. The API returns the
variable name and availability only. A TAXII sync validates the collection pages and commits the imported
reports and resume timestamp together. [TAXII guide](TAXII.md)

Source run and job history omit missing or deleted sources. When a source moves to a lower TLP, limited keys
see only history from the new sharing period. For operator feeds, limited keys receive job and run statuses
and times with an empty message, since counts and diagnostics can describe more restricted reports.

| Route | Result |
| --- | --- |
| `GET /api/sources` | Curated sources and operator sources visible to the caller, with `key`, `name`, `url`, `note`, `category`, `optional`, `reuse`, `in_use` and the latest five permitted runs. Operator entries have category `operator` and include their `tlp`. |
| `GET /api/operator-sources` | Visible operator-defined feeds. Each entry includes `key`, `name`, `kind`, `url`, `tlp`, `reuse`, `enabled`, `revision`, creation/update times, the actor, `collection_id`, `credential_env` and `configured`. |
| `GET /api/operator-sources/{key}` | One definition. Hidden and missing sources both return `404`. |
| `POST /api/operator-sources` | Create a feed, switched off, and return its definition with `201`. Send `name` and `url`. Defaults are `kind: rss` (RSS or Atom), `tlp: AMBER` and `reuse: metadata`. Set `reuse: public` only when the publisher permits sharing the text. |
| `PUT /api/operator-sources/{key}` | Replace the definition using the same fields. Changing the endpoint, collection, source kind or credential variable switches the source and schedule off. Saving a label above the instance ceiling returns `403`. |
| `PUT /api/operator-sources/{key}/switch` | Send `{"enabled": true}` to permit future syncs or `{"enabled": false}` to disable syncs and the schedule. |
| `DELETE /api/operator-sources/{key}` | Remove the feed definition and its schedule. The reports keep their handling labels and follow metadata-only reuse. Returns `{"deleted": "<key>"}`. |
| `POST /api/sources/{key}/sync` | Sync one enabled source. Returns `{"message": …}`, `404` for an unknown source, `409` if switched off or another sync is running, and `502` on provider failure. Operator sources require a browser session or an unlimited read-write key. |
| `GET /api/schedules` | `[{source_key, interval_minutes, next_run_at, updated_at}]` for every visible source. `interval_minutes` is `0` (syncs only when asked, the default), `60`, `360` or `1440`. Times are ISO-8601 UTC. |
| `PUT /api/schedules/{key}` | Body `{"interval_minutes": 0 \| 60 \| 360 \| 1440, "at": "HH:MM"}` (`at` optional, UTC: the time of day the syncs start from; every next sync keeps that slot); returns the schedule as above. **Browser session only**: API keys get `403` (how often Insight goes online by itself is the operator's decision; `insight schedule` on the host does the same). `404` unknown source, `409` turning on a schedule for a switched-off source, `422` other intervals. Without `at`, a schedule turned on runs within a minute, then every interval. Audited as `schedule.update`. Scheduled syncs run only in a process with `INSIGHT_RUN_JOBS=on` (the default for `insight serve`). |
| `GET /api/jobs?limit=20` | Recent background jobs (scheduled syncs, alert deliveries, automatic CVE lookups), newest first: `[{id, kind, key, status, attempts, run_after, started_at, finished_at, message, actor, created_at}]`. `status`: `queued`, `running`, `succeeded` or `failed`. A failed sync is tried again after 5, then 10 minutes, then marked `failed`. `limit` 1-100. Finished jobs are kept 30 days. |
| `POST /api/sources/sync-all` | `{"results": [{key, name, status, message}]}`: every enabled eligible source, one at a time. Requires a browser session or an unlimited read-write key. `status` is `success` or `error`; a failing source does not stop the others and is recorded as an error run. Always `200` once it has run; `409` another sync running. |
| `POST /api/enrichment/greynoise/{ip}` | Approve a GreyNoise Community lookup of one public IPv4 accepted in a current TLP:CLEAR report. Requires a signed-in session with CSRF or an unlimited read-write key. A fresh cached answer avoids network traffic. The result includes `provider`, `ip`, `found` and `fetched_at`; a match also includes `noise`, `riot`, `classification`, `name` and `last_seen`. Returns `503` for a missing host key, `404` for an ineligible address, `429` with `Retry-After` for a rate limit or `502` for a provider error. |
| `GET /api/ips/{ip}/greynoise` | Read the last cached response without external traffic. Available to read-only and TLP-limited keys. Returns `404` when no eligible reviewed CLEAR observation or cached response exists. |
| `POST /api/enrichment/shodan/{ip}` | Optional ([ADR 0031](adr/0031-shodan.md)). Approve a Shodan host lookup of one public IPv4 accepted in a current TLP:CLEAR report, with the same callers and caching as GreyNoise. The result has `provider`, `ip`, `found`, `fetched_at` and `attribution`; a match also has `ports` (at most 100), `port_count`, `hostnames`, `org`, `isp`, `asn`, `country_code`, `os`, `tags`, `vulns` (CVE IDs Shodan infers) and `last_update`. `503` without `INSIGHT_SHODAN_KEY` (no call is made), `404` for an ineligible address, `429` with `Retry-After`, `502` when Shodan refuses the key, plan or credits (the message says which). |
| `GET /api/ips/{ip}/shodan` | The last cached Shodan answer with `attribution`, without external traffic. Available to read-only and TLP-limited keys. `404` when nothing eligible is cached. |
| `POST /api/enrichment/censys/{ip}` | Approve one Censys Platform v3 host lookup with JSON `{"approved":true}`. Only a private session with CSRF or unlimited read-write key may call. Requires an accepted observation of the public IPv4/IPv6 in a current CLEAR report and host `INSIGHT_CENSYS_PAT`; optional `INSIGHT_CENSYS_ORG_ID` selects an organization. Responses have `provider`, `ip`, `found`, `fetched_at`, `attribution`; a match adds up to 100 `services` (`port`, `protocol`, `transport`, `observed_at`), `service_count`, up to 20 `hostnames`, `asn`, `network_name`, `prefix`, `country_code`. Reuses fresh answers for 24 hours. `422` without explicit approval, `404` if ineligible, `503` if not configured or temporary open access is on, `429` with Retry-After for throttling, `502` for other provider failures. [Account conditions](CENSYS.md). |
| `GET /api/ips/{ip}/censys` | Read the last eligible cached Censys answer without external traffic; available to private sessions and read/TLP-limited keys. Rechecks the current CLEAR accepted observation. `404` for missing/ineligible context and `503` while temporary open access is on. Censys context is not included in intelligence exports or MCP. |
| `POST /api/enrichment/{provider}/{cve}` | Provider JSON (`epss`, `nvd`), or for `vulncheck` the metadata Insight keeps from VulnCheck KEV (needs `INSIGHT_VULNCHECK_API_KEY`, else `422`; one request every 2 s), cached. Only the CVE number is sent. `422` invalid input or unknown CVE (checked first, so it uses no lookup window), `429` with `Retry-After` when the provider's window is taken: one request every 6.5 s at NVD (0.7 s with `INSIGHT_NVD_API_KEY`) and every 1 s at EPSS, shared with every other caller and with automatic lookups, so the wait may come from Insight itself. `502` provider failure, `403` for TLP-limited keys (a lookup can name a CVE from any report to a provider). |
| `GET /api/cves?days=30&limit=50` | The prioritised CVE view ([ADR 0024](adr/0024-prioritised-cves.md)): the CVEs that current reports received in the last `days` days (1-365) mention, most urgent first, from the reports the caller may see (TLP limit; the demo and rejected mentions left out). `{days, since, total, truncated, cves: [cve]}`; `limit` 1-500 rows. A row is `{cve, tier, label, reason, details: [line], reports, sources, first_seen, last_seen, report: {id, title}, kev: {date_added, due_date, ransomware, name, document_id} \| null, cvss: {score, source, csaf}, nvd, epss, exploit}`. `tier`: 1 used in ransomware (CISA KEV), 2 known exploited (KEV), 3 reported exploited (VulnCheck KEV), 4 public exploit (a report or VulnCheck), 5 likely to be attacked soon (EPSS 10% or more), 6 critical (CVSS 9 or more), 7 high (CVSS 7 or more), 8 no strong signal (tiers 3 and 4 since 0.9.0, [ADR 0028](adr/0028-exploit-availability.md)); within a tier, higher EPSS, higher CVSS, more reports, most recently seen. `details` are plain-English lines; `nvd`/`epss` as in the scores route. `exploit` is `null` or `{public_exploit, reported_exploited, reports: {poc\|metasploit\|exploit-db: count}, vulncheck, attribution}`: `reports` counts current reports the caller may see that mention that kind of public exploit near the CVE; `vulncheck` is VulnCheck KEV's cached answer `{listed, date_added, exploits: [{xdb_id, url, exploit_type, date_added}], exploit_count, reported_count, canaries, ransomware}` or `null`, and `attribution` is the notice VulnCheck's terms require when it is shown. `truncated`: more than 20,000 mentions, older ones left out |
| `GET /api/cves/{cve}/scores` | The cached scores, read without contacting anyone ([ADR 0023](adr/0023-automatic-cve-lookups.md)): `{cve, nvd, epss, nvd_checked_at, epss_checked_at, vulncheck, vulncheck_checked_at, exploit}` (`vulncheck` and `exploit` as in `GET /api/cves`). `nvd` is `{score, severity, version, vector, status, published, description, cwes}` or `null` (not looked up, or NVD has no record); `score` is the CVSS base score from the newest version NVD has (4.0, 3.1, 3.0, then 2), `null` when NVD has not scored it (`status` says why, such as `Awaiting Analysis` or `Rejected`). `epss` is `{probability, percentile, date}` (both 0-1; probability of exploitation attempts in the next 30 days) or `null`. A `*_checked_at` time with a `null` score means the provider was asked and has none. `404` unless a current report the caller may see mentions the CVE, so TLP-limited keys can use it for their own reports. |


Sync, enrichment and approved infrastructure pivots are the only routes that cause outbound network traffic. A schedule makes the same syncs happen by
themselves; an unchanged feed is skipped (conditional requests with `If-None-Match` / `If-Modified-Since`, then a
payload hash), and its run says `Unchanged since the last sync.`

**Automatic CVE lookups** ([ADR 0023](adr/0023-automatic-cve-lookups.md)) are switched on per provider in the
workspace's *Sources* tab (off by default; there is no API for the switches). Then the job runner looks up, by
itself, each CVE that a current TLP:CLEAR or GREEN report mentions and that has no recent answer (EPSS after
7 days, NVD after 30), newest reports first, as `lookup` jobs in `GET /api/jobs` (key `epss` or `nvd`). CVEs
seen only in AMBER or RED reports are never looked up by themselves. The answers fill
`GET /api/cves/{cve}/scores`. This product uses the NVD API but is not endorsed or certified by the NVD.

## Executive brief

### `GET /api/brief?days=7`

Returns the same deterministic brief used by the landing page. Requires a browser session or API key;
read-only keys are accepted. Uses the normal `read` rate budget. `days` is an integer from 1 to 30,
default 7; invalid values return `422`. It reads stored data and makes no source or AI request.

| Field | JSON type | Meaning |
| --- | --- | --- |
| `days` | integer | Requested reporting window in days. |
| `since` | string | Window start, as an ISO-8601 UTC timestamp. |
| `as_of` | string | Window end, as an ISO-8601 UTC timestamp. This is the brief's reference time, not a source's last successful sync. |
| `report_count` | integer | Current, visible, non-demo reports included in this brief after its date filters. |
| `source_count` | integer | Distinct source identities among those reports: connector key, or case/space-normalized source name for other reports. Not a count of independent confirmations or all configured connectors. |
| `recent_reports` | integer | Included reports received during the last 24 hours relative to `as_of`. Retained as compatibility metadata; the workspace has no separate receipt card or highlight. This is not a count of attacks or newly published vulnerabilities. |
| `summary` | array of strings | Plain-English executive summary. The existing field is retained; its wording can change. |
| `highlights` | array of objects | Prioritized explanations with `{title, text, action, evidence}`. The first three values are strings; `evidence` is an array of brief items described below. `action` is a conditional next step, not an instruction executed by Insight. |
| `coverage` | array of strings | Notes explaining the data covered, count limits, excluded invalid/future dates and stored source-check freshness. Connector error details are omitted. |
| `sections` | array of objects | Existing detail sections: `{title, items, empty}`. `title` and `empty` are strings; `items` is an array of brief items. Use `empty` when a section has no items. |

The added fields are always present and are not nullable. Empty collections are `[]`; counts may be zero.
Existing clients can continue using `summary` and `sections` and ignore the additions.
The receipt-count field remains, but `highlights` no longer includes a recent-receipt entry. Highlight titles
and summary wording are presentation text, not stable identifiers.

A **brief item** is `{text, document_id, entity, search}`. `text` is a string; the remaining values are strings
or `null`. A `document_id` opens a visible report; `entity` opens the indicator's evidence; `search` searches
the collected reports. The workspace checks them in that order. The item is evidence/navigation metadata,
not a claim that an extracted indicator is malicious.

The five detail sections remain:

| Section | Selection |
| --- | --- |
| **Exploited now** | CVEs added to the stored CISA KEV catalogue in the window, then older KEV CVEs mentioned by included reports from other sources; those CISA knows to be used in ransomware campaigns first, marked `· used in ransomware`. KEV records establish known exploitation; this label does not measure attacks happening now. |
| **Most severe** | CVSS base scores of 9 or higher, highest first, one item per CVE: from included CISA advisories, and NIST NVD's cached score of any CVE an included report mentions (marked `(NIST NVD)`; NVD's own score is shown beside an advisory's when they differ; rejected CVEs never count). A high score does not itself establish exploitation. |
| **Your watch terms** | Literal matches for configured terms in included reports. A match does not establish that the operator uses an affected product. |
| **Seen in several sources** | Indicators mentioned in included reports with at least two distinct source identities. Repetition does not establish independent corroboration or rising attack volume. |
| **Most-mentioned vendors** | Vendor names from included advisory metadata and recent KEV additions. |

Each detail section and each highlight's evidence list contains at most five items. Report-derived counts,
text and links use only current reports the caller may see, including authorized pasted reports as well as connector reports. The synthetic
demo is excluded. The query examines at most the latest 2,000 eligible received reports; counts describe
that bounded selection, not the entire database. Coverage notes disclose a truncated selection. Stored KEV
catalogue facts are public and can contribute even when there is no visible report to link or `report_count`
is zero.

The reporting window preserves publication-date filtering: a KEV report uses CISA's date added; a CISA
advisory uses its first release date, rather than the date of a later revision; reports without a known
publisher date use their receipt date. An old advisory first downloaded today does not become a newly
published advisory. Invalid or future dates are excluded. The separate 24-hour count uses received timestamps
for the current report version within the included set, so a received report can be an update. No
comparison against a previous period is made in the brief itself (the threat landscape, `GET /api/landscape`,
makes one), so repeated coverage must not be interpreted as an increase in attacks. Full behavior and interpretation: [Executive brief](EXECUTIVE_BRIEF.md).

## Hunt guide previews and downloads

These authenticated GET routes accept a browser session or any API-key access level that can read.
They use the normal `read` rate budget and the stricter of the instance and caller TLP ceilings. They
make no external request, call no model and run no search against organisational telemetry. Guide generation
only writes its audit event; it saves no guide, package, product or finding.

| Route | Result |
| --- | --- |
| `GET /api/hunt-guides?kind=theme&q=ransom` | Choice lists, filtered before the 50-choice cap per kind. `kind` is optional; omit it for all nine lists. `q` defaults to empty and is at most 120 characters. |
| `GET /api/hunt-guides/{kind}/{ref}?format=json` | Build the guide from then-current visible evidence. `format` is `json` (default), `md` or `pdf`. Markdown/PDF are attachments with `Cache-Control: no-store`. |

Kinds are `industry`, `theme`, `actor`, `cve`, `document`, `exploit`, `software`, `indicator` and `campaign`.
Choice JSON maps each requested kind to an array of `[ref, display_name]` pairs. Use the returned `ref` in
the guide path: an industry or theme key; catalog or analyst actor ID; CVE identifier; document ID; software ID;
entity ID for an indicator; or campaign ID. For `exploit`, the ref is a CVE with saved exploit/exploitation context.
`kind` is at most 20 characters and path `ref` at most 128. Unknown kinds, hidden subjects and missing
subjects return the same `404 Hunt guide choice not found`. Invalid bounds or format return `422`.

Report choices use existing title, source and body search. Other choices search their names, aliases or
identifiers as applicable. Hidden, rejected-only and superseded-only indicator mentions cannot supply a
starting subject. Search again to reach a match outside the first 50 choices; no pagination token is returned.
For `industry`, a blank query lists the existing 15 sector categories. Search matches their names, scopes
and source aliases. For example, `industry/healthcare` builds from source-backed groups and related current
reports added in the last 30 days. Sector mentions and explicit group links retain distinct match reasons;
they create no attribution. Guide generation makes no source lookup.

The JSON guide is `{kind, ref, title, summary, tlp, created_at, sections}`. All fields except `sections` are
strings; `created_at` is the generation time in UTC. A section is `{title, lines: [string]}`. Guides include
fixed planning steps, library source references and saved metadata, never publisher bodies, summaries or
private analyst notes. The output retains its aggregate sharing label even if a list or text is shortened.
PDF repeats TLP on each page. Markdown/PDF defang network indicators and escape untrusted text.

Limits: 20 current reports, 100 eligible reviewed indicators and 12 techniques. Report plans consider up to
12 CVE references; campaign plans inspect up to 200 visible links and note other indicator/software links
for separate review. Section text is capped at 40,000 characters, with per-line/section bounds and visible
limit notes. See [Threat Hunt](THREAT_HUNT.md) for selection, attribution and copyright rules.

Successful generation is audited as `hunt.guide`, with `object_id=ref`, caller actor and detail containing
kind, format and TLP. UI previews record the same action with format `preview`; choice listing is not audited.
These reads never create actor attribution or establish that an indicator is malicious.

## Workspace

| Route | Result |
| --- | --- |
| `GET /api/stats` | `{documents, entities, unreviewed, observations_unreviewed}` (current revisions only) |
| `GET /api/brief?days=7` | Executive summary, report/source counts, compatibility receipt-count metadata, linked highlights, coverage notes and detail sections. No recent-receipt highlight. See the [executive brief contract](#executive-brief). |
| `GET /api/landscape?days=7` | The threat landscape that opens the workspace ([ADR 0020](adr/0020-threat-landscape.md)), built from the data (no AI). `days` 1-30 (default 7); the period is compared with the 4 periods before it. `{days, since, compared_since, compared_periods, tlp, reports, sources, summary: [sentence], caveats: [sentence], threats: [threat], quieter: [threat], tactics: [tactic], brief}`. A threat is `{key, name, change: {label, current, usual}, sources, what, impact, check, reports: [{text, document_id}], words, techniques}`; `label` is `rising`, `new`, `steady`, `quieter` or `no-history` (nothing before the period to compare with); `usual` is reports per period before, `null` without history. A tactic is `{shortname, name, plain, change, techniques: [[id, name, reports]]}`. `brief` is the intel brief below for the same period. `tlp` is the most restrictive label of the reports counted: share no wider. Built only from reports the caller may see (TLP limit) |
| `GET /api/landscape/briefing?days=7` | The same as a Markdown briefing (`text/markdown`, attachment `insight-threat-landscape-7d.md`), marked with its TLP on the first and last lines; text from reports is escaped. Audited as `landscape.briefing` |
| `GET /api/audit` | Latest 200 audit events: `{action, object_id, detail, actor, created_at}`. Not available to TLP-limited keys |
| `GET /api/watch-terms` | `[{id, term}]`. Not available to TLP-limited keys: terms often name clients or internal systems |
| `POST /api/demo` | `{"created": n}`; loads the synthetic demo, idempotent. **Browser session only** (API keys get `403`: scripts must not add practice data to a real dataset); reports above `INSIGHT_MAX_TLP` are left out |
| `GET /health` | Public liveness check. Returns `{"status": "ok"}`. |

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

## Actor activity and software Navigator

| Method | Route | Meaning |
| --- | --- | --- |
| GET | `/api/actors/{ref}/timeline` | Dated source and local events; `days=3650` (1–36,500), `limit=100` (1–200). |
| GET | `/api/actors/{ref}/campaigns` | Up to 200 visible explicit campaign associations. |
| POST | `/api/actors/{ref}/campaigns` | Explicit association: `campaign_id`, optional `note` (2,000 characters), `tlp` (CLEAR default). Returns 201. |
| DELETE | `/api/actors/{ref}/campaigns/{campaign_id}` | Remove the visible association; campaign label stays raised. |
| GET | `/api/software/{software_id}/navigator` | Public catalog software techniques as a Navigator 4.5 JSON attachment. |

Normal authentication applies. Writes require write access and browser CSRF/Origin checks, and respect both
instance and caller TLP ceilings. Unknown and hidden associations return 404. Payloads reject extra fields.
Audit actions: `actor.campaign.link`, `actor.campaign.unlink`, `software.navigator`.

Timeline format `insight-actor-timeline-1`: `ref`, `since`, `until`, `tlp`, `limit`, `truncated`, and `events`.
Each event has `id`, `at` (UTC), `kind`, `title`, `source`, `source_ref`, `relation`, `tlp`, `detail`, `url`.
Kinds include campaign first/last seen, campaign linked, report added, hunt published/retired and sighting
first/last seen. The date meaning is explicit; a name match or indicator sighting is not actor attribution.
Guide format `insight-threat-guide-1` gains an additive `timeline` field; existing fields remain unchanged.
See [collection limits and historical coverage](THREAT_GUIDES.md#activity-timeline-and-software-layers-tip-47-part-3).

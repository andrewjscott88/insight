# API guide: every call, with curl

A practical companion to the [API reference](API.md): how to authenticate, how limits and errors behave, and a
`curl` command for every route. Every `sh` block in this guide runs as written, in order, against a running
instance (they were executed end to end before this guide was published); `bash` blocks need your own values.

- [1. Before you start](#1-before-you-start)
- [2. Authentication](#2-authentication)
- [3. Conventions: errors, rate limits, TLP, paging](#3-conventions-errors-rate-limits-tlp-paging)
- [4. Every endpoint](#4-every-endpoint)
- [5. Recipes](#5-recipes)
- [6. Troubleshooting](#6-troubleshooting)

## 1. Before you start

You need a running instance (`make up`, or `insight serve`) and, for scripts, the API key. There is one key at a
time, created on the host; it is printed once and only its hash is stored:

```bash
make api-key-create NAME=scripts ACCESS=read-write           # Docker
insight api-key create --name scripts --access read-write    # local Python
# A read-only key for a SIEM that never sees AMBER or RED reports:
make api-key-create NAME=siem MAX_TLP=GREEN
```

Then put the base URL and the key in your shell. Keep the key out of scripts, URLs and shell history (a secret
manager, or `read -rs INSIGHT_API_KEY` to type it without echo):

```bash
export INSIGHT_URL=http://127.0.0.1:8080     # your public URL behind the reverse proxy, e.g. https://insight.example.org
read -rs INSIGHT_API_KEY && export INSIGHT_API_KEY   # paste the insk_... key, then Enter
```

The examples use `curl -sS` (quiet, but errors are shown) and, where a value is picked out of a response, `jq`.
Check that everything works:

```sh
curl -sS "$INSIGHT_URL/health"
curl -sS "$INSIGHT_URL/api/stats" -H "Authorization: Bearer $INSIGHT_API_KEY"
```

```json
{"status":"ok"}
{"documents":4,"entities":10,"unreviewed":4,"observations_unreviewed":12}
```

The threat landscape that opens the workspace (what is trending and why it matters, built from the data, no
AI), as JSON or as a Markdown briefing to share; and the intel brief alone:

```sh
curl -sS "$INSIGHT_URL/api/landscape?days=7" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  | jq -r '.tlp, .summary[], (.threats[] | "\(.name): \(.change.label), \(.change.current) reports")'
curl -sS -OJ "$INSIGHT_URL/api/landscape/briefing?days=30" -H "Authorization: Bearer $INSIGHT_API_KEY"
curl -sS "$INSIGHT_URL/api/brief?days=7" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq -r '.summary[], (.sections[] | .title, (.items[].text))'
```

## 2. Authentication

Every `/api/*` route needs either the API key or a signed-in browser session. `/health` needs neither.

### 2.1 API key (scripts, SIEMs)

Send `Authorization: Bearer <key>` on every request. No cookie or CSRF token is involved.

| Key setting | Effect |
| --- | --- |
| `ACCESS=read` (default) | `GET` routes only; any `POST` gets `403 "This API key is read-only"` |
| `ACCESS=read-write` | Also ingest, triage, notes, demo, source sync and enrichment |
| `MAX_TLP=GREEN` (optional) | Reports above GREEN are invisible to the key (they look like missing reports), exports are capped at GREEN, and the audit log, watch terms and starting CVE lookups are refused (cached scores of CVEs in reports the key can see stay readable) |
| `EXPIRES=90` | Days until expiry (1-365, default 90). `make api-key-status` shows the date |

Manage it with `make api-key-status`, `make api-key-rotate` (the old key stops working at once) and
`make api-key-revoke`. `/api/session` and the workspace UI are browser-only.

### 2.2 Browser session (what the workspace uses)

Scripts should use the key. For completeness, this is the session flow with `curl`: a cookie jar, the sign-in
form's CSRF token, then the API's CSRF token on every write. `INSIGHT_PASSWORD` is the workspace password.

```sh
JAR=$(mktemp)      # holds the session cookie: treat it like the password, delete it afterwards
FORM_TOKEN=$(curl -sS -c "$JAR" "$INSIGHT_URL/login" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p')
curl -sS -o /dev/null -w 'sign-in: %{http_code}\n' -b "$JAR" -c "$JAR" "$INSIGHT_URL/login" \
  --data-urlencode "csrf_token=$FORM_TOKEN" --data-urlencode "password=$INSIGHT_PASSWORD"
CSRF=$(curl -sS -b "$JAR" "$INSIGHT_URL/api/session" | jq -r .csrf_token)
curl -sS -b "$JAR" "$INSIGHT_URL/api/stats"                                     # reads: cookie only
curl -sS -b "$JAR" -X POST "$INSIGHT_URL/api/demo" -H "X-CSRF-Token: $CSRF"     # writes: plus X-CSRF-Token
```

`sign-in: 303` means success. With MFA on (`make mfa-enable`), add the authenticator code to the sign-in POST:
`--data-urlencode "otp=123456"`. Each code works once. Sign out (revokes the session on the server):

```sh
LOGOUT_TOKEN=$(curl -sS -b "$JAR" "$INSIGHT_URL/logout" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p')
curl -sS -o /dev/null -w 'sign-out: %{http_code}\n' -b "$JAR" -c "$JAR" "$INSIGHT_URL/logout" \
  --data-urlencode "csrf_token=$LOGOUT_TOKEN"
rm -f "$JAR"
```

Browser sessions last 8 hours and survive a restart; changing the password or the MFA setting ends them all. A
request from a browser page on another site is refused (`Origin` check, `SameSite=Strict` cookie, CSRF token).

## 3. Conventions: errors, rate limits, TLP, paging

**Requests and responses.** JSON in and out; send `Content-Type: application/json` with a body. Request bodies
are limited to 2 MB. IDs are UUID strings; timestamps are ISO-8601 UTC strings (`2026-11-16T21:33:39.434188+00:00`).
The API is unversioned; breaking changes are listed under "Upgrade notes" in the [CHANGELOG](../CHANGELOG.md).

**Status codes.**

| Code | Meaning |
| --- | --- |
| `200` | Success. Exports add `Content-Disposition: attachment; filename="..."` |
| `303` | Sign-in and sign-out redirects (HTML forms only) |
| `400` | The `Host` header is not in `INSIGHT_ALLOWED_HOSTS` |
| `401` | No valid key or session. A bad key also gets `WWW-Authenticate: Bearer error="invalid_token"` |
| `403` | Read-only key writing; TLP-limited key on the audit log, watch terms or starting a CVE lookup; missing CSRF token (sessions); cross-site `Origin`; browser-only route |
| `404` | Not found, **or** above the key's TLP limit (the two are indistinguishable by design) |
| `409` | Another source sync is running, or a concurrent import (retry once) |
| `413` | Request body larger than 2 MB |
| `422` | Invalid input, too many indicators in one report, a report above the instance's TLP limit, too large an IOC export |
| `429` | Rate limited, or a CVE lookup within the provider's window: wait for `Retry-After` seconds |
| `502` | An external source or provider failed (sync, enrichment) |
| `503` | Sign-in only: MFA is on but no authenticator app is paired |

**Errors** are `{"detail": "message"}`. Request-body validation errors (FastAPI) list every problem instead:

```json
{"detail":[{"type":"string_too_short","loc":["body","title"],"msg":"String should have at least 1 character","input":"","ctx":{"min_length":1}}]}
```

**Rate limits** apply per caller: the API key and the browser session have separate budgets.

| Policy | Requests | Budget |
| --- | --- | --- |
| `read` | `GET`, except the IOC export | 300 per minute |
| `write` | `POST` | 60 per minute |
| `ioc-export` | `GET /api/iocs/export` | 30 per hour |
| invalid keys | wrong, revoked or expired keys, per client address | 10 per minute (never blocks the valid key) |

Every limited response says where you stand (IETF draft `RateLimit` headers); a `429` adds `Retry-After`:

```sh
curl -sS -D - -o /dev/null "$INSIGHT_URL/api/stats" -H "Authorization: Bearer $INSIGHT_API_KEY" | grep -i '^ratelimit'
```

```text
ratelimit-policy: "read";q=300;w=60       # 300 requests per 60 s
ratelimit: "read";r=299;t=1               # 299 left; the budget is full again in 1 s
```

Budgets refill continuously (read: 5 per second; ioc-export: one every 2 minutes). Source sync (one at a time:
`409`) and enrichment (one lookup per 6.5 s across everyone: `429`) have their own rules. Limits live in server
memory and reset on restart.

**TLP.** Reports carry a TLP label (`CLEAR`, `GREEN`, `AMBER`, `AMBER+STRICT`, `RED`; default `AMBER`). A
`TLP:` marking in the text raises the label, never lowers it. The instance refuses reports above
`INSIGHT_MAX_TLP` (default `AMBER+STRICT`, so TLP:RED is refused). A key with `MAX_TLP` only sees, changes and
stores reports at or below its limit.

**Paging.** `GET /api/documents` and `GET /api/entities/{id}` take `offset` and `limit` (at most 200); results
are newest first. See [the paging recipe](#53-page-through-every-report).

## 4. Every endpoint

The [API reference](API.md) lists every field. Here, each route with a working command.

### Health

```sh
curl -sS "$INSIGHT_URL/health"
```

This public endpoint returns `{"status":"ok"}` when Insight is up. Monitors can call it without signing in.

### Sign-in pages (browser)

| Route | Purpose |
| --- | --- |
| `GET /login` | Sign-in form (contains `csrf_token`) |
| `POST /login` | Form fields `csrf_token`, `password`, and `otp` when MFA is on. `303` success, `401` wrong password or code, `403` bad CSRF, `429` throttled, `503` MFA on but no app paired |
| `GET /logout` | Sign-out confirmation form (contains `csrf_token`) |
| `POST /logout` | Form field `csrf_token`; revokes the session, `303` to `/login` |
| `GET /api/session` | Returns `{"csrf_token": "...", "version": "..."}` for a signed-in browser session. API keys receive `403`. |

Commands: [section 2.2](#22-browser-session-what-the-workspace-uses).

### Documents (reports)

**Ingest a report** (`POST /api/documents`, read-write key). `tlp` defaults to `AMBER`; `source_url` is optional.

```sh
curl -sS "$INSIGHT_URL/api/documents" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"title": "Phishing wave", "source_name": "SOC", "tlp": "GREEN",
       "body": "Lure linked to hxxps://login-portal[.]example[.]com/verify and 203.0.113.45."}' \
  | jq '{id, created, tlp, tlp_raised_from, observations: [.observations[] | {kind, value}]}'
```

```json
{"id": "ba9ab617-...", "created": true, "tlp": "GREEN", "tlp_raised_from": null,
 "observations": [{"kind": "url", "value": "https://login-portal.example.com/verify"},
                  {"kind": "domain", "value": "login-portal.example.com"}, {"kind": "ip", "value": "203.0.113.45"}]}
```

`created: false` means an exact duplicate (same title, body, source, URL and label) already existed.
`tlp_raised_from` is set when a `TLP:` marking in the text raised the label. To ingest a file, see
[recipe 5.2](#52-ingest-a-text-file).

**Search and list** (`GET /api/documents`): `q` (literal text, case- and accent-insensitive), `status`
(`new`/`reviewing`/`reviewed`), `tlp`, `include_superseded`, `offset`, `limit`.

```sh
curl -sS "$INSIGHT_URL/api/documents?q=phishing&status=new&limit=20" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  | jq '.[] | {id, title, tlp, status, entity_count}'
DOC_ID=$(curl -sS "$INSIGHT_URL/api/documents?q=phishing&limit=1" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq -r '.[0].id')
echo "$DOC_ID"
```

**Read one report** (`GET /api/documents/{id}`): body, observations (with offsets and KEV context), notes and
revisions.

```sh
curl -sS "$INSIGHT_URL/api/documents/$DOC_ID" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  | jq '{title, tlp, status, content_hash, notes, observations: [.observations[] | {id, kind, value, review_status}]}'
OBS_ID=$(curl -sS "$INSIGHT_URL/api/documents/$DOC_ID" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq -r '.observations[0].id')
```

**Import a local PDF advisory** with a read-write key. For an advisory you have permission to retain,
put its metadata in a header and send the original file bytes as the request body. The response includes the
report ID and a SHA-256 digest you can compare with your local file.

```sh
META=$(python -c 'import base64,json; data={"title":"Example advisory","source_name":"Example publisher","tlp":"GREEN"}; print(base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode())')
curl --fail-with-body -sS "$INSIGHT_URL/api/documents/pdf" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H "X-Insight-Document: $META" -H 'Content-Type: application/pdf' --data-binary @advisory.pdf
```

**Import a local STIX 2.1 bundle** with a read-write key. The response lists the report IDs and the
number of new revisions. The same file can be imported from the workspace ingest dialog.

```sh
curl --fail-with-body -sS "$INSIGHT_URL/api/import/stix" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' --data-binary @bundle.json
```

**Triage a report** (`POST /api/documents/{id}/review`): `new`, `reviewing` or `reviewed`.

```sh
curl -sS "$INSIGHT_URL/api/documents/$DOC_ID/review" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"status": "reviewing"}'
```

**Review an extracted indicator** (`POST /api/observations/{id}/review`): `unreviewed`, `accepted` or
`rejected`. Rejected mentions are left out of IOC exports by default.

```sh
curl -sS "$INSIGHT_URL/api/observations/$OBS_ID/review" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"status": "accepted"}'
```

**Add an analyst note** (`POST /api/documents/{id}/notes`, up to 10,000 characters; returns the note's `id`):

```sh
curl -sS "$INSIGHT_URL/api/documents/$DOC_ID/notes" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"body": "Escalated to the SOC lead."}'
```

**Export one report** (`GET /api/documents/{id}/export`, `insight-report-v1`, audited). `-OJ` saves it under
the server's file name (`insight-report-<id>.json`):

```sh
curl -sS -OJ "$INSIGHT_URL/api/documents/$DOC_ID/export" -H "Authorization: Bearer $INSIGHT_API_KEY"
ls insight-report-*.json && rm -f insight-report-*.json
```

### IOC export

`GET /api/iocs/export`: every indicator across the selected reports, once, with its sources and the most
restrictive TLP of those sources (`insight-ioc-v1`, **not STIX**; guide: [IOC_EXPORT](IOC_EXPORT.md)).
Repeat `kind`, `review_status` and `document_id` for several values. Budget: 30 per hour.

```sh
# Everything except rejected mentions, saved as insight-iocs-<time>.json
curl -sS -OJ "$INSIGHT_URL/api/iocs/export" -H "Authorization: Bearer $INSIGHT_API_KEY"
# Only IPs and domains an analyst accepted, from reports up to GREEN
curl -sS "$INSIGHT_URL/api/iocs/export?kind=ip&kind=domain&review_status=accepted&max_tlp=GREEN" \
  -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '{tlp, counts, values: [.iocs[].value]}'
# Safe to paste into a ticket or e-mail: defanged, without the report text around each indicator
curl -sS "$INSIGHT_URL/api/iocs/export?defang=true&evidence=false&max_tlp=GREEN" \
  -H "Authorization: Bearer $INSIGHT_API_KEY" | jq -r '.iocs[] | "\(.kind)\t\(.value)"'
# One report's indicators
curl -sS "$INSIGHT_URL/api/iocs/export?document_id=$DOC_ID" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.counts'
# `+` must be encoded (AMBER%2BSTRICT); --data-urlencode does it for you
curl -sS -G "$INSIGHT_URL/api/iocs/export" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  --data-urlencode 'max_tlp=AMBER+STRICT' | jq '.filters.max_tlp'
# Only indicators an analyst judged malicious, without private or documentation addresses
curl -sS "$INSIGHT_URL/api/iocs/export?verdict=malicious&exclude_flag=non-routable&exclude_flag=documentation" \
  -H "Authorization: Bearer $INSIGHT_API_KEY" | jq -r '.iocs[] | "\(.kind)\t\(.value)\t\(.flags)"'
rm -f insight-iocs-*.json
```

| Parameter | Values (case-sensitive) | Default |
| --- | --- | --- |
| `kind` | `cve` `url` `domain` `ip` `cidr` `email` `md5` `sha1` `sha256` `sha512` | all |
| `review_status` | `unreviewed` `accepted` `rejected` | `unreviewed`, `accepted` |
| `max_tlp` | a TLP label: only reports at or below it | none (a TLP-limited key: its limit) |
| `defang` | `true` / `false` | `false` |
| `evidence` | `true` / `false` (`false`: no report text around mentions) | `true` |
| `document_id` | report IDs | all reports |
| `verdict` | `unknown` `benign` `suspicious` `malicious` | all |
| `exclude_flag` | `non-routable` `documentation` `reserved-name` `common-benign` `personal-data` | none |
| `q`, `status`, `tlp`, `include_superseded` | as for `GET /api/documents` | |

Use `exclude_flag=personal-data` to omit e-mail indicator entries. Other entries can still carry addresses in report titles or evidence.

An invalid value is a `422` naming it (`kind 'IP': Input should be 'cve', ...`); more than 100,000 matching
mentions is a `422` too (narrow the filters).

### STIX 2.1 bundles

To share accepted indicators with a partner cleared for TLP:GREEN, download a bundle with evidence excerpts omitted:

```sh
curl --fail --silent --show-error --get "$INSIGHT_URL/api/iocs/stix" \
  -H "Authorization: Bearer $INSIGHT_API_KEY" \
  --data-urlencode 'review_status=accepted' --data-urlencode 'max_tlp=GREEN' \
  --data-urlencode 'evidence=false' --output partner-stix.json
```

The download retains source report UUIDs and TLP 2.0 markings. Consumers can match indicators across
filtered exports by canonical STIX pattern or value while retaining each download's markings.
[STIX object mapping and sharing rules](IOC_EXPORT.md#stix-21-export)

### Blocklists

`GET /api/iocs/blocklist?kind=…`: values safe to block, one per line: a `malicious` verdict that has not
expired, an accepted mention, no warning flag, within your TLP limit (full rules: [API](API.md)). Shares the
export budget of 30 per hour.

```sh
curl -sS "$INSIGHT_URL/api/iocs/blocklist?kind=ip" -H "Authorization: Bearer $INSIGHT_API_KEY"
# With the date of each verdict, when it expires and its label
curl -sS "$INSIGHT_URL/api/iocs/blocklist?kind=domain&format=csv" -H "Authorization: Bearer $INSIGHT_API_KEY"
```

For a sensor, download rules to a staging file and review them before replacing a loaded file.

```sh
curl --fail -sS "$INSIGHT_URL/api/iocs/blocklist?kind=domain&format=suricata" \
  -H "Authorization: Bearer $INSIGHT_API_KEY" -o insight-domains.staging.rules
curl --fail -sS "$INSIGHT_URL/api/iocs/blocklist?kind=ip&format=snort" \
  -H "Authorization: Bearer $INSIGHT_API_KEY" -o insight-ips.staging.rules
```

### Entities (indicators and pivots)

```sh
# Search canonical indicators (up to 200, with how many reports mention each)
curl -sS "$INSIGHT_URL/api/entities?q=example" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.[0:3]'
ENTITY_ID=$(curl -sS "$INSIGHT_URL/api/entities?q=203.0.113.45" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq -r '.[0].id')
# Pivot: every report mentioning it, newest first (offset/limit, at most 200 per page)
curl -sS "$INSIGHT_URL/api/entities/$ENTITY_ID?offset=0&limit=50" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  | jq '{kind, value, flags, assessment, first_seen_at, last_seen_at, document_count, reports: [.documents[] | {id, title, tlp}]}'
# Record a verdict: what the indicator means (review only says it was copied correctly). Needs a read-write key.
curl -sS -X POST "$INSIGHT_URL/api/entities/$ENTITY_ID/assessment" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"verdict": "malicious", "reason": "C2 in the March campaign", "tlp": "GREEN", "valid_until": "2027-06-30"}' | jq
# "unknown" clears it
curl -sS -X POST "$INSIGHT_URL/api/entities/$ENTITY_ID/assessment" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"verdict": "unknown"}'
```

### ATT&CK techniques

Reports are tagged with the MITRE ATT&CK® technique IDs written in them; analysts add the rest. Adding or
removing a technique needs a read-write key.

```sh
# Look a technique up in the bundled catalog
curl -sS "$INSIGHT_URL/api/attack/techniques?q=powershell" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.techniques[0]'
# What reports described over the last 30 days, most reports first
curl -sS "$INSIGHT_URL/api/attack/summary?days=30" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  | jq -r '.techniques[] | "\(.reports)\t\(.id)\t\(.name)"'
# The reports behind one technique
curl -sS "$INSIGHT_URL/api/attack/techniques/T1486/documents" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  | jq '.documents[] | {id, title}'
# A layer to open in ATT&CK Navigator ("Open Existing Layer" > "Upload from local")
curl -sS -OJ "$INSIGHT_URL/api/attack/navigator?days=90" -H "Authorization: Bearer $INSIGHT_API_KEY"
# One report's techniques; add one, remove one
curl -sS "$INSIGHT_URL/api/documents/$DOC_ID/techniques" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq
curl -sS -X POST "$INSIGHT_URL/api/documents/$DOC_ID/techniques" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"technique_id": "T1566.001"}' | jq
curl -sS -X DELETE "$INSIGHT_URL/api/documents/$DOC_ID/techniques/T1059.001" -H "Authorization: Bearer $INSIGHT_API_KEY"
```

### Industry threats and threat guides

Pick an industry, see the top groups a cited source names for it, then export a group's threat guide, its ATT&CK
Navigator layer and its indicator sweep list. `G0016` is an ATT&CK group ID from the bundled library; an actor
you created has a UUID instead. Writes need a read-write key. See [THREAT_GUIDES.md](THREAT_GUIDES.md).

```sh
# Industries, and how many groups a cited source names for each
curl -sS "$INSIGHT_URL/api/industries" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  | jq -r '.industries[] | "\(.groups)\t\(.key)\t\(.name)"'
# The top ten for healthcare, with the evidence for each (reports naming them counted over 90 days)
curl -sS "$INSIGHT_URL/api/industries/healthcare/actors?days=90" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  | jq '.actors[] | {rank, name, reports_naming_it, evidence: [.evidence[] | {source, url}]}'
# Find a group by name, alias or ID; list the actors you created
curl -sS "$INSIGHT_URL/api/actors?q=cozy" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.groups[] | {ref, name}'
# Track your own actor (optionally the same as an ATT&CK group)
ACTOR_ID=$(curl -sS -X POST "$INSIGHT_URL/api/actors" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"name": "Copper Fox", "aliases": ["CF-1"], "tlp": "AMBER"}' | jq -r .ref)
# One group: names, industry claims with sources, your decisions, linked reports
curl -sS "$INSIGHT_URL/api/actors/G0016" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq
# Track a campaign and record an explicit technique link at a chosen label
CAMPAIGN_ID=$(curl -fsS -X POST "$INSIGHT_URL/api/campaigns" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"name":"Example series","tlp":"GREEN"}' | jq -r .id)
curl -fsS "$INSIGHT_URL/api/campaigns" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq
curl -fsS "$INSIGHT_URL/api/campaigns/$CAMPAIGN_ID" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq
curl -fsS -X POST "$INSIGHT_URL/api/campaigns/$CAMPAIGN_ID/links" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"target_kind":"technique","target_id":"T1059.001","tlp":"GREEN"}'
curl -fsS "$INSIGHT_URL/api/campaigns/$CAMPAIGN_ID/links" -H "Authorization: Bearer $INSIGHT_API_KEY"
curl -fsS -X DELETE "$INSIGHT_URL/api/campaigns/$CAMPAIGN_ID/links/technique/T1059.001" -H "Authorization: Bearer $INSIGHT_API_KEY"
# The same link operations accept a local actor UUID
curl -fsS -X POST "$INSIGHT_URL/api/actors/$ACTOR_ID/links" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"target_kind":"technique","target_id":"T1059.001","tlp":"GREEN"}'
curl -fsS "$INSIGHT_URL/api/actors/$ACTOR_ID/links" -H "Authorization: Bearer $INSIGHT_API_KEY"
curl -fsS -X DELETE "$INSIGHT_URL/api/actors/$ACTOR_ID/links/technique/T1059.001" -H "Authorization: Bearer $INSIGHT_API_KEY"
# Link a report to the group (your decision; Insight never infers it), and remove the link
curl -sS -X POST "$INSIGHT_URL/api/actors/G0016/documents" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d "{\"document_id\": \"$DOC_ID\", \"note\": \"Same loader\"}"
curl -sS -X DELETE "$INSIGHT_URL/api/actors/G0016/documents/$DOC_ID" -H "Authorization: Bearer $INSIGHT_API_KEY"
# Add an industry with a citation, or remove a library claim with a reason
curl -sS -X POST "$INSIGHT_URL/api/actors/G0016/industries" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"industry": "energy", "citation_url": "https://example.org/report", "tlp": "CLEAR"}'
# The guide as JSON or Markdown; at most GREEN (for sharing)
curl -sS "$INSIGHT_URL/api/actors/G0016/guide" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.hunt.hypotheses[0]'
curl -sS -OJ "$INSIGHT_URL/api/actors/G0016/guide?format=md&max_tlp=GREEN" \
  -H "Authorization: Bearer $INSIGHT_API_KEY"
# ATT&CK Navigator layer, and the indicator sweep list (things to search for, not proof of the group)
curl -sS -OJ "$INSIGHT_URL/api/actors/G0016/navigator" -H "Authorization: Bearer $INSIGHT_API_KEY"
curl -sS -OJ "$INSIGHT_URL/api/actors/G0016/sweep?format=csv" -H "Authorization: Bearer $INSIGHT_API_KEY"
# By default only reports you linked feed the sweep list; opt in to reports that only name the group
curl -sS -OJ "$INSIGHT_URL/api/actors/G0016/sweep?format=csv&linked_only=false" \
  -H "Authorization: Bearer $INSIGHT_API_KEY"
# Hunts: start one, record a check for one hypothesis, close it
curl -sS "$INSIGHT_URL/api/actors/G0016/hunts" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq
HUNT_ID=$(curl -sS -X POST "$INSIGHT_URL/api/actors/G0016/hunts" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"title": "APT29 hunt, Q4", "tlp": "AMBER"}' | jq -r .id)
curl -sS -X PUT "$INSIGHT_URL/api/hunts/$HUNT_ID/checks/T1059.001" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"result": "nothing-found", "data_checked": "EDR process events",
  "period_start": "2026-10-01", "period_end": "2026-11-20"}'
curl -sS -X PUT "$INSIGHT_URL/api/hunts/$HUNT_ID" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"status": "closed", "summary": "Nothing found in 7 weeks."}'
curl -sS "$INSIGHT_URL/api/hunts/$HUNT_ID" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.checks'
# Rules: store a Sigma or YARA rule as text (never run), link it to a group or technique, list, read, delete
RULE_ID=$(curl -sS -X POST "$INSIGHT_URL/api/rules" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' --data-binary @- <<'JSON' | jq -r .id
{"kind": "sigma", "name": "Encoded PowerShell", "licence": "DRL-1.1", "tlp": "CLEAR",
 "body": "title: Encoded PowerShell\nlogsource:\n  product: windows\ndetection:\n  sel:\n    CommandLine|contains: ' -enc '\n  condition: sel\n"}
JSON
)
curl -sS -X POST "$INSIGHT_URL/api/rules/$RULE_ID/links" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"target_kind": "technique", "target_id": "T1059.001"}'
curl -sS -X DELETE "$INSIGHT_URL/api/rules/$RULE_ID/links" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"target_kind": "technique", "target_id": "T1059.001"}'
curl -sS "$INSIGHT_URL/api/rules?kind=sigma" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.[] | {id, name, linked_to}'
curl -sS "$INSIGHT_URL/api/rules/$RULE_ID" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq -r .body
curl -fsS "$INSIGHT_URL/api/rules/$RULE_ID/export" -H "Authorization: Bearer $INSIGHT_API_KEY" -o rule.zip
curl -sS -X DELETE "$INSIGHT_URL/api/rules/$RULE_ID" -H "Authorization: Bearer $INSIGHT_API_KEY"
```

### Cases

One investigation's reports, indicators, actors, campaigns and notes ([ADR 0029](adr/0029-cases.md)). A case
takes the strictest label of what it holds and keeps it when items are removed. A closed case answers `409`
to changes until it is reopened.

```bash
# Open a case, add a report and an indicator, and note what you asked for
CASE_ID=$(curl -fsS -X POST "$INSIGHT_URL/api/cases" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"title": "Gateway intrusion", "tlp": "GREEN"}' | jq -r .id)
curl -fsS -X POST "$INSIGHT_URL/api/cases/$CASE_ID/items" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d "{\"kind\": \"document\", \"target_id\": \"$DOC_ID\"}"
ITEM_ID=$(curl -fsS -X POST "$INSIGHT_URL/api/cases/$CASE_ID/items" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d "{\"kind\": \"indicator\", \"target_id\": \"$ENTITY_ID\"}" | jq -r .id)
curl -fsS -X POST "$INSIGHT_URL/api/cases/$CASE_ID/notes" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"text": "Asked the network team for firewall logs."}'
# Open cases, one case with its items, and what happened to it
curl -fsS "$INSIGHT_URL/api/cases?status=open" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.cases[] | {id, title, tlp, items}'
curl -fsS "$INSIGHT_URL/api/cases/$CASE_ID" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.items[] | {kind, name, tlp}'
curl -fsS "$INSIGHT_URL/api/cases/$CASE_ID/timeline" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq -r '.events[] | "\(.at)\t\(.action)\t\(.actor)"'
# Change the summary, remove an item (the label stays), close with a note, reopen, delete
curl -fsS -X PATCH "$INSIGHT_URL/api/cases/$CASE_ID" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"summary": "Edge appliance compromise."}'
curl -fsS -X DELETE "$INSIGHT_URL/api/cases/$CASE_ID/items/$ITEM_ID" -H "Authorization: Bearer $INSIGHT_API_KEY"
curl -fsS -X POST "$INSIGHT_URL/api/cases/$CASE_ID/close" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  -H 'Content-Type: application/json' -d '{"note": "Contained; the gateway is patched."}'
curl -fsS -X POST "$INSIGHT_URL/api/cases/$CASE_ID/reopen" -H "Authorization: Bearer $INSIGHT_API_KEY"
curl -fsS -X DELETE "$INSIGHT_URL/api/cases/$CASE_ID" -H "Authorization: Bearer $INSIGHT_API_KEY"
```

### Sources and enrichment (outbound internet)

These are the only routes that make Insight contact other servers. Sync imports a curated public feed; enrichment
sends only the CVE identifier to FIRST EPSS or NIST NVD.

```sh
# Registry and the last 5 runs of each source: cisa-kev, cisa-csaf, sans-isc, ncsc
curl -sS "$INSIGHT_URL/api/sources" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.[] | {key, name, last_run: .runs[0]}'
# Run one source now (read-write key). 409: another sync is running; 502: the source failed (recorded as a run)
curl -sS -X POST "$INSIGHT_URL/api/sources/cisa-kev/sync" -H "Authorization: Bearer $INSIGHT_API_KEY"
# Run every source in turn (read-write key); each result says success or error, and one failure does not stop the rest
curl -sS -X POST "$INSIGHT_URL/api/sources/sync-all" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.results[] | {key, status}'
# How often each source syncs by itself (0: only when asked, the default)
curl -sS "$INSIGHT_URL/api/schedules" -H "Authorization: Bearer $INSIGHT_API_KEY"
# Recent background jobs (scheduled syncs, alerts, automatic CVE lookups) and how they went
curl -sS "$INSIGHT_URL/api/jobs?limit=5" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.[] | {kind, key, status, message}'
# Look up a CVE that a report mentions (provider: epss or nvd; read-write key). Cached. One request per provider
# window (NVD 6.5 s, or 0.7 s with a key; EPSS 1 s) across all callers and automatic lookups: 429 says how long to wait
curl -sS -X POST "$INSIGHT_URL/api/enrichment/epss/CVE-2023-34362" -H "Authorization: Bearer $INSIGHT_API_KEY"
# This POST authorizes sharing the address with GreyNoise. Set IP to a reviewed public IPv4 in a CLEAR report.
curl -sS -X POST "$INSIGHT_URL/api/enrichment/greynoise/$IP" -H "Authorization: Bearer $INSIGHT_API_KEY"
# This GET reads only the cached result and its timestamp.
curl -sS "$INSIGHT_URL/api/ips/$IP/greynoise" -H "Authorization: Bearer $INSIGHT_API_KEY"
# Optional, with your own INSIGHT_SHODAN_KEY: send the same reviewed CLEAR address to Shodan (ADR 0031), then read the cache
curl -sS -X POST "$INSIGHT_URL/api/enrichment/shodan/$IP" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '{ports, vulns, org, attribution}'
curl -sS "$INSIGHT_URL/api/ips/$IP/shodan" -H "Authorization: Bearer $INSIGHT_API_KEY"
# The CVEs in your reports, most urgent first (ransomware, known exploited, likely attacked, critical, high), and why
curl -sS "$INSIGHT_URL/api/cves?days=30&limit=10" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  | jq '.cves[] | {cve, label, reason, cvss: .cvss.score, epss: .epss.probability}'
# Read the cached CVSS and EPSS scores without contacting anyone (404 unless a report you can see mentions the CVE)
curl -sS "$INSIGHT_URL/api/cves/CVE-2023-34362/scores" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  | jq '{cvss: .nvd.score, severity: .nvd.severity, epss: .epss.probability, percentile: .epss.percentile}'
# Reports about a subject, best match first (every word must match; quotes keep a phrase together)
curl -sS -G "$INSIGHT_URL/api/search" --data-urlencode 'q="initial access" broker' \
  -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.results[] | {title, score, snippet}'
# What a report links to, and what is two steps away (indicators, reports, techniques, groups, actors, campaigns)
curl -sS "$INSIGHT_URL/api/graph?node=report:$DOC_ID&depth=2" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  | jq '{nodes: [.nodes[] | {type, label}], edges: (.edges | length)}'
```

Turning a schedule on or off is for a signed-in browser session (the *Sources* tab, or the cookie jar of §2.2)
or the host's CLI, never an API key (`403`):

```sh
curl -sS -b "$JAR" -X PUT "$INSIGHT_URL/api/schedules/cisa-kev" -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' -d '{"interval_minutes": 1440, "at": "00:00"}'   # daily at midnight UTC
insight schedule all --every 24h --at 00:00     # on the host: every source daily at 00:00 UTC (off: only when asked)
```

Enrichment answers `422` for a malformed or unknown CVE (`Import a report mentioning this CVE first`), `429`
within 6.5 s of the previous lookup, and `502` when the provider fails. A refused request (`422`) does not start
the 6.5 s window. TLP-limited keys cannot use enrichment (`403`).

### Workspace

```sh
# Counters (current revisions only; a TLP-limited key counts only what it can see)
curl -sS "$INSIGHT_URL/api/stats" -H "Authorization: Bearer $INSIGHT_API_KEY"
# The latest 200 audit events, with who acted: operator, api-key:<key id>, cli, connector:<source>, system
curl -sS "$INSIGHT_URL/api/audit" -H "Authorization: Bearer $INSIGHT_API_KEY" | jq '.[0:3]'
# Organisation watch terms (not for TLP-limited keys)
curl -sS "$INSIGHT_URL/api/watch-terms" -H "Authorization: Bearer $INSIGHT_API_KEY"
# Load the synthetic demo reports (idempotent; the cookie jar of §2.2). Do not use on a production instance
curl -sS -b "$JAR" -X POST "$INSIGHT_URL/api/demo" -H "X-CSRF-Token: $CSRF"   # browser session only (API keys: 403)
```

## 5. Recipes

### 5.1 Feed a SIEM or firewall on a schedule

A read-only key limited to what the device may hold (`make api-key-create NAME=siem MAX_TLP=GREEN`), then one
blocklist per kind per run. Every 15 minutes for two kinds uses 8 of the 30 requests per hour.

```bash
#!/usr/bin/env bash
# Cron: */15 * * * * /opt/siem/pull-insight-blocklists.sh   (INSIGHT_URL and INSIGHT_API_KEY from a protected env file)
set -euo pipefail
for kind in ip domain; do
  out=/var/lib/siem/insight-$kind.txt
  curl -sS --fail-with-body --retry 3 "$INSIGHT_URL/api/iocs/blocklist?kind=$kind" \
    -H "Authorization: Bearer $INSIGHT_API_KEY" -o "$out.tmp"
  mv "$out.tmp" "$out"   # the firewall only ever reads a complete file
done
```

The blocklist holds only values an analyst judged **malicious** (a verdict, recorded in the reader or with
`POST /api/entities/{id}/assessment`), with an accepted mention and no warning flag, until the verdict expires.
That is the safe input for a blocking control. **Accepted is not a verdict:** it means Insight copied the value
correctly, and a report can name an indicator as a victim, a test address or a counter-example.

For context in searches and alerts rather than blocking, pull the full export instead (every 5 minutes uses
12 of the 30 requests per hour, so run one or the other at that rate):

```bash
#!/usr/bin/env bash
# Cron: */5 * * * * /opt/siem/pull-insight-iocs.sh   (INSIGHT_URL and INSIGHT_API_KEY from a protected env file)
set -euo pipefail
out=/var/lib/siem/insight-iocs.json
curl -sS --fail-with-body --retry 3 \
  "$INSIGHT_URL/api/iocs/export?review_status=accepted&evidence=false" \
  -H "Authorization: Bearer $INSIGHT_API_KEY" -o "$out.tmp"
mv "$out.tmp" "$out"     # the SIEM only ever reads a complete file
```

`--retry` also waits out `429` responses (curl honours `Retry-After`). Each IOC in the export carries its
`verdict` and `flags`, so the SIEM can weigh a `malicious` indicator differently from an `unknown` one and skip
flagged values.

### 5.2 Ingest a text file

`jq -Rs` turns the file into a JSON string safely (quotes, newlines, any characters):

```sh
printf 'Observed beaconing to 198.51.100.23 and CVE-2024-3400 exploitation.\nTLP:AMBER\n' > report.txt
jq -Rs --arg title "Incident 2026-014" --arg source "IR team" \
  '{title: $title, source_name: $source, tlp: "AMBER", body: .}' report.txt \
  | curl -sS "$INSIGHT_URL/api/documents" -H "Authorization: Bearer $INSIGHT_API_KEY" \
      -H 'Content-Type: application/json' -d @- | jq '{id, created, tlp, entity_count}'
rm -f report.txt
```

Reports up to 200,000 characters and 2,000 indicator mentions are accepted; split longer ones.

### 5.3 Page through every report

```sh
offset=0
while :; do
  page=$(curl -sS "$INSIGHT_URL/api/documents?offset=$offset&limit=200" -H "Authorization: Bearer $INSIGHT_API_KEY")
  count=$(echo "$page" | jq length)
  echo "$page" | jq -r '.[] | "\(.created_at)\t\(.tlp)\t\(.title)"'
  [ "$count" -lt 200 ] && break
  offset=$((offset + 200))
done
```

### 5.4 Accept every indicator in a report

```sh
curl -sS "$INSIGHT_URL/api/documents/$DOC_ID" -H "Authorization: Bearer $INSIGHT_API_KEY" \
  | jq -r '.observations[] | select(.review_status == "unreviewed") | .id' \
  | while read -r obs; do
      curl -sS "$INSIGHT_URL/api/observations/$obs/review" -H "Authorization: Bearer $INSIGHT_API_KEY" \
        -H 'Content-Type: application/json' -d '{"status": "accepted"}'; echo
    done
```

Review before accepting in bulk: rejected mentions are how analysts keep wrong extractions out of exports.

### 5.5 Back off on 429 in your own code

```sh
insight_get() {   # usage: insight_get /api/path  ->  prints the body; waits out rate limits
  local path=$1 headers body status wait
  headers=$(mktemp); body=$(mktemp)
  for attempt in 1 2 3 4 5; do
    status=$(curl -sS -D "$headers" -o "$body" -w '%{http_code}' "$INSIGHT_URL$path" \
      -H "Authorization: Bearer $INSIGHT_API_KEY")
    [ "$status" != 429 ] && break
    wait=$(sed -n 's/^[Rr]etry-[Aa]fter: *\([0-9]*\).*/\1/p' "$headers"); sleep "${wait:-5}"
  done
  cat "$body"; rm -f "$headers" "$body"
  [ "$status" -lt 400 ]
}
insight_get /api/stats
```

### 5.6 Python

```python
import os

import httpx

client = httpx.Client(
    base_url=os.environ['INSIGHT_URL'],
    headers={'Authorization': f'Bearer {os.environ["INSIGHT_API_KEY"]}'},
    timeout=30,
)
stats = client.get('/api/stats').raise_for_status().json()
export = client.get('/api/iocs/export', params=[('kind', 'ip'), ('kind', 'domain'), ('max_tlp', 'GREEN')])
export.raise_for_status()
print(stats['documents'], 'reports;', export.json()['counts']['iocs'], 'IP/domain IOCs up to GREEN')
print('read budget left:', client.get('/api/stats').headers['ratelimit'])
```

`params` as a list of pairs repeats a parameter and encodes `+` for you.

## 6. Troubleshooting

| Response | Cause | Fix |
| --- | --- | --- |
| `401 Invalid or expired API key` | Typo, expired, revoked or rotated key | `make api-key-status`; rotate if needed. Check for a missing `Bearer ` |
| `401 Sign in required` | No `Authorization: Bearer` header, or the session ended (8 h, sign-out, new password) | Send the key, or sign in again |
| `403 This API key is read-only` | `POST` with a read key | `make api-key-rotate ACCESS=read-write` |
| `403 Not available to TLP-limited API keys` | Audit log or enrichment with a `MAX_TLP` key | Use an unlimited key (`make api-key-rotate MAX_TLP=RED` lifts the limit) |
| `403 Invalid CSRF token` | Session write without `X-CSRF-Token` | Fetch it from `/api/session` (section 2.2) |
| `403 Forbidden` (plain text) | `Origin` header does not match the site | Call the API from scripts, not another website; behind a proxy set `INSIGHT_TRUSTED_PROXIES` |
| `404 Report not found` for a report you know exists | It is above the key's `MAX_TLP` | Expected: the key may not see it |
| `400 Invalid host header` | URL host not in `INSIGHT_ALLOWED_HOSTS` | Add the host name you use |
| `413 Request too large` | Body over 2 MB | Split the report |
| `422 ... cannot be stored here` / `Refused: the text carries a TLP:RED marking` | Report above `INSIGHT_MAX_TLP` (or the key's limit) | Do not store it here, or reword a marking that only mentions the label |
| `429` | Budget used up | Wait `Retry-After` seconds (recipe 5.5). Sign-in: a wrong password after 30 failures per minute (the right one still signs in) |
| `502` | The external source or provider failed | Retry later; `GET /api/sources` shows the recorded error |
| `503` on sign-in | MFA on, no authenticator app paired | `make mfa-enable` (pairs it) or `make mfa-disable` |

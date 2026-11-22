# TAXII 2.1 server

Insight serves its reviewed indicators, the CISA KEV catalog and your published hunt packages over TAXII 2.1, so a SIEM or threat-intelligence platform can poll them
on a schedule without a custom script ([ADR 0026](adr/0026-taxii-server.md)). The server is read-only: clients
can list collections and read objects, but nothing can be written or created.

## What a client gets

### Software associations

The Reviewed indicators collection also carries explicitly linked catalog software as `malware`
(`is_family: true`) or `tool`. Selected report/software links become `related-to` relationships. An explicit
analyst actor/campaign/software link becomes `uses` when its software or subject is selected. Shared report
mentions never imply use. These projections follow the existing accepted-indicator selection and publisher
reuse rules; an unrelated report is not pulled into the collection.

Each software projection and relationship carries its own effective TLP marking. A restricted association
does not add a reference to a less restricted report's `object_refs`. Software IDs depend on its saved
catalog ID, name, type and label; relationship IDs include their saved link and endpoints. Link timestamps
contribute to change dates, so a new association to an old report reaches `added_after` clients. Saved
name/type snapshots keep old links exportable after catalog removal. Notes and candidate matches are not
exported as associations. Software projections are validated with the rest of the STIX bundle.

### Collections

Three fixed collections. **Reviewed indicators** (ID `5b2f8a7e-4c1d-4e3a-9f6b-0d8c7a1e2f34`):

- every indicator and CVE an analyst **accepted**, as STIX 2.1 `indicator` and `vulnerability` objects;
- the `report` objects that mention them, with publisher text only where the publisher allows it;
- the ATT&CK techniques tagged on those reports (`attack-pattern`, cited by technique ID);
- your actors and campaigns (`threat-actor`, `campaign`) and their `relationship` objects, wherever you linked
  them to one of those reports, indicators or techniques;
- the TLP 2.0 marking definitions they use.

The same rules as the STIX export apply ([IOC export](IOC_EXPORT.md)): the API key's TLP limit, current report
revisions only, and the publishers' reuse rules. Unreviewed and rejected mentions are never served, and an
actor, campaign or link above the key's limit is left out.

**CISA Known Exploited Vulnerabilities** (ID `c4e1b7d2-6a35-4f08-8b9e-3d7f2a5c1e60`): every KEV entry Insight
has synced, as a `vulnerability` with CISA's name for the weakness and an `x_insight_kev` property holding
the vendor, product, date added, due date, required action, ransomware use and CWEs. It is public data
(TLP:CLEAR), so every key may read it. Its vulnerability IDs differ from the indicators collection's CVE
objects, which carry different content; relate the two by the `cve` external reference.

**Hunt packages** (ID `9d3f6b1a-2c4e-4a7b-8e5d-1f0a3c6b9e27`): one hypothesis per package for a hunt tool to
test in its own data ([ADR 0034](adr/0034-hunt-packages.md)). Each published package is:

- a `grouping` (context `suspicious-activity`) whose `name` is the title and `description` the hypothesis,
  with the threat group and the reports behind it as external references (report text is never included);
- an `attack-pattern` for each ATT&CK technique, and an `indicator` (or `vulnerability`, for a CVE) for each
  indicator;
- an `indicator` for each detection rule, with the rule text as its `pattern` and `pattern_type` `sigma`,
  `yara`, `suricata` or `snort`, and an `indicates` relationship to each package technique the rule is
  linked to;
- the package's TLP marking on every object.

A key sees a package only within its TLP limit. Drafts are never served. A retired package is served once more
with every object `revoked: true`, so drop it when you see that; publishing it again later brings new IDs. Any
change to a package brings a new version of all its objects. Find the objects of one package through the
grouping's `object_refs`.

## Connect a client

1. Create an API key for the client (`make api-key-create NAME=sentinel`, or `insight api-key create`). A
   read-only key with the lowest TLP limit that works is best, for example `MAX_TLP=GREEN`. Insight has one
   active key at a time, so the client shares it with any other script.
2. Point the client at the discovery URL, `https://insight.example.org/taxii2/`, or straight at the API root,
   `https://insight.example.org/taxii2/insight/`.
3. Send the key as a Bearer token: `Authorization: Bearer <key>`. Insight does not accept a user name and
   password, and a signed-in browser is refused.

With `curl`:

```bash
KEY=...   # the API key
BASE=https://insight.example.org/taxii2/insight
curl -s -H "Authorization: Bearer $KEY" -H 'Accept: application/taxii+json;version=2.1' "$BASE/collections/"
curl -s -H "Authorization: Bearer $KEY" -H 'Accept: application/taxii+json;version=2.1' \
  "$BASE/collections/5b2f8a7e-4c1d-4e3a-9f6b-0d8c7a1e2f34/objects/?added_after=2026-11-01T00:00:00Z"
```

With the OASIS Python client (`taxii2-client`):

```python
import requests
from taxii2client.v21 import Server, as_pages


class Bearer(requests.auth.AuthBase):
    def __init__(self, key: str) -> None:
        self.key = key

    def __call__(self, request):
        request.headers['Authorization'] = f'Bearer {self.key}'
        return request


server = Server('https://insight.example.org/taxii2/', auth=Bearer(KEY))
collection = server.api_roots[0].collections[0]
for page in as_pages(collection.get_objects, per_request=1000, added_after='2026-11-01T00:00:00Z'):
    for obj in page.get('objects', []):
        ...
```

## Polling

- **Ask only for changes.** Save the `X-TAXII-Date-Added-Last` header of the last page, and send it as
  `added_after` next time. An indicator appears again when a new visible report mentions it, or when an analyst
  accepts it, even in an old report.
- **Follow `next`.** A page holds up to 1,000 objects (`limit`, default 1,000). While `more` is `true`, send the
  page's `next` value unchanged.
- **IDs are stable.** The same indicator, technique, actor, campaign, link or KEV entry always has the same
  STIX ID, whichever report or key it comes from, so clients can update rather than duplicate. Hunt package
  objects belong to their package and its publication. A technique's
  ID includes the ATT&CK version, so an ATT&CK upgrade in Insight brings new technique objects.
- **Links count as new.** An actor or campaign appears after your last poll when you link it to something the
  key can see, even if you created it long before. A KEV entry appears again only when CISA changes it.
- **Removals are not sent.** If an indicator is later rejected, or its report is deleted, it simply stops
  appearing. To drop such indicators, re-pull the whole collection now and then. Hunt packages are the
  exception: a retired package comes back as revoked objects.
- **Budget.** Collection reads draw on a `taxii` budget of 240 requests per hour per key. A client polling
  every 15 minutes uses 4 to 8 of them.

Filters: `added_after`, `match[id]`, `match[type]` (for example `indicator`), `match[version]` (`last`, `first`,
`all` or a timestamp; Insight keeps one version of each object) and `match[spec_version]` (`2.1`). Also
available: `manifest/`, `objects/{id}/` and `objects/{id}/versions/`.

## Errors

Errors use the TAXII error format, for example
`{"title": "Invalid added_after", "description": "...", "http_status": "400"}`.

| Status | Meaning |
| --- | --- |
| `401` | No API key, or a wrong, revoked or expired one |
| `403` | A browser session instead of an API key |
| `404` | Unknown collection, or an object that does not exist or is above the key's TLP limit |
| `405` | A write (Insight's TAXII server is read-only) |
| `406` | The client does not accept `application/taxii+json;version=2.1` |
| `413` | More than 100,000 accepted mentions, or more than 500 hunt packages to serve: the collection is too large to serve |
| `429` | The `taxii` budget is used up; wait for `Retry-After` |

Every read is audited as `taxii.read`, with the key that made it.

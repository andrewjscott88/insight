# Exporting indicators of compromise (IOCs)

Insight can give you **one JSON file listing every indicator found in your reports, each listed once**, with the
reports that mention it, the surrounding text, and the handling label you must respect. This guide covers:

1. [In 30 seconds](#1-in-30-seconds)
2. [Quick start: workspace, command line, API](#2-quick-start)
3. [Recipes: "I want to…"](#3-recipes-i-want-to)
4. [How the filters combine](#4-how-the-filters-combine)
5. [Reading the file](#5-reading-the-file)
6. [TLP and sharing](#6-tlp-and-sharing)
7. [Defanging](#7-defanging)
8. [Using the file in other tools](#8-using-the-file-in-other-tools)
9. [Limits and troubleshooting](#9-limits-and-troubleshooting)
10. [Format versioning](#10-format-versioning)

Field-by-field reference: [API.md](API.md#ioc-export). Machine-readable schema:
[schemas/insight-ioc-v1.schema.json](schemas/insight-ioc-v1.schema.json). Complete example file:
[examples/insight-iocs-example.json](examples/insight-iocs-example.json).

## 1. In 30 seconds

- **What you get:** a file in the `insight-ioc-v1` format. For every indicator you get its value, its type, the
  reports it appears in (with a short piece of the surrounding text from each), how analysts reviewed it, CISA KEV
  context for CVEs, and a TLP label.
- **What it is not:** it is **not STIX**, and it is **not a list of malicious things**. Insight extracts anything
  that looks like an indicator, including vendor sites and example addresses that a report merely mentions.
  Accepting a mention in Insight means "the extraction is accurate", not "this is malicious".
- **Who may see it:** the file carries the most restrictive TLP of the reports it includes. Treat the whole file
  at that label. An export is not permission to share.

### Words used in this guide

| Term | Meaning |
| --- | --- |
| **Indicator / IOC** | A CVE, URL, domain, IP address, CIDR network range, e-mail address, or MD5/SHA1/SHA256/SHA512 hash found in a report. CVEs are vulnerabilities rather than IOCs in the strict sense; they are included so you can export them too. |
| **Report** | A document in the inbox (pasted or synced). Indicators are extracted from the report **body**, not its title. |
| **Mention** | One occurrence of an indicator in one report. An indicator mentioned three times in one report has three mentions. |
| **Review status** | An analyst's verdict on **one mention**: `unreviewed`, `accepted` (the extraction is accurate) or `rejected` (wrong or not useful). Set with **Accept / Reject / Reset** in the report reader. |
| **Triage status** | The **report's** state in the inbox: `new`, `reviewing`, `reviewed` (the **Document review** selector). In the file it is the `status` field of each source. Not a verdict on any indicator. |
| **TLP** | Traffic Light Protocol label, least to most restrictive: `CLEAR` < `GREEN` < `AMBER` < `AMBER+STRICT` < `RED`. |
| **Evidence** | The report text around a mention, included so a reader can check the context. It can be left out. |
| **Defang** | Rewriting an indicator so it cannot be clicked or resolved by accident: `https://evil.example` → `hxxps://evil[.]example`. |

## 2. Quick start

The workspace, the command line and the API produce the same file. They share one implementation, and every
export is recorded in the audit log.

### In the workspace

**All reports:**

1. Click **Export IOCs** (top right, next to **＋ Ingest intelligence**).
2. Choose what to include. The defaults are shown in brackets:
   - **Indicator types** [all];
   - **Observation review status** [`unreviewed` and `accepted`; rejected mentions are left out]. Accepted means
     an analyst confirmed the extraction is accurate, not that the indicator is malicious;
   - **Most restrictive TLP to include** [No limit];
   - **Only reports matching the current inbox search and filters** [off]. When ticked, the search text, the
     status and TLP selectors and **Include superseded revisions** from the inbox also apply;
   - **Defang values** [off];
   - **Include evidence excerpts** [on]. Untick it before sharing (see [§6](#6-tlp-and-sharing)).
3. Read the preview line, for example *Will export 7 indicators from 3 reports (9 mentions).* It updates as you
   change the options. If it says *Nothing matches these filters.* or *Too large: …*, adjust the filters.
   Download is refused in those cases.
4. Click **Download JSON ↓**. A new browser tab opens and the file `insight-iocs-<date>T<time>Z.json` downloads.

**One report:** open it in the inbox and click **Export this report's IOCs ↗** under its observations. This uses
the default options (all types, rejected mentions left out, evidence included). For other options, use
`--document` on the command line or `document_id` in the API.

### On the command line

```sh
insight export-iocs iocs.json                       # everything except rejected mentions
insight export-iocs share.json --max-tlp GREEN --review-status accepted --defang --no-evidence
```

```text
Exported 24 IOCs (38 mentions) from 1 report to iocs.json (TLP:AMBER). Handle the file according to that label.
```

- **Database:** the command reads the same database as the server: `INSIGHT_DATABASE_URL`, or
  `INSIGHT_DATA_DIR/insight.db` (default `./data/insight.db`). `.env` is read from the current directory.
- **Output file:** it is created with owner-only permissions (`0600`) and is never overwritten; choose a new
  name each time.
- **Empty exports** are still written (useful in scripts), and the summary line says why they may be empty.
- **Exit codes:** `0` success, `1` export failed (message on stderr), `2` no file name given.
- `insight --help` lists every option with its values and shows examples.

In Docker, write the file into the data volume (the container's root filesystem is read-only), copy it out,
then remove the copy from the volume:

```sh
docker compose exec insight insight export-iocs /data/iocs-$(date +%F).json --max-tlp GREEN --review-status accepted
docker compose cp insight:/data/iocs-YYYY-MM-DD.json ./
docker compose exec insight rm /data/iocs-YYYY-MM-DD.json
```

All options. Option values are case-insensitive on the command line:

| Option | Values | Default |
| --- | --- | --- |
| `--kind KIND` (repeatable) | `cve` `url` `domain` `ip` `cidr` `email` `md5` `sha1` `sha256` `sha512` | all |
| `--review-status REVIEW` (repeatable) | `unreviewed` `accepted` `rejected`: the review state of each **mention** | `unreviewed` and `accepted` |
| `--max-tlp LABEL` | `CLEAR` `GREEN` `AMBER` `AMBER+STRICT` `RED`: include reports at or below this label | no limit |
| `--defang` | flag: defang values, titles and evidence | off |
| `--no-evidence` | flag: leave out the report text around each indicator | evidence included |
| `--document ID` (repeatable) | a report ID (from the reader's export file name, or `GET /api/documents`) | all reports |
| `--query TEXT` | inbox search text, at most 200 characters | none |
| `--status TRIAGE` | the **report's** triage status: `new` `reviewing` `reviewed` | any |
| `--tlp LABEL` | reports with **exactly** this label | any |
| `--include-superseded` | flag: also older revisions of synced items | off |

### Through the API

`GET /api/iocs/export` with the API key (recommended for scripts and SIEMs; see the
[API guide](API_GUIDE.md)) or a signed-in session; GET requests need no CSRF header. Each caller may export 30
times per hour (`429` with `Retry-After` beyond that), and a key created with `--max-tlp` never exports reports
above its limit. The parameters are the same
as the CLI options, written `kind`, `review_status`, `max_tlp`, `defang`, `evidence` (`false` to leave
evidence out), `document_id`, `q`, `status`, `tlp` and `include_superseded`. Values are **case-sensitive** here:
`ip`, not `IP`; `GREEN`, not `green`.

With curl and the API key (`make api-key-create NAME=siem MAX_TLP=GREEN` creates a read-only one):

```sh
curl -fsS -OJ -H "Authorization: Bearer $INSIGHT_API_KEY" \
  "http://127.0.0.1:8080/api/iocs/export?kind=ip&kind=domain&review_status=accepted&max_tlp=GREEN&defang=true&evidence=false"
```

With curl and a browser session instead (signing in through the form):

```sh
BASE=http://127.0.0.1:8080
JAR=$(mktemp)
TOKEN=$(curl -fsS -c "$JAR" "$BASE/login" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p')
curl -fsS -b "$JAR" -c "$JAR" -o /dev/null \
  --data-urlencode "csrf_token=$TOKEN" --data-urlencode "password=$INSIGHT_PASSWORD" "$BASE/login"
curl -fsS -b "$JAR" -OJ \
  "$BASE/api/iocs/export?kind=ip&kind=domain&review_status=accepted&max_tlp=GREEN&defang=true&evidence=false"
rm -f "$JAR"
```

`-OJ` saves the file under the server's name (`insight-iocs-<date>T<time>Z.json`). For `AMBER+STRICT`, let curl
encode the value (`--get --data-urlencode "max_tlp=AMBER+STRICT"`) or write `AMBER%2BSTRICT`. A literal `+` in a
URL means a space, and the request fails.

With Python (extends the minimal client in [API.md](API.md)):

```python
import os
import re
from pathlib import Path

import httpx

PASSWORD = os.environ['INSIGHT_PASSWORD']
c = httpx.Client(base_url='http://127.0.0.1:8080')
token = re.search(r'name="csrf_token" value="([^"]+)"', c.get('/login').text).group(1)
c.post('/login', data={'csrf_token': token, 'password': PASSWORD})

response = c.get(
    '/api/iocs/export',
    params=[  # a list of pairs, so `kind` and `review_status` can repeat
        ('kind', 'ip'),
        ('kind', 'domain'),
        ('review_status', 'accepted'),
        ('max_tlp', 'AMBER+STRICT'),  # httpx encodes the + correctly
        ('defang', 'true'),
    ],
)
response.raise_for_status()  # 422 = invalid filter or more than 100,000 mentions
export = response.json()
Path('insight-iocs.json').write_bytes(response.content)
print(export['tlp'], export['counts'])
```

Files saved from the browser or the API get your normal file permissions. Restrict them yourself (for example
`chmod 600 insight-iocs-*.json`); only the CLI creates the file as `0600`.

## 3. Recipes: "I want to…"

| I want to… | Workspace dialog | Command line |
| --- | --- | --- |
| **Share with a trusted community** (TLP:GREEN) | TLP ≤ `GREEN`; review status `accepted` only; defang on; evidence **off** | `--max-tlp GREEN --review-status accepted --defang --no-evidence` |
| **Feed a firewall, proxy or DNS blocklist** | use the blocklist instead: `GET /api/iocs/blocklist?kind=ip` ([API](API.md)) | (API only) |
| **Hunt for files in EDR** | types MD5, SHA-1, SHA-256, SHA-512 | `--kind md5 --kind sha1 --kind sha256 --kind sha512` |
| **Prioritise patching** | type CVE | `--kind cve`, then list the KEV entries (see [§8](#8-using-the-file-in-other-tools)) |
| **Paste indicators into a ticket or e-mail** | defang on | `--defang`, and read [§7](#7-defanging) first |
| **Export one report** | **Export this report's IOCs ↗** in the report reader | `--document ID` |
| **Export one campaign** | search the inbox for its name, tick "Only reports matching…" | `--query "SALT MERIDIAN"` |
| **Check extraction quality** (QA) | tick all three review statuses | `--review-status unreviewed --review-status accepted --review-status rejected` |
| **Include history** of synced items | inbox switch **Include superseded revisions** + "Only reports matching…" | `--include-superseded` |

> **Before you load anything into a blocking control:** "accepted" means a value was copied correctly, not
> that it is harmful. Reports mention legitimate infrastructure (vendor sites, cloud services, documentation
> addresses) and victims' own addresses. For blocking, use the **blocklist** (`GET /api/iocs/blocklist`): it
> holds only values an analyst judged `malicious`, with an accepted mention and no warning flag, until the
> verdict expires. In an export, filter with `verdict=malicious` and check each IOC's `flags`.

## Network sensor rules

On `GET /api/iocs/blocklist`, choose `kind=ip` or `kind=domain` and `format=suricata` or `format=snort`.
The download contains passive alert rules for the selected engine. Each indicator has a current malicious
verdict, an accepted mention within the caller's sharing limit and no warning flag. An empty selection
returns HTTP 422. IPs and domains appear in live, machine-readable form. Review the staged file and check
the sensor configuration before loading it. Refresh the file to retire expired verdicts.

- **IPs.** IPv4 and IPv6 rules match traffic in either direction involving the exact address.
- **Suricata domains.** The DNS query buffer matches the entire queried name, case-insensitively.
- **Snort 3 domains.** The rule checks the first uncompressed question in a standard UDP query to port 53.
  DNS over TCP and encrypted DNS are outside the scope of these Snort signatures.
- **Rule IDs.** Reserve local SIDs 1,000,000,000–1,499,999,999 for these IP rules and
  1,500,000,000–1,999,999,999 for domains. IDs derive from the canonical value, with collisions resolved
  within the sorted file. Replace each file as a unit. Review the matched value when correlating alerts.

## 4. How the filters combine

- **Every filter must match** (AND). Within **types**, **review statuses** and **reports** (`--document`), any of
  the chosen values matches (OR).
- **Report filters** decide which **reports** take part: search text, triage status, exact TLP, superseded
  revisions, most restrictive TLP and chosen reports. They work exactly like the inbox, with one difference: the
  API and CLI reject search text longer than 200 characters, while the inbox and the dialog shorten it.
- **Review status applies to each mention, not to the indicator.** If `192.0.2.44` is accepted in one report but
  unreviewed in another, an accepted-only export lists it with only the first report as its source.
- **`tlp` versus `max_tlp`:**
  - `tlp=GREEN` means only reports labelled exactly GREEN;
  - `max_tlp=GREEN` means CLEAR **and** GREEN reports, for sharing up to a level.
- **Superseded revisions** (older versions of synced items) are left out unless requested. An indicator that a
  publisher removed in a later revision therefore disappears from the default export. A report you choose
  explicitly with `--document` is always included, even if it is a superseded revision.
- Nothing matching is not an error: the CLI and API give you a valid file with an empty `iocs` list. The
  workspace refuses to download an empty file.

## 5. Reading the file

A complete example, generated from the synthetic demo data (reserved documentation addresses only), is in
[examples/insight-iocs-example.json](examples/insight-iocs-example.json). Before it was exported, the analyst had
accepted two mentions in the first demo report, rejected `2001:db8::42` in the second, and marked the first
report as reviewed. The example's IDs and timestamps are stable placeholders (`scripts/make_ioc_example.py`
regenerates it); real exports contain random IDs and real times.

The file starts with a summary. Check it before anything else:

```json
{
  "format": "insight-ioc-v1",
  "export_id": "00000000-0000-4000-8000-000000000001",
  "generated_at": "2026-01-16T09:00:00+00:00",
  "tlp": "AMBER+STRICT",
  "defanged": false,
  "filters": { "review_statuses": ["unreviewed", "accepted"], "max_tlp": null, "document_ids": [],
               "include_evidence": true, "…": "…" },
  "counts": { "iocs": 6, "documents": 3, "mentions": 8,
              "by_kind": { "cve": 2, "domain": 1, "ip": 1, "sha256": 1, "url": 1 } }
}
```

- `tlp` is the label for the **whole file**: AMBER+STRICT, because one included report carries it.
- `filters` records exactly what was asked for, with defaults filled in, so the file documents itself.
- `counts.mentions` (8) is larger than `counts.iocs` (6) because some indicators appear in more than one report.
- The rejected `2001:db8::42` is absent: rejected mentions are left out by default.

Then one entry per indicator, sorted by type and then value. An excerpt:

```json
{
  "kind": "domain",
  "value": "relay.example.org",
  "tlp": "GREEN",
  "first_ingested_at": "2026-01-15T09:00:00+00:00",
  "last_ingested_at": "2026-01-15T09:05:00+00:00",
  "review_statuses": { "unreviewed": 1, "accepted": 1 },
  "kev": null,
  "verdict": "unknown",
  "verdict_valid_until": null,
  "flags": ["reserved-name"],
  "sources": [
    { "title": "Training scenario: edge appliance activity", "tlp": "CLEAR", "status": "reviewed",
      "extractor_version": "regex-v4", "mentions": 1,
      "evidence": "raining data, not real intelligence. An analyst observed 192.0.2.44 connecting to https://relay.example.org/beacon?case=Alpha. The bulletin mentions CVE-2024-3400 as a research reference, not evide" },
    { "title": "Training scenario: shared infrastructure pivot", "tlp": "GREEN", "status": "new",
      "extractor_version": "regex-v4", "mentions": 1,
      "evidence": "This is synthetic training data. The host relay.example.org and 192.0.2.44 appear in a second lab report. Their co-occurrence is a lead, not proof of" }
  ]
}
```

How to read it:

- **`verdict`** is what an analyst decided the indicator means: `unknown` (nothing recorded yet), `benign`,
  `suspicious` or `malicious`, with `verdict_valid_until` when it expires. A verdict whose own TLP label is
  above the export's limit shows as `unknown`.
- **`flags`** say why a value is unsafe to block, whatever its verdict: `non-routable` (private, loopback,
  shared or reserved addresses), `documentation` (example ranges such as 192.0.2.0/24), `reserved-name`
  (`.local`, `.test`, `example.org`, as here) and `common-benign` (a short list of vendor domains such as
  `microsoft.com`). E-mail addresses carry `personal-data`. Flags are computed from the value.

- **`tlp: GREEN`** is the most restrictive label among *this indicator's* sources (CLEAR and GREEN). It is
  lower than the file's AMBER+STRICT, because no AMBER+STRICT report mentions this domain.
- **`review_statuses`** counts the included mentions: accepted in the first report, not yet reviewed in the
  second.
- **`status`** in each source is the **report's** triage state (`reviewed`, `new`), not a verdict on the
  indicator.
- **`evidence`** is the text around the first included mention in that report, up to 90 characters on each side.
  It is cut at fixed character positions, so it can start or end mid-word ("raining data…"). It can also contain
  other indicators and any other text that happened to be nearby. It is `null` when the export was made without
  evidence.
- **`extractor_version`** names the extractor that produced the report's observations (`regex-v4` adds e-mail addresses, `regex-v5` recognizes additional defanged forms).
  Reports ingested before 0.2.0 say `regex-v1`, and their values can differ slightly in form.
- **`first_ingested_at` / `last_ingested_at`** are when the oldest and newest source reports were **added to
  Insight**. They are not publication dates, and not dates the indicator was seen in the wild.
- **`kev`** is filled in for CVEs that are in the imported CISA KEV catalogue (run the CISA KEV source first) with
  `date_added`, `due_date`, `required_action`, `vendor`, `product` and `imported_at`; otherwise `null`.
- **`entity_id`** and **`document_id`** let you look the indicator or report up in Insight
  (`GET /api/entities/{id}`, `GET /api/documents/{id}`), or export that report again with `--document`.
- **Values are canonical:** defanged input is refanged, host names are lower-case, international names use
  punycode (`xn--…`), and IPv4-mapped IPv6 addresses become IPv4.
  A network range has kind `cidr` and keeps its prefix length, for example `203.0.113.0/24`.
  Use `--kind cidr` to export ranges or `--kind email` to export e-mail addresses. The blocklist excludes both kinds.

## 6. TLP and sharing

- **How labels are worked out.** Each indicator gets the most restrictive label of its *included* reports, and the
  file gets the most restrictive label of *all* included reports. Reports left out by your filters do not count.
  In the example, an accepted-only export labels `relay.example.org` **CLEAR**: only the CLEAR report's accepted
  mention is included. Labels are never lowered ([ADR 0009](adr/0009-tlp-policy.md)).
- **An empty file is labelled AMBER**, the workspace default, never CLEAR.
- **Publishers' words stay in Insight unless they allow otherwise.** For reports synced from a source whose
  publisher allows metadata only (every feed except CISA's KEV list and CSAF advisories), `evidence` is `null`
  even when evidence is included; the indicator, its title, link and dates are still exported
  ([ADR 0021](adr/0021-threat-research-sources.md)). Reports you pasted yourself are yours: their evidence is
  included as chosen.
- **To share at a given level, filter when exporting** (`max_tlp`), rather than editing a larger file afterwards.
  That way, evidence and titles from more restricted reports are never in the file at all.
- **Leave evidence out when sharing.** An excerpt is raw report text around a mention, so it can carry things you
  did not choose to share. In the synthetic GLASS HARBOR report, the analyst rejects `10.20.30.40` (the victim's
  internal network). Yet the excerpt of the accepted download URL next to it still reads "…movement to internal
  host 10.20.30.40 (victim network…". Rejecting a mention removes it from the indicator list, not from other
  mentions' context. Untick **Include evidence excerpts** (`--no-evidence`, `evidence=false`) for anything that
  leaves your team; titles and provenance stay.
- **E-mail addresses.** Add `exclude_flag=personal-data` to an API export to omit the flagged indicator entries.
  Addresses can also appear in a report title, evidence excerpt, or source metadata. Use `evidence=false`
  to omit excerpts and check the remaining text before sharing. Defanged addresses still identify the mailbox.
- **If you split a file,** each part takes the most restrictive label of the entries it contains. Each entry's own
  `tlp` is safe to use for that part.
- **Traceability.** Every export is written to the audit log as `ioc.export`. The event's `object_id` is the
  file's `export_id`, and its detail records the counts, the file's TLP, whether it was defanged, and the filters,
  including whether evidence was included (`GET /api/audit` lists the latest 200 events). The workspace's preview
  count is not audited; only downloads are.
- A label is metadata, not enforcement. Insight cannot stop a file from being forwarded. See
  [SECURITY.md](SECURITY.md).

## 7. Defanging

When defanging is on, indicator **values**, report **titles** and **evidence excerpts** are rewritten:

| What | Example |
| --- | --- |
| URL | `https://relay.example.org/beacon?case=Alpha` → `hxxps://relay[.]example[.]org/beacon?case=Alpha` |
| Domain | `relay.example.org` → `relay[.]example[.]org` |
| IPv4 / IPv6 | `192.0.2.44` → `192[.]0[.]2[.]44`; `2001:db8::1` → `2001[:]db8[:][:]1` |
| E-mail address (domain part) | `billing@invoices.example.net` → `billing@invoices[.]example[.]net` |
| CIDR range | `203.0.113.0/24` → `203[.]0[.]113[.]0/24`; `2001:db8::/32` → `2001[:]db8[:][:]/32` |
| File-like name with a real TLD | `update.zip` → `update[.]zip` (`.zip`, `.mov`, `.py` and similar are real top-level domains) |
| Word cut at the edge of an excerpt | `…ttps://mail-relay.example.org/owa/auth/logon.aspx` → `…ttps://mail-relay[.]example[.]org/owa/auth/logon[.]aspx` |
| CVE, hashes | unchanged (they cannot be clicked or resolved) |

Left as written, on purpose:

- the **source URL** (the publisher's link, which you may want to keep clickable) and the source name;
- version numbers that only look like IPv4 addresses (`firmware 10.2.9.1`) and file or code names without a real
  top-level domain (`svchost.exe`, `Net.WebClient`);
- names with unknown top-level domains (they cannot resolve);
- the host of an IPv6 URL (`hxxp://[2001:db8::1]/` keeps its colons; the scheme is defanged).

Defanging is designed to be thorough, but it is text rewriting: glance at the file before you send it. Each
defanged value turns back into the original when refanged, by Insight's extractor or any common refanging tool.
The file as a whole is not designed to be re-imported: pasting it into Insight would also extract the publisher
URLs and anything else in the evidence.

Entries are sorted by value *as written*, so a defanged file can list them in a slightly different order from
an undefanged one.

## 8. Using the file in other tools

Check the file's label and scope first:

```sh
jq '{tlp, defanged, counts, filters}' insight-iocs.json
jq -c '[.iocs[].sources[].tlp] | unique' insight-iocs.json     # labels actually present, e.g. ["CLEAR","GREEN"]
```

Plain lists (one value per line):

```sh
jq -r '.iocs[] | select(.kind == "ip") | .value' insight-iocs.json
jq -r '.iocs[] | select(.kind == "url" or .kind == "domain" or .kind == "ip") | .value' insight-iocs.json
```

A spreadsheet-friendly CSV:

```sh
jq -r '["kind","value","tlp","reports"], (.iocs[] | [.kind, .value, .tlp, (.sources | length)]) | @csv' \
  insight-iocs.json > iocs.csv
```

Indicators that several reports mention, and CVEs that are in CISA KEV with their due dates:

```sh
jq -r '.iocs[] | select((.sources | length) >= 2) | "\(.kind) \(.value)"' insight-iocs.json
jq -r '.iocs[] | select(.kind == "cve" and .kev != null) | [.value, .kev.due_date] | @tsv' insight-iocs.json
```

Which reports an indicator came from:

```sh
jq -r '.iocs[] | select(.value == "192.0.2.44") | .sources[] | "\(.tlp)\t\(.title)"' insight-iocs.json
```

In Python:

```python
import json

export = json.load(open('insight-iocs.json', encoding='utf-8'))
assert export['format'] == 'insight-ioc-v1'
print('Handle as TLP:' + export['tlp'])
for ioc in export['iocs']:
    print(ioc['kind'], ioc['value'], len(ioc['sources']), 'report(s)')
```

To validate files automatically, use the JSON Schema
([schemas/insight-ioc-v1.schema.json](schemas/insight-ioc-v1.schema.json)), for example
`check-jsonschema --schemafile docs/schemas/insight-ioc-v1.schema.json insight-iocs.json`.

**Converting to STIX 2.1 yourself.** Insight does not produce STIX. If you convert, these are the usual
mappings. Convert from an export **without** defanging:

| Insight `kind` | STIX 2.1 |
| --- | --- |
| `ip`, `cidr` | `ipv4-addr` or `ipv6-addr` (a `:` in the value means IPv6) |
| `domain` | `domain-name` |
| `email` | `email-addr` |
| `url` | `url` |
| `md5`, `sha1`, `sha256`, `sha512` | `file` with `hashes` keys `MD5`, `SHA-1`, `SHA-256`, `SHA-512` |
| `cve` | `vulnerability` (with an external reference to the CVE), not an indicator |
| file and entry `tlp` | the matching TLP 2.0 marking definition |

## 9. Limits and troubleshooting

| Symptom | Cause | What to do |
| --- | --- | --- |
| Preview says *Too large: … mentions match* (API 422, CLI: `More than 100,000 indicator mentions match…`) | One export is capped at 100,000 mentions | Export in parts: by type, by TLP, by report or with a search |
| Preview says *Nothing matches these filters.* (CLI: `Exported 0 IOCs … Nothing matched the filters …`) | Rejected mentions and superseded revisions are left out by default; accepted-only needs accepted mentions | Loosen the filters, or review mentions first |
| The download tab shows `{"detail":"Sign in required"}` | Your session ended (8 hours, a sign-out, or a new password) | Sign in again and repeat the export |
| ``max_tlp: Input should be 'CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT' or 'RED'``, even though you wrote `AMBER+STRICT` | In a URL, `+` means a space | Write `AMBER%2BSTRICT`, or let your client encode it (`curl --get --data-urlencode`, httpx `params`) |
| ``kind 'IP': Input should be 'cve', 'url', …`` (API) or ``--kind 'ipv4': …`` (CLI) | Unknown type, or upper case in the API | Use the names from [§2](#2-quick-start). The CLI accepts any case |
| ``--status: Input should be 'new', 'reviewing' or 'reviewed'`` | `--status`/`status` is the **report's** triage status | For mention verdicts use `--review-status`/`review_status` |
| ``--query: String should have at most 200 characters`` | Search text too long for the API/CLI | Use a shorter distinctive phrase |
| ``Export failed: iocs.json already exists; exports never overwrite, choose a new name`` | The CLI never overwrites | Choose a new file name |
| ``Export failed: cannot create …: Permission denied. Choose a writable directory (in Docker: /data).`` (also `Read-only file system`) | The output directory is not writable; in Docker, anything outside `/data` | Write under a writable directory; in Docker, `/data/...` (see [§2](#2-quick-start)) |
| ``Export failed: could not write …: No space left on device`` | The file could not be written; nothing is kept and nothing is audited | Free space, then export again |
| ``Export failed: No database at …`` | The CLI is pointed at a database file that does not exist | Check `INSIGHT_DATABASE_URL` / `INSIGHT_DATA_DIR` and the directory you run it from |
| ``Export failed: The database schema is not current; run `insight migrate` first.`` | The database is from an older release | Back up, then run `insight migrate` |
| An indicator you expected is missing | It was rejected, it appears only in a superseded revision or in a title, its report is above `max_tlp`, or the extractor does not recognise it | Check those filters, and see the known gaps in [EXTRACTION.md](EXTRACTION.md) |
| The same indicator appears twice in slightly different forms | Entries from the pre-0.2.0 extractor alongside current ones (compare `extractor_version`) | Expected in old workspaces; use the `extractor_version` to identify how a value was recorded |

## 10. Format versioning

`format` identifies the file layout. Within `insight-ioc-v1`, fields may be **added** but not renamed, removed
or given a different meaning, so consumers should ignore fields they do not know. Any incompatible change will
use a new identifier (`insight-ioc-v2`) and be listed under "Upgrade notes" in the
[CHANGELOG](../CHANGELOG.md). The [schema](schemas/insight-ioc-v1.schema.json) describes every v1 field.

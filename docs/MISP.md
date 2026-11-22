# MISP event exchange

Use the host CLI to share a reviewed set of indicators with a CERT or ISAC, or to bring a trusted MISP event into the review inbox. Both commands work with a single local JSON file. A configured MISP instance also supports one-event transfers.

## Export a file

```sh
insight misp-export community.json --max-tlp GREEN
insight misp-export selected.json --document REPORT_UUID --include-personal-data
```

The export includes accepted observations from current reports. Use `--document` repeatedly to select particular report revisions. `--include-unreviewed` approves unreviewed observations for this transfer. Rejected observations are always excluded. A filter that matches nothing produces an error. Files are owner-only and require a new filename.

The event contains canonical indicator values suitable for MISP, including IPv4 and IPv6 networks as `ip-dst`, CVEs as `vulnerability`, and e-mail addresses as `email-dst`. E-mail addresses and URLs containing possible mailbox references are omitted by default. `--include-personal-data` includes them, and e-mail attributes receive the tag `insight:personal-data`.

`--include-evidence` adds a defanged excerpt from an eligible source. Insight omits excerpts from metadata-only publishers, and skips excerpts containing possible e-mail addresses unless personal data was requested. Review excerpts for other identifying information before sharing. The default export contains no excerpts, report bodies, notes or source links.

## TLP and MISP distribution

Each attribute carries the most restrictive TLP label of its eligible source reports. The event carries the most restrictive included attribute label. Attributes inherit the event's MISP distribution. The instance ceiling in `INSIGHT_MAX_TLP` always applies. `--max-tlp` can narrow it. To exchange RED, set `INSIGHT_MAX_TLP=RED` and supply `--allow-red`. Choose a destination whose people are the named recipients.

| Event TLP | MISP distribution |
|---|---|
| CLEAR | 3, all communities |
| GREEN | 1, this community only |
| AMBER, AMBER+STRICT, RED | 0, your organisation only |

The JSON uses the MISP event creation format. MISP assigns its own database and organisation IDs. Events are unpublished and attributes have `to_ids=false`. An accepted observation means the analyst confirmed what the report says. For an unchanged set of reports, values, labels and evidence, the event and attribute UUIDs stay the same. The event date is the date of the newest contributing report. The test suite validates a synthetic export against PyMISP’s event schema offline. [MISP core format](https://misp-standard.org/formats/core/) · [PyMISP event schema](https://github.com/MISP/PyMISP/blob/e929887bd93b79c8bcfa869fe1046d99afd545fa/pymisp/data/schema-lax.json)

## Import a file

```sh
insight misp-import partner-event.json
```

The importer accepts one event with a UUID, title and flat attribute list. It supports domains/hostnames, URLs, source and destination IPs and networks, source and destination e-mails, CVEs, and MD5, SHA-1, SHA-256 and SHA-512 hashes. The new report contains unreviewed observations. It keeps the event UUID as its external ID. Importing the same snapshot again reuses its report. Changed title, date, handling or active indicators under that UUID produce a revision. A revision can retain or raise its handling label. Deleted attributes are left out of the current snapshot. Publisher comments and attachments are never copied into the report.

MISP distribution and tags can both narrow handling on import. An unmarked event starts at AMBER. Organisation-only distribution raises it to at least AMBER+STRICT. Community distribution raises it to at least GREEN. The most restrictive applicable label wins for the whole report. Insight rejects active sharing groups, unsupported attribute types and populated object containers. Each file or HTTP response has an 8 MB limit. Each event can contain up to 2,000 attributes and must fit in one Insight report.

## Exchange with a trusted MISP instance

Set `INSIGHT_MISP_URL` to the trusted HTTPS instance URL on the CLI host, and keep `INSIGHT_MISP_KEY` in its environment or its private `.env`. A base path such as `https://misp.example.org/instance` is supported. The key is sent in the Authorization header. File exchange needs neither setting.

By default the instance must resolve to public addresses, like every other outbound request. For a MISP instance on your own network (`10.x`, `172.16-31.x`, `192.168.x`, carrier-grade NAT or IPv6 unique local addresses), also set `INSIGHT_MISP_PRIVATE_NETWORK=on`. Loopback, link-local (cloud metadata), multicast and reserved addresses stay blocked even then, and the request still goes only to the addresses Insight checked, over HTTPS with the certificate checked against the host name. The setting affects only MISP transfers; source syncs and lookups stay public-only.

```sh
insight misp-export --push --max-tlp GREEN
insight misp-import --fetch 7440c54c-d11c-4bc7-b825-1ae6e5ee028f
```

`--push` creates an unpublished event at `POST /events/add` and checks the returned event UUID. `--fetch` calls `GET /events/view/{uuid}` and checks the requested UUID before import. A lost receipt can mean MISP already created the event. Check for its UUID before retrying. The host CLI alone can initiate either transfer. Connections use validated public IPs, pinned TLS on port 443 and no redirects. Use files for a private-network MISP instance.

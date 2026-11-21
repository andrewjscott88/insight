# Alerts

Insight can tell you, without anyone watching the workspace:

- when a **new report mentions one of your watch terms** (the same match as the inbox highlights: capital
  letters and accents do not matter; the report's title and text count, its source name does not); and
- when **CISA adds an entry to its Known Exploited Vulnerabilities list** (after Insight has imported the list
  once, so the first import of the whole list is not news).

Each alert fires once per destination. A new revision of a report that already fired for a term adds nothing;
a revision that newly mentions another watch term fires for that term. The synthetic demo never fires alerts.
More than 10 new KEV entries in one import become a single alert that lists them. Design: ADR 0022.

## Destinations

Add them on the **Watch terms** tab under **Alerts**, or use the host CLI. API keys cannot add, change or read
them, as they cannot change schedules.

| Kind | What it sends |
| --- | --- |
| Chat webhook | `{"text": "..."}` to a Slack, Mattermost, Rocket.Chat or Google Chat incoming webhook. `&`, `<` and `>` in report titles are escaped, so a title cannot add links or mentions. The workspace shows only the host: the address is a secret |
| Signed JSON webhook | An `insight-alert-v1` document (below) to your own tool, signed with a secret shown once when you add it |
| E-mail | A plain-text message through your mail server (settings below) |

**Send a test alert** sends straight away and shows the result. Turning a destination off keeps its queued
alerts until it is on again; removing it deletes them.

## Manage destinations on the host

Run `insight notify` to list the destination IDs, names, styles, sharing limits and enabled state.
Use `add` to create a destination. Enter the address at the hidden prompt or pipe it on standard input.
For a signed JSON webhook, the command prints the signing secret once after creating the destination.

```sh
insight notify add --name "Incident desk" --style json --max-tlp GREEN
insight notify list
insight notify disable --target DESTINATION_ID
insight notify enable --target DESTINATION_ID
insight notify remove --target DESTINATION_ID
```

The styles are `chat`, `json` and `email`. The default sharing limit is AMBER. Removing a destination
also deletes its queued alerts. These commands use the same database and audit events as the workspace.

## TLP

Each destination has a **TLP limit** (default AMBER). For a report labelled above the limit, and for every
TLP:RED report, the alert says only that a new report with that label mentions the watch term, with a link:
**no title and no source**. Alerts never contain a report's text or evidence, so each publisher's reuse rule
(ADR 0021) holds. E-mail subjects carry the label: `[Insight] [TLP:AMBER] Watch term "Acme": ...`.

## Settings

Set in `.env` (see `.env.example`; `compose.yaml` passes them on). A wrong value stops Insight at start-up.

| Setting | Meaning |
| --- | --- |
| `INSIGHT_PUBLIC_URL` | The address people open Insight at, such as `https://insight.example.org`. Alerts then link to `/?report=<id>`, which opens the report after sign-in |
| `INSIGHT_SMTP_HOST`, `INSIGHT_SMTP_FROM` | Needed for e-mail |
| `INSIGHT_SMTP_PORT` | Default 587 (465 with `tls`) |
| `INSIGHT_SMTP_SECURITY` | `starttls` (default), `tls`, or `none` only for a relay on this host (`localhost`) |
| `INSIGHT_SMTP_USERNAME`, `INSIGHT_SMTP_PASSWORD` | If your mail server needs a sign-in |
| `INSIGHT_ALERT_PRIVATE_TARGETS` | `off` (default): webhooks must resolve to public internet addresses. `on` allows private networks, such as a chat server on your LAN. Link-local addresses (cloud metadata services) are always refused |

Alerts are sent by the job runner (`INSIGHT_RUN_JOBS=on`, the default), within about 15 seconds. Webhooks must
use HTTPS; redirects are not followed; each send has 10 seconds. A failed send is tried again after 5, then 10
minutes, then marked **Failed** in **Recent alerts**, with the reason.

## The JSON document

```json
{
  "format": "insight-alert-v1",
  "id": "4f0c...",
  "trigger": "watch",
  "created_at": "2026-11-21T14:02:11.120394+00:00",
  "subject": "Acme VPN",
  "summary": "A new report mentions your watch term \"Acme VPN\".",
  "tlp": "GREEN",
  "link": "https://insight.example.org/?report=9b1e...",
  "report": {
    "id": "9b1e...",
    "tlp": "GREEN",
    "withheld": false,
    "title": "Attackers exploit Acme VPN gateways",
    "source": "Cisco Talos",
    "received_at": "2026-11-21T14:02:10.981223+00:00"
  }
}
```

`trigger` is `watch`, `kev` or `test`. For `kev` and `test`, `report` is `null` and `subject` names the KEV
entries or says "Test alert". When the title is withheld, `report` holds only `id`, `tlp` and
`"withheld": true`. `link` is `null` without `INSIGHT_PUBLIC_URL` (for `kev`, CISA's catalog page).

### Checking the signature

Each request carries `X-Insight-Timestamp` (Unix seconds) and
`X-Insight-Signature: sha256=<hex HMAC-SHA256 of timestamp + "." + body, keyed with the secret>`. Check it
against the raw body, and refuse old timestamps to stop replays:

```python
import hashlib, hmac, time


def verify(secret: str, body: bytes, timestamp: str, signature: str, max_age: int = 300) -> bool:
    if abs(time.time() - int(timestamp)) > max_age:
        return False
    expected = hmac.new(secret.encode(), timestamp.encode() + b'.' + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f'sha256={expected}', signature)
```

## Security notes

- Destinations and their secrets (the JSON signing secret, and chat webhook addresses, which work as
  passwords) are stored in Insight's database. Protect database backups like the `.env` file.
- Additions, changes, removals and test alerts are audited (`alert.target.*`, `alert.test`); the audit log never
  holds a destination's address.
- A webhook's address is checked when each alert is sent, but the check and the connection resolve the name
  separately; an egress firewall remains the protection against DNS rebinding (as for sources, TIP 0.4).

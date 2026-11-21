# ADR 0022: Alerts on watch-term matches and new KEV entries, sent by the job runner

Status: accepted (unreleased)

## Context
Analysts only learned about a watch-term match or a new KEV entry by opening the workspace (issue #15, TIP 1.4).
Premium platforms push such events to chat, e-mail and automation. Sending them makes Insight contact
destinations the operator chooses, which raises three questions: what may leave (TLP, publishers' terms),
where it may go (server-side request forgery), and what happens when it fails.

## Decision
1. **Two triggers.** A *new* current report whose title or text contains a watch term (the inbox's literal,
   case- and accent-insensitive match; the source name does not count), and a KEV entry that is new since the
   previous import (never on the first import of the whole list; more than 10 at once become one alert).
2. **Once per destination.** Each alert is a row per target with a `dedupe_key` (term and source item, or the
   CVE), unique per target. Revisions of an item, re-submissions and re-imports add nothing. The demo is quiet.
3. **Fire inside the transaction, send outside it.** Ingest and the KEV import only queue rows. The job runner's
   tick queues one delivery job when an alert is due (`ix_alerts_due`), and the job sends. A failure is tried
   again after 5, then 10 minutes, then marked failed with a plain reason. *Send a test alert* sends at once.
4. **TLP decides the content.** Each target has a limit (default AMBER; RED cannot be chosen). Above it, and
   for every TLP:RED report, the alert names only the label, the watch term and a link. No report text or
   evidence is ever sent, so publishers' reuse rules (ADR 0021) hold.
5. **Three styles.** Chat webhooks (`{"text"}`, with `&`, `<`, `>` escaped), signed JSON webhooks
   (`insight-alert-v1`, HMAC-SHA256 over timestamp and body with a per-target secret shown once), and e-mail
   through the operator's SMTP server (STARTTLS or TLS; plain only to a relay on the same host).
6. **Where alerts may go.** Webhooks must be HTTPS without credentials in the address, resolve only to public
   addresses unless `INSIGHT_ALERT_PRIVATE_TARGETS=on`, and never to link-local addresses (cloud metadata);
   redirects are not followed; 10-second timeout. Targets are managed in the workspace only, never with an API
   key, and audited without their addresses.
7. **Links back.** With `INSIGHT_PUBLIC_URL`, alerts link to `/?report=<id>`, which the workspace opens.

## Consequences
- Analysts hear about matches and newly exploited weaknesses within about 15 seconds of the sync that brought
  them, in the tools they already watch, at no more than the TLP the operator allows.
- Destinations and secrets live in the database (chat webhook addresses are credentials); backups need the same
  care as `.env`. Encrypting stored secrets belongs with TIP 0.6.
- The address check and the connection resolve names separately: an egress firewall remains the defence
  against DNS rebinding (TIP 0.4).
- Later triggers fit the same queue: a daily landscape digest, verdict changes, techniques or actors of
  interest.

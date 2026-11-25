# ADR 0012: One API key, managed from the CLI; per-caller rate limits

Status: Accepted

## Context
Scripts and a SIEM need to call the API. Until now the only credential was the browser session: clients had to
scrape the login form, keep a cookie and send a CSRF token. The instance is headed for a public deployment with
one operator and one organisation, on SQLite without Redis. Nothing limited the request rate apart from the
sign-in throttle (ADR 0002) and the global enrichment interval, so a runaway script could ingest or export
without bound.

## Decision
- **At most one active API key**, sent as `Authorization: Bearer insk_<key id>_<secret>`. Only its SHA-256 is
  stored (a slow hash adds nothing for 256 random bits and would let bogus keys burn CPU). The `insk_` prefix
  lets secret scanners recognise leaks; the public key ID goes in logs, never the key.
- **Managed only from the CLI** (`insight api-key create|rotate|revoke|status`). Shell access to the host is the
  proof of authority, so a hijacked browser session cannot mint a key. There is no API or UI for it.
- Keys are **read-only by default**; `read-write` must be chosen. Expiry is required (default 90, at most 365
  days). Revocation and rotation take effect on the next request, without a restart. Creation and revocation
  are audited.
- Key requests need no CSRF token (a browser never attaches the header by itself) and cannot use
  `/api/session` or the workspace. Other `Authorization` schemes (e.g. a proxy's Basic auth) are ignored, so
  the session still applies.
- Every authenticated `/api` request draws from an in-process token bucket per caller and policy: `read`
  300/min, `write` 60/min, `ioc-export` 30/hour. The operator's session and the key never share a bucket.
  Invalid keys are limited per client address (10/min) in a separate limiter; a valid key is never refused
  by it, so floods cannot lock the integration out (the same principle as ADR 0002).
- Responses carry `RateLimit-Policy`/`RateLimit` (IETF httpapi draft); 429s add `Retry-After`.

## Consequences
Integrations get a stable credential with least privilege by default. Limits live in process memory, like
sessions: one worker, and a restart resets them. Several workers or hosts need a shared store (Redis) behind the
same `RateLimiter.hit` interface. Behind a reverse proxy, the invalid-key limiter needs `INSIGHT_TRUSTED_PROXIES` to
see real client addresses. Audit events do not yet record whether the
session or the key performed an action; the `insight.auth` log records every key write with its key ID.

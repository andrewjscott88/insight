# Security posture

Insight is a single-operator workbench, not a hardened multi-user service. Docker Compose binds it to loopback. It can be published for its one operator (and that operator's scripts and SIEM) behind a TLS reverse proxy, following the checklist at the end of this page; never expose port 8080 itself.

The normal configuration requires sign-in. The explicit, default-off `INSIGHT_DEV_NO_AUTH` exception is
documented under [Temporary public operator access](#temporary-public-operator-access); enabling it grants
every visitor the browser operator's access.

Implemented controls: required operator password and signing secret; constant-time password comparison; signed HttpOnly SameSite=Strict cookie; expiring, revocable session ID stored in the database only as a hash keyed to the password and MFA setting (a database copy cannot sign anyone in, and a new password ends every session), with **Sign out everywhere**; serialised password checks with a per-failure delay (1 s, served outside the check lock) plus a 30-failures-per-minute backstop that refuses only wrong passwords, and logging of failed attempts (a delay, not a lockout: nobody can keep the operator out, [ADR 0002](adr/0002-login-delay-not-lockout.md)); `Referrer-Policy: same-origin` (not `no-referrer`, under which browsers send `Origin: null` and the Origin check would block every sign-in); `Cache-Control: no-store` on application responses, never overriding immutable framework assets; CSRF for form/API writes; same-origin request and socket checks; callback authentication rechecks; bounded document/HTTP/connector inputs (connector downloads: 8 MB and 120 seconds in all, code review L6); parameterized database queries; text-only rendering; explicit fixed-host outbound connectors; no redirects or ambient proxy configuration; XML entity expansion disabled; local export provenance; no AI calls. Login rate limits are process-local; sessions are stored in the database. Run one worker only. The `insight_theme` and `insight_text` cookies (Light/Dark/System and "Larger text", [ADR 0016](adr/0016-colour-themes-and-per-device-choice.md), [ADR 0017](adr/0017-readability-standard.md)) are display preferences set by the page's JavaScript: they are not credentials, only their known values (`system`, `light`, `dark`; `standard`, `large`) are accepted, and any other value falls back to the default and is never written into a page.

The environment stores the operator password in plaintext to support a small local bootstrap. Anyone with access to `.env`, Docker inspection or the host can recover it. Treat host administrator access as trusted. Optional TOTP MFA (`make mfa-enable`) protects against a stolen password. Before any multi-user deployment use OIDC, secret management, a proper account database and durable sessions.

API key ([ADR 0012](adr/0012-single-api-key-and-rate-limits.md)): at most one active key, created, rotated and revoked only with `insight api-key` on the host (no API or UI can create one); read-only unless `read-write` is chosen; mandatory expiry (at most 365 days); only its SHA-256 is stored and only its public key ID is logged; invalid, revoked and expired keys get one identical `401`. Key requests need no CSRF token, because browsers never attach `Authorization: Bearer` on their own and cross-origin requests are refused. Any holder of the key has the operator's access to every report at every TLP (within its read-only/read-write limit): treat it like the password and keep it in a secret store. Rate limits per caller (`read` 300/min, `write` 60/min, `ioc-export` 30/hour) and a per-address limit on invalid keys are in-process; the invalid-key limit never refuses the valid key. Behind a reverse proxy, set `INSIGHT_TRUSTED_PROXIES` so that limit sees real client addresses.

TLP policy: the default label is AMBER. A `TLP:` marking in a report's title or body raises the label to the most restrictive marking found and never lowers it; every raise is audited (`document.tlp_raised`). Credentials embedded in URLs (`https://user:pass@host/`) are stripped from extracted indicators and never stored as entity values; the source text itself is kept as evidence. Sign-ins, failures and schema migrations are logged by the `insight.*` loggers (never passwords).

TLP limit ([ADR 0013](adr/0013-instance-tlp-limit.md)): `INSIGHT_MAX_TLP` (default `AMBER+STRICT`) refuses, before anything is stored, any upload from the workspace or the API whose label, after marking-based raising, is above the limit. TLP:RED is meant for named recipients only, so by default it never reaches an internet-facing instance. Refusals are logged without content. Reports stored before the limit remain (start-up logs the count) and are readable by the session and the API key alike. Curated connectors and the synthetic demo are exempt (public or synthetic data).

Sign-in MFA ([ADR 0015](adr/0015-totp-second-factor.md)): **off by default**. `INSIGHT_MFA=on` (`make mfa-enable`) requires a TOTP code (RFC 6238, 6 digits, 30 s, ±1 step for clock drift) from a paired authenticator app, verified together with the password with one generic error for either mistake. The code is only checked after the password is correct, so guesses never consume valid codes; every accepted code is marked used, and older codes are refused (no replay). Pairing (`insight mfa setup`) requires a matching code before anything is saved. With MFA on and no app paired, sign-in is refused (fail closed), and an invalid `INSIGHT_MFA` value stops start-up. Pairing and the switch are managed only on the host (CLI, `.env`, Makefile), so shell access to the host remains the root of trust and the recovery path. The TOTP secret is stored in the database in recoverable form (TOTP requires it), and **in plain text** for now: a copy of the database or a backup, together with the password, gets past MFA. Encrypting it at rest with a key derived from `INSIGHT_SESSION_SECRET` is planned (code review L2, TIP 0.6; tracked by a strict expected-failure test) and needs the `cryptography` package added to the hash-pinned locks. Until then, protect backups like `.env`. With MFA off, the instance relies on the password alone: consider turning it on before exposing the instance.

Per-key TLP limit ([ADR 0014](adr/0014-per-key-tlp-limit.md)): a key created with `--max-tlp` cannot see, change or store reports above that label. Enforcement is in the service layer (one `max_tlp` parameter on every report query), hidden reports are indistinguishable from missing ones (`404`), and routes that span all reports or name the organisation's interests (audit log, CVE enrichment, watch terms: code review L3) are refused. A test sweeps every API route for a planted marker, and an architecture test fails if a route calls a report query without the caller's limit. The workspace session is not limited. Audit events record the actor (`operator`, `api-key:<key ID>`, `cli`, `connector:<source>`). With `INSIGHT_SECURE_COOKIES=1`, responses carry `Strict-Transport-Security: max-age=31536000` (no `includeSubDomains`, so other hosts under the same domain are unaffected).

Reverse proxy: `X-Forwarded-For`/`X-Forwarded-Proto` are honoured only from `INSIGHT_TRUSTED_PROXIES` (IPs or CIDR networks, validated at start-up; `*` is refused). This restores the Origin check behind TLS termination and gives the invalid-API-key limiter real client addresses. From any other peer the headers are ignored. The sign-in throttle stays global by design (ADR 0002).

TLP labels are metadata, not a complete access-control engine. No automatic sharing occurs. A local export is not permission to redistribute. Source reuse/retention rights remain the operator's responsibility. Do not upload leaked secrets, unnecessary personal data, or documents you lack permission to retain.

IOC exports (see [IOC_EXPORT.md](IOC_EXPORT.md)) change no reports or review states; each one adds an audit event (`ioc.export`, whose object ID is the `export_id` inside the file). Each file carries the most restrictive TLP of the reports it includes, and `max_tlp` keeps more restrictive reports out of a file entirely. Residual risks the operator must manage: evidence excerpts are raw report text (up to 90 characters either side of a mention) and can carry names, internal host names or indicators an analyst rejected, so exports that leave the team should be made without evidence (`--no-evidence`, `evidence=false`, or the dialog's **Include evidence excerpts**); defanging covers values, titles and evidence (including e-mail domains, CIDR ranges and file-like names) but leaves source URLs as stored; browser and API downloads use the operator's default file permissions, while the CLI writes owner-only files; and an extracted or accepted indicator is not a maliciousness verdict, so exports must not feed blocking controls without review.

Outbound requests (source syncs, CVE lookups, alert webhooks) resolve the host once, check every address it resolves to, and then connect to one of those checked addresses, with the host name kept for TLS (SNI and the certificate check) and the `Host` header (`insight.egress`, code review L1, TIP 0.4). A DNS answer that changes between the check and the connection (DNS rebinding) can no longer redirect a request to loopback, a private network or a cloud metadata address. IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) are judged by the IPv4 address they reach. An outbound network policy remains the backstop and is still recommended. The framework supplies local JS/CSS assets; the GUI uses no application-authored model calls or remote font/CDN assets.

Supply chain: all Python dependencies are hash-pinned (runtime, dev, e2e and build-backend locks), the image installs with `--require-hashes` and builds the wheel without build isolation, the container runs as UID 10001 with a read-only root filesystem and no capabilities, and releases are signed with cosign (keyless) and carry SBOM and build-provenance attestations. See `docs/CI_CD.md`.

Logs and audit rows are not append-only or cryptographically verifiable. No data deletion endpoint is provided yet; implement policy-aware deletion/retention before storing data with strict deletion obligations.

## Temporary public operator access

`INSIGHT_DEV_NO_AUTH=on` is an explicit temporary switch for entering the workspace without a password.
It is **off by default**, accepts only `on` to enable it, and refuses malformed settings. The configured
password and signing secret remain required. Enabling this mode together with `INSIGHT_MFA=on` is rejected,
so it cannot silently bypass an enabled second factor.

While enabled, `GET /login` issues the existing expiring, revocable operator session and a fresh CSRF token,
then redirects to the workspace. Signed HttpOnly SameSite=Strict cookies, secure-cookie configuration,
CSRF for writes, Host/Origin/socket checks, API-key permissions and request limits still apply. API requests
without a session or valid key still receive `401`. These controls do not make the open workspace private:
any visitor can obtain a session, read the reports and use operator editing, export and synchronization
tools. Browser sessions have no per-key TLP limit. Audit events identify this shared access as `operator`,
not as distinct people.

On a public domain, this is a deliberate grant of public operator access, including existing stored
material. It is not anonymous read-only publishing. The workspace notice makes the active mode visible;
signing out cannot restrict entry while anyone can obtain a new session. No automatic expiry is configured
for the switch itself: an operator must turn it off.

Set `INSIGHT_DEV_NO_AUTH=off` or remove it and recreate/restart the application with the changed environment
to restore the retained password. The authentication-mode change invalidates sessions created during the
open period. Restore the earlier MFA setting if it was changed. Verify both a fresh browser and an old
open-mode session are refused without sign-in; the exact steps are in
[RUNBOOK: Temporary password-free access](RUNBOOK.md#temporary-password-free-access).
Restoration cannot reverse visitors' edits or recall reports they already read or exported.

## Publishing an instance: checklist

For one operator reaching their own instance (and their scripts/SIEM) over the internet:

| Control | Provided by Insight | You configure |
| --- | --- | --- |
| TLS, HSTS | HSTS header when `INSIGHT_SECURE_COOKIES=1` | TLS at the reverse proxy; `INSIGHT_SECURE_COOKIES=1` |
| Real client addresses, correct `Origin` checks | Trusted proxy headers, validated at start-up | `INSIGHT_TRUSTED_PROXIES`, `INSIGHT_ALLOWED_HOSTS` (RUNBOOK, "Reverse proxy") |
| Sign-in | Password, throttling, optional TOTP MFA | Keep `INSIGHT_DEV_NO_AUTH=off` for protected access; use a strong password (`make env`); `make mfa-enable` is strongly recommended |
| Automation access | One hashed, expiring, scoped API key; per-key TLP limit | `make api-key-create` with the least access and lowest `MAX_TLP` that works; rotate before expiry |
| Abuse and overload | Per-caller rate limits, invalid-key throttling, 2 MB bodies | Optional edge limits at the proxy (connections, request rate) |
| Data on the server | TLP:RED refused by default (`INSIGHT_MAX_TLP`) | Review reports stored before the limit (start-up logs the count) |
| Accountability | Audit actor per event; key ID in logs | Ship logs somewhere you monitor (RUNBOOK section 11) |
| Backups | `make backup`, tested restore drill | Store backups encrypted, off the host |
| Egress | Fixed connector hosts, no redirects; scheduled syncs only for sources the operator scheduled, never set by an API key, every run recorded ([ADR 0018](adr/0018-opt-in-scheduled-syncs.md)); new sources off until switched on ([ADR 0021](adr/0021-threat-research-sources.md)); alerts only to destinations the operator added in the workspace, HTTPS webhooks to public addresses unless `INSIGHT_ALERT_PRIVATE_TARGETS=on`, never link-local, no redirects, report titles only up to each destination's TLP limit and never report text ([ADR 0022](adr/0022-alerts.md)); automatic CVE lookups off until switched on per provider, only CVE numbers from TLP:CLEAR and GREEN reports, one throttle per provider shared by every caller, the optional NVD key sent only in NVD's header and never logged ([ADR 0023](adr/0023-automatic-cve-lookups.md)) | Connections go to the checked address (L1); an outbound firewall as the backstop; `INSIGHT_RUN_JOBS=off` if no process should go online by itself |

Still missing before any **multi-user** or shared use: SSO/OIDC, per-user accounts and roles, TLP recipient
enforcement, shared rate limits (several workers or hosts), tamper-evident audit logs, and
policy-based retention and deletion.

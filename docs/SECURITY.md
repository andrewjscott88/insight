# Security posture

## Manual infrastructure connections

Censys Platform receives one explicitly approved, reviewed public IPv4 or IPv6 address from a current
CLEAR report. Its fixed HTTPS host is `api.platform.censys.io`; allow only that host if enabling the
connector. `INSIGHT_CENSYS_PAT` is a bearer header, never a URL or database value. The optional organization
UUID selects account access. The shared downloader checks DNS addresses, refuses redirects and caps the
reply at 1 MB; one shared in-flight lookup and a two-second throttle apply. Every outbound attempt and
cache write is audited. Both cached reads and new lookups are refused under temporary open access.
Censys metadata is private context, excluded from all intelligence exports; contact details and banners
are discarded. [Account terms, configuration and limits](CENSYS.md).

TIP 4.6 part 1 adds RDAP and RIPEstat, each off by default with an audited Settings switch. An uncached
lookup needs one explicit operator approval and an accepted observation in a current TLP:CLEAR report.
Sessions and unlimited read-write keys can request lookups; limited keys can only read eligible cached data.

RDAP connects only to HTTPS servers present in the pinned IANA DNS/IPv4/IPv6 bootstrap files. HTTP-only
servers are unsupported. No returned URL, referral or redirect is followed. `scripts/update_rdap_bootstrap.py`
manually fetches updated bootstrap files from `data.iana.org`; review host changes and commit the SHA-256 pins
together with the files. RIPEstat connects only to `stat.ripe.net` over HTTPS, using network-info and
prefix-overview. Both requests consume the same provider throttle. No DNS-based enrichment is used.

Every request uses `connectors.download` and checked public destination addresses, a 30-second total deadline
and a two-megabyte cap. Returned subjects/prefixes must match the requested value. Cache reads expire after
24 hours and recheck eligibility. Personal RDAP contact details are never persisted. Errors contain no raw
provider text or credentials. Graph nodes remain provider context and cannot create observations or verdicts.

The operator must comply with each registry's terms and
[RIPEstat's terms](https://stat.ripe.net/docs/getting-started/what-is-ripestat), including its commercial-use
permission requirement. See [ADR 0037](adr/0037-infrastructure-pivots.md).

Insight is a single-operator workbench, not a hardened multi-user service. Docker Compose binds it to loopback. It can be published for its one operator (and that operator's scripts and SIEM) behind a TLS reverse proxy, following the checklist at the end of this page; never expose port 8080 itself.

The normal configuration requires sign-in. The explicit, default-off `INSIGHT_DEV_NO_AUTH` exception is
documented under [Temporary public operator access](#temporary-public-operator-access); enabling it grants
every visitor the browser operator's access.

Implemented controls: required operator password and signing secret; constant-time password comparison of both values padded to one fixed width, so timing reveals neither the password nor its length (code review N4; no hashing, nothing is stored); signed HttpOnly SameSite=Strict cookie; expiring, revocable session ID stored in the database only as a hash keyed to the password and MFA setting (a database copy cannot sign anyone in, and a new password ends every session), with **Sign out everywhere**; serialised password checks with a per-failure delay (1 s, served outside the check lock) plus a 30-failures-per-minute backstop that refuses only wrong passwords, and logging of failed attempts (a delay, not a lockout: nobody can keep the operator out, [ADR 0002](adr/0002-login-delay-not-lockout.md)); `Referrer-Policy: same-origin` (not `no-referrer`, under which browsers send `Origin: null` and the Origin check would block every sign-in); `Cache-Control: no-store` on application responses, never overriding immutable framework assets; CSRF for form/API writes; same-origin request and socket checks; callback authentication rechecks; bounded document/HTTP/connector inputs (connector downloads: 8 MB and 120 seconds in all, code review L6); parameterized database queries; text-only rendering; explicit fixed-host outbound connectors; no redirects or ambient proxy configuration; XML entity expansion disabled; local export provenance; no AI calls. Login rate limits are process-local; sessions are stored in the database. Run one worker only. The `insight_theme` and `insight_text` cookies (Light/Dark/System and "Larger text", [ADR 0016](adr/0016-colour-themes-and-per-device-choice.md), [ADR 0017](adr/0017-readability-standard.md)) are display preferences set by the page's JavaScript: they are not credentials, only their known values (`system`, `light`, `dark`; `standard`, `large`) are accepted, and any other value falls back to the default and is never written into a page.

The environment stores the operator password in plaintext to support a small local bootstrap. Anyone with access to `.env`, Docker inspection or the host can recover it. Treat host administrator access as trusted. Optional TOTP MFA (`make mfa-enable`) protects against a stolen password. Before any multi-user deployment use OIDC, secret management, a proper account database and durable sessions.

API key ([ADR 0012](adr/0012-single-api-key-and-rate-limits.md)): at most one active key, created, rotated and revoked only with `insight api-key` on the host (no API or UI can create one); read-only unless `read-write` is chosen (`read-feedback` adds exactly two writes, filing a request for information with `POST /api/rfis` and reporting a sighting of a known indicator with `POST /api/sightings`, so a hunt tool can ask questions and report what it saw without changing anything else); mandatory expiry (at most 365 days); only its SHA-256 is stored and only its public key ID is logged; invalid, revoked and expired keys get one identical `401`. Key requests need no CSRF token, because browsers never attach `Authorization: Bearer` on their own and cross-origin requests are refused. Any holder of the key has the operator's access to every report at every TLP (within its read-only/read-write limit): treat it like the password and keep it in a secret store. Rate limits per caller (`read` 300/min, `write` 60/min, `ioc-export` 30/hour) and a per-address limit on invalid keys are in-process; the invalid-key limit never refuses the valid key. Behind a reverse proxy, set `INSIGHT_TRUSTED_PROXIES` so that limit sees real client addresses.

TLP policy: the default label is AMBER. A `TLP:` marking in a report's title or body raises the label to the most restrictive marking found and never lowers it; every raise is audited (`document.tlp_raised`). Credentials embedded in URLs (`https://user:pass@host/`) are stripped from extracted indicators and never stored as entity values; the source text itself is kept as evidence. Sign-ins, failures and schema migrations are logged by the `insight.*` loggers (never passwords).

TLP limit ([ADR 0013](adr/0013-instance-tlp-limit.md)): `INSIGHT_MAX_TLP` (default `AMBER+STRICT`) refuses, before anything is stored, any upload from the workspace or the API whose label, after marking-based raising, is above the limit. TLP:RED is meant for named recipients only, so by default it never reaches an internet-facing instance. Refusals are logged without content. Reports stored before the limit remain (start-up logs the count) and are readable by the session and the API key alike. Curated connectors and the synthetic demo are exempt (public or synthetic data).

Sign-in MFA ([ADR 0015](adr/0015-totp-second-factor.md)): **off by default**. `INSIGHT_MFA=on` (`make mfa-enable`) requires a TOTP code (RFC 6238, 6 digits, 30 s, ±1 step for clock drift) from a paired authenticator app, verified together with the password with one generic error for either mistake. The code is only checked after the password is correct, so guesses never consume valid codes; every accepted code is marked used, and older codes are refused (no replay). Pairing (`insight mfa setup`) requires a matching code before anything is saved. With MFA on and no app paired, sign-in is refused (fail closed), and an invalid `INSIGHT_MFA` value stops start-up. Pairing and the switch are managed only on the host (CLI, `.env`, Makefile), so shell access to the host remains the root of trust and the recovery path. With MFA off, the instance relies on the password alone.

Insight encrypts the paired authenticator's secret with AES-256-GCM before storing it.
It derives the encryption key from `INSIGHT_SESSION_SECRET` using HKDF-SHA256. Recovering the secret from the
encrypted row requires the matching host secret. A host administrator with access to both can recover the
pairing. Store the host secret separately from database backups. Copies taken before revision `0017` can
contain the plaintext pairing secret, including backups, snapshots and database logs. Follow your retention
policy for those copies. If an older copy may have been exposed, replace the pairing on the host.
[Pairing and recovery](RUNBOOK.md#sign-in-second-factor-mfa)

Per-key TLP limit ([ADR 0014](adr/0014-per-key-tlp-limit.md)): a key created with `--max-tlp` cannot see, change or store reports above that label. Enforcement is in the service layer (one `max_tlp` parameter on every report query), hidden reports are indistinguishable from missing ones (`404`), and routes that span all reports or name the organisation's interests (audit log, CVE enrichment, watch terms: code review L3) are refused. A test sweeps every API route for a planted marker, and an architecture test fails if a route calls a report query without the caller's limit. The workspace session is not limited. Audit events record the actor (`operator`, `user:<id>`, `api-key:<key ID>`, `cli`, `connector:<source>`). With `INSIGHT_SECURE_COOKIES=1`, responses carry `Strict-Transport-Security: max-age=31536000` (no `includeSubDomains`, so other hosts under the same domain are unaffected).

Roles ([ADR 0046](adr/0046-sso-sign-in-and-roles.md), TIP 3.4a): every caller acts as a `viewer`, an `analyst` or an `admin`, and one table in code (`insight.permissions`) gives the lowest role each permission needs. The password sign-in is the built-in operator, an admin; a `read` or `read-feedback` key acts as a viewer and a `read-write` key as an analyst, so no key ever has admin permissions. The API looks up each request's permission by method and path template (`web/route_permissions.py`) and refuses a route with no entry, even to the operator; an architecture test fails when a registered route has no `require_auth` or no entry, and an API test runs the full role-by-route matrix through the real middleware. The workspace checks the session's role inside `Workspace.write(permission)` on every callback (and before outside lookups and syncs), so a role change applies at once; an AST test fails when a workspace action names no permission. Sessions record the person; a person waiting for approval or disabled is not signed in, and changing a role, disabling or removing a person ends their sessions. Downgrading the schema below `0033` ends people's sessions first, so none can turn into the operator's. Each person has their own rate-limit budget, and **Sign out everywhere** ends only the caller's own sessions. People are managed with `insight users` on the host (the break-glass); sign-in through an identity provider follows in TIP 3.4b, so until then only the operator signs in to the workspace. Roles do not change TLP.

Reverse proxy: `X-Forwarded-For`/`X-Forwarded-Proto` are honoured only from `INSIGHT_TRUSTED_PROXIES` (IPs or CIDR networks, validated at start-up; `*` is refused). This restores the Origin check behind TLS termination and gives the invalid-API-key limiter real client addresses. From any other peer the headers are ignored. The sign-in throttle stays global by design (ADR 0002).

TLP labels are metadata, not a complete access-control engine. No automatic sharing occurs. A local export is not permission to redistribute. Source reuse/retention rights remain the operator's responsibility. Do not upload leaked secrets, unnecessary personal data, or documents you lack permission to retain.

**MCP is API-key only** ([ADR 0039](adr/0039-read-only-mcp.md)). `POST /mcp` offers only fixed read tools,
uses the key's TLP ceiling and publisher reuse rules, and has its own per-key rate budget. The exact MCP
transport POST accepts read-only keys; other write routes retain their permissions. Browser sessions cannot
authorize it, including open-access development sessions. It does not offer OAuth, write tools, model calls,
provider lookups or executable rules. Every tool call reaching validation is audited with the key actor,
tool name and outcome, without arguments or returned text. Existing key last-use metadata is preserved.
Origin, Host and proxy-trust checks still apply. Bodies, queries and results are bounded.

A key holder can send allowed intelligence to their chosen agent or model. That is a disclosure to that
client, governed by its retention and access rules; use the lowest useful TLP ceiling. The server marks tools
as read-only and source text as untrusted, but a client still must resist prompt injection in evidence.
Do not use an Insight API key as an OAuth client secret. Protocol revision and client limitations are in
[MCP.md](MCP.md). None of this enables Insight's separate opt-in LLM proposal contract.

IOC exports (see [IOC_EXPORT.md](IOC_EXPORT.md)) change no reports or review states; each one adds an audit event (`ioc.export`, whose object ID is the `export_id` inside the file). Each file carries the most restrictive TLP of the reports it includes, and `max_tlp` keeps more restrictive reports out of a file entirely. Residual risks the operator must manage: evidence excerpts are raw report text (up to 90 characters either side of a mention) and can carry names, internal host names or indicators an analyst rejected, so exports that leave the team should be made without evidence (`--no-evidence`, `evidence=false`, or the dialog's **Include evidence excerpts**); defanging covers values, titles and evidence (including e-mail domains, CIDR ranges and file-like names) but leaves source URLs as stored; browser and API downloads use the operator's default file permissions, while the CLI writes owner-only files; and an extracted or accepted indicator is not a maliciousness verdict, so exports must not feed blocking controls without review.

Optional infrastructure pivots ([ADR 0037](adr/0037-infrastructure-pivots.md)) use `crt.sh` as an
outbound destination. The switch is off by default; each uncached request requires consent,
accepted evidence in a current CLEAR report, a shared throttle and audit. Cache reads recheck that evidence.
The guarded HTTPS downloader enforces the fixed host, public checked addresses, no redirects, 2 MB and
30 seconds. No certificate blobs, contact fields or new observations are kept. Provider conditions and
limitations: [Infrastructure pivots](INFRASTRUCTURE_PIVOTS.md).

Optional infrastructure pivots ([ADR 0037](adr/0037-infrastructure-pivots.md)) use `www.circl.lu` as an
outbound host. CIRCL requires host credentials and an off-by-default switch; each uncached
request needs consent, current accepted CLEAR evidence, audit and a shared throttle. Basic credentials go
in a header only; active query resolution is explicitly disabled. Guarded HTTPS pins public checked
addresses, refuses redirects and caps responses at 2 MB / 30 seconds. No response bodies or credentials
appear in errors. [Access conditions and metadata limits](INFRASTRUCTURE_PIVOTS.md).

Outbound requests (source syncs, CVE lookups, alert webhooks) resolve the host once, check every address it resolves to, and then connect to one of those checked addresses, with the host name kept for TLS (SNI and the certificate check) and the `Host` header (`insight.egress`, code review L1, TIP 0.4). A DNS answer that changes between the check and the connection (DNS rebinding) can no longer redirect a request to loopback, a private network or a cloud metadata address. IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) are judged by the IPv4 address they reach. Private-network access requires an explicit opt-in for webhooks (`INSIGHT_ALERT_PRIVATE_TARGETS=on`), the configured MISP instance (`INSIGHT_MISP_PRIVATE_NETWORK=on`) or operator-defined sources (`INSIGHT_SOURCES_PRIVATE_NETWORK=on`). Each setting applies only to its named feature. Link-local and reserved addresses remain blocked. MISP and operator-defined sources also block loopback. An outbound network policy remains the backstop and is still recommended. The framework supplies local JS/CSS assets; the GUI uses no application-authored model calls or remote font/CDN assets.

**Operator-defined sources.** Saving a feed requires a signed-in operator and a CSRF token. Each feed starts
off. Its downloader accepts HTTPS on port 443, follows no redirects, and can connect only to the checked
address of that feed's hostname. Download size and time are bounded. The operator chooses a TLP floor for
every report and records whether the publisher allows its text to be shared. Exports use the current rule
and treat unknown or deleted operator sources as metadata-only. Reads through an API key respect its TLP
ceiling, including source lists and schedules.

For TAXII, the database holds the collection ID and the optional name of a host environment variable.
Insight reads the credential from that variable for the request and sends it in the Authorization header
to the configured host. A missing or empty variable blocks the request. A pagination token is passed as a
query value to that same collection. The source settings, run history and audit log omit the credential
value. Publisher restrictions survive subsequent imports and changes to the source's reuse rule.
[ADR 0040](adr/0040-operator-defined-sources.md)

Threat guides ([ADR 0025](adr/0025-threat-guides.md)): guides and their exports (JSON, Markdown, Navigator layer, sweep CSV/JSON) carry the most restrictive label of anything they include (sweep rows and their verdicts, and reports behind counts, included) and follow the caller's TLP limit plus an optional stricter `max_tlp`; every export is audited (`actor.guide`). Actors, report links, industry decisions, rules and hunts carry their own labels; labelled writes are refused above the caller's or the instance limit. Sweep CSV cells are protected against spreadsheet formula injection, Markdown links are limited to `http(s)` and escaped, and the CLI writes owner-only files that are never overwritten. YARA, Sigma, Suricata and Snort rules are stored and shown as text only, never compiled or executed. `insight threat-library-sync` contacts only `raw.githubusercontent.com` through the connector allowlist (HTTPS, no redirects, size-capped) and refuses any file whose SHA-256 differs from the pinned release. The sweep list takes indicators only from reports linked to the group unless the caller opts in to reports that merely name it. Above-limit industry decisions, hunts and rules look missing (`404`). Nothing infers attribution.

Exploit availability ([ADR 0028](adr/0028-exploit-availability.md)): Insight stores no exploit code. Report signals (proof of concept, Metasploit, Exploit-DB mentions) keep only the report, CVE, kind and time; readers see them only through reports within their TLP limit. VulnCheck KEV lookups are off by default, send only CVE numbers from CLEAR/GREEN reports, and use the operator's own token (Bearer header, never logged). From each answer Insight keeps dates, counts and links to `vulncheck.com` pages only; descriptions and repository clone addresses are dropped before caching, and links are checked again when read. Third-party terms: VulnCheck KEV is free for community members and requires prominent attribution, which Insight shows wherever its data appears ("Exploitation and exploit data from VulnCheck KEV, provided by VulnCheck."). Check VulnCheck's current terms before enabling it for a commercial service. Exploit-DB, GitHub code search and Metasploit's module index are not contacted: their terms were not reviewed for this use.

Supply chain: all Python dependencies are hash-pinned (runtime, dev, e2e and build-backend locks), the image installs with `--require-hashes` and builds the wheel without build isolation, the container runs as UID 10001 with a read-only root filesystem and no capabilities, and releases are signed with cosign (keyless) and carry SBOM and build-provenance attestations. See `docs/CI_CD.md`.

Logs and audit rows are not append-only or cryptographically verifiable. No data deletion endpoint is provided yet; implement policy-aware deletion/retention before storing data with strict deletion obligations.

## Temporary public operator access

`INSIGHT_DEV_NO_AUTH=on` is an explicit temporary switch for entering the workspace without a password.
It is **off by default**, accepts only `on` to enable it, and refuses malformed settings. The configured
password and signing secret remain required. Enabling this mode together with `INSIGHT_MFA=on` is rejected,
so it cannot silently bypass an enabled second factor.

While enabled, `GET /login` issues the existing expiring, revocable operator session and a fresh CSRF token,
then returns a same-origin page that confirms the session before continuing to the workspace. This ends a
cross-site redirect chain without relaxing cookie policy; a fixed link works when scripts are blocked.
Signed HttpOnly SameSite=Strict cookies, secure-cookie configuration,
CSRF for writes, Host/Origin/socket checks, API-key permissions and request limits still apply. API requests
without a session or valid key still receive `401`. These controls do not make the open workspace private:
any visitor can obtain a session, read the reports and use operator editing, export and synchronization
tools. Browser sessions have no per-key TLP limit. Audit events identify this shared access as `operator`,
not as distinct people.

On a public domain, this is a deliberate grant of public operator access, including existing stored
material. It is not anonymous read-only publishing. The workspace notice makes the active mode visible;
signing out cannot restrict entry while anyone can obtain a new session. No automatic expiry is configured
for the switch itself: an operator must turn it off.

Two things stay off while it is on, because any visitor could otherwise point them at a host of their
choosing: Censys lookups and their cache ([ADR 0043](adr/0043-censys-platform-enrichment.md)), and the host
credentials of operator TAXII sources. A TAXII source that names a credential shows as not configured and
makes no request; collections without a credential still sync.

Set `INSIGHT_DEV_NO_AUTH=off` or remove it and recreate/restart the application with the changed environment
to restore the retained password. The authentication-mode change invalidates sessions created during the
open period. Restore the earlier MFA setting if it was changed. Verify both a fresh browser and an old
open-mode session are refused without sign-in; the exact steps are in
[RUNBOOK: Temporary password-free access](RUNBOOK.md#temporary-password-free-access).
Restoration cannot reverse visitors' edits or recall reports they already read or exported.

## Read-only public view

`INSIGHT_PUBLIC_VIEW=on` ([ADR 0046](adr/0046-sso-sign-in-and-roles.md), TIP 3.4c) lets visitors who are not signed in read the workspace as viewers, and replaces temporary open access for public demonstrations. Start-up refuses it unless `INSIGHT_MAX_TLP=CLEAR`, and together with `INSIGHT_DEV_NO_AUTH=on`. A visitor is never signed in: the API still answers `401` without a session or key, so the API, MCP, TAXII and every download stay closed to them. In the workspace a visitor is a viewer limited to TLP:CLEAR: every read passes that limit (an architecture test fails when a workspace call to a TLP-filtering service passes no limit), so a report stored above CLEAR before the limit was lowered stays invisible, `?report=<id>` included. A visitor writes nothing, not even an audit event: `Workspace.write` and `Workspace.actor` refuse them whatever the permission. Settings, Share, analyst notes, watch terms and their matches, intelligence requirements, hunt records, saved hunt packages, products, outside lookups and provider context are not shown, because they are a team's working material or licensed data rather than published intelligence. Page loads are rate-limited per client address (the `read` budget); interactive callbacks are not counted separately, so rate-limit at the reverse proxy as well. Controls a role cannot use are hidden; the server-side checks remain the control.

## Publishing an instance: checklist

For one operator reaching their own instance (and their scripts/SIEM) over the internet:

| Control | Provided by Insight | You configure |
| --- | --- | --- |
| TLS, HSTS | HSTS header when `INSIGHT_SECURE_COOKIES=1` | TLS at the reverse proxy; `INSIGHT_SECURE_COOKIES=1` |
| Real client addresses, correct `Origin` checks | Trusted proxy headers, validated at start-up | `INSIGHT_TRUSTED_PROXIES`, `INSIGHT_ALLOWED_HOSTS` (RUNBOOK, "Reverse proxy") |
| Anonymous visitors | Refused, or with `INSIGHT_PUBLIC_VIEW=on` a read-only TLP:CLEAR view of the workspace with no API access | `INSIGHT_PUBLIC_VIEW=on` with `INSIGHT_MAX_TLP=CLEAR` instead of `INSIGHT_DEV_NO_AUTH=on` (RUNBOOK, "Public view") |
| Sign-in | Password, throttling, optional TOTP MFA; `INSIGHT_REQUIRE_HARDENED=on` refuses to start without secure cookies and MFA, and an internet-facing instance without them logs a warning | Keep `INSIGHT_DEV_NO_AUTH=off` for protected access; use a strong password (`make env`); `make mfa-enable`, then `INSIGHT_REQUIRE_HARDENED=on` |
| Automation access | One hashed, expiring, scoped API key; per-key TLP limit; the read-only TAXII server answers API keys only, with accepted indicators within the key's TLP limit and publishers' reuse rules ([ADR 0026](adr/0026-taxii-server.md)) | `make api-key-create` with the least access and lowest `MAX_TLP` that works; rotate before expiry |
| Abuse and overload | Per-caller rate limits, invalid-key throttling, 2 MB bodies | Optional edge limits at the proxy (connections, request rate) |
| Data on the server | TLP:RED refused by default (`INSIGHT_MAX_TLP`) | Review reports stored before the limit (start-up logs the count) |
| Accountability | Audit actor per event; key ID in logs | Ship logs somewhere you monitor (RUNBOOK section 11) |
| Backups | `make backup`, tested restore drill | Store backups encrypted, off the host |
| Egress | Fixed connector hosts, no redirects; scheduled syncs only for sources the operator scheduled, never set by an API key, every run recorded ([ADR 0018](adr/0018-opt-in-scheduled-syncs.md)); new sources off until switched on ([ADR 0021](adr/0021-threat-research-sources.md)); alerts only to destinations the operator added in the workspace or host CLI, HTTPS webhooks to public addresses unless `INSIGHT_ALERT_PRIVATE_TARGETS=on`, never link-local, no redirects, report titles only up to each destination's TLP limit and never report text ([ADR 0022](adr/0022-alerts.md)); automatic CVE lookups off until switched on per provider, only CVE numbers from TLP:CLEAR and GREEN reports, one throttle per provider shared by every caller, the optional NVD key sent only in NVD's header and never logged ([ADR 0023](adr/0023-automatic-cve-lookups.md)); manual GreyNoise and Shodan IP lookups only with a host key, only for reviewed public IPv4s in current TLP:CLEAR reports, each approved by the operator, never scheduled; the Shodan key travels in Shodan's URL, so Insight writes its own error messages and hides `key=` in httpx log lines ([ADR 0031](adr/0031-shodan.md)) | Connections go to the checked address (L1); an outbound firewall as the backstop; `INSIGHT_RUN_JOBS=off` if no process should go online by itself |

Still missing before any **multi-user** or shared use: SSO/OIDC, per-user accounts and roles, TLP recipient
enforcement, shared rate limits (several workers or hosts), tamper-evident audit logs, and
policy-based retention and deletion.

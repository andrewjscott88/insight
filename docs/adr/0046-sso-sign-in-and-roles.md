# ADR 0046: SSO sign-in, users and roles (TIP 3.4)

- Status: Proposed
- Date: 2026-11-25
- Roadmap: [TIP 3.4](../ROADMAP-TIP.md#34-oidc-sign-in-and-rbac), issue #14

Four choices below are Claude's recommendations, made while Andrew's answers were pending. They are marked
**(to confirm)** and can change in review without changing the rest of the design.

## Context

Insight has one person in the workspace: the operator. They sign in with `INSIGHT_PASSWORD`, plus a TOTP code
if MFA is on. Sessions are stored in the database, bound to the current password and MFA setting. Every UI
write is audited as `operator` (`Workspace.write()`). API keys are minted only on the host with the CLI
(ADRs 0012 and 0015). Each key has an access level (`read`, `read-write`, `read-feedback`) and an optional TLP
limit. For demonstrations, `INSIGHT_DEV_NO_AUTH=on` opens the whole workspace, writes included, to anyone.

TIP 3.4 makes Insight a shared SOC tool. People sign in through the organisation's identity provider and act
with a role, and the authorisation matrix is enforced and tested. The roadmap's acceptance criteria:

- A viewer cannot ingest, sync or change schedules.
- An analyst can triage, but cannot mint keys or notification destinations.
- Architecture tests stop routes from dropping authentication.
- A single-operator deployment upgrades to a single admin and keeps working.

Issue #14 adds three more:

- the matrix is tested against a containerised identity provider;
- the gate runs an authenticated ZAP active scan;
- there are notes for a staging environment.

## Decision

### 1. OpenID Connect, authorisation code flow, no new dependency

Insight signs people in with one OpenID Connect provider, set on the host:

- `INSIGHT_OIDC_ISSUER`, `INSIGHT_OIDC_CLIENT_ID` and `INSIGHT_OIDC_CLIENT_SECRET`;
- optionally `INSIGHT_OIDC_SCOPES` (default `openid email profile`) and `INSIGHT_OIDC_GROUPS_CLAIM` (default
  `groups`).

Any standards-compliant provider works, for example Microsoft Entra ID, Google, Okta, Keycloak or Authentik.
**(To confirm: which provider gets the first live test.)**

- **Discovery.** Insight reads `{issuer}/.well-known/openid-configuration` through `connectors.download`. That
  call is allowlisted to the issuer host and to the hosts the document names for its token endpoint and its
  key set, so the redirect URI is the only endpoint Insight trusts the browser to reach. All of them must be
  HTTPS on public addresses. A self-hosted provider on a private network needs
  `INSIGHT_OIDC_PRIVATE_NETWORK=on`, like MISP's switch. Loopback, link-local and metadata addresses stay
  blocked.
- **The flow.**
  - Authorisation code with PKCE (S256), as a confidential client.
  - `state`, `nonce` and the PKCE verifier sit in the signed session cookie for at most ten minutes, and each
    is used once.
  - The code is exchanged at the token endpoint through `connectors.download`.
- **ID token checks.**
  - The signature uses `RS256`, `PS256` or `ES256` with a key from the provider's key set, verified with
    `cryptography`, which Insight already depends on. `none`, `HS*` and every other algorithm are refused.
  - `iss` must equal the configured issuer. `aud` must contain the client ID, and `azp` must be it when there
    are several audiences.
  - `exp` and `iat` are checked with two minutes of clock skew, and `nonce` must match.
  - An email is used only when `email_verified` is true.
  
  Every check has a negative test.
- **No library.** AGENTS.md prefers no dependencies, and the flow is short. A client library such as Authlib
  would add a dependency, a lock refresh and a licence review for code this small. If the hand-written client
  ever grows past token validation, revisit this choice in a new ADR.

### 2. Users and three fixed roles

- **Users.** A new `users` table records each person:
  - the provider's subject (issuer and `sub` together are unique);
  - email and display name;
  - a role: `viewer`, `analyst`, `admin`, or none while pending;
  - first and last sign-in, and a disabled flag.
  
  Roles are fixed in code. There's one role per user and no separate `roles` table in v1, which is enough for
  three nested roles.
- **First sign-in.** **(To confirm.)**
  - If the host names provider groups (`INSIGHT_OIDC_ADMIN_GROUPS`, `INSIGHT_OIDC_ANALYST_GROUPS`,
    `INSIGHT_OIDC_VIEWER_GROUPS`, comma-separated), the highest matching group sets the role at every sign-in.
    Insight shows those users as managed by the provider.
  - Otherwise a new user is **pending**: signed in, but with no access, until an admin gives them a role in
    Settings → People. The CLI can do the same on the host (`insight users …`), as a break-glass.
- **The operator.** The existing password sign-in, with MFA, stays as the built-in **operator** account with
  the admin role. That is the upgrade path: today's deployments keep working as one admin.
  `INSIGHT_SSO_ONLY=on` turns password sign-in off. The CLI on the host remains the break-glass.

### 3. The permission matrix

One table in code (`insight.permissions`) maps each action to the lowest role allowed to do it:

| Role | May |
| --- | --- |
| viewer | Read the workspace and the API; download exports, briefs, products and hunt guides |
| analyst | Everything a viewer may, plus intelligence work: add and import reports; review indicators and verdicts; write notes and links; edit products, requirements, RFIs and hunt packages; sync a source now; **approve an outside lookup for a provider an admin has turned on (to confirm)** |
| admin | Everything an analyst may, plus settings: switch sources and providers on or off; operator sources; schedules; retention and deleting reports; threat-library sync; MFA; people and their roles; ending other people's sessions |

API keys keep their CLI-only life cycle. A `read` key gets viewer permissions, and a `read-write` key gets
analyst permissions; no key ever gets admin permissions. `read-feedback` and session-only routes stay as they
are. Notification destinations and keys remain CLI-only, so no role can create them in the workspace.

Roles do not change TLP in v1: everyone signed in reads up to the instance limit. Per-user TLP ceilings and
recipient groups come later, as the roadmap says.

### 4. Enforcement in one place for each surface, refusing by default

- **API.** `require_auth` looks up every request's permission by route (method and path template). A route
  with no entry is refused. An architecture test fails when any registered route lacks an entry or drops
  `require_auth`.
- **Workspace.** `Workspace.write(permission)` checks the current session's role on every callback, so a role
  change or a disabled account applies at once. Asynchronous lookups go through the same check. Controls a role
  cannot use are hidden, but the server-side check is the control. An AST test fails when a `write(...)` call
  names no permission.
- **Services** keep their TLP filtering and are unchanged.

### 5. Sessions and audit

- Stored sessions gain the user. Changing a user's role, disabling them or removing them ends their sessions.
  An admin can end anyone's sessions.
- Audit events name `user:<id>`, and the audit view shows the person's name and email. The password account
  stays `operator`, keys stay `api-key:<id>` and the CLI stays `cli`.

### 6. A read-only public view **(to confirm)**

`INSIGHT_PUBLIC_VIEW=on` lets visitors who are not signed in use the workspace with viewer permissions, minus
anything that is not published intelligence: the audit log, watch terms and settings stay hidden.

- Start-up refuses it unless `INSIGHT_MAX_TLP=CLEAR`, so nothing above CLEAR can exist on that instance.
- Start-up also refuses it together with `INSIGHT_DEV_NO_AUTH`.
- It opens no API access; a key is still required. Visitors are rate-limited by address.
- People with a role sign in from the same page to work.

This replaces temporary open access for public demonstrations. TIP 0.1's check becomes "anonymous visitors can
read published intelligence but cannot write or reach the API".

### 7. Proving it

- **Unit and API tests:**
  - an in-process fake provider (discovery, key set, token endpoint);
  - every token check, including the refusals;
  - the full role × route matrix through the real middleware;
  - the workspace's write checks.
- **The milestone gate:**
  - signs in through a containerised provider (Dex, pinned by digest) as a viewer, an analyst and an admin;
  - runs the matrix in the browser;
  - runs ZAP's active scan as an analyst.
- **Staging:** `docs/RUNBOOK.md` gets steps for a staging instance against the real provider.

## Out of scope for v1

- SAML; several providers at once; SCIM provisioning.
- Passwords for anyone but the operator; per-user API keys.
- Per-user TLP ceilings and recipient groups.

## Consequences

- **The auth path grows.** Refusing by default, one table and the architecture tests keep the matrix honest.
  The token checks are the riskiest new code: a short algorithm allowlist and negative tests cover them.
- **Migration `0033`** (or the next number) adds `users` and the session's user. Existing deployments keep the
  operator as their only admin, and nothing changes until the host sets `INSIGHT_OIDC_*`.
- **Codex's MCP endpoint and TAXII** remain key-only and are unchanged.

## Plan

| Part | What | Migration |
| --- | --- | --- |
| 3.4a | Users, roles, the matrix and its enforcement in the API and workspace; operator as admin; `insight users` CLI; architecture tests | 0033 |
| 3.4b | OIDC sign-in: discovery, PKCE flow, token checks, group mapping, pending users and Settings → People, `INSIGHT_SSO_ONLY`; set-up notes per provider | — |
| 3.4c | Read-only public view, and TIP 0.1's new check | — |
| 3.4d | Gate: containerised provider, browser matrix, authenticated ZAP active scan; staging notes | — |

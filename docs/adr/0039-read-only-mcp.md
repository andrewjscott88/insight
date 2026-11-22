# 0039: Read-only MCP with the existing API-key boundary

Status: Proposed; security review required before merge.

## Context

TIP 4.8 gives agents bounded access to existing intelligence. It must preserve the same TLP, publisher,
authentication and auditing rules as other clients. The approved brief explicitly excludes OAuth and write
tools. It requires initialization, ping and tool discovery/calls over stateless HTTP.

## Decision

Implement the small MCP Streamable HTTP subset directly with FastAPI, the existing Pydantic dependency and
the standard library. Support **2026-07-28** per-request metadata and `server/discover`, alongside
**2025-11-25** initialization for legacy clients. This meets both the brief's current-protocol requirement
and its named legacy methods. Neither path creates connection state. No dependency or migration is added.

Modern requests validate required metadata and matching version/method/name HTTP headers before dispatch,
including Base64-encoded names. Version errors list supported versions; header failures use `-32020`, and
missing required metadata uses `-32602`. Modern results carry `resultType: complete` and server identity.
Unknown modern methods return `404` with `-32601`. Legacy behavior stays selected by the explicit legacy
revision or initial handshake; unsupported modern metadata never falls back to legacy authorization.

`POST /mcp` requires an Insight bearer API key and has a separate per-key 120/minute budget. This exact
method/path accepts read-only keys because its fixed registry contains only reads. All other POST permission
checks remain unchanged. Cookie-only authentication is refused even in development's open-access mode.
Unknown, expired and revoked tokens use the existing uniform failure response and failure limiter.

The existing ASGI boundary checks Host, Origin, proxy trust and body size. MCP also rejects duplicate Origin
headers, non-JSON media, unsupported version headers, duplicate JSON members, non-finite numbers, batches
and over-limit bodies. There is no transport session, event stream, notification-driven tool invocation,
client callback or server-initiated request. No resources, prompts, sampling or elicitation are advertised.

Two tools call `services.mcp_read` with the authenticated ceiling. Projections reuse domain reads rather
than making HTTP loopback calls or building SQL in the route. Reports use export publisher rules; brief
composition drops the private watchlist. Missing and forbidden-by-TLP records produce identical tool errors.
JSON and text results match; schemas and output budgets bound queries and responses. Every tool result's
conservative `sharing_tlp` is its key's ceiling (RED if unlimited); actual source labels stay separate, and
group profiles also retain the strictest returned report/link label. No rule code is run or
returned, and no tool starts enrichment, ingestion, exports, jobs or model calls.

`mcp.call` records the key actor, tool name and fixed outcome without retaining arguments or intelligence.
Authentication retains existing last-use metadata. No intelligence records are written. Tool content is
untrusted evidence; consumers must not treat it as instructions. Key holders control disclosure to their
chosen client or model and must preserve TLP and publisher restrictions.

## Consequences and validation

Clients must support a listed protocol revision and custom bearer headers. OAuth-only clients are outside the
supported surface. A small implementation avoids new dependencies but requires maintained protocol tests.
Limits are conservative: no arbitrary full-text report dump, tool result pagination or live event stream.

Unit tests cover projections, reuse restrictions, bounded schemas/results and unchanged database contents.
API tests exercise methods/errors, authentication, cookie refusal, Origin/Host/proxy checks, rate isolation,
auditing and every-tool GREEN/AMBER leakage. A workspace simulation confirms that a signed-in browser still
cannot use MCP. Required ruff, strict mypy, SQLite and PostgreSQL gates and maintainer security review apply.

References: [MCP guide](../MCP.md), [modern transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http),
[legacy lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle),
[2026-07-28 versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning).

## Part 1 and integration

This independent main-based part exposes only `get_indicator`, `search_reports`.
Both parts repeat the same protocol, authentication, rate and audit support so each is independently testable.
When integrating, keep one copy of that support and combine the tool registry, projections and tests.
Do not replace one registry with the other. The whole TIP 4.8 item remains incomplete until both parts
are integrated and their combined security tests pass. No migration or new dependency is needed.

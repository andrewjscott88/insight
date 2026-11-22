# Brief: TIP 4.8 Read-only MCP endpoint

Required for 1.0. ADR number reserved: **0039**. Read [AGENTS.md](../../AGENTS.md) first.

## Goal

Let AI agents read Insight's intelligence through the Model Context Protocol (MCP), with the same API keys and
TLP ceilings as every other client. The endpoint is read-only, and Insight itself still calls no model and
writes nothing a model produced ([LLM_EXTENSION.md](../LLM_EXTENSION.md); TIP 3.6 stays separate and opt-in).

## What already exists (reuse it)

- **API keys** (`apikeys.py`, `web/auth.py`): bearer tokens, access levels, a per-key `max_tlp`, rate-limit
  budgets (`rate_limit_policy`), and audit entries that name the key.
- **The TAXII server** ([ADR 0026](../adr/0026-taxii-server.md), `web/routes/taxii.py`) is the model for a
  read-only machine interface: API keys only (a browser session is refused), its own path, its own budget,
  every read audited.
- **The services layer**: ranked search, reports, indicators with verdicts and confidence, requirements and
  requests for information, hunt packages, threat groups and guides, the landscape and the brief. Every tool
  must call these services with the key's limit; none may query the database itself.

## Build

1. **Transport.** The current MCP specification's Streamable HTTP transport at `/mcp`: JSON-RPC 2.0 over
   `POST`, stateless, no server-initiated messages (`GET` answers `405`). Support `initialize`,
   `notifications/initialized`, `ping`, `tools/list` and `tools/call`. Validate the `Origin` header as the
   specification requires, so a web page cannot reach a local Insight (DNS rebinding).
2. **Authentication.** `Authorization: Bearer <Insight API key>` only. A browser session is refused, as for
   TAXII; an unknown, revoked or expired key gets the same `401` as the API. Any access level may call, because
   every tool only reads; the key's `max_tlp` applies to every tool.
3. **Tools**, each a thin wrapper over existing services, with input schemas, size-capped results and both
   structured content and text: search reports and indicators; a report's summary (metadata, and publisher
   text only where the publisher's reuse rules allow it, as in exports); an indicator with its verdict,
   confidence and when it was first and last seen; open requirements and requests for information; a hunt
   package; a threat group's profile; the landscape summary.
4. **No writes and no model.** No tool changes anything. No resources, prompts, sampling or elicitation for
   now.
5. **Limits and audit.** Its own rate-limit budget per key, like TAXII's; every call audited as `mcp.call` with
   the tool name.

## Not in scope

Write tools; OAuth (API keys only for now); calling a model from Insight; serving STIX through MCP (TAXII does
that).

## Constraints

- Prefer no new dependency: the subset above is small enough to implement with Pydantic models. If you use
  the official MCP Python SDK instead, it must pass hash-locking and the licence check, and the ADR must say why.
- Security-sensitive: the maintainer reviews this pull request before it is merged.
- Tests: the protocol (each method, malformed JSON-RPC, unknown tools and methods), authentication (session
  refused, `401`, `Origin` check), rate limits and audit; and the GREEN-key TLP sweep must call every tool
  against the AMBER data in its `world` fixture and find no secret in any answer.

## Suggested parts

1. Transport, authentication, two tools (search and indicator) and their TLP sweep.
2. The remaining tools, docs/MCP.md (connecting common MCP clients with a header), and the API.md and
   SECURITY.md entries.

## Done when

Every item in the AGENTS.md checklist is met for each part, docs/MCP.md, API.md, SECURITY.md, CHANGELOG.md,
README.md, ROADMAP.md and ROADMAP-TIP.md are updated, and ADR 0039 records the decisions.

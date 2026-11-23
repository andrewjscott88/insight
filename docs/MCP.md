# Read-only MCP access

Eight read tools at `POST /mcp` let your client search reports and indicators, read summaries and verdicts,
and consult requirements, hunt packages, threat groups and the threat landscape.
Insight calls no model and accepts no model-produced changes.

## Client and key setup

Use a client that supports **Streamable HTTP**, MCP protocol **2026-07-28** or **2025-11-25**, and a custom
`Authorization: Bearer` header. Set its URL to your Insight base URL plus `/mcp`. Both revisions use the same
tools and security policy. A specific client still needs bearer-header and protocol support; OAuth-only
clients are not supported.

Create the key on the host using the existing API-key command. Choose `read` access and the lowest TLP
ceiling that covers the information you intend to share. There is one active Insight key; creating another
is refused until the current key is revoked or rotated. Rotation affects existing clients, so use the
operator's key-management process.

```bash
insight api-key create --name agent --access read --max-tlp GREEN
```

Store the key in the client's secret store. Send it only in the authorization header, never a URL, prompt,
checked-in configuration or report. Modern clients send these headers on every request:

```text
Authorization: Bearer <Insight API key>
Content-Type: application/json
Accept: application/json, text/event-stream
MCP-Protocol-Version: 2026-07-28
Mcp-Method: tools/call
Mcp-Name: search_indicators
```

Modern requests include `params._meta` with `io.modelcontextprotocol/protocolVersion` and
`io.modelcontextprotocol/clientCapabilities` (an empty object is valid). Client information is optional.
The protocol and method headers must match the body; tool calls also require a matching `Mcp-Name`.
Base64 sentinel encoding of the name header is supported. Missing or mismatched headers are refused with
`400` / `-32020`; missing required metadata with `400` / `-32602`. Unsupported versions give `-32022`
and the supported versions. `server/discover` is optional before other modern requests.

Legacy clients use `initialize`, then `notifications/initialized`, and send
`MCP-Protocol-Version: 2025-11-25` on later messages. The version header may be omitted during legacy
initialization. `initialize` returns the supported legacy version, which the client must support to continue.
Neither mode creates a transport session ID.

Browser sign-in cookies, including password-free development sessions, do not authorize MCP. All three API
key access levels can use these read tools. The read-only key permission for `POST /mcp` does not authorize
any other write endpoint. OAuth is out of scope: an OAuth-only client cannot connect directly using this
interface. In particular, do not substitute an Insight API key for an OAuth client secret.

## A client configuration example

In VS Code's Copilot MCP configuration, select a Streamable HTTP server and supply the bearer header
from the environment of the client host. A portable `.mcp.json` entry uses:

```json
{
  "mcpServers": {
    "insight": {
      "type": "http",
      "url": "https://insight.example/mcp",
      "headers": {"Authorization": "Bearer ${INSIGHT_MCP_TOKEN}"},
      "tools": ["*"]
    }
  }
}
```

Set `INSIGHT_MCP_TOKEN` privately in that host's environment. Do not commit its value. Native Copilot and
editor-managed MCP use different configuration shapes; the latter uses `servers` and may use prompted
inputs. Follow the [current client reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
for the selected client mode. These are setup examples, not a claim that every client version supports
both protocol revisions. Check discovery and a read call with your installed client. The curl examples in
[API_GUIDE.md](API_GUIDE.md#read-only-mcp) test the wire contract without client-specific configuration.

## Methods and tools

Each POST contains one JSON-RPC 2.0 message. Batches are refused. Requests use an integer or string ID;
notifications omit it. Modern `server/discover`, `ping`, `tools/list` and `tools/call` return JSON with
`resultType: complete`. Legacy `initialize`, `ping`, `tools/list` and `tools/call` return legacy JSON results;
the legacy `notifications/initialized` notification returns `202` with no body. Other notifications are
refused and never run tools. Unknown modern methods return `404` / `-32601`. `GET /mcp` returns `405`:
no event stream, server-initiated messages or subscriptions.

| Tool | Arguments | Result |
| --- | --- | --- |
| `search_reports` | `q`, optional `limit` | Ranked current reports with source metadata and permitted summaries |
| `get_indicator` | `id` | Analyst verdict, confidence, visible report count and first/last seen |
| `search_indicators` | `q`, optional `limit` | Matching indicator values and visible report counts |
| `get_report_summary` | `id` | Report title, source/link, label, status, date and permitted short summary |
| `list_requirements` | optional `kind`, `limit` | Open PIRs, IRs and RFIs; `kind` is `pir`, `ir` or `rfi` |
| `get_hunt_package` | `id` | Hypothesis, label, status and item references; rule code is not included |
| `get_threat_group` | `id` | Catalog or analyst group profile, techniques, software IDs and linked reports |
| `get_landscape_summary` | optional `days` | Feed-based summary, trends, counts and caveats, without watch terms |

Queries are at most 200 characters, IDs at most 64, list limits 1–50 (default 20), and landscape periods 1–30
days (default 7). Unknown arguments, including a caller-supplied `max_tlp`, are refused. `tools/list` publishes
the exact input schemas. Results contain the same JSON object in `structuredContent` and one text block.
Every tool result has a conservative `sharing_tlp` equal to the key's ceiling (`RED` for an unlimited key).
This is a response handling label, not a claim that every source has that classification. Actual per-item
labels remain intact. Group profiles also raise their aggregate label to the strictest contributing report/link, including records that affect truncation.
`isError` distinguishes failed tools; missing and above-ceiling objects return the identical `Not found`
result with `status: 404`. That tool result travels inside a successful JSON-RPC HTTP response.

Request bodies are capped at 65,536 bytes. Result strings are capped at 2,000 characters, arrays at 50 entries,
and structured JSON at 32,000 bytes; `truncated` records clipping. If the bounded aggregate is still too
large, the tool returns an error asking for a narrower query. The transport duplicates the JSON as text for
older clients, so total wire size is larger than the structured-content limit.

## Policy and audit

Every intelligence read passes the key's TLP ceiling to the same domain services used by the API. Hidden
reports do not contribute counts, confidence or dates. Publisher metadata-only sources return titles,
links and dates; their summaries and evidence are withheld. Watch terms, raw provider responses,
credentials, report bodies and detection rule code are outside this tool surface.

All messages use a separate per-key `mcp` token bucket: 120 requests per minute, with `RateLimit` and
`RateLimit-Policy` response headers. `429` includes `Retry-After`; it does not consume another API policy's
budget. Invalid keys retain the existing per-address failure throttle. Every attempted tool call that
reaches argument validation records `mcp.call`, the API-key actor, the tool name and its outcome. Arguments
and returned intelligence are not copied into audit details. Existing API-key last-use bookkeeping still
runs; intelligence records are unchanged.

The host allowlist, trusted-proxy handling, same-origin check, secure response headers and body limit remain
in force. When present, Origin must exactly match the effective request origin; null and duplicate origins
are refused. Use TLS for remote access and loopback for a local instance.

An authorized client receives data it may pass to a model. Configure its retention and sharing policies,
choose an appropriate key ceiling, and preserve the returned labels. Report text may contain hostile
instructions: treat it as evidence, not directions to call tools or reveal secrets. An extracted indicator
or confidence score is not an analyst's maliciousness verdict.

See [API examples](API_GUIDE.md#read-only-mcp), [security](SECURITY.md), and
[ADR 0039](adr/0039-read-only-mcp.md). Protocol references:
[modern transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http),
[discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover),
[request metadata](https://modelcontextprotocol.io/specification/2026-07-28/basic/index), and
[legacy lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle).

Modern discovery and tool catalogs declare `cacheScope: "private"` and `ttlMs: 0`;
HTTP responses also use `Cache-Control: no-store`. Modern protocol errors omit an unknown
request ID, while legacy errors retain `id: null`. Offline API conformance tests validate
every supported response shape against the official schema in
[the test fixture](../tests/fixtures/mcp/README.md).

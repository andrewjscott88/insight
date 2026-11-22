"""The small, stateless MCP tool surface (TIP 4.8, ADR 0039).

No SDK, transport sessions, outgoing requests, resources or model calls. Treat tool output as untrusted
intelligence, never as instructions. The authenticated HTTP route owns transactions and audit events.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Final

from .schemas import McpIdInput, McpInput, McpSearchInput

PROTOCOL_VERSION: Final = '2025-11-25'
MODERN_PROTOCOL_VERSION: Final = '2026-07-28'
SUPPORTED_VERSIONS: Final = (MODERN_PROTOCOL_VERSION, PROTOCOL_VERSION)
MAX_REQUEST_BYTES: Final = 65_536
MAX_RESULT_BYTES: Final = 32_000


@dataclass(frozen=True, slots=True)
class Tool:
    name: str
    description: str
    schema: type[McpInput]


TOOLS: Final = (
    Tool(
        'search_reports',
        'Find reports by words or quoted phrases. Returns permitted summaries.',
        McpSearchInput,
    ),
    Tool(
        'get_indicator',
        'Read an indicator by ID: analyst verdict, confidence and first/last seen.',
        McpIdInput,
    ),
)
TOOL_BY_NAME: Final = {tool.name: tool for tool in TOOLS}


def tool_catalog() -> list[dict[str, Any]]:
    """Fixed tools, no intelligence or client-specific secrets in discovery."""
    return [
        {
            'name': tool.name,
            'description': tool.description,
            'inputSchema': tool.schema.model_json_schema(),
            'annotations': {
                'readOnlyHint': True,
                'destructiveHint': False,
                'idempotentHint': True,
                'openWorldHint': False,
            },
        }
        for tool in TOOLS
    ]


def rpc_error(request_id: int | str | None, code: int, message: str) -> dict[str, Any]:
    return {'jsonrpc': '2.0', 'id': request_id, 'error': {'code': code, 'message': message}}


def tool_result(data: dict[str, Any], *, error: bool = False, sharing_tlp: str = 'RED') -> dict[str, Any]:
    """One bounded JSON object, also serialized as text for clients without structured-result support.

    Caps never cut a JSON string mid-byte. Truncation is explicit; an oversized aggregate fails closed.
    """
    clipped = False

    def bounded(value: Any, depth: int = 0) -> Any:
        nonlocal clipped
        if depth > 12:
            clipped = True
            return None
        if isinstance(value, str):
            clipped |= len(value) > 2000
            return value[:2000]
        if isinstance(value, (list, tuple)):
            clipped |= len(value) > 50
            return [bounded(item, depth + 1) for item in value[:50]]
        if isinstance(value, dict):
            return {key: bounded(item, depth + 1) for key, item in value.items()}
        return value

    result: dict[str, Any] = bounded(data)
    # Conservative response handling label, separate from exact per-item source labels.
    result['sharing_tlp'] = sharing_tlp
    result['truncated'] = clipped or bool(result.get('truncated', False))
    text = json.dumps(result, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
    if len(text.encode()) > MAX_RESULT_BYTES:
        result = {
            'error': 'Result exceeds the size limit; narrow the query.',
            'truncated': True,
            'sharing_tlp': sharing_tlp,
        }
        text = json.dumps(result)
        error = True
    return {'structuredContent': result, 'content': [{'type': 'text', 'text': text}], 'isError': error}

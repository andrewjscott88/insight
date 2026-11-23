"""Offline validation of MCP responses against the unmodified upstream protocol schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA = json.loads(
    (Path(__file__).parent / 'fixtures/mcp/schema-2026-07-28.json').read_text(encoding='utf-8')
)


def conforms(value: Any, definition: str) -> None:
    schema = SCHEMA | {'$ref': '#/$defs/' + definition}
    Draft202012Validator(schema).validate(value)


def response_conforms(value: dict[str, Any], method: str) -> None:
    if 'error' in value:
        conforms(value, 'JSONRPCErrorResponse')
        specific = {-32020: 'HeaderMismatchError', -32022: 'UnsupportedProtocolVersionError'}
        if value['error']['code'] in specific:
            conforms(value, specific[value['error']['code']])
    else:
        conforms(value, 'JSONRPCResultResponse')
        definition = {
            'server/discover': 'DiscoverResult',
            'ping': 'Result',
            'tools/list': 'ListToolsResult',
            'tools/call': 'CallToolResult',
        }[method]
        conforms(value['result'], definition)

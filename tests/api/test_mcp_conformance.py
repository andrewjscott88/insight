"""Regression coverage for the complete modern result schema, independently of implementation models."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from insight.mcp import MODERN_PROTOCOL_VERSION, PROTOCOL_VERSION, TOOL_BY_NAME

from ..mcp_schema import response_conforms
from .test_mcp import mcp_headers as mcp_headers
from .test_mcp_modern import modern


@pytest.mark.parametrize('method', ['server/discover', 'tools/list'])
def test_discovery_cache_metadata(client: TestClient, mcp_headers: dict[str, str], method: str) -> None:
    """Regression: modern discovery/catalog responses require private cache scope and a lifetime."""
    response = modern(client, mcp_headers, method)
    assert response.status_code == 200
    result = response.json()['result']
    assert result['cacheScope'] == 'private'
    assert result['ttlMs'] == 0
    assert response.headers['cache-control'] == 'no-store'


@pytest.mark.parametrize('name', sorted(TOOL_BY_NAME))
def test_each_tool_result_conforms(client: TestClient, mcp_headers: dict[str, str], name: str) -> None:
    """Regression: every registered tool returns the current standard's complete result shape."""
    arguments: dict[str, Any] = {}
    if name.startswith('search_'):
        arguments = {'q': 'nothing'}
    elif name.startswith('get_') and name != 'get_landscape_summary':
        arguments = {'id': 'G0016' if name == 'get_threat_group' else 'missing'}
    response = modern(client, mcp_headers, 'tools/call', {'name': name, 'arguments': arguments})
    assert response.status_code == 200
    result = response.json()['result']
    assert json.loads(result['content'][0]['text']) == result['structuredContent']
    invalid = modern(client, mcp_headers, 'tools/call', {'name': name, 'arguments': {'extra': True}})
    assert invalid.status_code == 200
    assert invalid.json()['result']['isError']


@pytest.mark.parametrize('version', [PROTOCOL_VERSION, MODERN_PROTOCOL_VERSION])
@pytest.mark.parametrize(
    'body',
    [
        b'{',
        b'[]',
        b'{"jsonrpc":"2.0","id":null,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":true,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":1.5,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":"\\ud800","method":"ping"}',
    ],
)
def test_unknown_error_ids_follow_protocol_era(
    client: TestClient, mcp_headers: dict[str, str], version: str, body: bytes
) -> None:
    """Regression: an unknown request ID is omitted in modern errors, but null for legacy clients."""
    headers = mcp_headers | {
        'MCP-Protocol-Version': version,
        'Mcp-Method': 'ping',
        'Content-Type': 'application/json',
    }
    response = client.post('/mcp', headers=headers, content=body)
    assert response.status_code == 400
    value = response.json()
    assert value['error']['code'] in (-32700, -32600)
    if version == MODERN_PROTOCOL_VERSION:
        assert 'id' not in value
        response_conforms(value, 'ping')
    else:
        assert value['id'] is None

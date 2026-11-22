"""MCP 2026-07-28 over the same authenticated, bounded read-only endpoint as legacy clients."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services
from insight.mcp import MODERN_PROTOCOL_VERSION, SUPPORTED_VERSIONS
from insight.mcp_transport import CAPABILITIES_FIELD, VERSION_FIELD

from ..mcp_schema import response_conforms
from .test_mcp import mcp_headers as mcp_headers


def modern(
    client: TestClient, headers: dict[str, str], method: str, params: dict[str, Any] | None = None
) -> Any:
    params = dict(params or {})
    params['_meta'] = {VERSION_FIELD: MODERN_PROTOCOL_VERSION, CAPABILITIES_FIELD: {}}
    headers = headers | {'MCP-Protocol-Version': MODERN_PROTOCOL_VERSION, 'Mcp-Method': method}
    if method == 'tools/call':
        headers['Mcp-Name'] = params['name']
    response = client.post(
        '/mcp', headers=headers, json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}
    )
    response_conforms(response.json(), method)
    return response


@pytest.mark.parametrize('method', ['server/discover', 'ping', 'tools/list', 'tools/call'])
def test_current_methods_need_no_handshake(
    client: TestClient,
    mcp_headers: dict[str, str],
    method: str,
) -> None:
    params = {'name': 'search_indicators', 'arguments': {'q': 'nothing'}} if method == 'tools/call' else {}
    response = modern(client, mcp_headers, method, params)
    assert response.status_code == 200
    result = response.json()['result']
    assert result['resultType'] == 'complete'
    assert result['_meta']['io.modelcontextprotocol/serverInfo']['name'] == 'Insight'
    assert 'mcp-session-id' not in response.headers
    if method == 'server/discover':
        assert result['supportedVersions'] == list(SUPPORTED_VERSIONS)
        assert result['capabilities'] == {'tools': {}}


def test_current_unknown_method_and_tool_status(client: TestClient, mcp_headers: dict[str, str]) -> None:
    response = modern(client, mcp_headers, 'initialize')
    assert response.status_code == 404
    assert response.json()['error']['code'] == -32601
    unknown = modern(client, mcp_headers, 'tools/call', {'name': 'write_report', 'arguments': {}})
    assert unknown.status_code == 400
    assert unknown.json()['error']['code'] == -32602


@pytest.mark.parametrize(
    ('change', 'code'),
    [
        ('missing-capabilities', -32602),
        ('missing-meta', -32602),
        ('missing-method', -32020),
        ('wrong-name', -32020),
        ('wrong-version', -32020),
        ('unsupported-version', -32022),
        ('duplicate-header', -32020),
    ],
)
def test_current_invalid_metadata_never_dispatches(
    app: FastAPI,
    client: TestClient,
    mcp_headers: dict[str, str],
    change: str,
    code: int,
) -> None:
    headers = mcp_headers | {
        'MCP-Protocol-Version': MODERN_PROTOCOL_VERSION,
        'Mcp-Method': 'tools/call',
        'Mcp-Name': 'search_indicators',
    }
    meta = {VERSION_FIELD: MODERN_PROTOCOL_VERSION, CAPABILITIES_FIELD: {}}
    params: dict[str, Any] = {'name': 'search_indicators', 'arguments': {'q': 'nothing'}, '_meta': meta}
    if change == 'missing-capabilities':
        del meta[CAPABILITIES_FIELD]
    elif change == 'missing-meta':
        del params['_meta']
    elif change == 'missing-method':
        del headers['Mcp-Method']
    elif change == 'wrong-name':
        headers['Mcp-Name'] = 'get_indicator'
    elif change == 'wrong-version':
        headers['MCP-Protocol-Version'] = '1999-01-01'
    elif change == 'unsupported-version':
        headers['MCP-Protocol-Version'] = meta[VERSION_FIELD] = '2099-01-01'
    sent_headers = list(headers.items())
    if change == 'duplicate-header':
        sent_headers.append(('mcp-method', 'tools/call'))
    response = client.post(
        '/mcp',
        headers=sent_headers,
        json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': params},
    )
    assert response.status_code == 400
    response_conforms(response.json(), 'tools/call')
    assert response.json()['error']['code'] == code
    if change == 'unsupported-version':
        assert response.json()['error']['data']['supported'] == list(SUPPORTED_VERSIONS)
    with app.state.session_factory() as db:
        assert not any(event.action == 'mcp.call' for event in services.audit_events(db))

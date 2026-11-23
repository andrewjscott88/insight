"""MCP through the real auth, Origin, request-size and rate-limit boundary."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import apikeys, services
from insight.config import Settings
from insight.main import create_app
from insight.mcp import MAX_REQUEST_BYTES, PROTOCOL_VERSION, TOOL_BY_NAME
from insight.ratelimit import MCP, READ, WRITE
from insight.schemas import DocumentInput

from .test_dev_access import enter

ACCEPT = 'application/json, text/event-stream'


@pytest.fixture
def mcp_headers(app: FastAPI) -> dict[str, str]:
    with app.state.session_factory.begin() as db:
        _, token = services.create_api_key(db, name='mcp-test', access='read', max_tlp='GREEN')
    return {'Authorization': f'Bearer {token}', 'Accept': ACCEPT, 'MCP-Protocol-Version': PROTOCOL_VERSION}


def rpc(client: TestClient, headers: dict[str, str], method: str, **params: Any) -> Any:
    return client.post(
        '/mcp', headers=headers, json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}
    )


def test_initialize_notification_ping_and_catalog(client: TestClient, mcp_headers: dict[str, str]) -> None:
    answer = rpc(
        client,
        mcp_headers,
        'initialize',
        protocolVersion=PROTOCOL_VERSION,
        capabilities={},
        clientInfo={'name': 'Test', 'version': '1'},
    )
    result = answer.json()['result']
    assert result['protocolVersion'] == PROTOCOL_VERSION
    assert result['capabilities'] == {'tools': {'listChanged': False}}
    assert result['serverInfo']['name'] == 'Insight'
    assert 'mcp-session-id' not in answer.headers
    notified = client.post(
        '/mcp', headers=mcp_headers, json={'jsonrpc': '2.0', 'method': 'notifications/initialized'}
    )
    assert (notified.status_code, notified.content) == (202, b'')
    assert rpc(client, mcp_headers, 'ping').json()['result'] == {}
    tools = rpc(client, mcp_headers, 'tools/list').json()['result']['tools']
    expected = {
        'search_reports',
        'search_indicators',
        'get_report_summary',
        'get_indicator',
        'list_requirements',
        'get_hunt_package',
        'get_threat_group',
        'get_landscape_summary',
    }
    assert len(tools) == len(expected)
    assert {tool['name'] for tool in tools} == set(TOOL_BY_NAME) == expected
    assert all(tool['annotations']['readOnlyHint'] for tool in tools)
    assert all(tool['inputSchema']['additionalProperties'] is False for tool in tools)
    assert client.get('/mcp', headers=mcp_headers).status_code == 405


@pytest.mark.parametrize('access', ['read', 'read-feedback', 'read-write'])
@pytest.mark.parametrize('tool', ['search_reports', 'search_indicators'])
def test_all_key_access_levels_can_use_read_tools(
    app: FastAPI, client: TestClient, access: str, tool: str
) -> None:
    with app.state.session_factory.begin() as db:
        _, key = services.create_api_key(db, name='test', access=access)
    headers = {'Authorization': f'Bearer {key}', 'Accept': ACCEPT, 'MCP-Protocol-Version': PROTOCOL_VERSION}
    result = rpc(client, headers, 'tools/call', name=tool, arguments={'q': 'nothing'})
    assert result.status_code == 200
    assert not result.json()['result']['isError']
    assert result.json()['result']['structuredContent']['sharing_tlp'] == 'RED'


def test_session_and_open_browser_mode_never_authorize_mcp(
    client: TestClient,
    login: Callable[..., str],
    settings: Settings,
) -> None:
    csrf = login(client)
    assert rpc(client, {'Accept': ACCEPT, 'X-CSRF-Token': csrf}, 'ping').status_code == 401
    with TestClient(
        create_app(replace(settings, dev_no_auth=True), with_ui=False), follow_redirects=False
    ) as opened:
        assert rpc(opened, {'Accept': ACCEPT}, 'ping').status_code == 401
        csrf = enter(opened)
        assert rpc(opened, {'Accept': ACCEPT, 'X-CSRF-Token': csrf}, 'ping').status_code == 401


def test_invalid_expired_and_revoked_keys_answer_identically(
    app: FastAPI,
    client: TestClient,
    mcp_headers: dict[str, str],
) -> None:
    invalid = rpc(client, {'Accept': ACCEPT, 'Authorization': 'Bearer malformed'}, 'ping')
    with app.state.session_factory.begin() as db:
        key = services.active_api_key(db)
        assert key
        key.expires_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    expired = rpc(client, mcp_headers, 'ping')
    with app.state.session_factory.begin() as db:
        _, token = services.create_api_key(db, name='new-key', access='read')
        services.revoke_api_key(db)
    revoked = rpc(client, mcp_headers | {'Authorization': f'Bearer {token}'}, 'ping')
    unknown = rpc(client, mcp_headers | {'Authorization': f'Bearer {apikeys.generate().token}'}, 'ping')
    assert invalid.status_code == expired.status_code == revoked.status_code == unknown.status_code == 401
    assert invalid.json() == expired.json() == revoked.json() == unknown.json()
    assert invalid.headers['www-authenticate'] == expired.headers['www-authenticate']


@pytest.mark.parametrize('origin', ['https://attacker.invalid', 'null', 'http://localhost.attacker.invalid'])
def test_cross_origin_is_refused(client: TestClient, mcp_headers: dict[str, str], origin: str) -> None:
    assert rpc(client, mcp_headers | {'Origin': origin}, 'ping').status_code == 403


def test_origin_host_and_proxy_boundary(client: TestClient, mcp_headers: dict[str, str]) -> None:
    assert rpc(client, mcp_headers | {'Origin': 'http://testserver'}, 'ping').status_code == 200
    assert rpc(client, mcp_headers | {'Host': 'rebinding.invalid'}, 'ping').status_code == 400
    assert (
        rpc(
            client, mcp_headers | {'Origin': 'https://localhost', 'X-Forwarded-Proto': 'https'}, 'ping'
        ).status_code
        == 403
    )
    headers = [*mcp_headers.items(), ('Origin', 'https://attacker.invalid'), ('Origin', 'http://localhost')]
    response = client.post('/mcp', headers=headers, json={'jsonrpc': '2.0', 'id': 1, 'method': 'ping'})
    assert response.status_code == 403


@pytest.mark.parametrize(
    ('origin', 'host'),
    [
        ('', 'testserver'),
        ('null', 'testserver'),
        ('http://testserver:bad', 'testserver:bad'),
        ('http://testserver:65536', 'testserver:65536'),
        ('http://testserver:0', 'testserver:0'),
        ('http://testserver:', 'testserver:'),
        ('http://testserver/', 'testserver'),
        ('http://user@testserver', 'testserver'),
        ('http://testserver?x=y', 'testserver'),
    ],
)
def test_malformed_origin_is_rejected_before_auth(client: TestClient, origin: str, host: str) -> None:
    # A valid Host reaches the MCP Origin validator. TrustedHost may reject an invalid Host first.
    assert client.post('/mcp', headers={'Origin': origin, 'Host': 'testserver'}).status_code == 403
    assert client.post('/mcp', headers={'Origin': origin, 'Host': host}).status_code in (400, 403)


def test_valid_origin_with_explicit_port(client: TestClient, mcp_headers: dict[str, str]) -> None:
    headers = mcp_headers | {'Host': 'testserver:8080', 'Origin': 'http://testserver:8080'}
    assert rpc(client, headers, 'ping').status_code == 200


@pytest.mark.parametrize(
    ('body', 'code'),
    [
        ('{', -32700),
        ('{"jsonrpc":"2.0","jsonrpc":"2.0"}', -32700),
        ('NaN', -32700),
        ('[]', -32600),
        ('null', -32600),
        ('{}', -32600),
        ('{"jsonrpc":"1.0","id":1,"method":"ping"}', -32600),
        ('{"jsonrpc":"2.0","id":true,"method":"ping"}', -32600),
        ('{"jsonrpc":"2.0","id":null,"method":"ping"}', -32600),
    ],
)
def test_malformed_protocol(client: TestClient, mcp_headers: dict[str, str], body: str, code: int) -> None:
    response = client.post('/mcp', headers=mcp_headers | {'Content-Type': 'application/json'}, content=body)
    assert response.status_code == 400
    assert response.json()['error']['code'] == code


@pytest.mark.parametrize(
    'body',
    [
        r'{"jsonrpc":"2.0","id":"\ud800","method":"ping"}',
        r'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_reports",'
        r'"arguments":{"q":"\udfff"}}}',
        r'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_indicators",'
        r'"arguments":{"q":"\udfff"}}}',
        r'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"key":"\ud800"}}}',
        r'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"\ud800":"value"}}}',
        r'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_reports",'
        r'"arguments":{"q":"\u0000"}}}',
        r'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_indicators",'
        r'"arguments":{"q":"\u0000"}}}',
    ],
)
def test_escaped_invalid_text_is_refused_before_dispatch(
    app: FastAPI,
    client: TestClient,
    mcp_headers: dict[str, str],
    body: str,
) -> None:
    """Regression: escaped lone surrogates reached JSONResponse/SQL and caused a 500 during UTF-8 encoding."""
    response = client.post('/mcp', headers=mcp_headers | {'Content-Type': 'application/json'}, content=body)
    assert response.status_code == 400
    assert response.json()['error']['code'] == -32700
    with app.state.session_factory() as db:
        assert not any(event.action == 'mcp.call' for event in services.audit_events(db))


def test_media_versions_limits_and_unknown_methods(client: TestClient, mcp_headers: dict[str, str]) -> None:
    assert rpc(client, mcp_headers | {'Content-Type': 'text/plain'}, 'ping').status_code == 415
    assert rpc(client, mcp_headers | {'Accept': 'application/json'}, 'ping').status_code == 406
    assert rpc(client, mcp_headers | {'MCP-Protocol-Version': '1999-01-01'}, 'ping').status_code == 400
    no_version = {name: value for name, value in mcp_headers.items() if name != 'MCP-Protocol-Version'}
    assert rpc(client, no_version, 'ping').status_code == 400
    huge = client.post(
        '/mcp',
        headers=mcp_headers | {'Content-Type': 'application/json'},
        content=' ' * (MAX_REQUEST_BYTES + 1),
    )
    assert huge.status_code == 413
    for method in ('resources/list', 'prompts/list', 'sampling/createMessage', 'unknown', 'server/discover'):
        assert rpc(client, mcp_headers, method).json()['error']['code'] == -32601
    assert rpc(client, mcp_headers, 'tools/list', cursor='unknown').json()['error']['code'] == -32602
    assert rpc(client, mcp_headers, 'initialize').json()['error']['code'] == -32602
    unsupported = rpc(
        client,
        no_version,
        'initialize',
        protocolVersion='2099-01-01',
        capabilities={},
        clientInfo={'name': 'Test', 'version': '1'},
    )
    assert unsupported.json()['result']['protocolVersion'] == PROTOCOL_VERSION


@pytest.mark.parametrize('tool', ['search_reports', 'search_indicators'])
def test_tool_arguments_errors_and_audit(
    app: FastAPI, client: TestClient, mcp_headers: dict[str, str], tool: str
) -> None:
    hidden_query = 'Never log this query'
    unknown = rpc(client, mcp_headers, 'tools/call', name='write_report', arguments={})
    assert unknown.json()['error']['code'] == -32602
    for args in ({'q': hidden_query, 'limit': 51}, {'q': hidden_query, 'max_tlp': 'RED'}, {'q': 12}):
        result = rpc(client, mcp_headers, 'tools/call', name=tool, arguments=args).json()['result']
        assert result['isError']
        assert hidden_query not in json.dumps(result)
    good = rpc(client, mcp_headers, 'tools/call', name=tool, arguments={'q': hidden_query})
    assert not good.json()['result']['isError']
    with app.state.session_factory() as db:
        events = [event for event in services.audit_events(db) if event.action == 'mcp.call']
    assert len(events) == 5
    assert all(event.actor.startswith('api-key:') for event in events)
    assert all(hidden_query not in event.detail for event in events)
    assert {json.loads(event.detail)['tool'] for event in events} == {tool, 'write_report'}


def test_separate_rate_budget_and_read_only_post_exception(
    app: FastAPI,
    client: TestClient,
    mcp_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(app.state.rate_limiter, 'clock', lambda: 1.0)
    for _ in range(MCP.limit):
        assert rpc(client, mcp_headers, 'ping').status_code == 200
    limited = rpc(client, mcp_headers, 'ping')
    assert limited.status_code == 429
    assert int(limited.headers['Retry-After']) > 0
    assert '"mcp"' in limited.headers['RateLimit']
    read = client.get('/api/stats', headers=mcp_headers)
    assert read.status_code == 200
    assert f'q={READ.limit}' in read.headers['RateLimit-Policy']
    write = client.post('/api/documents', headers=mcp_headers, json={})
    assert write.status_code == 403
    assert MCP.name not in (READ.name, WRITE.name)


def test_notifications_never_run_tools(app: FastAPI, client: TestClient, mcp_headers: dict[str, str]) -> None:
    notified = client.post(
        '/mcp',
        headers=mcp_headers,
        json={
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {'name': 'get_landscape_summary', 'arguments': {}},
        },
    )
    assert notified.status_code == 400
    with app.state.session_factory() as db:
        assert not any(event.action == 'mcp.call' for event in services.audit_events(db))


def test_report_result_has_matching_structured_text(
    app: FastAPI,
    client: TestClient,
    mcp_headers: dict[str, str],
) -> None:
    with app.state.session_factory.begin() as db:
        report, _ = services.ingest(
            db, DocumentInput(title='Sample', body='Observed 192.0.2.5.', source_name='Lab', tlp='GREEN')
        )
    response = rpc(client, mcp_headers, 'tools/call', name='search_reports', arguments={'q': 'Sample'})
    result = response.json()['result']
    assert json.loads(result['content'][0]['text']) == result['structuredContent']
    assert result['structuredContent']['reports'][0]['id'] == report.id
    assert response.headers['cache-control'] == 'no-store'


def test_summary_result_has_matching_structured_text(
    app: FastAPI,
    client: TestClient,
    mcp_headers: dict[str, str],
) -> None:
    with app.state.session_factory.begin() as db:
        report, _ = services.ingest(
            db, DocumentInput(title='Sample', body='Observed 192.0.2.5.', source_name='Lab', tlp='GREEN')
        )
    response = rpc(client, mcp_headers, 'tools/call', name='get_report_summary', arguments={'id': report.id})
    result = response.json()['result']
    assert json.loads(result['content'][0]['text']) == result['structuredContent']
    assert result['structuredContent']['id'] == report.id
    assert response.headers['cache-control'] == 'no-store'

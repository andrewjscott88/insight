"""A working workspace session must not become an MCP credential."""

from types import SimpleNamespace

from nicegui.testing.user import User


async def test_workspace_session_cannot_call_mcp(user: User, ui_env: SimpleNamespace) -> None:
    await user.should_see('Insight')
    response = await ui_env.client.post(
        '/mcp',
        headers={'Accept': 'application/json, text/event-stream'},
        json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'},
    )
    assert response.status_code == 401
    assert (await ui_env.client.get('/api/stats')).status_code == 200

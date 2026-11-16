"""In-process NiceGUI user simulation against the *real* application stack.

NiceGUI's stock ``user`` fixture talks to NiceGUI's inner app and would bypass Insight's session/CSRF/Boundary
middleware, so this fixture builds the full app, signs in through the real login form, and then hands the
authenticated HTTP client to ``nicegui.testing.User``.
"""

from __future__ import annotations

import re
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from nicegui.testing.general import nicegui_reset_globals
from nicegui.testing.user import User

from insight.config import Settings

PASSWORD = 'correct-password'


@pytest.fixture
async def ui_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, database_url: str
) -> AsyncIterator[SimpleNamespace]:
    monkeypatch.setenv('NICEGUI_STORAGE_PATH', str(tmp_path / '.nicegui'))
    # nicegui_reset_globals() evicts the page-defining modules from sys.modules on exit; restore them so
    # later tests keep using the same module objects (and therefore the same monkeypatch targets).
    saved = {name: mod for name, mod in sys.modules.items() if name.partition('.')[0] == 'insight'}
    try:
        with nicegui_reset_globals():
            from insight.main import create_app  # Must be imported after the reset.

            settings = Settings(database_url=database_url, password=PASSWORD, session_secret='s' * 48)
            app: FastAPI = create_app(settings)
            async with (
                app.router.lifespan_context(app),
                httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='http://localhost') as client,
            ):
                yield SimpleNamespace(app=app, client=client)
    finally:
        sys.modules.update(saved)


async def sign_in(client: httpx.AsyncClient) -> None:
    page = await client.get('/login')
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match
    response = await client.post('/login', data={'csrf_token': match.group(1), 'password': PASSWORD})
    assert response.status_code == 303


@pytest.fixture
async def user(ui_env: SimpleNamespace) -> User:
    await sign_in(ui_env.client)
    simulated = User(ui_env.client)
    await simulated.open('/')
    return simulated

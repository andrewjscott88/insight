"""Fresh-process boot of the full app (API + NiceGUI) over HTTP.

Runs in a subprocess because NiceGUI keeps process-global state; this is the closest check to
``insight serve`` without opening a port. It does not replace real-browser visual testing.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.slow, pytest.mark.ui]

SCRIPT = """
import re, sys
from fastapi.testclient import TestClient
from insight.config import Settings
from insight.main import create_app

open_access = sys.argv[2] == "on"
settings = Settings(
    database_url="sqlite:///" + sys.argv[1], password="correct-password", session_secret="s" * 48,
    dev_no_auth=open_access,
)
app = create_app(settings)
with TestClient(app) as client:
    assert client.get("/", follow_redirects=False).status_code == 303
    if open_access:
        entry = client.get("/")
        assert entry.status_code == 200 and "Continue to workspace" in entry.text
        # A browser continues after its 200 entry page commits and confirms the session.
        response = client.get("/")
    else:
        token = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login").text).group(1)
        response = client.post("/login", data={"csrf_token": token, "password": "correct-password"})
    assert response.status_code == 200, response.status_code
    assert "Threat landscape" in response.text and "Threat intelligence workbench" in response.text
    assert ("Temporary open access" in response.text) is open_access
    assert ("End session" in response.text) is open_access
    assert '<html lang="en-US"' in response.text, "regression: no page language (WCAG 3.1.1)"
    logout = client.get("/logout")
    assert logout.status_code == 200
    assert ("returning to Insight starts a new one" in logout.text) is open_access
    assert client.get("/static/app.css").status_code == 200
    csrf = client.get("/api/session").json()["csrf_token"]
    assert client.post("/api/demo", headers={"X-CSRF-Token": csrf}).status_code == 200
    response = client.get("/")
    assert "Training scenario" in response.text and "Settings" in response.text
print("OK")
"""


@pytest.mark.parametrize('dev_no_auth', ['off', 'on'])
def test_full_app_boots_and_renders(tmp_path: Path, dev_no_auth: str) -> None:
    env = {**os.environ, 'NICEGUI_STORAGE_PATH': str(tmp_path / '.nicegui')}
    result = subprocess.run(  # fixed interpreter and script
        [sys.executable, '-c', SCRIPT, str(tmp_path / 'ui.db'), dev_no_auth],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip().endswith('OK')

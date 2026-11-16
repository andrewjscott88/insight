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

settings = Settings(
    database_url="sqlite:///" + sys.argv[1], password="correct-password", session_secret="s" * 48
)
app = create_app(settings)
with TestClient(app) as client:
    assert client.get("/", follow_redirects=False).status_code == 303
    token = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login").text).group(1)
    response = client.post("/login", data={"csrf_token": token, "password": "correct-password"})
    assert response.status_code == 200, response.status_code
    assert "Intelligence workspace" in response.text and "Source reporting" in response.text
    assert client.get("/static/app.css").status_code == 200
    csrf = client.get("/api/session").json()["csrf_token"]
    assert client.post("/api/demo", headers={"X-CSRF-Token": csrf}).status_code == 200
    response = client.get("/")
    assert "Training scenario" in response.text and "Sources" in response.text
print("OK")
"""


def test_full_app_boots_and_renders(tmp_path: Path) -> None:
    env = {**os.environ, 'NICEGUI_STORAGE_PATH': str(tmp_path / '.nicegui')}
    result = subprocess.run(  # fixed interpreter and script
        [sys.executable, '-c', SCRIPT, str(tmp_path / 'ui.db')],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip().endswith('OK')

"""Backup/restore drill (milestone gate): prove a backup taken from a *running* instance restores cleanly.

1. start ``insight serve`` on a fresh data directory, sign in, load the demo and write a note;
2. take an online backup with ``insight backup`` while it is still serving;
3. stop it, restore the backup into a new data directory and start a second instance;
4. sign in and verify the stats and the note survived.

    python scripts/backup_restore_drill.py [--insight PATH_TO_insight_EXECUTABLE]
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx

if __package__ in (None, ''):  # executed as `python scripts/backup_restore_drill.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts import smoke


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port: int = sock.getsockname()[1]
        return port


@contextmanager
def running(insight: str, data_dir: Path, env: dict[str, str]) -> Iterator[httpx.Client]:
    port = free_port()
    process = subprocess.Popen(
        [insight, 'serve', '--port', str(port)],
        env={**env, 'INSIGHT_DATA_DIR': str(data_dir), 'NICEGUI_STORAGE_PATH': str(data_dir / '.nicegui')},
        cwd=data_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        with httpx.Client(base_url=f'http://127.0.0.1:{port}', timeout=30, trust_env=False) as client:
            smoke.wait_until_healthy(client, timeout=90)
            yield client
    finally:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()


def drill(insight: str, workdir: Path) -> dict[str, Any]:
    password = secrets.token_urlsafe(18)
    env = {**os.environ, 'INSIGHT_PASSWORD': password, 'INSIGHT_SESSION_SECRET': secrets.token_urlsafe(48)}
    env.pop('INSIGHT_DATABASE_URL', None)
    original, restored = workdir / 'original', workdir / 'restored'
    original.mkdir()
    restored.mkdir()
    backup_file = workdir / 'insight-backup.db'

    with running(insight, original, env) as client:
        before = smoke.run(client, password)
        token = client.get('/api/session').json()['csrf_token']
        doc_id = client.get('/api/documents').json()[0]['id']
        note = client.post(
            f'/api/documents/{doc_id}/notes', json={'body': 'drill note'}, headers={'X-CSRF-Token': token}
        )
        smoke.check(note.status_code == 200, f'writing a note failed: {note.status_code}')
        result = subprocess.run(
            [insight, 'backup', str(backup_file)],
            env={**env, 'INSIGHT_DATA_DIR': str(original)},
            capture_output=True,
            text=True,
            check=False,
        )
        smoke.check(result.returncode == 0, f'insight backup failed: {result.stderr}')

    shutil.copyfile(backup_file, restored / 'insight.db')
    with running(insight, restored, env) as client:
        smoke.sign_in(client, password)
        after: dict[str, Any] = client.get('/api/stats').json()
        notes = client.get(f'/api/documents/{doc_id}').json()['notes']
    smoke.check(after == before, f'stats differ after restore: {before} != {after}')
    smoke.check([n['body'] for n in notes] == ['drill note'], f'note missing after restore: {notes}')
    return after


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--insight', default=shutil.which('insight') or 'insight')
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as tmp:
        try:
            stats = drill(args.insight, Path(tmp))
        except smoke.SmokeFailure as exc:
            print(f'DRILL FAILED: {exc}', file=sys.stderr)
            return 1
    print(f'Backup/restore drill passed: {stats}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

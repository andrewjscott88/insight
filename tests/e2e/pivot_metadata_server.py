"""Isolated browser fixture: synthetic host settings and metadata; no provider traffic."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import uvicorn
from sqlalchemy import select


def serve(port: int, folder: Path, provider: str) -> None:
    os.environ['INSIGHT_DATA_DIR'] = str(folder)
    os.environ['NICEGUI_STORAGE_PATH'] = str(folder / '.nicegui')
    os.environ['INSIGHT_CIRCL_PDNS_USER'] = 'synthetic-user'
    os.environ['INSIGHT_CIRCL_PDNS_PASSWORD'] = 'synthetic-password'
    from insight import pivots, services
    from insight.config import Settings
    from insight.main import create_app
    from insight.models import Observation
    from insight.schemas import DocumentInput

    selected_provider = provider

    async def offline(provider: str, value: str) -> dict[str, Any]:
        assert provider == selected_provider
        name = 'node-' + 'a' * 55 + '.' + 'b' * 55 + '.example.com'
        if provider == 'crtsh':
            records = [
                {
                    'name': name,
                    'issuer': 'x' * 1024,
                    'not_before': '2025-01-01T00:00:00+00:00',
                    'not_after': '2027-01-01T00:00:00+00:00',
                }
            ]
            return {'found': True, 'certificates': records, 'nodes': []}
        assert provider == 'circl'
        return {
            'found': True,
            'records': [
                {
                    'name': value,
                    'type': 'TXT',
                    'answer': 'x' * 2048,
                    'first_seen': '2025-01-01T00:00:00+00:00',
                    'last_seen': '2026-01-01T00:00:00+00:00',
                    'count': None,
                }
            ],
            'nodes': [],
        }

    pivots._fetch = offline
    app = create_app(
        Settings(
            database_url=f'sqlite:///{folder / "synthetic.db"}',
            password='synthetic-password-only',
            session_secret='synthetic-secret-' * 4,
            allowed_hosts=('127.0.0.1', 'localhost'),
            run_jobs=False,
        )
    )
    with app.state.session_factory.begin() as db:
        document, _ = services.ingest(
            db,
            DocumentInput(
                title='Synthetic provider metadata',
                source_name='Browser fixture',
                body='Synthetic reviewed indicator: example.com.',
                tlp='CLEAR',
            ),
        )
        for observation in db.scalars(select(Observation).where(Observation.document_id == document.id)):
            services.set_observation_status(db, observation.id, 'accepted')
        services.set_pivot_switch(db, provider, True)
    uvicorn.run(app, host='127.0.0.1', port=port, log_level='warning')


if __name__ == '__main__':
    serve(int(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])

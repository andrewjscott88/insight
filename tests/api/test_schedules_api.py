"""Schedules and jobs over the API: anyone signed in may read them; only a browser session may change them."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from insight import services
from insight.connectors import SOURCES
from insight.models import AuditEvent


def key_headers(app: FastAPI, access: str = 'read-write') -> dict[str, str]:
    with app.state.session_factory.begin() as db:
        _, token = services.create_api_key(db, name='script', access=access)
    return {'Authorization': f'Bearer {token}'}


def test_every_source_starts_unscheduled(authed: TestClient) -> None:
    listed = authed.get('/api/schedules').json()
    assert [s['source_key'] for s in listed] == list(SOURCES)
    assert all(s['interval_minutes'] == 0 and s['next_run_at'] is None for s in listed)


def test_the_operator_turns_a_schedule_on_and_off(app: FastAPI, authed: TestClient) -> None:
    response = authed.put('/api/schedules/cisa-kev', json={'interval_minutes': 360})
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    assert (body['source_key'], body['interval_minutes']) == ('cisa-kev', 360)
    assert body['next_run_at'] <= datetime.now(UTC).isoformat()  # runs at the next tick
    listed = {s['source_key']: s['interval_minutes'] for s in authed.get('/api/schedules').json()}
    assert listed == {'cisa-kev': 360, 'cisa-csaf': 0, 'sans-isc': 0, 'ncsc': 0}
    assert authed.put('/api/schedules/cisa-kev', json={'interval_minutes': 0}).json()['interval_minutes'] == 0
    with app.state.session_factory() as db:
        events = db.scalars(select(AuditEvent).where(AuditEvent.action == 'schedule.update')).all()
        assert [(e.object_id, e.detail, e.actor) for e in events] == [
            ('cisa-kev', 'every 360 minutes', 'operator'),
            ('cisa-kev', 'off', 'operator'),
        ]


@pytest.mark.parametrize(
    ('path', 'body', 'status'),
    [
        ('/api/schedules/nope', {'interval_minutes': 60}, 404),
        ('/api/schedules/ncsc', {'interval_minutes': 30}, 422),
        ('/api/schedules/ncsc', {'interval_minutes': 'daily'}, 422),
        ('/api/schedules/ncsc', {}, 422),
    ],
)
def test_bad_schedule_changes_are_refused(
    authed: TestClient, path: str, body: dict[str, Any], status: int
) -> None:
    assert authed.put(path, json=body).status_code == status


def test_api_keys_may_read_schedules_but_never_change_them(app: FastAPI, client: TestClient) -> None:
    headers = key_headers(app)
    assert client.get('/api/schedules', headers=headers).status_code == 200
    assert client.get('/api/jobs', headers=headers).status_code == 200
    response = client.put('/api/schedules/ncsc', headers=headers, json={'interval_minutes': 60})
    assert response.status_code == 403
    assert 'workspace' in response.json()['detail']
    assert all(s['interval_minutes'] == 0 for s in client.get('/api/schedules', headers=headers).json())


def test_a_session_without_its_csrf_token_cannot_change_a_schedule(authed: TestClient) -> None:
    response = authed.put(
        '/api/schedules/ncsc', json={'interval_minutes': 60}, headers={'X-CSRF-Token': 'wrong'}
    )
    assert response.status_code == 403


def test_jobs_list_the_newest_first(app: FastAPI, authed: TestClient) -> None:
    with app.state.session_factory.begin() as db:
        services.enqueue_job(
            db, services.SOURCE_SYNC, 'ncsc', at=datetime(2026, 11, 20, tzinfo=UTC), actor='schedule'
        )
    (job,) = authed.get('/api/jobs', params={'limit': 5}).json()
    assert {k: job[k] for k in ('kind', 'key', 'status', 'attempts', 'actor')} == {
        'kind': 'source.sync', 'key': 'ncsc', 'status': 'queued', 'attempts': 0, 'actor': 'schedule'
    }  # fmt: skip
    assert authed.get('/api/jobs', params={'limit': 0}).status_code == 422

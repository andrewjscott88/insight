"""Timeline routes retain normal authentication, CSRF, write access and TLP boundaries."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI
from fastapi.testclient import TestClient

from insight import services
from insight.schemas import ActorCampaignInput, CampaignInput

from .test_threat_guides_api import key


def test_explicit_campaign_api_and_green_key_hidden_world(app: FastAPI, client: TestClient) -> None:
    writer = key(app)
    with app.state.session_factory.begin() as db:
        visible = services.create_campaign(db, CampaignInput(name='Visible series', tlp='GREEN'))
        hidden = services.create_campaign(db, CampaignInput(name='HIDDEN SERIES', tlp='AMBER'))
        visible_id, hidden_id = visible.id, hidden.id
        services.link_actor_campaign(db, 'G0016', ActorCampaignInput(campaign_id=hidden_id))
    path = '/api/actors/G0016/campaigns'
    assert (
        client.post(path, headers=writer, json={'campaign_id': visible_id, 'unexpected': 1}).status_code
        == 422
    )
    added = client.post(path, headers=writer, json={'campaign_id': visible_id})
    assert added.status_code == 201
    with app.state.session_factory.begin() as db:
        services.revoke_api_key(db)
    reader = key(app, access='read', max_tlp='GREEN')
    assert client.post(path, headers=reader, json={'campaign_id': visible_id}).status_code == 403
    for route in (
        path,
        '/api/actors/G0016/timeline',
        '/api/actors/G0016/guide',
        '/api/actors/G0016/guide?format=md',
        '/api/software/S0154/navigator',
    ):
        response = client.get(route, headers=reader)
        assert response.status_code == 200, response.text
        assert 'HIDDEN SERIES' not in response.text
        assert hidden_id not in response.text
    assert client.delete(f'{path}/{hidden_id}', headers=reader).status_code == 403
    for query in ('limit=0', 'limit=201', 'days=0', 'days=36501'):
        assert client.get(f'/api/actors/G0016/timeline?{query}', headers=reader).status_code == 422
    assert client.get('/api/actors/missing/timeline', headers=reader).status_code == 404
    assert client.get('/api/software/missing/navigator', headers=reader).status_code == 404
    with app.state.session_factory.begin() as db:
        services.revoke_api_key(db)
    limited_writer = key(app, max_tlp='GREEN')
    assert client.delete(f'{path}/{hidden_id}', headers=limited_writer).status_code == 404
    assert client.delete(f'{path}/{visible_id}', headers=limited_writer).status_code == 200


def test_browser_campaign_write_requires_csrf(client: TestClient, login: Callable[..., str]) -> None:
    login(client)
    response = client.post(
        '/api/actors/G0016/campaigns',
        headers={'X-CSRF-Token': 'wrong'},
        json={'campaign_id': '00000000-0000-0000-0000-000000000000'},
    )
    assert response.status_code == 403

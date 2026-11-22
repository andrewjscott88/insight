"""Exchange only eligible MISP attribute data, with labels, receipt checks and a bounded pinned transport."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import jsonschema
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import egress, services
from insight.cli import main
from insight.misp_export import export_misp_event
from insight.misp_import import import_misp_event, parse_misp_event
from insight.misp_remote import exchange
from insight.models import Document, Observation
from insight.schemas import TLP, DocumentInput

EVENT_UUID = '2b250e5d-0524-48e9-b195-bfb0cfbecdd9'


def report(
    db: Session, body: str, tlp: TLP = 'GREEN', source: str | None = None, review: str = 'accepted'
) -> Document:
    ref = services.SourceRef(source, 'test-report') if source else None
    doc, _ = services.ingest(
        db, DocumentInput(title='Fixture', body=body, source_name='Local fixture', tlp=tlp), ref=ref
    )
    for observation in db.scalars(select(Observation).where(Observation.document_id == doc.id)):
        observation.review_status = review
    db.flush()
    return doc


def test_review_privacy_and_tlp_narrow_the_event_before_serialization(db: Session) -> None:
    report(db, 'Reviewed 192.0.2.0/24. Contact person@example.org.')
    report(db, 'https://example.org/link?contact=person%40example.org')
    report(db, 'Unreviewed 198.51.100.42', review='unreviewed')
    report(db, 'Rejected 198.51.100.43', review='rejected')
    report(db, 'Restricted 198.51.100.44', tlp='RED')
    event = export_misp_event(db, max_tlp='GREEN')['Event']
    attrs = event['Attribute']
    assert [a['value'] for a in attrs] == ['192.0.2.0/24', 'example.org']
    assert 'person' not in json.dumps(event)
    assert all(
        a['value'] != '198.51.100.44' for a in export_misp_event(db, max_tlp='RED')['Event']['Attribute']
    )
    assert event['published'] is False
    assert event['distribution'] == '1'
    assert event['Tag'] == [{'name': 'tlp:green'}]
    assert all(not a['to_ids'] and a['distribution'] == '5' and 'comment' not in a for a in attrs)
    all_items = export_misp_event(db, max_tlp='AMBER', include_unreviewed=True, include_personal_data=True)
    by_value = {a['value']: a for a in all_items['Event']['Attribute']}
    assert by_value['192.0.2.0/24']['type'] == 'ip-dst'
    assert by_value['person@example.org']['type'] == 'email-dst'
    assert {'name': 'insight:personal-data'} in by_value['person@example.org']['Tag']
    assert '198.51.100.42' in by_value
    assert '198.51.100.43' not in by_value
    assert '198.51.100.44' not in by_value


def test_only_reusable_evidence_can_leave_and_snapshot_ids_are_stable(db: Session) -> None:
    first = report(db, 'PUBLISHER SECRET 203.0.113.8', source='urlhaus')
    second = report(db, 'Local wording 192.0.2.2', tlp='CLEAR')
    report(db, 'Contact person@example.org about CVE-2026-5678')
    result = export_misp_event(db, max_tlp='GREEN', include_evidence=True)
    attrs = {a['value']: a for a in result['Event']['Attribute']}
    assert 'comment' not in attrs['203.0.113.8']
    assert 'comment' not in attrs['CVE-2026-5678']
    assert attrs['192.0.2.2']['comment'] == 'Local wording 192[.]0[.]2[.]2'
    assert 'PUBLISHER SECRET' not in json.dumps(result)
    assert result == export_misp_event(db, max_tlp='GREEN', include_evidence=True)
    assert export_misp_event(db, max_tlp='GREEN', document_ids=[first.id]) != result
    filtered = export_misp_event(db, max_tlp='CLEAR', document_ids=[second.id])
    assert filtered['Event']['distribution'] == '3'
    assert str(UUID(result['Event']['uuid'])) == result['Event']['uuid']
    assert len({a['uuid'] for a in attrs.values()}) == len(attrs)
    event_uuid, imported, mentions = parse_misp_event(json.dumps(result).encode())
    assert event_uuid == result['Event']['uuid']
    assert imported.tlp == 'GREEN'
    assert {m.value for m in mentions} == set(attrs)


def test_wire_types_and_categories_cover_all_ten_kinds(db: Session) -> None:
    body = '\n'.join(
        [
            'CVE-2026-1234',
            '198.51.100.14',
            '2001:db8:42::/48',
            'misp.example.org',
            'https://wire.example.test/path',
            'analyst@example.org',
            *('a' * n for n in (32, 40, 64, 128)),
        ]
    )
    report(db, body, tlp='AMBER+STRICT')
    event = export_misp_event(db, max_tlp='AMBER+STRICT', include_personal_data=True)
    schema = json.loads((Path(__file__).parents[1] / 'fixtures/misp/schema-lax.json').read_text())
    jsonschema.Draft4Validator(schema).validate(event)
    pairs = {(a['type'], a['category']) for a in event['Event']['Attribute']}
    assert pairs == {
        ('ip-dst', 'Network activity'),
        ('domain', 'Network activity'),
        ('email-dst', 'Network activity'),
        ('url', 'Network activity'),
        ('vulnerability', 'External analysis'),
        *((kind, 'Payload delivery') for kind in ('md5', 'sha1', 'sha256', 'sha512')),
    }
    assert event['Event']['distribution'] == '0'
    imported, created = import_misp_event(db, json.dumps(event).encode(), max_tlp='AMBER+STRICT')
    assert created
    assert imported.tlp == 'AMBER+STRICT'
    assert all(o['review_status'] == 'unreviewed' for o in services.detail(db, imported)['observations'])


def test_file_cli_preserves_existing_files_and_requires_both_red_gates(
    database_url: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv('INSIGHT_DATABASE_URL', database_url)
    monkeypatch.setenv('INSIGHT_MAX_TLP', 'AMBER+STRICT')
    imported = tmp_path / 'red-event.json'
    imported.write_text(
        json.dumps(
            {
                'Event': {
                    'uuid': EVENT_UUID,
                    'info': 'Red training fixture',
                    'distribution': '0',
                    'Tag': [{'name': 'tlp:red'}],
                    'Attribute': [{'type': 'domain', 'value': 'red.example.org'}],
                }
            }
        )
    )
    assert main(['misp-import', str(imported), '--allow-red']) == 1
    monkeypatch.setenv('INSIGHT_MAX_TLP', 'RED')
    assert main(['misp-import', str(imported)]) == 1
    assert main(['misp-import', str(imported), '--allow-red']) == 0
    assert main(['misp-import', str(imported), '--allow-red']) == 0
    assert 'Already imported' in capsys.readouterr().out
    dest = str(tmp_path / 'share.json')
    assert main(['misp-export', dest, '--allow-red']) == 1  # unreviewed
    assert main(['misp-export', dest, '--include-unreviewed']) == 1
    assert not Path(dest).exists()
    cmd = ['misp-export', dest, '--allow-red', '--include-unreviewed']
    assert main(cmd) == 0
    original = Path(dest).read_bytes()
    assert json.loads(original)['Event']['Tag'] == [{'name': 'tlp:red'}]
    assert Path(dest).stat().st_mode & 0o777 == 0o600
    assert main(cmd) == 1
    assert Path(dest).read_bytes() == original


@pytest.mark.parametrize(
    'base',
    [
        'http://misp.example',
        'https://user@x.example',
        'https://x.example/a/../b',
        'https://x.example/%2F',
        'https://x.example/?key=secret',
        'https://x.example:9876',
    ],
)
async def test_unsafe_misp_config_fails_before_contact(base: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('INSIGHT_MISP_URL', base)
    with pytest.raises(ValueError, match='INSIGHT_MISP_URL'):
        await exchange(event_uuid=EVENT_UUID)


async def test_pinned_read_create_and_refusal_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('INSIGHT_MISP_URL', 'https://misp.example/instance/')
    monkeypatch.setenv('INSIGHT_MISP_KEY', 'fixture-secret')
    destinations: list[egress.IPAddress] = [ipaddress.ip_address('8.8.8.8')]

    async def resolve(host: str, port: int) -> list[egress.IPAddress]:
        assert (host, port) == ('misp.example', 443)
        return destinations

    monkeypatch.setattr(egress, 'resolve', resolve)
    requests = []
    response: dict[str, Any] = {'Event': {'uuid': EVENT_UUID}}
    status = 200

    def handler(req: httpx.Request) -> httpx.Response:
        requests.append(req)
        assert req.url.host == '8.8.8.8'
        assert req.headers['Host'] == 'misp.example'
        assert req.extensions['sni_hostname'] == 'misp.example'
        assert req.headers['Authorization'] == 'fixture-secret'
        assert 'fixture-secret' not in str(req.url)
        return httpx.Response(status, json=response, headers={'Location': 'https://elsewhere.example'})

    transport = httpx.MockTransport(handler)
    assert json.loads(await exchange(event_uuid=EVENT_UUID, transport=transport)) == response
    payload = json.dumps(response).encode()
    await exchange(event_uuid=EVENT_UUID, body=payload, transport=transport)
    assert [(r.method, r.url.path) for r in requests] == [
        ('GET', f'/instance/events/view/{EVENT_UUID}'),
        ('POST', '/instance/events/add'),
    ]
    assert requests[-1].content == payload
    response.clear()
    with pytest.raises(ValueError, match='confirm'):
        await exchange(event_uuid=EVENT_UUID, body=payload, transport=transport)
    status = 302
    with pytest.raises(ValueError, match='redirect'):
        await exchange(event_uuid=EVENT_UUID, transport=transport)
    status = 403
    with pytest.raises(ValueError, match='HTTP 403'):
        await exchange(event_uuid=EVENT_UUID, transport=transport)
    destinations.append(ipaddress.ip_address('127.0.0.1'))
    before = len(requests)
    with pytest.raises(ValueError, match='INSIGHT_MISP_PRIVATE_NETWORK=on'):
        await exchange(event_uuid=EVENT_UUID, transport=transport)
    assert len(requests) == before


@pytest.mark.parametrize(
    ('setting', 'address', 'outcome'),
    [
        ('', '10.20.0.5', 'INSIGHT_MISP_PRIVATE_NETWORK=on'),  # off by default
        ('off', '192.168.1.20', 'INSIGHT_MISP_PRIVATE_NETWORK=on'),
        ('on', '10.20.0.5', None),
        ('on', '192.168.1.20', None),
        ('on', 'fd12:3456::20', None),
        ('ON', '::ffff:10.20.0.5', None),  # judged by the IPv4 address it reaches
        ('on', '127.0.0.1', 'never connects'),  # loopback stays blocked
        ('on', '::ffff:127.0.0.1', 'never connects'),
        ('on', '169.254.169.254', 'never connects'),  # cloud metadata
        ('on', '224.0.0.1', 'never connects'),
    ],
)
async def test_a_misp_instance_on_a_private_network_is_an_explicit_opt_in(
    monkeypatch: pytest.MonkeyPatch, setting: str, address: str, outcome: str | None
) -> None:
    monkeypatch.setenv('INSIGHT_MISP_URL', 'https://misp.internal.example/')
    monkeypatch.setenv('INSIGHT_MISP_KEY', 'fixture-secret')
    monkeypatch.setenv('INSIGHT_MISP_PRIVATE_NETWORK', setting)

    async def resolve(host: str, port: int) -> list[egress.IPAddress]:
        return [ipaddress.ip_address(address)]

    monkeypatch.setattr(egress, 'resolve', resolve)
    sent: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        sent.append(req)
        assert req.headers['Host'] == 'misp.internal.example'
        assert req.extensions['sni_hostname'] == 'misp.internal.example'
        return httpx.Response(200, json={'Event': {'uuid': EVENT_UUID}})

    transport = httpx.MockTransport(handler)
    if outcome is None:
        await exchange(event_uuid=EVENT_UUID, transport=transport)
        assert len(sent) == 1
    else:
        with pytest.raises(ValueError, match=outcome):
            await exchange(event_uuid=EVENT_UUID, transport=transport)
        assert sent == []


async def test_the_private_network_setting_must_be_on_or_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('INSIGHT_MISP_URL', 'https://misp.internal.example/')
    monkeypatch.setenv('INSIGHT_MISP_KEY', 'fixture-secret')
    monkeypatch.setenv('INSIGHT_MISP_PRIVATE_NETWORK', 'yes')
    with pytest.raises(ValueError, match='must be "on" or "off"'):
        await exchange(event_uuid=EVENT_UUID)


def test_remote_cli_checks_the_fetched_uuid_and_audits_a_confirmed_push(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from insight import cli_misp
    from insight.models import database

    monkeypatch.setenv('INSIGHT_DATABASE_URL', database_url)
    other_uuid = '5d5e70ac-bc34-437a-ab01-deee6a22dd5e'
    incoming = {
        'Event': {
            'uuid': other_uuid,
            'info': 'Inbox fixture',
            'distribution': '1',
            'Tag': [{'name': 'tlp:green'}],
            'Attribute': [{'type': 'domain', 'value': 'test.example'}],
        }
    }
    pushed = []

    async def simulated(*, event_uuid: str, body: bytes | None = None) -> bytes:
        if body is None:
            assert event_uuid == EVENT_UUID
            return json.dumps(incoming).encode()
        event = json.loads(body)['Event']
        assert event['uuid'] == event_uuid
        pushed.append(event)
        return b'{}'

    monkeypatch.setattr(cli_misp, 'exchange', simulated)
    assert main(['misp-import', '--fetch', EVENT_UUID]) == 1
    assert 'UUID' in capsys.readouterr().err
    incoming['Event']['uuid'] = EVENT_UUID
    assert main(['misp-import', '--fetch', EVENT_UUID]) == 0
    assert main(['misp-export', '--push', '--include-unreviewed', '--max-tlp', 'GREEN']) == 0
    assert len(pushed) == 1
    assert pushed[0]['published'] is False
    assert pushed[0]['Attribute'][0]['value'] == 'test.example'
    engine, sessions = database(database_url, migrate=False)
    try:
        with sessions() as db:
            assert [d.external_id for d in db.scalars(select(Document))] == [EVENT_UUID]
            assert any(
                entry.action == 'misp.push' and entry.object_id == pushed[0]['uuid'] and entry.actor == 'cli'
                for entry in services.audit_events(db)
            )
    finally:
        engine.dispose()

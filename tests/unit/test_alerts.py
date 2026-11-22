"""Alerts: targets, when alerts fire, what they say under each TLP label, and how they are sent (ADR 0022)."""

from __future__ import annotations

import hashlib
import hmac
import json
import smtplib
import socket
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import alerts, connectors, jobs, services
from insight.config import AlertSettings
from insight.demo import seed
from insight.models import Alert, AlertTarget, AuditEvent, Job
from insight.schemas import DocumentInput
from insight.services import SourceRef, ingest

HOOK = 'https://hooks.example.org/services/T0/B0/secret-token'


def report(db: Session, title: str, body: str, *, tlp: str = 'GREEN', ref: SourceRef | None = None) -> str:
    doc, _ = ingest(db, DocumentInput(title=title, body=body, source_name='Feed', tlp=tlp), ref=ref)
    return doc.id


def target(db: Session, style: str = 'chat', *, max_tlp: str = 'AMBER', address: str = HOOK) -> AlertTarget:
    return services.add_target(db, name=f'{style} target', style=style, address=address, max_tlp=max_tlp)


def queued(db: Session) -> list[tuple[str, str, str]]:
    return sorted((a.trigger, a.subject, a.status) for a in db.scalars(select(Alert)))


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every host resolves to the addresses in the list (a public one by default)."""
    addresses = ['93.184.216.34']

    def fake(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (a, port)) for a in addresses]

    monkeypatch.setattr(socket, 'getaddrinfo', fake)
    return addresses


# --------------------------------------------------------------------------- targets


@pytest.mark.parametrize(
    ('style', 'address', 'message'),
    [
        ('chat', 'http://hooks.example.org/x', 'starts with https://'),
        ('json', 'https://user:pw@hooks.example.org/x', 'no user name or password'),
        ('email', 'soc@example', 'one e-mail address'),
        ('email', 'a@example.org, b@example.org', 'one e-mail address'),
        ('email', 'a@example.org\nBcc: x@example.org', 'one e-mail address'),
        ('sms', '+15550100', 'webhook or an e-mail'),
    ],
)
def test_bad_addresses_are_refused(db: Session, style: str, address: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        services.add_target(db, name='x', style=style, address=address)


def test_targets_are_checked_and_audited_without_their_address(db: Session) -> None:
    with pytest.raises(ValueError, match='up to TLP:AMBER\\+STRICT'):
        target(db, max_tlp='RED')
    with pytest.raises(ValueError, match='name of up to 80'):
        services.add_target(db, name=' ', style='chat', address=HOOK)
    chat, signed = target(db, 'chat'), target(db, 'json')
    assert (chat.kind, chat.secret) == ('webhook', '')
    assert len(signed.secret) == 64
    events = db.scalars(select(AuditEvent).where(AuditEvent.action == 'alert.target.add')).all()
    assert [e.detail for e in events] == ['chat: chat target', 'json: json target']
    assert all('secret-token' not in (e.detail or '') for e in events)
    services.set_target_enabled(db, chat.id, False)
    services.delete_target(db, signed.id)
    assert [t.id for t in services.list_targets(db)] == [chat.id]
    with pytest.raises(LookupError):
        services.delete_target(db, signed.id)


# --------------------------------------------------------------------------- firing


def test_a_new_report_naming_a_watch_term_fires_once_per_target(db: Session) -> None:
    services.add_watch_term(db, 'Acme VPN')
    services.add_watch_term(db, 'Globex')
    target(db)
    off = target(db, 'json')
    services.set_target_enabled(db, off.id, False)
    report(db, 'Unrelated', 'Nothing here.')
    report(db, 'Edge devices', 'Attackers exploit ACME vpn gateways.')
    assert queued(db) == [('watch', 'Acme VPN', 'pending')]  # the switched-off target gets nothing
    report(db, 'Edge devices', 'Attackers exploit ACME vpn gateways.')  # the same report again
    assert len(queued(db)) == 1


def test_revisions_of_the_same_item_do_not_fire_again(db: Session) -> None:
    services.add_watch_term(db, 'Acme')
    target(db)
    ref = SourceRef('sans-isc', 'diary-1')
    report(db, 'Diary', 'Acme scanning.', ref=ref)
    report(db, 'Diary', 'Acme scanning, updated.', ref=ref)
    assert len(queued(db)) == 1
    services.add_watch_term(db, 'Globex')
    report(db, 'Diary', 'Acme scanning, now also Globex.', ref=ref)
    assert [s for _, s, _ in queued(db)] == ['Acme', 'Globex']


def test_only_title_and_text_count_not_the_source_name(db: Session) -> None:
    services.add_watch_term(db, 'Feed')
    target(db)
    report(db, 'A report', 'No match in the words.')
    assert queued(db) == []


def test_nothing_fires_without_targets_or_for_the_demo(db: Session) -> None:
    services.add_watch_term(db, 'appliance')
    report(db, 'Appliance', 'An appliance.')
    assert queued(db) == []
    target(db)
    assert seed(db) > 0
    assert queued(db) == []


def test_new_kev_entries_fire_after_the_first_import(db: Session) -> None:
    def catalog(*cves: str) -> bytes:
        rows = [
            {
                'cveID': cve,
                'vendorProject': 'Acme',
                'product': 'Gateway',
                'vulnerabilityName': 'Acme Gateway flaw',
                'dateAdded': '2026-11-20',
                'shortDescription': 'A flaw.',
                'requiredAction': 'Apply updates.',
                'dueDate': '2026-12-11',
                'knownRansomwareCampaignUse': 'Unknown',
                'notes': '',
            }
            for cve in cves
        ]
        return json.dumps({'catalogVersion': '2026.11.20', 'vulnerabilities': rows}).encode()

    target(db)
    connectors.import_kev(db, catalog('CVE-2026-0001', 'CVE-2026-0002'))
    assert queued(db) == []  # the first import is the whole catalog, not news
    connectors.import_kev(db, catalog('CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003'))
    assert queued(db) == [('kev', 'CVE-2026-0003 · Acme Gateway', 'pending')]
    many = [f'CVE-2026-1{i:03d}' for i in range(12)]
    connectors.import_kev(db, catalog('CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003', *many))
    batch = [s for t, s, _ in queued(db) if s.startswith('12 new')]
    assert batch == [
        '12 new entries: CVE-2026-1000, CVE-2026-1001, CVE-2026-1002, CVE-2026-1003, CVE-2026-1004 and 7 more'
    ]


# --------------------------------------------------------------------------- what alerts say


def due(db: Session) -> list[services.DueAlert]:
    return services.due_alerts(db, at=datetime.now(UTC) + timedelta(seconds=1))


@pytest.mark.parametrize(
    ('report_tlp', 'max_tlp', 'hidden'),
    [
        ('GREEN', 'AMBER', False),
        ('AMBER', 'AMBER', False),
        ('AMBER', 'GREEN', True),
        ('AMBER+STRICT', 'AMBER', True),
        ('RED', 'AMBER+STRICT', True),
        ('CLEAR', 'CLEAR', False),
    ],
)
def test_titles_above_the_targets_limit_are_withheld(
    db: Session, report_tlp: str, max_tlp: str, hidden: bool
) -> None:
    services.add_watch_term(db, 'Acme')
    target(db, max_tlp=max_tlp)
    report(db, 'Secret Acme campaign', 'Acme was hit.', tlp=report_tlp)
    (alert,) = due(db)
    message = alerts.compose(alert, public_url='https://insight.example.org')
    text = '\n'.join(message.lines)
    assert message.lines[0] == f'TLP:{report_tlp}'
    assert message.tlp == report_tlp
    assert ('Secret Acme campaign' in text) is not hidden
    assert ('Secret Acme campaign' in json.dumps(message.payload)) is not hidden
    assert message.payload['report']['withheld'] is hidden
    assert f'https://insight.example.org/?report={alert.report.id}' in text  # type: ignore[union-attr]
    assert 'Acme was hit' not in text  # never the report's words


def test_kev_and_test_alerts(db: Session) -> None:
    tgt = target(db)
    services.queue_test_alert(db, tgt.id)
    services.queue_kev_alerts(db, [('CVE-2026-0003', 'Acme', 'Gateway')])
    kev, test = sorted(due(db), key=lambda a: a.trigger)
    kev_message = alerts.compose(kev, public_url='')
    assert (
        kev_message.subject == 'CISA added CVE-2026-0003 · Acme Gateway to its list of exploited weaknesses'
    )
    assert kev_message.lines[0] == 'TLP:CLEAR'
    assert kev_message.payload['link'] == alerts.KEV_PAGE
    assert alerts.compose(test, public_url='').subject == 'Test alert from Insight'


# --------------------------------------------------------------------------- sending


def capture(
    status: int = 200, headers: dict[str, str] | None = None
) -> tuple[httpx.MockTransport, list[httpx.Request]]:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(status, headers=headers)

    return httpx.MockTransport(handle), requests


async def test_json_webhooks_are_signed(
    session_factory: sessionmaker[Session], public_dns: list[str]
) -> None:
    with session_factory.begin() as db:
        services.add_watch_term(db, 'Acme')
        secret = target(db, 'json').secret
        report(db, 'Acme <b>&</b> friends', 'Acme.')
    transport, requests = capture()
    later = datetime.now(UTC) + timedelta(days=1)  # Alerts are queued at the real time, so count from it.
    summary = await alerts.deliver_due(
        session_factory, settings=AlertSettings(), transport=transport, clock=lambda: later
    )
    assert summary == 'Sent 1 alert(s); 0 failed.'
    (request,) = requests
    body = request.content
    expected = hmac.new(
        secret.encode(), request.headers['X-Insight-Timestamp'].encode() + b'.' + body, hashlib.sha256
    )
    assert request.headers['X-Insight-Signature'] == f'sha256={expected.hexdigest()}'
    payload = json.loads(body)
    assert (payload['format'], payload['trigger'], payload['subject']) == (
        'insight-alert-v1',
        'watch',
        'Acme',
    )
    assert payload['report']['title'] == 'Acme <b>&</b> friends'
    with session_factory() as db:
        (alert,) = db.scalars(select(Alert)).all()
        assert (alert.status, alert.attempts) == ('sent', 1)
        assert db.scalars(select(AlertTarget)).one().last_status == 'sent'


async def test_chat_webhooks_escape_report_text(
    session_factory: sessionmaker[Session], public_dns: list[str]
) -> None:
    with session_factory.begin() as db:
        services.add_watch_term(db, 'Acme')
        target(db, 'chat')
        report(db, 'Acme <!channel> & <https://evil.example|click>', 'Acme.')
    transport, requests = capture()
    await alerts.deliver_due(session_factory, settings=AlertSettings(), transport=transport)
    text = json.loads(requests[0].content)['text']
    assert 'Acme &lt;!channel&gt; &amp; &lt;https://evil.example|click&gt;' in text
    assert '<' not in text
    assert 'X-Insight-Signature' not in requests[0].headers


@pytest.mark.parametrize(
    ('addresses', 'allow', 'error'),
    [
        (['10.0.0.5'], False, 'is on a private network'),
        (['10.0.0.5'], True, ''),
        (['127.0.0.1'], False, 'is on a private network'),
        (['169.254.169.254'], True, 'never go to'),
        (['93.184.216.34', '192.168.1.2'], False, 'is on a private network'),
    ],
)
async def test_webhook_addresses_must_be_public_unless_allowed(
    public_dns: list[str], addresses: list[str], allow: bool, error: str
) -> None:
    public_dns[:] = addresses
    if error:
        with pytest.raises(alerts.AlertError, match=error):
            await alerts.check_address(HOOK, allow_private=allow)
    else:
        await alerts.check_address(HOOK, allow_private=allow)


async def test_failed_sends_are_retried_then_marked_failed(
    session_factory: sessionmaker[Session], public_dns: list[str]
) -> None:
    with session_factory.begin() as db:
        services.add_watch_term(db, 'Acme')
        target(db)
        report(db, 'Acme', 'Acme.')
    transport, _ = capture(500)
    start = datetime.now(UTC)  # Alerts are queued at the real time, so count from it.
    for attempt in range(1, 4):
        at = start + timedelta(days=1, hours=attempt)  # each retry is due by then

        def clock(at: datetime = at) -> datetime:
            return at

        summary = await alerts.deliver_due(
            session_factory, settings=AlertSettings(), transport=transport, clock=clock
        )
        assert summary == 'Sent 0 alert(s); 1 failed.'
        with session_factory() as db:
            alert = db.scalars(select(Alert)).one()
            assert alert.attempts == attempt
            assert alert.error == 'The webhook answered HTTP 500.'
    assert alert.status == 'failed'
    assert await alerts.deliver_due(session_factory, settings=AlertSettings(), transport=transport) == (
        'Sent 0 alert(s); 0 failed.'
    )


async def test_redirects_are_not_followed(
    session_factory: sessionmaker[Session], public_dns: list[str]
) -> None:
    with session_factory.begin() as db:
        alert_id = services.queue_test_alert(db, target(db).id).id
    transport, requests = capture(302, {'Location': 'http://169.254.169.254/'})
    await alerts.deliver_due(session_factory, ids=[alert_id], settings=AlertSettings(), transport=transport)
    assert len(requests) == 1
    with session_factory() as db:
        alert = db.get(Alert, alert_id)
        assert alert is not None
        assert (alert.status, alert.error) == (
            'failed',
            'The webhook answered with a redirect, which alerts do not follow.',
        )


class FakeSMTP:
    sent: ClassVar[list[Any]] = []
    calls: ClassVar[list[str]] = []

    def __init__(self, host: str, port: int, timeout: float = 0, **_: Any) -> None:
        self.calls.append(f'connect {host}:{port}')

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *args: object) -> None:
        self.calls.append('quit')

    def starttls(self, context: Any = None) -> None:
        self.calls.append('starttls')

    def login(self, user: str, password: str) -> None:
        self.calls.append(f'login {user}')

    def send_message(self, message: Any) -> None:
        self.sent.append(message)


async def test_email_alerts_use_tls_and_carry_the_label(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeSMTP.sent, FakeSMTP.calls = [], []
    monkeypatch.setattr(smtplib, 'SMTP', FakeSMTP)
    settings = AlertSettings(
        smtp_host='mail.example.org',
        smtp_from='insight@example.org',
        smtp_username='insight',
        smtp_password='pw',
    )
    with session_factory.begin() as db:
        services.add_watch_term(db, 'Acme')
        target(db, 'email', address='soc@example.org')
        report(db, 'Acme\r\nBcc: evil@example.org', 'Acme.', tlp='AMBER')
    assert await alerts.deliver_due(session_factory, settings=settings) == 'Sent 1 alert(s); 0 failed.'
    assert FakeSMTP.calls == ['connect mail.example.org:587', 'starttls', 'login insight', 'quit']
    (mail,) = FakeSMTP.sent
    assert mail['To'] == 'soc@example.org'
    assert mail['Subject'] == '[Insight] [TLP:AMBER] Watch term "Acme": Acme Bcc: evil@example.org'
    assert mail['Bcc'] is None
    assert mail.get_content().startswith('TLP:AMBER\n')


async def test_email_without_a_mail_server_fails_plainly(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as db:
        alert_id = services.queue_test_alert(db, target(db, 'email', address='soc@example.org').id).id
    await alerts.deliver_due(session_factory, ids=[alert_id], settings=AlertSettings())
    with session_factory() as db:
        alert = db.get(Alert, alert_id)
        assert alert is not None
        assert alert.error == 'E-mail is not set up: set INSIGHT_SMTP_HOST and INSIGHT_SMTP_FROM.'


async def test_the_job_runner_sends_due_alerts(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[str] = []

    async def fake_send(alert: services.DueAlert, settings: AlertSettings, **_: Any) -> None:
        sent.append(alert.subject)

    monkeypatch.setattr(alerts, 'send', fake_send)
    monkeypatch.setenv('INSIGHT_PUBLIC_URL', '')
    with session_factory.begin() as db:
        services.add_watch_term(db, 'Acme')
        target(db)
        report(db, 'Acme', 'Acme.')
    import asyncio

    assert await jobs.run_due(session_factory, asyncio.Lock(), clock=lambda: datetime.now(UTC)) == 1
    assert sent == ['Acme']
    with session_factory() as db:
        job = db.scalars(select(Job)).one()
        assert (job.kind, job.status, job.message) == ('alerts', 'succeeded', 'Sent 1 alert(s); 0 failed.')


# --------------------------------------------------------------------------- settings


@pytest.mark.parametrize(
    ('env', 'message'),
    [
        ({'INSIGHT_SMTP_SECURITY': 'ssl'}, 'INSIGHT_SMTP_SECURITY must be one of'),
        ({'INSIGHT_SMTP_HOST': 'mail.example.org', 'INSIGHT_SMTP_SECURITY': 'none'}, 'relay on this host'),
        ({'INSIGHT_SMTP_PORT': 'x'}, 'port number'),
        ({'INSIGHT_PUBLIC_URL': 'insight.example.org'}, 'must start with https://'),
        ({'INSIGHT_ALERT_PRIVATE_TARGETS': 'yes'}, '"on" or "off"'),
    ],
)
def test_alert_settings_refuse_mistakes(env: dict[str, str], message: str) -> None:
    with pytest.raises(RuntimeError, match=message):
        AlertSettings.from_env(env)


def test_alert_settings_defaults() -> None:
    assert not AlertSettings.from_env({}).email
    settings = AlertSettings.from_env(
        {
            'INSIGHT_SMTP_HOST': 'mail.example.org',
            'INSIGHT_SMTP_FROM': 'insight@example.org',
            'INSIGHT_SMTP_SECURITY': 'tls',
            'INSIGHT_PUBLIC_URL': 'https://insight.example.org/',
        }
    )
    assert (settings.email, settings.smtp_port, settings.public_url) == (
        True,
        465,
        'https://insight.example.org',
    )
    assert (
        AlertSettings.from_env({'INSIGHT_SMTP_HOST': 'localhost', 'INSIGHT_SMTP_SECURITY': 'none'}).smtp_port
        == 587
    )


def test_compose_and_the_example_env_name_every_alert_setting() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    compose, example = (root / 'compose.yaml').read_text(), (root / '.env.example').read_text()
    for name in (
        'INSIGHT_PUBLIC_URL',
        'INSIGHT_SMTP_HOST',
        'INSIGHT_SMTP_PORT',
        'INSIGHT_SMTP_SECURITY',
        'INSIGHT_SMTP_USERNAME',
        'INSIGHT_SMTP_PASSWORD',
        'INSIGHT_SMTP_FROM',
        'INSIGHT_ALERT_PRIVATE_TARGETS',
    ):
        assert f'{name}: ${{{name}:-' in compose, name
        assert f'# {name}=' in example, name

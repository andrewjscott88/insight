"""Sending alerts: what each one says, signed webhooks, e-mail, and retries (ADR 0022).

``services.alerts`` decides when an alert fires and queues it; the job runner calls :func:`deliver_due` within
a tick. What an alert says depends on TLP: a report labelled more restrictively than the target allows (and
every TLP:RED report) is announced without its title or source, only its label, the watch term and a link.
Publishers' words (report text, evidence) are never sent, so each source's reuse rule (ADR 0021) holds.

- **JSON webhooks** get an ``insight-alert-v1`` document, signed with the target's secret:
  ``X-Insight-Signature: sha256=HMAC(secret, timestamp + "." + body)`` and ``X-Insight-Timestamp``.
- **Chat webhooks** get ``{"text": ...}`` (Slack, Mattermost, Rocket.Chat, Google Chat), with ``&``, ``<``
  and ``>`` escaped so report titles cannot add links or mentions.
- **E-mail** goes through the SMTP server in ``AlertSettings``, with TLS unless it is a relay on this host.

A webhook must use HTTPS and resolve to public internet addresses (``INSIGHT_ALERT_PRIVATE_TARGETS=on`` allows
private networks; link-local addresses such as cloud metadata services are never allowed). Redirects are not
followed. A failed send is tried again after 5, then 10 minutes, then marked failed.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import smtplib
import socket
import ssl
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from . import __version__, egress, services
from .config import AlertSettings
from .models import AlertTarget, SessionFactory
from .schemas import TLP_LEVELS
from .services import DueAlert

FORMAT: Final = 'insight-alert-v1'
TIMEOUT: Final = 10.0
USER_AGENT: Final = f'Insight/{__version__} (alerts)'
KEV_PAGE: Final = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'


class AlertError(Exception):
    """A send failed for a reason worth showing the operator (no secrets in the message)."""


@dataclass(frozen=True, slots=True)
class Message:
    tlp: str
    subject: str
    #: Plain-text lines: the first is always the TLP label.
    lines: tuple[str, ...]
    payload: dict[str, Any]


def withheld(report_tlp: str, max_tlp: str) -> bool:
    """Whether a report's title and source must stay out of alerts to a target allowing up to ``max_tlp``."""
    if report_tlp == 'RED' or report_tlp not in TLP_LEVELS or max_tlp not in TLP_LEVELS:
        return True
    return TLP_LEVELS.index(report_tlp) > TLP_LEVELS.index(max_tlp)


def _flat(text: str) -> str:
    return ' '.join(text.split())


def compose(alert: DueAlert, *, public_url: str) -> Message:
    """What ``alert`` says to its target."""
    report = alert.report
    link = f'{public_url}/?report={report.id}' if public_url and report else public_url
    payload: dict[str, Any] = {
        'format': FORMAT,
        'id': alert.id,
        'trigger': alert.trigger,
        'created_at': alert.created_at,
        'subject': alert.subject,
        'report': None,
        'link': link or None,
    }
    if alert.trigger == 'watch':
        term = alert.subject
        if report is None:
            tlp, subject = 'AMBER', f'Watch term "{term}" in a report that was since deleted'
            lines = [
                f'A report mentioned your watch term "{term}". It was deleted before this alert was sent.'
            ]
        elif withheld(report.tlp, alert.target.max_tlp):
            tlp, subject = report.tlp, f'Watch term "{term}" in a new TLP:{report.tlp} report'
            lines = [
                f'A new report labelled TLP:{report.tlp} mentions your watch term "{term}".',
                'Its title is not sent here because of its TLP label. Open Insight to read it.',
            ]
            payload['report'] = {'id': report.id, 'tlp': report.tlp, 'withheld': True}
        else:
            title = _flat(report.title)
            tlp, subject = report.tlp, f'Watch term "{term}": {title}'
            lines = [
                f'A new report mentions your watch term "{term}".',
                f'Report: {title}',
                f'Source: {_flat(report.source_name)}',
                f'Received: {report.created_at[:16].replace("T", " ")} UTC',
            ]
            payload['report'] = {
                'id': report.id,
                'tlp': report.tlp,
                'withheld': False,
                'title': title,
                'source': _flat(report.source_name),
                'received_at': report.created_at,
            }
    elif alert.trigger == 'kev':
        tlp, subject = 'CLEAR', f'CISA added {alert.subject} to its list of exploited weaknesses'
        lines = [
            f'CISA added {alert.subject} to its Known Exploited Vulnerabilities list: attackers use it.',
            'Check whether you use the product, and fix it before other weaknesses.',
        ]
        link = link or KEV_PAGE
        payload['link'] = link
    else:
        tlp, subject = 'CLEAR', 'Test alert from Insight'
        lines = ['This is a test alert from Insight. Alerts to this destination work.']
    if link:
        lines.append(f'Open in Insight: {link}' if link != KEV_PAGE else f'More: {link}')
    payload['tlp'] = tlp
    payload['summary'] = lines[0]
    return Message(tlp, _flat(subject)[:200], (f'TLP:{tlp}', *lines), payload)


# --------------------------------------------------------------------------- webhooks


async def check_address(url: str, *, allow_private: bool) -> list[egress.IPAddress]:
    """The addresses of ``url``'s host, or :class:`AlertError` unless it is HTTPS to addresses alerts may
    reach. The webhook is then sent to one of these exact addresses (review L1: no second DNS lookup)."""
    parts = urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
        raise AlertError('The webhook address must start with https:// and hold no user name or password.')
    try:
        port = parts.port or 443
    except ValueError as exc:
        raise AlertError('The webhook address has an invalid port.') from exc
    try:
        addresses = await egress.resolve(parts.hostname, port)
    except OSError as exc:
        raise AlertError(f'Could not find {parts.hostname} (DNS).') from exc
    if not addresses:
        raise AlertError(f'Could not find {parts.hostname} (DNS).')
    for address in addresses:
        if egress.never_allowed(address):
            raise AlertError(f'{parts.hostname} resolves to an address alerts never go to ({address}).')
        if not egress.effective(address).is_global and not allow_private:
            raise AlertError(
                f'{parts.hostname} is on a private network. Set INSIGHT_ALERT_PRIVATE_TARGETS=on to allow it.'
            )
    return addresses


def _chat_text(message: Message) -> str:
    text = '\n'.join(message.lines)
    return 'Insight alert\n' + text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """The ``X-Insight-Signature`` value for ``body`` sent at ``timestamp`` (Unix seconds)."""
    digest = hmac.new(secret.encode(), timestamp.encode() + b'.' + body, hashlib.sha256).hexdigest()
    return f'sha256={digest}'


async def send_webhook(
    target: AlertTarget,
    message: Message,
    *,
    allow_private: bool,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    addresses = await check_address(target.address, allow_private=allow_private)
    if target.style == 'chat':
        body = json.dumps({'text': _chat_text(message)}).encode()
    else:
        body = json.dumps(message.payload, sort_keys=True).encode()
    headers = {'Content-Type': 'application/json', 'User-Agent': USER_AGENT}
    if target.style == 'json' and target.secret:
        timestamp = str(int(time.time()))
        headers['X-Insight-Timestamp'] = timestamp
        headers['X-Insight-Signature'] = sign(target.secret, timestamp, body)
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(TIMEOUT), follow_redirects=False, trust_env=False, transport=transport
    ) as client:
        for index, address in enumerate(addresses):
            pinned = egress.pin(target.address, address)
            try:
                response = await client.post(
                    pinned.url,
                    content=body,
                    headers={**headers, **pinned.headers},
                    extensions=pinned.extensions,
                )
                break
            except httpx.ConnectError:
                if index == len(addresses) - 1:
                    raise
    if response.is_redirect:
        raise AlertError('The webhook answered with a redirect, which alerts do not follow.')
    if not response.is_success:
        raise AlertError(f'The webhook answered HTTP {response.status_code}.')


# --------------------------------------------------------------------------- e-mail


def send_email(target: AlertTarget, message: Message, settings: AlertSettings) -> None:
    if not settings.email:
        raise AlertError('E-mail is not set up: set INSIGHT_SMTP_HOST and INSIGHT_SMTP_FROM.')
    mail = EmailMessage()
    mail['From'] = settings.smtp_from
    mail['To'] = target.address
    mail['Subject'] = f'[Insight] [TLP:{message.tlp}] {message.subject}'
    mail.set_content('\n\n'.join(message.lines) + '\n')
    context = ssl.create_default_context()
    smtp: smtplib.SMTP
    if settings.smtp_security == 'tls':
        smtp = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=TIMEOUT, context=context)
    else:
        smtp = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=TIMEOUT)
    with smtp:
        if settings.smtp_security == 'starttls':
            smtp.starttls(context=context)
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(mail)


# --------------------------------------------------------------------------- the queue


async def send(
    alert: DueAlert, settings: AlertSettings, *, transport: httpx.AsyncBaseTransport | None = None
) -> None:
    message = compose(alert, public_url=settings.public_url)
    if alert.target.kind == 'email':
        await asyncio.to_thread(send_email, alert.target, message, settings)
    else:
        await send_webhook(alert.target, message, allow_private=settings.private_targets, transport=transport)


def _reason(exc: Exception) -> str:
    if isinstance(exc, AlertError):
        return str(exc)
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return 'The mail server refused the user name or password.'
    if isinstance(exc, httpx.TimeoutException | TimeoutError | socket.timeout):
        return 'No answer in time.'
    return f'{type(exc).__name__}: {str(exc)[:200]}'


async def deliver_due(
    sessions: SessionFactory,
    *,
    ids: Sequence[str] = (),
    settings: AlertSettings | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    transport: httpx.AsyncBaseTransport | None = None,
) -> str:
    """Send the alerts that are due (or exactly ``ids``) and record each result; returns a summary."""
    settings = settings or AlertSettings.from_env()
    with sessions() as db:
        due = services.due_alerts(db, at=clock(), ids=ids)
    sent = failed = 0
    for alert in due:
        error = ''
        try:
            await send(alert, settings, transport=transport)
            sent += 1
        except (AlertError, httpx.HTTPError, OSError, smtplib.SMTPException, ValueError) as exc:
            error, failed = _reason(exc), failed + 1
        with sessions.begin() as db:
            services.mark_alert(db, alert.id, error=error, at=clock())
    return f'Sent {sent} alert(s); {failed} failed.'

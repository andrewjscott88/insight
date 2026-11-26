"""Alerts in the workspace: where they go, a test button, and what was sent recently (ADR 0022).

Targets are set here only, never with an API key. A JSON webhook's signing secret is shown once, when it is
added. Sending happens in the job runner; *Send a test alert* sends straight away so the operator sees the
result.
"""

from __future__ import annotations

from functools import partial
from typing import Final

from nicegui import ui

from .. import alerts, services
from ..config import AlertSettings
from ..permissions import Permission
from ..services.alerts import TARGET_TLPS
from .messages import tell
from .offered import setting_switch
from .typography import heading
from .workspace import Workspace

STYLE_NAMES: Final[dict[str, str]] = {
    'chat': 'Chat webhook (Slack, Mattermost, Google Chat)',
    'json': 'Signed JSON webhook (for your own tools)',
    'email': 'E-mail',
}
STATUS_NAMES: Final[dict[str, str]] = {'pending': 'Waiting to send', 'sent': 'Sent', 'failed': 'Failed'}


def _settings() -> AlertSettings | None:
    try:
        return AlertSettings.from_env()
    except RuntimeError:
        return None


def _shown_address(kind: str, address: str) -> str:
    """Chat webhook addresses are secrets: show only the host."""
    if kind == 'email':
        return address
    return address.split('/')[2] if address.count('/') >= 2 else address


def build_alerts(ws: Workspace) -> None:
    def show_secret(secret: str) -> None:
        with (
            ui.dialog().props('aria-label="Signing secret"') as dialog,
            ui.card().classes('dialog-card gap-3'),
        ):
            heading('Signing secret', 2)
            ui.label(
                'Your tool can check that each alert came from Insight with this secret. It is shown only '
                'once. Keep it with your other secrets.'
            ).classes('prose')
            ui.label(secret).classes('break-value font-mono')
            ui.button('Done', on_click=dialog.close)
        dialog.open()

    def add() -> None:
        if not ws.allowed(Permission.ALERTS):
            return
        try:
            with ws.write(Permission.ALERTS) as db:
                target = services.add_target(
                    db,
                    name=name_input.value or '',
                    style=style_select.value,
                    address=address_input.value or '',
                    max_tlp=tlp_select.value,
                )
                secret = target.secret
        except ValueError as exc:
            tell(str(exc), 'warning')
            return
        name_input.set_value('')
        address_input.set_value('')
        targets.refresh()
        tell('Destination added. Send a test alert to check it.', 'success')
        if secret:
            show_secret(secret)

    def toggle(target_id: str, on: bool) -> None:
        if not ws.allowed(Permission.ALERTS):
            return
        with ws.write(Permission.ALERTS) as db:
            services.set_target_enabled(db, target_id, on)
        tell('Alerts to this destination are on.' if on else 'Alerts to this destination are off.', 'success')

    def remove(target_id: str) -> None:
        if not ws.allowed(Permission.ALERTS):
            return
        with ws.write(Permission.ALERTS) as db:
            services.delete_target(db, target_id)
        targets.refresh()
        recent.refresh()
        tell('Destination removed.', 'success')

    async def test(target_id: str, button: ui.button) -> None:
        if not ws.allowed(Permission.ALERTS):
            return
        button.disable()
        try:
            with ws.write(Permission.ALERTS) as db:
                alert_id = services.queue_test_alert(db, target_id).id
            await alerts.deliver_due(ws.sessions, ids=[alert_id])
        finally:
            button.enable()
        with ws.read() as db:
            ((sent, _),) = [(a, n) for a, n in services.recent_alerts(db, limit=50) if a.id == alert_id]
            status, error = sent.status, sent.error
        targets.refresh()
        recent.refresh()
        if status == 'sent':
            tell('Test alert sent.', 'success')
        else:
            tell(f'The test alert failed: {error}', 'warning')

    @ui.refreshable
    def targets() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            rows = [
                (t.id, t.name, t.kind, t.style, t.address, t.max_tlp, t.enabled, t.last_status, t.last_error)
                for t in services.list_targets(db)
            ]
        if not rows:
            ui.label('No alert destinations yet.').classes('muted text-sm')
        for target_id, name, kind, style, address, max_tlp, enabled, last, error in rows:
            with ui.column().classes('panel w-full p-3 gap-1'):
                heading(name, 4)
                ui.label(f'{STYLE_NAMES[style]} · {_shown_address(kind, address)}').classes(
                    'muted text-sm break-value'
                )
                ui.label(f'Report titles up to TLP:{max_tlp}').classes('muted text-sm')
                if last == 'failed':
                    ui.label(f'Last send failed: {error}').classes('text-warn text-sm prose')
                with ui.row().classes('items-center gap-3 flex-wrap'):
                    setting_switch(
                        ws,
                        Permission.ALERTS,
                        'Send alerts here',
                        enabled,
                        partial(toggle, target_id),
                        state=('Alerts go here', 'Alerts do not go here'),
                    )
                    if ws.can(Permission.ALERTS):  # Admins only (ADR 0046).
                        button = ui.button('Send a test alert').props('outline no-caps')
                        button.on_click(lambda i=target_id, b=button: test(i, b))
                        ui.button('Remove', on_click=lambda i=target_id: remove(i)).props(
                            f'flat dense no-caps aria-label="Remove {name}"'
                        )

    @ui.refreshable
    def recent() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            rows = [
                (a.created_at, a.trigger, a.subject, a.status, a.error, name)
                for a, name in services.recent_alerts(db)
            ]
        if not rows:
            ui.label('No alerts yet.').classes('muted text-sm')
        for created, trigger, subject, status, error, name in rows:
            what = {'watch': f'Watch term "{subject}"', 'kev': f'KEV: {subject}'}.get(trigger, subject)
            line = (
                f'{created[:16].replace("T", " ")} UTC · {what} · {name} · {STATUS_NAMES.get(status, status)}'
            )
            ui.label(line + (f': {error}' if status == 'failed' else '')).classes('text-sm prose break-value')

    settings = _settings()
    ws.on_refresh(recent.refresh)
    heading('Alerts', 3, 'subsection-title mt-6')
    ui.label(
        'Insight can tell you when a new report mentions one of your watch terms, or when CISA adds a '
        'weakness to its list of those attackers use. A report labelled above the level you choose is '
        'announced without its title. TLP:RED titles are never sent.'
    ).classes('muted prose')
    if settings is None:
        ui.label('Alert settings in the environment are not valid. Check the server log.').classes(
            'text-warn'
        )
    elif not settings.email:
        ui.label(
            'To send e-mail alerts, the server needs a mail server in its settings (INSIGHT_SMTP_HOST and '
            'INSIGHT_SMTP_FROM).'
        ).classes('muted text-sm prose')
    if not ws.app.state.settings.run_jobs:
        ui.label('This server does not send alerts by itself (INSIGHT_RUN_JOBS is off).').classes('text-warn')
    with ui.column().classes('w-full gap-3 mt-2'):
        targets()
    if ws.can(Permission.ALERTS):  # Admins only (ADR 0046).
        with ui.column().classes('panel w-full p-4 gap-2 mt-2'):
            heading('Add a destination', 4)
            style_select = (
                ui.select(STYLE_NAMES, value='chat', label='Kind').props('outlined').classes('w-full')
            )
            name_input = ui.input('Name', placeholder='e.g. Security team channel').props(
                'outlined maxlength=80'
            )
            address_input = ui.input(
                'Webhook address or e-mail', placeholder='https://… or alerts@example.org'
            ).props('outlined maxlength=2048')
            tlp_select = ui.select(
                {level: f'Titles up to TLP:{level}' for level in TARGET_TLPS},
                value='AMBER',
                label='TLP limit',
            ).props('outlined')
            ui.button('Add destination', on_click=add)
    else:
        ui.label('An admin chooses where alerts go.').classes('muted text-sm')
    heading('Recent alerts', 4)
    with ui.column().classes('w-full gap-1'):
        recent()

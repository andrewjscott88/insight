"""Censys metadata is private, attributed and displayed only after the operator approves disclosure."""

from __future__ import annotations

from typing import Any

from nicegui import ui

from .. import censys, services
from ..connectors import ProviderError
from .messages import problem_area
from .typography import heading, new_tab_link
from .workspace import Workspace


def build_censys_settings(ws: Workspace) -> None:
    heading('Censys infrastructure context', 3, 'subsection-title mt-4')
    with ui.column().classes('panel w-full gap-2 p-3'):
        ui.label('Look up one reviewed public IP to see services, host names and network details.').classes(
            'prose'
        )
        ui.label('Host token: configured' if censys.configured() else 'Host token: not configured').mark(
            'censys-status'
        )
        ui.label(
            'Set INSIGHT_CENSYS_PAT on the host; add INSIGHT_CENSYS_ORG_ID for an organization account. '
            'Keep tokens out of this page. Each lookup needs your approval and may use credits.'
        ).classes('prose')
        if ws.app.state.settings.dev_no_auth:
            ui.label(
                'Censys is unavailable during temporary open access. Private sign-in is required.'
            ).classes('prose')
        new_tab_link('Censys account and API setup', 'https://docs.censys.com/reference/get-started')


def _render(record: dict[str, Any] | None) -> None:
    if record is None:
        ui.label('No cached Censys context.')
        return
    if record['found']:
        for label, key in (
            ('Network', 'network_name'),
            ('Network number (ASN)', 'asn'),
            ('Network range', 'prefix'),
            ('Country', 'country_code'),
        ):
            if record.get(key):
                ui.label(f'{label}: {record[key]}').classes('break-value')
        if record['hostnames']:
            ui.label('Host names: ' + ', '.join(record['hostnames'])).classes('break-value')
        heading('Services Censys observed', 3)
        for item in record['services']:
            when = f' · seen {item["observed_at"]}' if item['observed_at'] else ''
            ui.label(f'{item["port"]}/{item["transport"]} · {item["protocol"]}{when}').classes('break-value')
        ui.label(f'Shows {len(record["services"])} of {record["service_count"]} observed services.').classes(
            'muted'
        )
    else:
        ui.label('Censys returned no accessible host record. This does not prove the address is unused.')
    ui.label(f'Fetched: {record["fetched_at"]}').classes('muted text-sm')
    ui.label('These are provider observations, not an analyst verdict or a scan run by Insight.').classes(
        'muted prose'
    )
    new_tab_link(censys.ATTRIBUTION, 'https://censys.com')


def open_censys(ws: Workspace, ip: str) -> None:
    if not ws.authorized():
        return
    private = not ws.app.state.settings.dev_no_auth
    ready = private and censys.configured()
    record = None
    with ws.read() as db:
        if not services.eligible_censys_ip(db, ip, max_tlp=ws.app.state.settings.max_tlp):
            return
        if private:
            record = services.cached_censys_context(db, ip, max_tlp=ws.app.state.settings.max_tlp)
    with (
        ui.dialog().props('aria-label="Censys infrastructure context"') as dialog,
        ui.card().classes('panel dialog-card gap-3'),
    ):
        heading('Censys infrastructure context', 2)
        ui.label(ip).classes('break-value')
        result = ui.column().classes('w-full gap-1').mark('censys-result')
        with result:
            _render(record)
        ui.label(
            'Censys receives this IP and can see your interest in it. Fresh lookups may use account '
            'credits. Insight reuses answers for 24 hours and does not share them in exports.'
        ).classes('prose')
        if not private:
            ui.label('Censys needs private sign-in. Turn off temporary open access before using it.').mark(
                'censys-private-required'
            )
        elif not ready:
            ui.label('Configure INSIGHT_CENSYS_PAT on the host; see Settings for setup.').mark(
                'censys-token-required'
            )
        new_tab_link('Check the terms for your Censys account', 'https://censys.com/terms-of-service/')
        consent = ui.checkbox(f'I approve sending {ip} to Censys under my account terms.').mark(
            'censys-consent'
        )
        consent.set_enabled(ready)
        problem = problem_area()

        async def fetch() -> None:
            if not ws.authorized() or ws.app.state.settings.dev_no_auth or not consent.value:
                return
            consent.set_value(False)
            problem.set_text('')
            try:
                answer = await censys.lookup(
                    ws.sessions,
                    ip,
                    actor='operator',
                    approved=True,
                    max_tlp=ws.app.state.settings.max_tlp,
                )
            except (ProviderError, censys.NotConfigured, censys.RateLimited, LookupError) as exc:
                if ws.authorized():
                    problem.set_text(str(exc))
                return
            if ws.authorized() and not ws.app.state.settings.dev_no_auth:
                result.clear()
                with result:
                    _render(answer)

        with ui.row().classes('w-full flex-wrap gap-2'):
            ui.button('Close', on_click=dialog.close).props('flat')
            ui.button('Look up at Censys', on_click=fetch).bind_enabled_from(consent, 'value').mark(
                'censys-fetch'
            )
    dialog.open()

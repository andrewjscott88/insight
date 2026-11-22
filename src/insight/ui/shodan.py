"""Optional Shodan exposure context for a reviewed public IP (TIP 3.7): read the cache, approve a lookup."""

from __future__ import annotations

from typing import Any

from nicegui import ui

from .. import services, shodan
from ..connectors import ProviderError
from .messages import problem_area
from .typography import heading
from .workspace import Workspace


def _render(result: dict[str, Any] | None) -> None:
    if result is None:
        ui.label('No cached Shodan context.')
        return
    if result['found']:
        ports = result['ports']
        shown = ', '.join(str(p) for p in ports) or 'none'
        more = f' (first {len(ports)} of {result["port_count"]})' if result['port_count'] > len(ports) else ''
        ui.label(f'Open ports Shodan saw: {shown}{more}').classes('break-value')
        for label, key in (
            ('Organisation', 'org'),
            ('Network', 'isp'),
            ('ASN', 'asn'),
            ('Country', 'country_code'),
        ):
            if result.get(key):
                ui.label(f'{label}: {result[key]}')
        if result.get('os'):
            ui.label(f'Operating system: {result["os"]}')
        if result['hostnames']:
            ui.label('Host names: ' + ', '.join(result['hostnames'])).classes('break-value')
        if result['tags']:
            ui.label('Shodan tags: ' + ', '.join(result['tags']))
        if result['vulns']:
            ui.label('CVEs Shodan links to this host: ' + ', '.join(result['vulns'])).classes('break-value')
            ui.label('Shodan infers these from software versions; they are not confirmed.').classes(
                'muted text-sm'
            )
        if result.get('last_update'):
            ui.label(f'Last updated by Shodan: {result["last_update"]}')
    else:
        ui.label('Shodan has no record for this address.')
    ui.label(f'Fetched: {result["fetched_at"]}').classes('muted text-sm')
    ui.label(shodan.ATTRIBUTION).classes('muted text-sm')


def open_shodan(ws: Workspace, ip: str) -> None:
    if not ws.authorized() or not shodan.configured():
        return
    with ws.read() as db:
        try:
            record = services.cached_ip_context(db, 'shodan', ip)
        except LookupError:
            return
    title = f'Shodan exposure context for {ip}'
    with ui.dialog().props(f'aria-label="{title}"') as dialog, ui.card().classes('panel dialog-card gap-3'):
        heading(title, 2)
        result = ui.column().classes('w-full gap-1').mark('shodan-result')
        with result:
            _render(record)
        ui.label(
            'Shodan is an optional paid service: it uses your key and your plan. It receives this IP address '
            'and can see your interest in it. Insight reuses answers fetched in the last 24 hours.'
        ).classes('muted prose')
        consent = ui.checkbox(f'I approve sending {ip} to Shodan.').mark('shodan-consent')
        problem = problem_area()

        async def fetch() -> None:
            if not ws.authorized() or not consent.value:
                return
            consent.set_value(False)
            problem.set_text('')
            try:
                answer = await shodan.lookup(ws.sessions, ip, actor='operator')
            except (ProviderError, shodan.NotConfigured, shodan.RateLimited, LookupError) as exc:
                if ws.authorized():
                    problem.set_text(str(exc))  # plan, credit and rate-limit refusals are shown as they are
                return
            if ws.authorized():
                result.clear()
                with result:
                    _render(answer)

        with ui.row():
            ui.button('Close', on_click=dialog.close).props('flat')
            ui.button('Look up at Shodan', on_click=fetch).bind_enabled_from(consent, 'value').mark(
                'shodan-fetch'
            )
    dialog.open()

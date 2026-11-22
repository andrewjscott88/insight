"""Operator switches and per-lookup consent for infrastructure context."""

from __future__ import annotations

from typing import Any

from nicegui import ui

from .. import pivot_data, pivots, services
from ..connectors import ProviderError
from .messages import problem_area, tell
from .typography import heading
from .workspace import Workspace


def _render_result(result: dict[str, Any]) -> None:
    if not result['found']:
        ui.label('This provider has no matching record.')
        return
    fields = {
        'network_name': 'Network name',
        'handle': 'Registry handle',
        'country': 'Country',
        'start_address': 'First address',
        'end_address': 'Last address',
        'prefix': 'Announced range',
    }
    for key, title in fields.items():
        if result.get(key):
            ui.label(f'{title}: {result[key]}').classes('break-value')
    for number in result.get('registrar_ids', []):
        ui.label(f'Registrar number: {number}')
    for name in result.get('name_servers', []):
        ui.label(f'Name server: {name}').classes('break-value')
    if result.get('status'):
        ui.label('Registry status: ' + ', '.join(result['status'])).classes('break-value')
    for event, date in result.get('dates', {}).items():
        ui.label(f'{event.capitalize()}: {date[:10]}')
    for network in result.get('networks', []):
        ui.label(f'Network AS{network["asn"]}: {network["holder"]}').classes('break-value')


def build_pivot_switches(ws: Workspace) -> None:
    heading('Infrastructure lookups', 3, 'subsection-title mt-4')
    ui.label(
        'Each provider starts off. Turning one on does not send any data. '
        'You must approve each new lookup. Cached answers are reused for 24 hours.'
    ).classes('muted prose')

    def change(provider: str, enabled: bool) -> None:
        if not ws.authorized():
            return
        with ws.write() as db:
            services.set_pivot_switch(db, provider, enabled)
        tell(f'{pivot_data.PROVIDERS[provider]} is {"on" if enabled else "off"}.', 'success')
        ws.refresh_all()

    with ws.read() as db:
        switches = services.pivot_switches(db)
    for provider, name in pivot_data.PROVIDERS.items():
        ui.switch(
            f'Use {name}', value=switches[provider], on_change=lambda e, p=provider: change(p, bool(e.value))
        ).mark(f'pivot-switch-{provider}')
    ui.label(
        'RDAP shows registration details without personal contacts. RIPEstat shows which network '
        'announces an address. Check each provider’s terms before use.'
    ).classes('muted prose')


def open_pivots(ws: Workspace, value: str) -> None:
    if not ws.authorized():
        return
    with ws.read() as db:
        try:
            cached = services.cached_pivots(db, value, max_tlp=None)
        except LookupError:
            return
        enabled = services.pivot_switches(db)
    kind, _ = pivot_data.subject(value)
    with ui.dialog() as dialog, ui.card().classes('panel dialog-card gap-3'):
        heading(f'Infrastructure around {value}', 2)
        ui.label(
            'These results describe infrastructure. They do not prove harm. '
            'Insight does not add them as indicators.'
        ).classes('muted prose')
        output = ui.column().classes('w-full break-value')

        def render() -> None:
            output.clear()
            with output:
                if not cached:
                    ui.label('No fresh cached results.')
                for result in cached:
                    heading(pivot_data.PROVIDERS[result['provider']], 3)
                    ui.label(f'Fetched: {result["fetched_at"]}').classes('muted text-sm')
                    _render_result(result)

        render()
        for provider, name in pivot_data.PROVIDERS.items():
            if not enabled[provider] or (provider == 'asn' and kind != 'ip'):
                continue
            with ui.column().classes('w-full gap-2'):
                consent = ui.checkbox(f'I approve sending {value} to {name}.')
                ui.label(
                    'The value leaves Insight. This provider can see your interest in it. '
                    'A fresh cached answer needs no new request.'
                ).classes('muted prose')
                problem = problem_area()

                async def fetch(
                    p: str = provider, checkbox: ui.checkbox = consent, error: ui.label = problem
                ) -> None:
                    if not ws.authorized() or not checkbox.value:
                        return
                    checkbox.set_value(False)
                    error.set_text('')
                    try:
                        result = await pivots.lookup(
                            ws.sessions, p, value, approved=True, actor='operator', max_tlp=None
                        )
                    except (ProviderError, ValueError, LookupError, pivots.RateLimited) as exc:
                        if ws.authorized():
                            error.set_text(str(exc))
                        return
                    if ws.authorized():
                        cached[:] = [r for r in cached if r['provider'] != p] + [result]
                        render()

                ui.button(f'Look up at {name}', on_click=fetch).bind_enabled_from(consent, 'value')
        ui.button('Close', on_click=dialog.close).props('flat')
    dialog.open()

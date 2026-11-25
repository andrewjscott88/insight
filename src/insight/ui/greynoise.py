"""Review passive IP context and approve a manual third-party lookup."""

from __future__ import annotations

from typing import Any

from nicegui import ui

from .. import greynoise, services
from ..connectors import ProviderError
from ..permissions import Permission
from .messages import problem_area
from .typography import heading
from .workspace import Workspace


def _render(result: dict[str, Any] | None) -> None:
    if result is None:
        ui.label('No cached GreyNoise context.')
        return
    if result['found']:
        ui.label(f'GreyNoise classification: {result["classification"]}')
        ui.label('Observed internet scanning: ' + ('yes' if result['noise'] else 'no'))
        ui.label('Listed in the GreyNoise RIOT dataset: ' + ('yes' if result['riot'] else 'no'))
        if result['name']:
            ui.label('Organisation: ' + result['name'])
        if result['last_seen']:
            ui.label('Last seen by GreyNoise: ' + result['last_seen'])
    else:
        ui.label('GreyNoise had no Community record for this address.')
    ui.label('Fetched: ' + result['fetched_at']).classes('muted text-sm')


def open_greynoise(ws: Workspace, ip: str) -> None:
    if not ws.authorized() or not greynoise.configured():
        return
    with ws.read() as db:
        try:
            record = services.cached_greynoise_context(db, ip)
        except LookupError:
            return
    title = f'GreyNoise context for {ip}'
    with ui.dialog().props(f'aria-label="{title}"') as dialog, ui.card().classes('panel dialog-card gap-3'):
        heading(title, 2)
        result = ui.column().classes('w-full gap-1')
        with result:
            _render(record)
        ui.label(
            'GreyNoise receives this IP address and can see your interest in it. '
            'Insight reuses responses fetched in the last 24 hours.'
        ).classes('muted prose')
        consent = ui.checkbox(f'I approve sending {ip} to GreyNoise.')
        problem = problem_area()

        async def fetch() -> None:
            if not ws.allowed(Permission.LOOKUPS) or not consent.value:
                return
            consent.set_value(False)
            problem.set_text('')
            try:
                answer = await greynoise.lookup(ws.sessions, ip, actor=ws.actor(Permission.LOOKUPS))
            except (ProviderError, greynoise.NotConfigured, greynoise.RateLimited, LookupError) as exc:
                if ws.authorized():
                    problem.set_text(str(exc))
                return
            if ws.authorized():
                result.clear()
                with result:
                    _render(answer)

        with ui.row():
            ui.button('Close', on_click=dialog.close).props('flat')
            ui.button('Look up at GreyNoise', on_click=fetch).bind_enabled_from(consent, 'value')
    dialog.open()

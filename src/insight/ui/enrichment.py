"""Explicit, consent-gated CVE enrichment (FIRST EPSS / NIST NVD)."""

from __future__ import annotations

import json
import time
from typing import Final

from nicegui import ui

from .. import services
from ..connectors import enrich_cve
from .messages import problem_area
from .typography import heading
from .workspace import Workspace

ENRICHMENT_INTERVAL_SECONDS: Final = 6.5


def open_enrichment_dialog(ws: Workspace, cve: str) -> None:
    if not ws.authorized():
        return
    title = f'Look up {cve}'
    with (
        ui.dialog().props(f'aria-label="{title}"') as dialog,
        ui.card().classes('panel dialog-card p-6 w-[42rem] max-w-full gap-3'),
    ):
        heading(title, 2)
        ui.label(
            'Insight sends only this CVE number to the service you choose. It sends no report text, notes or '
            'other indicators. The service may learn that you are interested in this weakness.'
        ).classes('muted prose')
        services_offered = {
            'epss': 'FIRST EPSS: how likely an attack is soon',
            'nvd': 'NIST NVD: description and severity',
        }
        provider = (
            ui.select(services_offered, value='epss', label='Provider').props('outlined').classes('w-full')
        )
        consent = ui.checkbox(f'I approve sending {cve} to the selected provider.')
        provider.on_value_change(lambda _: consent.set_value(False))
        result = ui.column().classes('w-full')
        with ws.read() as db:
            cached = [(r.provider, r.fetched_at, r.payload) for r in services.cached_enrichments(db, cve)]
        with result:
            for name, fetched_at, payload in cached:
                with ui.expansion(f'Cached {name.upper()} · {fetched_at[:16]}').classes('w-full'):
                    ui.label(payload).classes('source-body text-sm')

        async def lookup() -> None:
            if not ws.authorized() or not consent.value:
                return
            problem.set_text('')
            if time.monotonic() - ws.app.state.last_lookup < ENRICHMENT_INTERVAL_SECONDS:
                problem.set_text('Please wait a few seconds between lookups (at least 6.5 seconds).')
                return
            ws.app.state.last_lookup = time.monotonic()
            selected_provider = str(provider.value)
            consent.set_value(False)
            fetch.disable()
            try:
                payload = await enrich_cve(ws.sessions, cve, selected_provider)
                if ws.authorized():
                    result.clear()
                    with result:
                        heading('Provider response (just now)', 3)
                        ui.label(json.dumps(payload, indent=2)).classes(
                            'source-body w-full text-sm font-mono'
                        )
            except Exception as exc:  # Surface any failure to the analyst.
                if ws.authorized():
                    problem.set_text(f'The lookup did not work. Lookup failed: {exc}')
            finally:
                fetch.set_enabled(bool(consent.value))

        problem = problem_area()
        with ui.row():
            ui.button('Close', on_click=dialog.close).props('flat')
            fetch = ui.button('Fetch from provider', on_click=lookup).bind_enabled_from(consent, 'value')
    dialog.open()

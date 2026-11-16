"""Explicit, consent-gated CVE enrichment (FIRST EPSS / NIST NVD)."""

from __future__ import annotations

import json
import time
from typing import Final

from nicegui import ui

from .. import services
from ..connectors import enrich_cve
from .workspace import Workspace

ENRICHMENT_INTERVAL_SECONDS: Final = 6.5


def open_enrichment_dialog(ws: Workspace, cve: str) -> None:
    if not ws.authorized():
        return
    with ui.dialog() as dialog, ui.card().classes('panel p-6 w-[650px] max-w-full'):
        ui.label(f'Enrich {cve}').classes('text-xl')
        ui.label(
            'A lookup sends this CVE identifier to the selected provider. No source text, notes, '
            'or other indicators are sent. This may disclose interest in the vulnerability.'
        ).classes('muted text-sm')
        provider = (
            ui.select({'epss': 'FIRST EPSS', 'nvd': 'NIST NVD'}, value='epss', label='Provider')
            .props('outlined')
            .classes('w-full')
        )
        consent = ui.checkbox(f'I approve sending {cve} to the selected provider.')
        provider.on_value_change(lambda _: consent.set_value(False))
        result = ui.column().classes('w-full')
        with ws.read() as db:
            cached = [(r.provider, r.fetched_at, r.payload) for r in services.cached_enrichments(db, cve)]
        with result:
            for name, fetched_at, payload in cached:
                with ui.expansion(f'Cached {name.upper()} · {fetched_at[:16]}').classes('w-full'):
                    ui.label(payload).classes('source-body text-xs')

        async def lookup() -> None:
            if not ws.authorized() or not consent.value:
                return
            if time.monotonic() - ws.app.state.last_lookup < ENRICHMENT_INTERVAL_SECONDS:
                ui.notify('Wait at least 6.5 seconds between enrichment requests.', type='warning')
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
                        ui.label('Provider response · retrieved now').classes('eyebrow')
                        ui.label(json.dumps(payload, indent=2)).classes('source-body w-full text-xs')
            except Exception as exc:  # Surface any failure to the analyst.
                if ws.authorized():
                    ui.notify(f'Lookup failed: {exc}', type='negative', timeout=10000)
            finally:
                fetch.set_enabled(bool(consent.value))

        with ui.row():
            ui.button('Close', on_click=dialog.close).props('flat')
            fetch = ui.button('Fetch from provider', on_click=lookup).bind_enabled_from(consent, 'value')
    dialog.open()

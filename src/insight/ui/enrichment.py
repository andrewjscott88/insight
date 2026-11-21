"""Explicit, consent-gated CVE lookups (FIRST EPSS / NIST NVD), with readable scores (review C2).

The lookup goes through ``insight.lookups.request_lookup``, so it shares one throttle per provider with the
API and the automatic lookups (review B2).
"""

from __future__ import annotations

import json

from nicegui import ui

from .. import services
from ..cve_scores import EPSS_CAVEAT, CveScores, describe_epss, describe_nvd
from ..lookups import LookupThrottled, request_lookup
from .messages import problem_area
from .typography import heading
from .workspace import Workspace


def render_scores(found: CveScores) -> None:
    """What NVD and EPSS say about one CVE, in plain words."""
    if found.nvd is not None:
        ui.label(describe_nvd(found.nvd)).classes('prose')
        if found.nvd.description:
            ui.label(found.nvd.description).classes('muted text-sm prose')
        if found.nvd.cwes:
            ui.label('Weakness types: ' + ', '.join(found.nvd.cwes)).classes('muted text-sm')
    elif found.nvd_checked_at:
        ui.label('NIST NVD has no record of this CVE yet.').classes('muted text-sm')
    if found.epss is not None:
        ui.label(describe_epss(found.epss)).classes('prose')
        ui.label(EPSS_CAVEAT).classes('muted text-sm prose')
    elif found.epss_checked_at:
        ui.label('FIRST has no EPSS score for this CVE yet.').classes('muted text-sm')
    checked = ', '.join(
        f'{name} {at[:10]}'
        for name, at in (('NVD', found.nvd_checked_at), ('EPSS', found.epss_checked_at))
        if at
    )
    if checked:
        ui.label(f'Checked: {checked}').classes('muted text-sm')


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
        result = ui.column().classes('w-full gap-1')

        def show() -> None:
            with ws.read() as db:
                found = services.cve_scores(db, [cve]).get(cve)
                cached = [(r.provider, r.fetched_at, r.payload) for r in services.cached_enrichments(db, cve)]
            result.clear()
            with result:
                if found is not None and found.checked:
                    render_scores(found)
                for name, fetched_at, payload in cached:
                    with ui.expansion(f'What {name.upper()} sent · {fetched_at[:16]}').classes('w-full'):
                        ui.label(json.dumps(json.loads(payload), indent=2)).classes(
                            'source-body w-full text-sm font-mono'
                        )

        async def lookup() -> None:
            if not ws.authorized() or not consent.value:
                return
            problem.set_text('')
            selected_provider = str(provider.value)
            consent.set_value(False)
            fetch.disable()
            try:
                await request_lookup(ws.sessions, cve, selected_provider)
                if ws.authorized():
                    show()
            except LookupThrottled as exc:
                problem.set_text(str(exc))
            except Exception as exc:  # Surface any failure to the analyst.
                if ws.authorized():
                    problem.set_text(f'The lookup did not work. Lookup failed: {exc}')
            finally:
                fetch.set_enabled(bool(consent.value))

        show()
        problem = problem_area()
        with ui.row():
            ui.button('Close', on_click=dialog.close).props('flat')
            fetch = ui.button('Fetch from provider', on_click=lookup).bind_enabled_from(consent, 'value')
    dialog.open()

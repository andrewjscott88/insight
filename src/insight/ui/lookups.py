"""Automatic CVE lookups in the Sources tab: one switch per provider, and how many CVEs wait (ADR 0023)."""

from __future__ import annotations

from datetime import UTC, datetime

from nicegui import ui

from .. import services
from ..cve_scores import NVD_NOTICE
from ..lookups import NAMES
from .messages import tell
from .typography import heading
from .workspace import Workspace


def build_lookup_switches(ws: Workspace) -> None:
    def switch(provider: str, on: bool) -> None:
        if not ws.authorized():
            return
        with ws.write() as db:
            services.set_lookup_switch(db, provider, on, at=datetime.now(UTC))
        status.refresh()
        if on:
            tell(
                f'Insight will look up CVEs at {NAMES[provider]} by itself. It sends only CVE numbers.',
                'success',
            )
        else:
            tell(f'Automatic lookups at {NAMES[provider]} are off.', 'success')

    @ui.refreshable
    def status() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            switches = services.lookup_switches(db)
            waiting = services.lookup_backlog(db, at=datetime.now(UTC))
        for provider in ('nvd', 'epss'):
            if switches[provider]:
                count = waiting[provider]
                text = 'all looked up' if not count else f'{count} CVE(s) waiting, newest reports first'
                ui.label(f'{NAMES[provider]}: {text}').classes('muted text-sm')

    with ws.read() as db:
        switches = services.lookup_switches(db)
    ws.on_refresh(status.refresh)
    heading('Automatic CVE lookups', 3, 'subsection-title mt-6')
    ui.label(
        'Insight can look up each CVE that your TLP:CLEAR or GREEN reports mention, without a click: how '
        'severe it is at NIST NVD, and how likely an attack is soon at FIRST EPSS. It sends only the CVE '
        'number. A CVE seen only in AMBER or RED reports is never looked up by itself, because a lookup '
        'shows the provider that someone is interested in it.'
    ).classes('muted prose')
    ui.label(NVD_NOTICE).classes('muted text-sm prose')
    for provider, label in (
        ('nvd', 'Look up severity at NIST NVD by itself'),
        ('epss', 'Look up attack likelihood at FIRST EPSS by itself'),
    ):
        ui.switch(label, value=switches[provider], on_change=lambda e, p=provider: switch(p, bool(e.value)))
    if not ws.app.state.settings.run_jobs:
        ui.label('This server does not look anything up by itself (INSIGHT_RUN_JOBS is off).').classes(
            'text-warn'
        )
    with ui.column().classes('gap-0'):
        status()

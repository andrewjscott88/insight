"""Organisation watch terms: transparent literal matches that highlight relevant reporting, and alerts."""

from __future__ import annotations

from nicegui import ui

from .. import services
from ..permissions import Permission
from .alerts import build_alerts
from .messages import tell
from .typography import heading
from .workspace import Workspace


def build_watch_terms(ws: Workspace) -> None:
    def remove(term_id: str) -> None:
        if not ws.allowed(Permission.REQUIREMENTS):
            return
        with ws.write(Permission.REQUIREMENTS) as db:
            services.remove_watch_term(db, term_id)
        ws.refresh_all()

    @ui.refreshable
    def watch_terms() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            terms = [(t.id, t.term) for t in services.list_watch_terms(db)]
        if not terms:
            ui.label('No watch terms yet. Add a product, vendor, campaign, or technology.').classes(
                'muted text-sm'
            )
        for term_id, term in terms:
            with ui.row().classes('w-full items-center justify-between panel p-3'):
                ui.label(term).classes('break-value')
                if ws.can(Permission.REQUIREMENTS):
                    ui.button('Remove', on_click=lambda term_id=term_id: remove(term_id)).props(
                        'flat dense'
                    ).classes('text-xs')

    def add() -> None:
        if not ws.allowed(Permission.REQUIREMENTS):
            return
        try:
            with ws.write(Permission.REQUIREMENTS) as db:
                created = services.add_watch_term(db, term_input.value or '')
        except ValueError as exc:
            term_input.error = str(exc)
            tell(str(exc), 'warning')
            return
        if created is None:
            tell('That watch term already exists.', 'warning')
            return
        term_input.set_value('')
        ws.refresh_all()

    ws.on_refresh(watch_terms.refresh)
    heading('Watch terms', 2)
    ui.label(
        'Reports that contain one of these words are marked in the inbox. Capital letters do not matter. '
        'A match is a lead to follow, not a risk score.'
    ).classes('muted prose')
    with ui.row().classes('w-full items-center'):
        term_input = (
            ui.input('Watch term', placeholder='e.g. Palo Alto, VPN, identity')
            .props('outlined maxlength=120')
            .classes('flex-1')
        )
        if ws.can(Permission.REQUIREMENTS):
            ui.button('Add watch term', on_click=add)
    with ui.column().classes('w-full gap-3 mt-4'):
        watch_terms()
    build_alerts(ws)

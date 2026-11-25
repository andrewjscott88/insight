"""A narrow-screen activity list and deliberate campaign association editor."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..permissions import Permission
from ..schemas import ActorCampaignInput
from ..threat_guide import ThreatGuide
from .actors import _labels
from .messages import problem_area, tell
from .typography import heading, new_tab_link
from .workspace import Workspace


def render_actor_timeline(ws: Workspace, guide: ThreatGuide, refresh: Callable[[], Any]) -> None:
    heading('Activity timeline', 3, 'subsection-title mt-3')
    ui.label(
        'Dates show source activity, when a report was added, or an analyst action. '
        'A mention or sighting does not prove who was responsible.'
    ).classes('muted prose')
    timeline = guide.data.timeline
    if timeline is None or not timeline.events:
        ui.label('No dated events in this period.').classes('muted')
    else:
        for event in timeline.events:
            with ui.column().classes('panel w-full min-w-0 p-3 gap-1'):
                ui.label(f'{event.at[:10]} · {event.source} · TLP:{event.tlp}').classes('text-sm break-value')
                if event.url:
                    new_tab_link(event.title, event.url)
                else:
                    ui.label(event.title).classes('font-medium break-value')
                ui.label(event.detail).classes('text-sm prose break-value')
        if timeline.truncated:
            ui.label('This is a bounded view; more events may be available.').classes('muted prose')
    new_tab_link('Download activity timeline (JSON)', f'/api/actors/{guide.data.subject.ref}/timeline')
    ui.button('Link a campaign', on_click=lambda: _manage(ws, guide.data.subject.ref, refresh)).props(
        'outline no-caps'
    )


def _manage(ws: Workspace, ref: str, refresh: Callable[[], Any]) -> None:
    if not ws.authorized():
        return
    ceiling = ws.app.state.settings.max_tlp
    labels, start = _labels(ws)
    with (
        ui.dialog().props('aria-label="Campaign associations"') as dialog,
        ui.card().classes('dialog-card w-full'),
    ):
        heading('Campaign associations', 2)
        ui.label(
            'Only link a campaign when your evidence supports this association. '
            'Shared reports or indicators do not create a link.'
        ).classes('muted prose')
        query = ui.input('Find a campaign').props('outlined debounce=200 maxlength=120')
        note = ui.textarea('Why this campaign is linked').props('outlined maxlength=2000')
        label = ui.select(labels, value=start, label='Association sharing label').props('outlined')
        error = problem_area()

        @ui.refreshable
        def current() -> None:
            with ws.read() as db:
                rows = services.actor_campaigns(db, ref, max_tlp=ceiling)
            for row in rows:
                ui.label(f'{row.name} · TLP:{row.tlp}').classes('break-value')

                def remove(campaign_id: str = row.campaign_id) -> None:
                    if not ws.allowed(Permission.NOTES_AND_LINKS):
                        return
                    try:
                        with ws.write(Permission.NOTES_AND_LINKS) as db:
                            services.unlink_actor_campaign(db, ref, campaign_id, max_tlp=ceiling)
                    except LookupError as exc:
                        error.set_text(str(exc))
                        return
                    current.refresh()
                    dialog.close()
                    refresh()
                    tell('Campaign association removed.', 'success')

                ui.button('Remove campaign association', on_click=remove).props('flat no-caps')

        def add(campaign_id: str) -> None:
            if not ws.allowed(Permission.NOTES_AND_LINKS):
                return
            try:
                payload = ActorCampaignInput.model_validate(
                    {'campaign_id': campaign_id, 'note': note.value or '', 'tlp': label.value}
                )
                with ws.write(Permission.NOTES_AND_LINKS) as db:
                    services.link_actor_campaign(db, ref, payload, max_tlp=ceiling)
            except (LookupError, ValueError, ValidationError) as exc:
                error.set_text(str(exc))
                return
            current.refresh()
            dialog.close()
            refresh()
            tell('Campaign association saved.', 'success')

        @ui.refreshable
        def matches() -> None:
            term = (query.value or '').strip()
            if not term or not ws.authorized():
                return
            with ws.read() as db:
                rows = services.list_campaigns(db, max_tlp=ceiling, q=term, limit=12)
            for row in rows:
                ui.button(f'Link campaign: {row.name}', on_click=lambda cid=row.id: add(cid)).props(
                    'flat no-caps'
                )

        query.on_value_change(lambda _: matches.refresh())
        matches()
        current()
        ui.button('Close', on_click=dialog.close).props('flat')
    dialog.open()

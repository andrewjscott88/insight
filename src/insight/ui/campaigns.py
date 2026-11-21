"""Choose local actors and campaigns and manage the links an analyst records."""

from __future__ import annotations

from collections.abc import Callable

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..attack import search
from ..schemas import CampaignInput, ThreatLinkInput, ThreatSubjectKind, ThreatTargetKind
from .actors import _labels
from .messages import problem_area, tell
from .typography import heading
from .workspace import Workspace


def _new_campaign(ws: Workspace, saved: Callable[[], object]) -> None:
    if not ws.authorized():
        return
    labels, start = _labels(ws)
    with ui.dialog().props('aria-label="New campaign"') as dialog, ui.card().classes('dialog-card w-full'):
        heading('New campaign', 2)
        name = ui.input('Campaign name').props('outlined maxlength=120')
        aliases = ui.input('Other names, split by commas').props('outlined')
        description = ui.textarea('Description').props('outlined maxlength=5000')
        label = ui.select(labels, value=start, label='Sharing label').props('outlined')
        error = problem_area()

        def save() -> None:
            if not ws.authorized():
                return
            try:
                item = CampaignInput.model_validate(
                    {
                        'name': name.value or '',
                        'aliases': [v.strip() for v in (aliases.value or '').split(',') if v.strip()],
                        'description': description.value or '',
                        'tlp': label.value,
                    }
                )
                with ws.write() as db:
                    services.create_campaign(db, item, max_tlp=ws.app.state.settings.max_tlp)
            except (ValidationError, ValueError):
                error.set_text('Check the name, other names, and sharing label.')
                return
            dialog.close()
            saved()
            tell('Campaign saved.', 'success')

        with ui.row():
            ui.button('Save campaign', on_click=save)
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()


def _targets(ws: Workspace, kind: str, text: str) -> list[tuple[str, str]]:
    limit = ws.app.state.settings.max_tlp
    if kind == 'technique':
        return [(t.id, f'{t.id} · {t.full_name}') for t in search(text, 12)]
    with ws.read() as db:
        if kind == 'indicator':
            return [(e.id, e.value) for e, _ in services.list_entities(db, text, limit=12, max_tlp=limit)]
        return [
            (d.id, d.title)
            for d in services.search_documents(db, services.DocumentQuery(q=text, limit=12, max_tlp=limit))
        ]


def _manage(ws: Workspace, kind: ThreatSubjectKind, ref: str, name: str) -> None:
    if not ws.authorized():
        return
    labels, start = _labels(ws)
    ceiling = ws.app.state.settings.max_tlp
    with ui.dialog().props('aria-label="Manage links"') as dialog, ui.card().classes('dialog-card w-full'):
        heading(name, 2)
        choices: dict[ThreatTargetKind, str] = {
            'document': 'Report',
            'indicator': 'Indicator',
            'technique': 'Technique',
        }
        target = ui.select(choices, value='document', label='Link to').props('outlined')
        query = ui.input('Find a report, indicator, or technique').props(
            'outlined debounce=200 maxlength=120'
        )
        label = ui.select(labels, value=start, label='Link sharing label').props('outlined')
        error = problem_area()
        results = ui.column().classes('w-full').props('aria-live=polite')
        offset = 0

        @ui.refreshable
        def current() -> None:
            with ws.read() as db:
                rows = services.list_threat_links(db, kind, ref, max_tlp=ceiling, offset=offset, limit=21)
            heading('Saved links', 3)
            if not rows:
                ui.label('No saved links on this page.').classes('muted')
            for row in rows[:20]:
                with ui.row().classes('items-center'):
                    ui.label(f'{row.name} · TLP:{row.tlp}').classes('break-value')

                    def remove(link: services.ThreatLinkView = row) -> None:
                        if not ws.authorized():
                            return
                        try:
                            with ws.write() as db:
                                services.unlink_threat(
                                    db, kind, ref, link.target_kind, link.target_id, max_tlp=ceiling
                                )
                        except LookupError as exc:
                            error.set_text(str(exc))
                        current.refresh()

                    ui.button('Remove link', on_click=remove).props('flat dense no-caps')

            def page(step: int) -> None:
                nonlocal offset
                offset = max(0, offset + step)
                current.refresh()

            with ui.row():
                if offset:
                    ui.button('Previous links', on_click=lambda: page(-20)).props('flat')
                if len(rows) > 20:
                    ui.button('More links', on_click=lambda: page(20)).props('flat')

        def add(target_id: str) -> None:
            if not ws.authorized():
                return
            try:
                item = ThreatLinkInput.model_validate(
                    {'target_kind': target.value, 'target_id': target_id, 'tlp': label.value}
                )
                with ws.write() as db:
                    services.link_threat(db, kind, ref, item, max_tlp=ceiling)
            except (LookupError, ValueError) as exc:
                error.set_text(str(exc))
                return
            query.set_value('')
            current.refresh()
            tell('Link saved.', 'success')

        def matches() -> None:
            results.clear()
            text = (query.value or '').strip()
            if not ws.authorized() or not text:
                return
            with results:
                for target_id, shown in _targets(ws, target.value, text):
                    ui.button(f'Link {shown}', on_click=lambda r=target_id: add(r)).props(
                        'flat dense no-caps'
                    )

        target.on_value_change(lambda _: matches())
        query.on_value_change(lambda _: matches())
        current()
        ui.button('Close', on_click=dialog.close)
    dialog.open()


def render_tracked_threats(ws: Workspace) -> None:
    with ui.expansion('Actors and campaigns you track').classes('w-full'):
        ui.label('Choose a record to link a report, indicator, or technique to it.').classes('muted prose')
        text = ui.input('Find a tracked name').props('outlined debounce=200 maxlength=120')

        @ui.refreshable
        def records() -> None:
            term = (text.value or '').strip()
            with ws.read() as db:
                ceiling = ws.app.state.settings.max_tlp
                actors = [
                    a
                    for a in services.list_actors(db, max_tlp=ceiling)
                    if term.casefold() in a.name.casefold()
                ]
                campaigns = services.list_campaigns(db, max_tlp=ceiling, q=term, limit=12)
                options: list[tuple[ThreatSubjectKind, str, str]] = [
                    ('actor', a.id, a.name) for a in actors[:12]
                ]
                options.extend(('campaign', c.id, c.name) for c in campaigns)
            for kind, ref, name in options:
                ui.button(
                    f'{name} ({kind})', on_click=lambda k=kind, r=ref, n=name: _manage(ws, k, r, n)
                ).props('flat dense no-caps')

        ui.button('New campaign', on_click=lambda: _new_campaign(ws, records.refresh)).props(
            'outline no-caps'
        )
        text.on_value_change(lambda _: records.refresh())
        records()

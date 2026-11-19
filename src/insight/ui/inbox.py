"""Intelligence inbox: filters, document list and the evidence-first document reader."""

from __future__ import annotations

from typing import Any

from nicegui import ui

from .. import services
from ..demo import seed
from ..schemas import DOCUMENT_STATUSES, TLP_LEVELS
from .messages import tell
from .mobile import show_reader
from .reader import ReaderActions, render_empty, render_report
from .theme import tlp_badge
from .typography import heading
from .workspace import ALL_STATUSES, ALL_TLP, Workspace


def build_inbox(ws: Workspace) -> None:
    """Render the inbox tab: a filterable list on the left and the document reader on the right."""
    state = ws.state

    def choose(document_id: str) -> None:
        state.selected = document_id
        document_list.refresh()
        document_detail.refresh()
        show_reader()  # On a phone the reader is below the list: bring the report into view.

    ws.open_document = choose

    def review_document(doc_id: str, status: str) -> None:
        if not ws.authorized() or status not in DOCUMENT_STATUSES:
            return
        with ws.write() as db:
            found = services.set_document_status(db, doc_id, status) is not None
        if not found:
            tell('This item no longer exists.', 'warning')
            return
        ws.refresh_all()

    def review_observation(obs_id: str, status: str) -> None:
        if not ws.authorized():
            return
        with ws.write() as db:
            found = services.set_observation_status(db, obs_id, status) is not None
        if not found:
            tell('This item no longer exists.', 'warning')
            return
        ws.refresh_all()

    def current_query() -> services.DocumentQuery:
        return services.DocumentQuery(
            q=state.q,
            status=None if state.status == ALL_STATUSES else state.status,
            tlp=None if state.tlp == ALL_TLP else state.tlp,
            include_superseded=state.include_superseded,
            limit=services.MAX_PAGE_SIZE,
        )

    @ui.refreshable
    def document_list() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            docs = services.search_documents(db, current_query())
            terms = [t.term for t in services.list_watch_terms(db)]
            rows: list[dict[str, Any]] = [
                {**row, 'matches': services.watch_matches(terms, doc.title + ' ' + doc.body)}
                for row, doc in zip(services.summaries(db, docs), docs, strict=True)
            ]
        ui.label(f'{len(rows)} sources shown · newest first').classes('muted text-sm')
        if not rows:
            ui.label('No reports match. Add a report, or load the demo to try Insight.').classes(
                'muted p-2 prose'
            )
        for row in rows:
            selected = ' source-selected' if row['id'] == state.selected else ''
            with ui.column().classes('source-card gap-2' + selected):
                with ui.row().classes('w-full items-center justify-between'):
                    tlp_badge(row['tlp'])
                    status = row['status'] if row['is_current'] else f'{row["status"]} · superseded'
                    ui.label(status).classes('muted text-sm')
                ui.button(row['title'], on_click=lambda document_id=row['id']: choose(document_id)).props(
                    'flat no-caps align=left'
                ).classes('text-left p-0 w-full')
                if row['matches']:
                    ui.label('Watch matches: ' + ', '.join(row['matches'])).classes('text-primary text-sm')
                ui.label(row['summary']).classes('muted text-sm line-clamp-2 break-value')
                ui.label(
                    f'{row["source_name"]} · {row["entity_count"]} entities · {row["created_at"][:10]}'
                ).classes('muted text-sm')

    @ui.refreshable
    def document_detail() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            doc = services.get_document(db, state.selected) if state.selected else None
            data = services.detail(db, doc) if doc else None
        if data:
            render_report(ws, data, actions)
        else:
            render_empty()

    actions = ReaderActions(
        choose=choose,
        review_document=review_document,
        review_observation=review_observation,
        refresh=document_detail.refresh,
    )

    def set_filter(**changes: Any) -> None:
        for key, value in changes.items():
            setattr(state, key, value if value is not None else '')
        document_list.refresh()

    def seed_demo() -> None:
        if not ws.authorized():
            return
        with ws.write() as db:
            added = seed(db)
            newest = services.search_documents(db, services.DocumentQuery(limit=1))
            state.selected = newest[0].id if newest else None
        ws.refresh_all()
        tell(
            f'Synthetic demo loaded: {added} new reports. They are made up for practice, not real threats.',
            'success',
        )

    ws.on_refresh(document_list.refresh)
    ws.on_refresh(document_detail.refresh)

    with ui.row().classes('w-full items-start gap-5 flex-wrap lg:flex-nowrap'):
        list_pane = 'panel document-list-pane p-3 sm:p-4 w-full lg:w-[22rem] lg:shrink-0 gap-3'
        with ui.column().classes(list_pane):
            with ui.row().classes('w-full justify-between items-center'):
                heading('Reports', 2)
                ui.button('Load demo', on_click=seed_demo).props('flat dense no-caps')
            ui.input('Search intelligence', on_change=lambda e: set_filter(q=e.value)).props(
                'outlined debounce=300 clearable'
            ).classes('w-full')
            with ui.column().classes('w-full gap-3'):
                ui.select(
                    [ALL_STATUSES, *DOCUMENT_STATUSES],
                    value=ALL_STATUSES,
                    label='Status',
                    on_change=lambda e: set_filter(status=e.value),
                ).props('outlined').classes('w-full')
                ui.select(
                    [ALL_TLP, *TLP_LEVELS],
                    value=ALL_TLP,
                    label='TLP label',
                    on_change=lambda e: set_filter(tlp=e.value),
                ).props('outlined').classes('w-full')
            ui.switch(
                'Include superseded revisions',
                on_change=lambda e: set_filter(include_superseded=bool(e.value)),
            )
            # Markers give tests (and future browser automation) stable, unambiguous anchors.
            list_classes = 'document-list w-full gap-3 max-h-[60vh] lg:max-h-[900px] overflow-auto'
            with ui.column().classes(list_classes).mark('document-list'):
                document_list()
        reader_classes = 'panel document-reader p-4 sm:p-6 flex-1 min-w-0 w-full gap-3'
        with ui.column().classes(reader_classes).mark('document-detail'):
            document_detail()

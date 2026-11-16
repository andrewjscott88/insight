"""Intelligence inbox: filters, document list and the evidence-first document reader."""

from __future__ import annotations

from typing import Any

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..demo import seed
from ..schemas import DOCUMENT_STATUSES, TLP_LEVELS, NoteInput
from .enrichment import open_enrichment_dialog
from .theme import tlp_badge
from .workspace import ALL_STATUSES, ALL_TLP, Workspace


def build_inbox(ws: Workspace) -> None:
    """Render the inbox tab: a filterable list on the left and the document reader on the right."""
    state = ws.state

    def choose(document_id: str) -> None:
        state.selected = document_id
        document_list.refresh()
        document_detail.refresh()

    ws.open_document = choose

    def review_document(doc_id: str, status: str) -> None:
        if not ws.authorized() or status not in DOCUMENT_STATUSES:
            return
        with ws.write() as db:
            found = services.set_document_status(db, doc_id, status) is not None
        if not found:
            ui.notify('This item no longer exists.', type='warning')
            return
        ws.refresh_all()

    def review_observation(obs_id: str, status: str) -> None:
        if not ws.authorized():
            return
        with ws.write() as db:
            found = services.set_observation_status(db, obs_id, status) is not None
        if not found:
            ui.notify('This item no longer exists.', type='warning')
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
        ui.label(f'{len(rows)} sources shown · newest first').classes('muted text-xs')
        if not rows:
            ui.label('No sources match. Ingest a document or load the synthetic demo to begin.').classes(
                'muted p-4'
            )
        for row in rows:
            selected = ' source-selected' if row['id'] == state.selected else ''
            with ui.column().classes('source-card gap-2' + selected):
                with ui.row().classes('w-full items-center justify-between'):
                    tlp_badge(row['tlp'])
                    status = row['status'] if row['is_current'] else f'{row["status"]} · superseded'
                    ui.label(status).classes('muted text-xs')
                ui.button(row['title'], on_click=lambda document_id=row['id']: choose(document_id)).props(
                    'flat no-caps align=left'
                ).classes('text-left p-0 w-full text-sm')
                if row['matches']:
                    ui.label('Watch matches: ' + ', '.join(row['matches'])).classes('text-primary text-xs')
                ui.label(row['summary']).classes('muted text-xs line-clamp-2 break-value')
                ui.label(
                    f'{row["source_name"]} · {row["entity_count"]} entities · {row["created_at"][:10]}'
                ).classes('muted text-xs')

    def render_revisions(data: dict[str, Any]) -> None:
        if not data['is_current']:
            current = next((r for r in data['revisions'] if r['is_current']), None)
            with ui.row().classes('w-full items-center gap-3 panel p-3'):
                ui.label('Superseded revision. The publisher has since changed this item.').classes(
                    'text-amber-300 text-xs'
                )
                if current is not None:
                    ui.button(
                        'Open current revision', on_click=lambda doc_id=current['id']: choose(doc_id)
                    ).props('flat dense').classes('text-xs')
        if len(data['revisions']) > 1:
            with ui.expansion(f'Revisions · {len(data["revisions"])}').classes('w-full text-xs muted'):
                for rev in data['revisions']:
                    marker = ' · current' if rev['is_current'] else ''
                    here = ' · viewing' if rev['id'] == data['id'] else ''
                    ui.button(
                        f'{rev["created_at"][:16].replace("T", " ")}{marker}{here}',
                        on_click=lambda doc_id=rev['id']: choose(doc_id),
                    ).props('flat dense no-caps align=left').classes('text-xs')

    @ui.refreshable
    def document_detail() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            doc = services.get_document(db, state.selected) if state.selected else None
            data = services.detail(db, doc) if doc else None
        if not data:
            with ui.column().classes('items-center justify-center w-full min-h-[350px] p-8 text-center'):
                ui.label('✳').classes('text-5xl text-primary')
                ui.label('Your intelligence, connected.').classes('text-xl')
                ui.label(
                    'Select a source to inspect reporting, extracted entities, and supporting evidence.'
                ).classes('muted max-w-sm')
            return
        tlp_badge(data['tlp'])
        ui.label(data['title']).classes('text-2xl font-medium break-value')
        if data['truncated']:
            ui.label(
                'Truncated by the connector: the publisher text was longer than the stored summary, so the '
                'full report may contain more indicators. Open the original source.'
            ).classes('text-amber-300 text-xs')
        ui.label(f'{data["source_name"]} · {data["created_at"][:10]}').classes('muted text-xs')
        if data['source_url']:
            ui.link('Open original source ↗', data['source_url'], new_tab=True).classes('text-xs')
        render_revisions(data)
        ui.select(
            list(DOCUMENT_STATUSES),
            value=data['status'],
            label='Document review',
            on_change=lambda event: review_document(data['id'], event.value),
        ).props('outlined dense').classes('w-52')
        ui.label('SOURCE REPORTING').classes('eyebrow mt-3')
        ui.label(data['body']).classes('source-body w-full panel p-4')
        ui.label(f'EXTRACTED OBSERVATIONS · {len(data["observations"])}').classes('eyebrow mt-4')
        ui.label('Deterministic extraction is not a verdict. Review the evidence before accepting.').classes(
            'muted text-xs'
        )
        if not data['observations']:
            ui.label('No supported indicators were found in this source.').classes('muted')
        for obs in data['observations']:
            render_observation(obs)
        with ui.row().classes('gap-4 text-xs'):
            ui.link('Download local JSON export ↗', f'/api/documents/{data["id"]}/export', new_tab=True)
            report_iocs = f'/api/iocs/export?document_id={data["id"]}'
            ui.link("Export this report's IOCs ↗", report_iocs, new_tab=True)
        ui.label('Exports preserve TLP metadata; they do not grant sharing permission.').classes(
            'muted text-xs'
        )
        render_notes(data)
        with ui.expansion('Provenance & integrity').classes('w-full text-xs muted'):
            ui.label('SHA-256: ' + data['content_hash']).classes('break-value font-mono text-xs')
            ui.label('Extractor: ' + data['extractor_version'])
            if data['source_key']:
                ui.label(f'Source item: {data["source_key"]} / {data["external_id"]}').classes('break-value')

    def render_observation(obs: dict[str, Any]) -> None:
        with ui.column().classes('panel w-full p-4 gap-2'):
            with ui.row().classes('items-center w-full'):
                ui.badge(obs['kind']).props('outline')
                ui.label(obs['value']).classes('font-mono text-sm break-value flex-1')
            ui.label(obs['evidence']).classes('evidence text-xs w-full')
            ui.label(
                f'Source offsets {obs["start_offset"]}–{obs["end_offset"]} · {obs["review_status"]}'
            ).classes('muted text-xs')
            if kev := obs.get('kev'):
                ui.label(f'CISA KEV match · added {kev["date_added"]} · due {kev["due_date"]}').classes(
                    'text-amber-300 text-xs'
                )
                ui.label(kev['required_action']).classes('muted text-xs')
            if obs['kind'] == 'cve':
                ui.button(
                    'Optional CVE enrichment ↗',
                    on_click=lambda cve=obs['value']: open_enrichment_dialog(ws, cve),
                ).props('flat dense').classes('text-xs')
            with ui.row().classes('gap-2'):
                for value, label in (('accepted', 'Accept'), ('rejected', 'Reject'), ('unreviewed', 'Reset')):
                    ui.button(
                        label, on_click=lambda oid=obs['id'], status=value: review_observation(oid, status)
                    ).props('dense outline' if obs['review_status'] != value else 'dense').classes('text-xs')

    def render_notes(data: dict[str, Any]) -> None:
        ui.label('ANALYST NOTES').classes('eyebrow mt-4')
        for note in data['notes']:
            with ui.column().classes('panel p-3 w-full gap-1'):
                ui.label(note['body']).classes('text-sm whitespace-pre-wrap break-value')
                ui.label(note['created_at'][:16].replace('T', ' ')).classes('muted text-xs')
        doc_id = data['id']
        note_input = (
            ui.textarea(
                'Add a note',
                placeholder='Record context, assessment, or next steps…',
                value=state.note_drafts.get(doc_id, ''),
                on_change=lambda e: state.note_drafts.__setitem__(doc_id, e.value or ''),
            )
            .props('outlined autogrow maxlength=10000')
            .classes('w-full')
        )

        def save_note() -> None:
            if not ws.authorized():
                return
            try:
                item = NoteInput(body=note_input.value or '')
            except ValidationError:
                ui.notify('Enter a note between 1 and 10,000 characters.', type='warning')
                return
            with ws.write() as db:
                saved = services.add_note(db, doc_id, item.body) is not None
            if not saved:
                ui.notify('This item no longer exists.', type='warning')
                return
            state.note_drafts.pop(doc_id, None)
            document_detail.refresh()
            ui.notify('Note saved.')

        ui.button('Save note', on_click=save_note).props('outline')

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
        ui.notify(f'Synthetic demo loaded: {added} new reports. No live threat claims.')

    ws.on_refresh(document_list.refresh)
    ws.on_refresh(document_detail.refresh)

    with ui.row().classes('w-full items-start gap-5 flex-wrap lg:flex-nowrap'):
        with ui.column().classes('panel p-4 w-full lg:w-[340px] lg:shrink-0 gap-3'):
            with ui.row().classes('w-full justify-between items-center'):
                ui.label('Source reporting').classes('font-medium')
                ui.button('Load demo', on_click=seed_demo).props('flat dense').classes('text-xs')
            ui.input('Search intelligence', on_change=lambda e: set_filter(q=e.value)).props(
                'outlined dense debounce=300 clearable'
            ).classes('w-full')
            with ui.row().classes('w-full gap-2'):
                ui.select(
                    [ALL_STATUSES, *DOCUMENT_STATUSES],
                    value=ALL_STATUSES,
                    on_change=lambda e: set_filter(status=e.value),
                ).props('outlined dense').classes('flex-1')
                ui.select(
                    [ALL_TLP, *TLP_LEVELS], value=ALL_TLP, on_change=lambda e: set_filter(tlp=e.value)
                ).props('outlined dense').classes('flex-1')
            ui.switch(
                'Include superseded revisions',
                on_change=lambda e: set_filter(include_superseded=bool(e.value)),
            ).classes('text-xs muted')
            # Markers give tests (and future browser automation) stable, unambiguous anchors.
            with ui.column().classes('w-full gap-3 max-h-[900px] overflow-auto').mark('document-list'):
                document_list()
        with ui.column().classes('panel p-6 flex-1 min-w-0 w-full gap-3').mark('document-detail'):
            document_detail()

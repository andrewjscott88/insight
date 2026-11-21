"""MITRE ATT&CK® techniques in the workspace: the reader's section, the dialog that adds one, and the tab.

Insight tags a report with the technique IDs written in it; the analyst adds and removes the rest (ADR 0019).
The tab shows which techniques current reports describe, grouped by tactic in matrix order, with pivots to the
reports that load when a technique is opened (as in the entity explorer) and a layer for ATT&CK Navigator.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from nicegui import ui

from .. import services
from ..attack import catalog, search
from .messages import tell
from .typography import heading, new_tab_link
from .workspace import Workspace

#: Period choices on the tab, in days (0: all time).
PERIODS: Final[dict[int, str]] = {
    7: 'Last 7 days',
    30: 'Last 30 days',
    90: 'Last 90 days',
    365: 'Last 12 months',
    0: 'All time',
}
SEARCH_RESULTS: Final = 20
PIVOT_PAGE: Final = 25
DIALOG_TITLE: Final = 'Add an ATT&CK technique'


def since(days: int) -> str | None:
    """The earliest ``created_at`` in a period of ``days`` days (``None``: all time)."""
    return services.stamp(datetime.now(UTC) - timedelta(days=days)) if days else None


# --------------------------------------------------------------------------- the report reader


def render_report_techniques(
    ws: Workspace, doc_id: str, tags: list[services.TechniqueTag], on_changed: Callable[[], Any]
) -> None:
    heading(f'ATT&CK techniques ({len(tags)})', 3, 'subsection-title mt-4')
    ui.label(
        'How the attackers in this report work, in MITRE ATT&CK terms. Insight adds the technique IDs '
        'written in the report. You add the rest.'
    ).classes('muted prose')
    if not tags:
        ui.label('No techniques on this report yet.').classes('muted')
    for tag in tags:
        _render_tag(ws, doc_id, tag, on_changed)
    ui.button(
        'Add a technique', icon='add', on_click=lambda: open_technique_dialog(ws, doc_id, on_changed)
    ).props('outline no-caps')


def _render_tag(
    ws: Workspace, doc_id: str, tag: services.TechniqueTag, on_changed: Callable[[], Any]
) -> None:
    def remove() -> None:
        if not ws.authorized():
            return
        try:
            with ws.write() as db:
                services.untag_technique(db, doc_id, tag.technique_id)
        except LookupError:
            tell('This item no longer exists.', 'warning')
            return
        on_changed()
        tell(f'{tag.technique_id} removed. A new version of this report will not add it again.', 'success')

    with ui.column().classes('panel w-full p-3 gap-1'):
        with ui.row().classes('items-center w-full gap-2'):
            ui.badge(tag.technique_id).props('outline')
            ui.label(tag.name).classes('flex-1 break-value')
        if tag.tactics:
            ui.label('Tactic: ' + ', '.join(tag.tactics)).classes('muted text-sm')
        if tag.source == 'report':
            ui.label('The report names it here:').classes('muted text-sm')
            ui.label(tag.evidence).classes('evidence text-sm w-full')
        else:
            ui.label(f'Added by {tag.actor} on {tag.created_at[:10]}').classes('muted text-sm')
        if not tag.in_catalog:
            ui.label('This technique is no longer in ATT&CK.').classes('text-warn text-sm')
        with ui.row().classes('gap-x-6 gap-y-0 items-center'):
            if tag.in_catalog:
                new_tab_link(f'About {tag.technique_id} on the ATT&CK site', tag.url)
            ui.button('Remove', on_click=remove).props(
                f'flat dense no-caps aria-label="Remove {tag.technique_id}"'
            ).mark(f'remove-{tag.technique_id}')


def open_technique_dialog(ws: Workspace, doc_id: str, on_saved: Callable[[], Any]) -> None:
    if not ws.authorized():
        return
    with (
        ui.dialog().props(f'aria-label="{DIALOG_TITLE}"') as dialog,
        ui.card().classes('panel dialog-card w-[42rem] max-w-full p-6 gap-3'),
    ):
        heading(DIALOG_TITLE, 2)
        ui.label('Search by ID, such as T1566, or by a word in the name, such as phishing.').classes(
            'muted prose'
        )
        query = (
            ui.input('Technique ID or name')
            .props('outlined autofocus clearable debounce=250 maxlength=100')
            .classes('w-full')
        )
        results = ui.column().classes('w-full gap-1').props('aria-live=polite')

        def add(technique_id: str) -> None:
            if not ws.authorized():
                return
            try:
                with ws.write() as db:
                    services.tag_technique(db, doc_id, technique_id)
            except LookupError:
                dialog.close()
                tell('This item no longer exists.', 'warning')
                return
            except ValueError:
                tell('That is not a technique in this version of ATT&CK.', 'warning')
                return
            dialog.close()
            on_saved()
            tell(f'{technique_id} added to this report.', 'success')

        def show(value: str | None) -> None:
            results.clear()
            text = (value or '').strip()
            with results:
                if not text:
                    ui.label('Start typing to see matching techniques.').classes('muted text-sm')
                    return
                found = search(text, limit=SEARCH_RESULTS)
                if not found:
                    ui.label('No technique matches. Try fewer letters.').classes('muted text-sm')
                for match in found:
                    ui.button(
                        f'{match.id} · {match.full_name}', on_click=lambda tid=match.id: add(tid)
                    ).props('flat no-caps align=left').classes('w-full break-value')

        query.on_value_change(lambda event: show(event.value))
        show('')
        ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()


# --------------------------------------------------------------------------- the tab


def build_techniques(ws: Workspace) -> None:
    def render_page(container: ui.column, technique_id: str, offset: int, total: int) -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            docs = services.technique_documents(
                db, technique_id, since=since(ws.state.technique_days), offset=offset, limit=PIVOT_PAGE
            )
            rows = [(d.id, d.title, d.tlp, d.created_at) for d in docs]
        with container:
            for doc_id, title, tlp, created_at in rows:

                def open_source(document_id: str = doc_id) -> None:
                    ws.show_inbox()  # Before opening, so the reader is on screen when a phone scrolls to it.
                    ws.open_document(document_id)

                ui.button(f'{title} · TLP:{tlp} · {created_at[:10]}', on_click=open_source).props(
                    'flat no-caps align=left'
                ).classes('w-full')
            shown = offset + len(rows)
            if shown < total:
                more = ui.button(f'Show more ({total - shown} remaining)').props('flat dense no-caps')

                def load_more(button: ui.button = more, next_offset: int = shown) -> None:
                    button.delete()
                    render_page(container, technique_id, next_offset, total)

                more.on_click(load_more)

    def technique_row(count: services.TechniqueCount, name: str, url: str | None) -> None:
        expansion = ui.expansion(f'{count.technique_id} · {name} · {count.reports} report(s)').classes(
            'panel w-full break-value'
        )
        with expansion:
            ui.label(f'Newest report added on {count.last_seen[:10]}').classes('muted text-sm')
            if url:
                new_tab_link(f'About {count.technique_id} on the ATT&CK site', url)
            container = ui.column().classes('w-full gap-1')

        def on_open(event: Any, box: ui.column = container, found: services.TechniqueCount = count) -> None:
            if event.value and not box.default_slot.children:
                render_page(box, found.technique_id, 0, found.reports)

        expansion.on_value_change(on_open)

    @ui.refreshable
    def summary() -> None:
        if not ws.authorized():
            return
        days = ws.state.technique_days
        with ws.read() as db:
            counts = services.technique_summary(db, since=since(days))
        new_tab_link('Download a layer for ATT&CK Navigator', f'/api/attack/navigator?days={days}')
        if not counts:
            ui.label('No report from this time has a technique yet. Open a report to add one.').classes(
                'muted p-2'
            )
            return
        known = catalog()
        by_tactic: dict[str, list[services.TechniqueCount]] = {}
        retired: list[services.TechniqueCount] = []
        for count in counts:
            found = known.techniques.get(count.technique_id)
            if found is None:
                retired.append(count)
            for shortname in found.tactics if found else ():
                by_tactic.setdefault(shortname, []).append(count)
        for tactic in known.tactics:
            if items := by_tactic.get(tactic.shortname):
                heading(f'{tactic.name} ({len(items)})', 3, 'subsection-title mt-3')
                for count in items:
                    technique = known.techniques[count.technique_id]
                    technique_row(count, technique.full_name, technique.url)
        if retired:
            heading(f'No longer in ATT&CK ({len(retired)})', 3, 'subsection-title mt-3')
            for count in retired:
                technique_row(count, count.technique_id, None)

    def choose(days: int) -> None:
        ws.state.technique_days = days
        summary.refresh()

    ws.on_refresh(summary.refresh)
    heading('ATT&CK techniques', 2)
    ui.label(
        'The ways attackers work, as listed by MITRE ATT&CK, and how many of your reports describe each '
        'one. Insight counts the technique IDs written in reports and the ones you add. It never guesses '
        'them from the words.'
    ).classes('muted prose')
    ui.label(f'Uses version {catalog().version} of Enterprise ATT&CK.').classes('muted text-sm')
    ui.select(
        PERIODS, value=ws.state.technique_days, label='Reports added in', on_change=lambda e: choose(e.value)
    ).props('outlined').classes('w-60')
    with ui.column().classes('w-full gap-3'):
        summary()

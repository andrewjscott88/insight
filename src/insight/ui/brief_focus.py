"""Search saved intelligence for a focused brief, with explicit selection and linked evidence."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Final
from uuid import uuid4

from nicegui import ui

from .. import services
from .focus_choices import FOCUS_KINDS
from .messages import tell
from .theme import tlp_badge
from .typography import heading, new_tab_link
from .workspace import Workspace

if TYPE_CHECKING:
    from ..focused_brief import FocusedBrief

_ALL: Final = 'all'
_HINT: Final = 'Search for a sector, name, alias, flaw, report or source. Choose a match to see its brief.'


def build_brief_focus(ws: Workspace, changed: Callable[[tuple[str, str] | None], None]) -> None:
    """Keep search choices local; edits clear an old focus before another brief is shown."""
    matches: dict[str, tuple[str, str]] = {}
    active = False
    updating_matches = False
    with ui.column().classes('w-full min-w-0 gap-3').mark('brief-focus-search-panel'):
        with ui.row().classes('w-full gap-3 items-center'):
            kind = (
                ui.select({_ALL: 'All focus types', **FOCUS_KINDS}, value=_ALL, label='Search by')
                .props('outlined')
                .classes('w-full sm:w-60 min-w-0')
                .mark('brief-focus-kind')
            )
            query = (
                ui.input('Find intelligence', placeholder='Name, ID or keyword')
                .props('outlined clearable maxlength=120')
                .classes('w-full sm:w-auto sm:flex-1 min-w-0')
                .mark('brief-focus-query')
            )
            search = ui.button('Search', icon='search').mark('brief-focus-search')
            reset = ui.button('All intelligence').props('outline').mark('brief-focus-reset')
        hint = ui.label(_HINT).classes('muted prose').props('role=status aria-live=polite')
        with ui.row().classes('w-full gap-3 items-center') as result_row:
            match = (
                ui.select({}, label='Choose a match', with_input=True)
                .props('outlined clearable options-dense')
                .classes('w-full sm:w-auto sm:flex-1 min-w-0')
                .mark('brief-focus-match')
            )
            show = ui.button('Show brief', icon='article').mark('brief-focus-show')
        result_row.set_visibility(False)
        show.disable()

    def clear_matches() -> None:
        nonlocal updating_matches
        matches.clear()
        updating_matches = True
        try:
            match.set_options({}, value=None)
        finally:
            updating_matches = False
        show.disable()
        result_row.set_visibility(False)
        hint.set_text(_HINT)

    def invalidate() -> None:
        nonlocal active
        clear_matches()
        if active:
            active = False
            changed(None)

    def search_matches() -> None:
        if not ws.authorized():
            return
        invalidate()
        selected_kind = None if kind.value == _ALL else str(kind.value)
        if selected_kind is not None and selected_kind not in FOCUS_KINDS:
            tell('Choose a focus type from the list.', 'warning')
            return
        text = str(query.value or '').strip()[:120]
        if not text and selected_kind not in ('theme', 'industry'):
            hint.set_text('Enter a name or keyword, or choose Sector / Industry or Threat type to browse.')
            return
        with ws.read() as db:
            results = services.hunt_guide_choices(
                db, kind=selected_kind, q=text, max_tlp=ws.app.state.settings.max_tlp
            )
        options: dict[str, str] = {}
        for key, label in FOCUS_KINDS.items():
            for ref, name in results.get(key, [])[: 5 if selected_kind is None else 50]:
                option_id = uuid4().hex
                matches[option_id] = (key, ref)
                options[option_id] = f'{label} · {name}' if selected_kind is None else name
        if not options:
            hint.set_text('No matches in your saved intelligence. Try another search or import a report.')
            return
        match.set_options(options, value=None)
        result_row.set_visibility(True)
        hint.set_text(
            'Up to 5 matches per type. Choose a type or narrow your search to find more.'
            if selected_kind is None
            else 'Up to 50 matches. Narrow your search if you cannot see what you need.'
        )

    def choose_kind() -> None:
        invalidate()
        if kind.value in ('theme', 'industry') and not str(query.value or '').strip():
            search_matches()

    def show_brief() -> None:
        nonlocal active
        if not ws.authorized():
            return
        selected = matches.get(str(match.value))
        if selected is not None:
            active = True
            changed(selected)

    def choose_match() -> None:
        nonlocal active
        show.set_enabled(str(match.value) in matches)
        if active and not updating_matches:
            active = False
            changed(None)

    def all_intelligence() -> None:
        nonlocal active
        if not ws.authorized():
            return
        active = False
        query.set_value('')
        kind.set_value(_ALL)
        clear_matches()
        changed(None)

    kind.on_value_change(choose_kind)
    query.on_value_change(invalidate)
    query.on('keydown.enter', search_matches)
    match.on_value_change(choose_match)
    search.on_click(search_matches)
    show.on_click(show_brief)
    reset.on_click(all_intelligence)
    ws.on_refresh(clear_matches)


def render_focused_brief(ws: Workspace, result: FocusedBrief) -> None:
    """Render only the bounded brief and its evidence, never the longer hunt-guide sections."""

    def open_report(document_id: str) -> None:
        if not ws.authorized():
            return
        ws.show_inbox()
        ws.open_document(document_id)
        ui.run_javascript(
            'setTimeout(() => {'
            "const behavior = matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';"
            "document.querySelector('.document-reader')?.scrollIntoView({behavior, block: 'start'});"
            '}, 150);'
        )

    with ui.column().classes('summary-box w-full min-w-0 gap-3 p-4 sm:p-5').mark('focused-brief'):
        heading(result.title, 2)
        with ui.row().classes('w-full gap-3 items-center'):
            period = (
                f'Report window: last {result.days} days'
                if result.kind in ('actor', 'industry')
                else f'Last {result.days} days'
            )
            ui.label(period).classes('muted').mark('focused-brief-period')
            tlp_badge(result.tlp)
        with ui.element('ul').classes('w-full min-w-0 list-disc pl-5 m-0 space-y-2'):
            for line in result.summary[:3]:
                with ui.element('li').classes('min-w-0'):
                    ui.label(line).classes('brief-prose prose break-value')
        if result.sections:
            with ui.column().classes('w-full min-w-0 gap-5 mt-2').mark('focused-brief-profile'):
                for section in result.sections[:8]:
                    if not section.lines:
                        continue
                    with ui.column().classes('w-full min-w-0 gap-2'):
                        heading(section.title, 3)
                        for line in section.lines[:6]:
                            ui.label(line).classes('prose break-value')
        reports = [item for item in result.reports[:5] if item.document_id]
        if reports:
            heading('Supporting reports', 3)
            for item in reports:
                ui.button(
                    f'{item.title} · {item.source_name}' + (f' · {item.relevance}' if item.relevance else ''),
                    on_click=lambda doc_id=item.document_id: open_report(doc_id),
                ).props('flat dense no-caps align=left').classes(
                    'brief-evidence w-full break-value text-left'
                )
        if result.sources:
            heading('Sources', 3)
            with ui.row().classes('w-full gap-x-6 gap-y-1 items-center').mark('focused-brief-sources'):
                for source in result.sources[:6]:
                    if source.url.startswith(('https://', 'http://')):
                        new_tab_link(source.name, source.url).classes('break-value')
        for note in result.notes[:2]:
            ui.label(note).classes('muted prose break-value')

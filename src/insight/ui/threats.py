"""The industry threats tab (TIP 2.10, ADR 0025): pick an industry, see the ten groups that target it and why.

A group is listed only when a cited source says it targets the industry; each entry shows that evidence and
the reasons for its place. Opening a group shows its threat guide (``threat_guide.py``). Nothing here is
attribution: "named in your reports" means the report text contains one of the group's names.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from nicegui import ui

from .. import services
from ..industries import BY_KEY, INDUSTRIES
from ..threat_library import library
from .actors import open_actor_dialog
from .threat_guide import open_guide_dialog
from .typography import heading, new_tab_link
from .workspace import Workspace

SEARCH_RESULTS: Final = 12


def _entry(ws: Workspace, rank: int, entry: services.ProfileEntry) -> None:
    subject = entry.subject
    named = f' · named in {entry.mentions} of your reports' if entry.mentions else ''
    with ui.column().classes('panel w-full p-3 gap-1'):
        with ui.row().classes('items-center w-full gap-2'):
            ui.badge(str(rank)).props('outline')
            ui.label(f'{subject.name} ({subject.ref}){named}').classes('flex-1 break-value font-medium')
            ui.button('Open guide', on_click=lambda ref=subject.ref: ws.open_guide(ref)).props(
                f'outline dense no-caps aria-label="Open the guide for {subject.name}"'
            ).mark(f'guide-{subject.ref}')
        if subject.aliases:
            ui.label('Also called: ' + ', '.join(subject.aliases[:8])).classes('muted text-sm break-value')
        with ui.expansion(f'Why it is listed ({len(entry.reasons)})').classes('w-full'):
            for claim in entry.claims:
                with ui.column().classes('gap-0 w-full'):
                    ui.label(f'{claim.source_name} says:').classes('muted text-sm')
                    ui.label(claim.evidence).classes('evidence text-sm w-full')
                    if claim.url:
                        new_tab_link('Read the source', claim.url)
            for reason in entry.reasons[len(entry.claims) :]:
                ui.label(reason).classes('text-sm prose')


def build_threats(ws: Workspace) -> None:
    @ui.refreshable
    def profile() -> None:
        if not ws.authorized():
            return
        key = ws.state.threat_industry
        with ws.read() as db:
            found = services.industry_profile(db, key, now=datetime.now(UTC))
        ui.label(BY_KEY[key].covers).classes('muted text-sm')
        ui.label(
            f'{found.candidates} groups have a source that says they target this industry. '
            f'These are the top {len(found.entries)}.'
        ).classes('muted prose')
        ui.label(
            'Groups your reports named in the last 90 days come first. Then come groups with the newest '
            'public activity, then groups with the most known techniques.'
        ).classes('muted prose')
        if found.capped:
            ui.label(f'Only your newest {found.scanned} reports were read for names.').classes('text-warn')
        for rank, entry in enumerate(found.entries, start=1):
            _entry(ws, rank, entry)
        if found.removed:
            ui.label(f'You removed this industry from {len(found.removed)} group(s).').classes(
                'muted text-sm'
            )
        new_tab_link('Download this list as JSON', f'/api/industries/{key}/actors')

    def choose(key: str) -> None:
        ws.state.threat_industry = key
        profile.refresh()

    def open_guide(ref: str) -> None:
        if ws.authorized():
            open_guide_dialog(ws, ref, profile.refresh)

    ws.open_guide = open_guide
    ws.on_refresh(profile.refresh)
    heading('Industry threats', 2)
    ui.label(
        'Pick an industry to see the ten groups that most likely target it, with the source for each claim. '
        'Open a group for its threat guide and a hunt plan.'
    ).classes('muted prose')
    lib = library()
    ui.label(
        f'Group data: MITRE ATT&CK {lib.attack_version} and the MISP galaxy ({lib.edition} copy).'
    ).classes('muted text-sm')
    with ui.row().classes('items-end gap-3 w-full'):
        ui.select(
            {i.key: i.name for i in INDUSTRIES},
            value=ws.state.threat_industry,
            label='Industry',
            on_change=lambda e: choose(e.value),
        ).props('outlined').classes('w-72')
        ui.button(
            'Track your own actor', icon='add', on_click=lambda: open_actor_dialog(ws, open_guide)
        ).props('outline no-caps')
    _group_search(ws)
    with ui.column().classes('w-full gap-3'):
        profile()


def _group_search(ws: Workspace) -> None:
    with ui.expansion('Find any group by name').classes('w-full'):
        query = ui.input('Group name or ID, such as APT29 or G0016').props(
            'outlined clearable debounce=250 maxlength=100'
        )
        results = ui.column().classes('w-full gap-1').props('aria-live=polite')

        def show(value: str | None) -> None:
            results.clear()
            text = (value or '').strip()
            if not text or not ws.authorized():
                return
            with ws.read() as db:
                mine = [a for a in services.list_actors(db) if text.casefold() in a.name.casefold()]
                rows = [(a.id, f'{a.name} (your actor)') for a in mine]
            rows += [(g.id, f'{g.id} · {g.name}') for g in library().search(text, limit=SEARCH_RESULTS)]
            with results:
                if not rows:
                    ui.label('No group has that name. Try fewer letters.').classes('muted text-sm')
                for ref, text_shown in rows[:SEARCH_RESULTS]:
                    ui.button(text_shown, on_click=lambda r=ref: ws.open_guide(r)).props(
                        'flat no-caps align=left'
                    ).classes('w-full break-value')

        query.on_value_change(lambda event: show(event.value))

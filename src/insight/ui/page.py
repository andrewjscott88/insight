"""Page assembly: authentication gate, the side menu and its sections.

The workspace is organised around an analyst's day (Today, Triage, Investigate, Cases, Share, Settings).
The side menu is a vertical tab list, so keyboard and screen-reader users get the usual tab semantics; on a
phone it wraps into rows above the content.
"""

from __future__ import annotations

from typing import Final

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from nicegui import app as nicegui_app
from nicegui import ui

from ..appearance import (
    TEXT_SIZE_COOKIE,
    THEME_COOKIE,
    Theme,
    dark_mode_value,
    text_size_choice,
    theme_choice,
)
from ..models import SessionFactory
from .appearance import TextSizeSwitch, ThemeSwitch
from .cases import build_cases
from .confidence import build_source_ratings
from .cves import build_cves
from .entities import build_entities
from .glossary import open_glossary
from .inbox import build_inbox
from .ingest import build_ingest_dialog
from .ioc_export import open_ioc_export_dialog
from .landscape import build_landscape
from .requirements import build_requirements
from .share import build_share
from .sources import build_sources
from .stats import build_stats
from .techniques import build_techniques
from .theme import apply_theme
from .threats import build_threats
from .typography import heading
from .watch_terms import build_watch_terms
from .workspace import Workspace

RECONNECT_SECONDS: Final = 30.0
TAGLINE: Final = 'Threat intelligence workbench'
#: The side menu, in the order of an analyst's day: (name, label).
SECTIONS: Final = (
    ('today', 'Today'),
    ('requirements', 'Requirements'),
    ('triage', 'Triage'),
    ('investigate', 'Investigate'),
    ('cases', 'Cases'),
    ('share', 'Share'),
    ('settings', 'Settings'),
)
#: Investigate's own tabs: (name, label).
INVESTIGATE: Final = (
    ('indicators', 'Indicators'),
    ('cves', 'CVEs'),
    ('techniques', 'ATT&CK techniques'),
    ('groups', 'Threat groups'),
)


def _brand() -> None:
    with ui.row(wrap=False).classes('items-center gap-3 side-brand'):
        ui.label('✳').classes('text-3xl text-primary').props('aria-hidden="true"')
        with ui.column().classes('gap-0'):
            ui.label('Insight').classes('text-2xl font-medium')
            ui.label(TAGLINE).classes('brand-description muted')


def _investigate(ws: Workspace) -> ui.tabs:
    with ui.tabs().props('align=left no-caps').classes('evidence-tabs w-full') as tabs:
        for name, label in INVESTIGATE:
            ui.tab(name, label)
    with ui.tab_panels(tabs, value='indicators').classes('w-full bg-transparent p-0 pt-4'):
        for name, build in (
            ('indicators', build_entities),
            ('cves', build_cves),
            ('techniques', build_techniques),
            ('groups', build_threats),
        ):
            with ui.tab_panel(name).classes('panel p-4 sm:p-5'):
                build(ws)
    return tabs


def _toolbar(app: FastAPI, ws: Workspace, ingest_dialog: ui.dialog, dark: ui.dark_mode, theme: Theme) -> None:
    with ui.row().classes('workspace-toolbar w-full justify-between items-center gap-3'):
        with ui.row().classes('items-center gap-3'):
            ui.button('＋ Add intelligence', on_click=ingest_dialog.open).classes('flex-1 sm:flex-none')
            ui.button('Export IOCs', on_click=lambda: open_ioc_export_dialog(ws)).props('outline').classes(
                'flex-1 sm:flex-none'
            )
            ui.button('What the words mean', icon='help_outline', on_click=open_glossary).props(
                'flat no-caps'
            )
        with ui.row().classes('workspace-controls items-center gap-2 sm:gap-4 max-w-full'):
            ThemeSwitch(ws, dark, theme)
            TextSizeSwitch(ws, text_size_choice(ws.request.cookies.get(TEXT_SIZE_COOKIE)))
            # Backend provides a CSRF-protected logout confirmation form.
            ui.link('End session' if app.state.settings.dev_no_auth else 'Sign out', '/logout').classes(
                'muted target-link whitespace-nowrap'
            )


def register_ui(app: FastAPI, session_factory: SessionFactory) -> None:
    """Register pages and mount NiceGUI after the backend routes and middleware."""

    @ui.page('/', title=f'Insight · {TAGLINE}')
    async def workspace(request: Request) -> RedirectResponse | None:
        if not app.state.is_authenticated(request.session):
            return RedirectResponse('/login', status_code=303)
        # A theme picked on this device wins over the instance default (INSIGHT_THEME).
        theme = theme_choice(request.cookies.get(THEME_COOKIE), app.state.settings.theme)
        apply_theme(theme, text_size_choice(request.cookies.get(TEXT_SIZE_COOKIE)))
        dark = ui.dark_mode(dark_mode_value(theme))
        ws = Workspace(app=app, sessions=session_factory, request=request)
        ingest_dialog = build_ingest_dialog(ws)
        with ui.element('div').classes('app-shell'):
            with ui.element('nav').props('aria-label="Main"').classes('side-nav'):
                _brand()
                with ui.tabs().props('vertical no-caps').classes('side-tabs') as menu:
                    for name, label in SECTIONS:
                        ui.tab(name, label)
            # A div: NiceGUI's page is already the one <main> landmark (axe: landmark-no-duplicate-main).
            with ui.element('div').classes('workspace gap-4 sm:gap-6'):
                _toolbar(app, ws, ingest_dialog, dark, theme)
                if app.state.settings.dev_no_auth:
                    with ui.column().classes('panel w-full p-3 sm:p-4 gap-1').mark('open-access-banner'):
                        ui.label('Temporary open access').classes('font-semibold')
                        ui.label(
                            'Anyone with this link can view or change the data in this workspace.'
                        ).classes('prose')
                with ui.tab_panels(menu, value='today').classes('w-full bg-transparent p-0'):
                    with ui.tab_panel('today').classes('p-0 flex flex-col gap-6'):
                        build_landscape(ws)
                        build_stats(ws)
                    with ui.tab_panel('requirements').classes('panel p-4 sm:p-5'):
                        build_requirements(ws)
                    # Only the open section is in the page, so each has an h1 (axe: page-has-heading-one).
                    with ui.tab_panel('triage').classes('p-0 flex flex-col gap-4'):
                        heading('Triage', 1)
                        build_inbox(ws)
                    with ui.tab_panel('investigate').classes('p-0 flex flex-col gap-4'):
                        heading('Investigate', 1)
                        investigate = _investigate(ws)
                    with ui.tab_panel('cases').classes('panel p-4 sm:p-5'):
                        build_cases(ws)
                    with ui.tab_panel('share').classes('panel p-4 sm:p-5'):
                        build_share(ws)
                    with ui.tab_panel('settings').classes('p-0 flex flex-col gap-6'):
                        heading('Settings', 1)
                        with ui.column().classes('panel w-full p-4 sm:p-5'):
                            build_sources(ws)
                        with ui.column().classes('panel w-full p-4 sm:p-5'):
                            build_source_ratings(ws)
                        with ui.column().classes('panel w-full p-4 sm:p-5'):
                            build_watch_terms(ws)

        def show_section(name: str, tab: str | None = None) -> None:
            menu.set_value(name)
            if tab:
                investigate.set_value(tab)

        def show_entity(value: str) -> None:
            show_section('investigate', 'indicators')
            ws.find_entity(value)

        ws.show_section = show_section
        open_requirement = ws.show_requirement  # The Requirements section's dialog.

        def show_requirement(requirement_id: str) -> None:
            show_section('requirements')
            open_requirement(requirement_id)

        ws.show_requirement = show_requirement
        ws.show_inbox = lambda: show_section('triage')
        ws.show_entity = show_entity
        # Alerts link to /?report=<id> (ADR 0022). An unknown ID opens nothing, as a deleted report would.
        report = request.query_params.get('report', '')
        if 0 < len(report) <= 36:
            ws.show_inbox()
            ws.open_document(report)
        return None

    ui.run_with(
        app,
        storage_secret=app.state.settings.session_secret,
        title='Insight',
        favicon='✳',
        dark=None,  # Per page from the theme preference; None ("auto") follows the device.
        language='en-US',  # <html lang>: screen readers and read-aloud tools pick the right voice.
        # A phone that loses signal or sleeps for a moment keeps its page (reading position, unsaved note)
        # instead of reloading it once NiceGUI's default 3 s have passed.
        reconnect_timeout=RECONNECT_SECONDS,
        show_welcome_message=False,
    )
    # Quasar's 2 px loading bar is decoration (results are announced as messages), but it is an unnamed
    # progressbar outside the page's landmarks: hide it from assistive technology (axe, ADR 0017).
    nicegui_app.config.quasar_config['loadingBar']['aria-hidden'] = 'true'

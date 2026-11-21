"""Page assembly: authentication gate, layout shell and tab wiring."""

from __future__ import annotations

from typing import Final

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from nicegui import app as nicegui_app
from nicegui import ui

from ..appearance import TEXT_SIZE_COOKIE, THEME_COOKIE, dark_mode_value, text_size_choice, theme_choice
from ..models import SessionFactory
from .appearance import TextSizeSwitch, ThemeSwitch
from .entities import build_entities
from .glossary import open_glossary
from .inbox import build_inbox
from .ingest import build_ingest_dialog
from .ioc_export import open_ioc_export_dialog
from .landscape import build_landscape
from .sources import build_sources
from .stats import build_stats
from .techniques import build_techniques
from .theme import apply_theme
from .typography import heading
from .watch_terms import build_watch_terms
from .workspace import Workspace

RECONNECT_SECONDS: Final = 30.0


def _tab(label: str, short: str) -> ui.tab:
    """A tab with its full label, shortened on phones; tabs that still do not fit wrap onto a second line.

    ``max-sm:hidden``, not ``hidden sm:block``: Quasar's ``.hidden`` is ``!important`` and beats ``sm:block``.
    """
    if short == label:
        return ui.tab(label)
    with ui.tab(label, label='') as tab:
        ui.label(label).classes('max-sm:hidden')
        ui.label(short).classes('sm:hidden')
    return tab


def register_ui(app: FastAPI, session_factory: SessionFactory) -> None:
    """Register pages and mount NiceGUI after the backend routes and middleware."""

    @ui.page('/', title='Insight · Cyber Threat Intelligence Feed')
    async def workspace(request: Request) -> RedirectResponse | None:
        if not app.state.is_authenticated(request.session):
            return RedirectResponse('/login', status_code=303)
        # A theme picked on this device wins over the instance default (INSIGHT_THEME).
        theme = theme_choice(request.cookies.get(THEME_COOKIE), app.state.settings.theme)
        text_size = text_size_choice(request.cookies.get(TEXT_SIZE_COOKIE))
        apply_theme(theme, text_size)
        dark = ui.dark_mode(dark_mode_value(theme))
        ws = Workspace(app=app, sessions=session_factory, request=request)
        ingest_dialog = build_ingest_dialog(ws)
        with ui.column().classes('workspace gap-4 sm:gap-6'):
            with ui.row().classes('w-full justify-between items-center border-b divider pb-3 sm:pb-5 gap-2'):
                with ui.row(wrap=False).classes('items-center gap-2 sm:gap-3'):
                    ui.label('✳').classes('text-3xl sm:text-4xl text-primary')
                    with ui.column().classes('gap-0'):
                        ui.label('Insight').classes('text-2xl font-medium')
                        ui.label('Cyber Threat Intelligence Feed').classes('brand-description muted')
                with ui.row().classes('workspace-controls items-center gap-2 sm:gap-4 max-w-full'):
                    ThemeSwitch(ws, dark, theme)
                    TextSizeSwitch(ws, text_size)
                    # Backend provides a CSRF-protected logout confirmation form.
                    ui.link(
                        'End session' if app.state.settings.dev_no_auth else 'Sign out', '/logout'
                    ).classes('muted target-link whitespace-nowrap')
            if app.state.settings.dev_no_auth:
                with ui.column().classes('panel w-full p-3 sm:p-4 gap-1').mark('open-access-banner'):
                    ui.label('Temporary open access').classes('font-semibold')
                    ui.label('Anyone with this link can view or change the data in this workspace.').classes(
                        'prose'
                    )
            build_landscape(ws)
            ui.link_target('report-tools')
            with ui.row().classes('workspace-tools w-full justify-between items-center gap-4'):
                with ui.column().classes('gap-1'):
                    heading('Work with the evidence', 2)
                    ui.label(
                        'Read the reports, check the details, and keep your sources up to date.'
                    ).classes('muted prose')
                with ui.row().classes('items-center gap-3 w-full sm:w-auto'):
                    ui.button('What the words mean', icon='help_outline', on_click=open_glossary).props(
                        'flat no-caps'
                    ).classes('w-full sm:w-auto')
                    ui.button('Export IOCs', on_click=lambda: open_ioc_export_dialog(ws)).props(
                        'outline'
                    ).classes('flex-1 sm:flex-none')
                    ui.button('＋ Ingest intelligence', on_click=ingest_dialog.open).classes(
                        'flex-1 sm:flex-none'
                    )
            build_stats(ws)
            with ui.tabs().props('align=left no-caps').classes('evidence-tabs w-full') as tabs:
                inbox_tab = _tab('Intelligence inbox', 'Inbox')
                entities_tab = _tab('Entity explorer', 'Entities')
                techniques_tab = _tab('ATT&CK techniques', 'ATT&CK')
                watch_tab = _tab('Watch terms', 'Watch')
                sources_tab = _tab('Sources', 'Sources')

            def show_inbox() -> None:
                tabs.set_value(inbox_tab)

            def show_entity(value: str) -> None:
                tabs.set_value(entities_tab)
                ws.find_entity(value)

            ws.show_inbox = show_inbox
            ws.show_entity = show_entity
            with ui.tab_panels(tabs, value=inbox_tab).classes('w-full bg-transparent p-0'):
                with ui.tab_panel(inbox_tab).classes('p-0'):
                    build_inbox(ws)
                with ui.tab_panel(entities_tab).classes('panel p-4 sm:p-5'):
                    build_entities(ws)
                with ui.tab_panel(techniques_tab).classes('panel p-4 sm:p-5'):
                    build_techniques(ws)
                with ui.tab_panel(watch_tab).classes('panel p-4 sm:p-5'):
                    build_watch_terms(ws)
                with ui.tab_panel(sources_tab).classes('panel p-4 sm:p-5'):
                    build_sources(ws)
        # Alerts link to /?report=<id> (ADR 0022). An unknown ID opens nothing, as a deleted report would.
        report = request.query_params.get('report', '')
        if 0 < len(report) <= 36:
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

"""Page assembly: authentication gate, layout shell and tab wiring."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from nicegui import ui

from ..models import SessionFactory
from .entities import build_entities
from .inbox import build_inbox
from .ingest import build_ingest_dialog
from .ioc_export import open_ioc_export_dialog
from .sources import build_sources
from .stats import build_stats
from .theme import apply_theme
from .watch_terms import build_watch_terms
from .workspace import Workspace


def register_ui(app: FastAPI, session_factory: SessionFactory) -> None:
    """Register pages and mount NiceGUI after the backend routes and middleware."""

    @ui.page('/', title='Insight · Intelligence workspace')
    async def workspace(request: Request) -> RedirectResponse | None:
        if not app.state.is_authenticated(request.session):
            return RedirectResponse('/login', status_code=303)
        apply_theme()
        ws = Workspace(app=app, sessions=session_factory, request=request)
        ingest_dialog = build_ingest_dialog(ws)
        with ui.column().classes('workspace gap-6'):
            with ui.row().classes('w-full justify-between items-center border-b border-slate-700 pb-5'):
                with ui.row().classes('items-center gap-3'):
                    ui.label('✳').classes('text-4xl text-primary')
                    ui.label('Insight').classes('text-2xl font-medium')
                    ui.label('PRIVATE INTELLIGENCE WORKSPACE').classes('eyebrow hidden sm:block ml-4')
                # Backend provides a CSRF-protected logout confirmation form.
                ui.link('Sign out ↗', '/logout').classes('muted text-xs')
            with ui.row().classes('w-full justify-between items-center gap-4'):
                with ui.column().classes('gap-1'):
                    ui.label('COLLECT. CONNECT. UNDERSTAND.').classes('eyebrow')
                    ui.label('Intelligence workspace').classes('text-3xl font-medium')
                    ui.label('Turn source reporting into reviewed, connected intelligence.').classes(
                        'muted text-sm'
                    )
                with ui.row().classes('items-center gap-3'):
                    ui.button('Export IOCs', on_click=lambda: open_ioc_export_dialog(ws)).props('outline')
                    ui.button('＋ Ingest intelligence', on_click=ingest_dialog.open)
            build_stats(ws)
            with ui.tabs().classes('w-full justify-start') as tabs:
                inbox_tab = ui.tab('Intelligence inbox')
                entities_tab = ui.tab('Entity explorer')
                watch_tab = ui.tab('Watch terms')
                sources_tab = ui.tab('Sources')

            def show_inbox() -> None:
                tabs.set_value(inbox_tab)

            ws.show_inbox = show_inbox
            with ui.tab_panels(tabs, value=inbox_tab).classes('w-full bg-transparent p-0'):
                with ui.tab_panel(inbox_tab).classes('p-0'):
                    build_inbox(ws)
                with ui.tab_panel(entities_tab).classes('panel p-5'):
                    build_entities(ws)
                with ui.tab_panel(watch_tab).classes('panel p-5'):
                    build_watch_terms(ws)
                with ui.tab_panel(sources_tab).classes('panel p-5'):
                    build_sources(ws)
        return None

    ui.run_with(
        app,
        storage_secret=app.state.settings.session_secret,
        title='Insight',
        favicon='✳',
        dark=True,
        show_welcome_message=False,
    )

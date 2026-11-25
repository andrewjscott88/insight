"""Choose a focus, build a hunt guide, then download it or explicitly save a draft package."""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import quote

from nicegui import ui

from .. import services
from ..hunt_guide import HuntGuide
from ..permissions import Permission
from .cases import build_cases
from .focus_choices import FOCUS_KINDS
from .hunt_packages import build_hunt_packages
from .messages import tell
from .theme import tlp_badge
from .typography import heading
from .workspace import Workspace

KINDS = FOCUS_KINDS


def _guide_builder(ws: Workspace, open_saved: Callable[[str], None]) -> None:
    guide: HuntGuide | None = None
    saved_id: str | None = None
    with ws.read() as db:
        choices = services.hunt_guide_choices(db, kind='theme', max_tlp=ws.app.state.settings.max_tlp)

    heading('1. Choose your focus', 2, 'subsection-title')
    ui.label('What do you want to investigate? Start from a sector, a threat, a report or a clue.').classes(
        'prose'
    )
    focus = (
        ui.select(KINDS, value='theme', label='Start from')
        .props('outlined')
        .classes('w-full min-w-0')
        .mark('hunt-guide-kind')
    )
    with ui.row().classes('w-full gap-3 items-center'):
        query = (
            ui.input('Search this list')
            .props('outlined maxlength=120 clearable')
            .classes('flex-1 min-w-0')
            .mark('hunt-guide-query')
        )
        search = ui.button('Search', icon='search').props('outline').mark('hunt-guide-search')
    ui.label(
        'Search by sector, name, alias, report title or source. '
        'For a security advisory or new flaw bulletin, add the report to Insight first.'
    ).classes('muted prose')
    subject = (
        ui.select(dict(choices['theme']), label=KINDS['theme'], with_input=True)
        .props('outlined clearable options-dense')
        .classes('w-full min-w-0')
        .mark('hunt-guide-subject')
    )
    found = ui.label('Choose from the list, or search to find more.').classes('muted prose')

    @ui.refreshable
    def preview() -> None:
        with ui.column().classes('w-full gap-3 min-w-0').mark('hunt-guide-preview'):
            if guide is None:
                ui.label('Choose a focus, then build your guide to see it here.').classes('muted prose')
                return
            heading(guide.title, 3)
            ui.label(guide.summary).classes('prose break-value')
            tlp_badge(guide.tlp)
            for section in guide.sections:
                with ui.column().classes('w-full gap-2 min-w-0'):
                    heading(section.title, 4, 'subsection-title')
                    for line in section.lines:
                        ui.label(line).classes('prose break-value whitespace-pre-wrap')

    def invalidate() -> None:
        nonlocal guide, saved_id
        guide = None
        saved_id = None
        build.set_enabled(bool(subject.value))
        markdown.disable()
        pdf.disable()
        save_package.disable()
        save_package.set_text('Save as hunt package')
        preview.refresh()

    def find_choices() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            results = services.hunt_guide_choices(
                db, kind=focus.value, q=query.value or '', max_tlp=ws.app.state.settings.max_tlp
            )
        options = dict(results[focus.value])
        subject.set_options(options, value=None)
        found.set_text(
            'Choose from these matches. Refine your search if you cannot see what you need.'
            if options
            else 'No matches. Try a different search, or add a report to Insight.'
        )
        invalidate()

    def choose_kind() -> None:
        if not ws.authorized():
            return
        query.set_value('')
        subject.set_label(KINDS[focus.value])
        find_choices()

    def build_guide() -> None:
        nonlocal guide
        if not ws.allowed(Permission.READ) or not subject.value:
            return
        invalidate()
        try:
            with ws.write(Permission.READ) as db:
                built = services.hunt_guide(
                    db, focus.value, subject.value, max_tlp=ws.app.state.settings.max_tlp
                )
                services.audit(db, 'hunt.guide', built.ref, f'{built.kind}; preview; TLP:{built.tlp}')
        except (LookupError, ValueError):
            invalidate()
            tell('This focus is no longer available. Choose another one.', 'error')
            return
        guide = built
        preview.refresh()
        markdown.enable()
        pdf.enable()
        save_package.enable()
        tell('Your guide is ready. Review it below, then save a hunt package or download it.', 'success')

    def save_as_package() -> None:
        nonlocal saved_id
        if not ws.allowed(Permission.HUNTING) or guide is None or not save_package.enabled:
            return
        if saved_id is not None:
            open_saved(saved_id)
            return
        save_package.disable()
        try:
            with ws.write(Permission.HUNTING) as db:
                package_id = services.create_hunt_package_from_guide(
                    db, guide.kind, guide.ref, max_tlp=ws.app.state.settings.max_tlp
                ).id
        except (LookupError, ValueError):
            tell('This guide could not be saved. Build it again from the current intelligence.', 'error')
            return
        finally:
            save_package.enable()
        saved_id = package_id
        save_package.set_text('Open saved package')
        open_saved(package_id)
        tell('Saved as a draft hunt package. Review it before publishing.', 'success')

    def download(format: str) -> None:
        if not ws.authorized() or guide is None:
            return
        target = f'/api/hunt-guides/{guide.kind}/{quote(guide.ref, safe="")}?format={format}'
        ui.navigate.to(target, new_tab=True)

    heading('2. Build your guide', 2, 'subsection-title')
    ui.label(
        'The guide brings together known tactics, useful reports and checks for your team. '
        'It uses the intelligence already in Insight. Review it before you begin a hunt.'
    ).classes('prose')
    build = ui.button('Build guide', icon='description', on_click=build_guide).mark('hunt-guide-build')
    build.disable()
    heading('3. Save or download your hunt', 2, 'subsection-title')
    ui.label(
        'Save this selection and its guide as a draft hunt package to review and keep in Insight. '
        'Or download Markdown or PDF to use outside Insight. Downloads open in a new tab.'
    ).classes('prose')
    with ui.row().classes('w-full gap-3'):
        save_package = (
            ui.button('Save as hunt package', icon='save', on_click=save_as_package)
            .classes('flex-1 sm:flex-none')
            .mark('hunt-guide-save-package')
        )
        markdown = (
            ui.button('Download Markdown', icon='download', on_click=lambda: download('md'))
            .props('outline aria-label="Download Markdown (opens in a new tab)"')
            .classes('flex-1 sm:flex-none')
            .mark('hunt-guide-markdown')
        )
        pdf = (
            ui.button('Download PDF', icon='download', on_click=lambda: download('pdf'))
            .props('outline aria-label="Download PDF (opens in a new tab)"')
            .classes('flex-1 sm:flex-none')
            .mark('hunt-guide-pdf')
        )
    markdown.disable()
    pdf.disable()
    save_package.disable()
    preview()
    focus.on_value_change(choose_kind)
    subject.on_value_change(invalidate)
    search.on_click(find_choices)
    query.on('keydown.enter', find_choices)

    def refresh() -> None:
        if ws.authorized():
            find_choices()

    ws.on_refresh(refresh)


def build_threat_hunt(ws: Workspace) -> None:
    heading('Threat hunt', 1)
    ui.label(
        'Turn a threat you care about into a guide your team can use. '
        'Choose a focus, review the guide, then take it to your hunting tools.'
    ).classes('muted prose')

    def open_saved(package_id: str) -> None:
        packages.open()
        show_package(package_id)

    with ui.column().classes('w-full gap-4 min-w-0').mark('hunt-guide-builder'):
        _guide_builder(ws, open_saved)
    ui.separator().classes('my-4')
    with (
        ui.expansion('Saved hunt packages', icon='inventory_2')
        .classes('w-full')
        .mark('saved-hunt-packages') as packages
    ):
        show_package = build_hunt_packages(ws, embedded=True)
    with (
        ui.expansion('Advanced: intelligence reports', icon='folder_open')
        .classes('w-full mt-4')
        .mark('saved-intelligence-reports')
    ):
        ui.label(
            'Write a separate assessment here. This does not build a hunt from the selection above.'
        ).classes('muted prose')
        build_cases(ws, embedded=True)

"""An offline browser for the selected ATT&CK domain's public technique catalog."""

from __future__ import annotations

from collections.abc import Callable

from nicegui import ui

from ..attack import Domain, catalog, search
from .typography import new_tab_link


def build_catalog_browser(domain: Callable[[], Domain]) -> Callable[[], None]:
    with ui.expansion('Browse the technique catalog', icon='menu_book').classes('panel w-full'):
        query = (
            ui.input('Search catalog', placeholder='Technique ID or name')
            .props('outlined clearable debounce=250 maxlength=100')
            .classes('w-full')
            .mark('attack-catalog-query')
        )

        @ui.refreshable
        def results() -> None:
            selected = domain()
            matches = search(str(query.value or ''), limit=20, domain=selected)
            ui.label(
                f'{len(catalog(selected).techniques)} techniques available offline. '
                'Showing up to 20 matches; narrow your search to see more.'
            ).classes('muted prose')
            if not matches:
                ui.label('No technique matches. Try fewer letters.').classes('muted')
            for match in matches:
                new_tab_link(f'{match.id} · {match.full_name}', match.url).classes('break-value')

        query.on_value_change(results.refresh)
        with ui.column().classes('w-full gap-2').mark('attack-catalog-results'):
            results()

    def refresh() -> None:
        results.refresh()

    return refresh

"""Phone layout helpers for the inbox.

Below Tailwind's ``lg`` breakpoint the document list and the reader are stacked, so opening a report from the
list would render it off-screen. These scroll the reader into view, and back to the list, on narrow screens
only (side by side on wider screens, nothing needs to move).
"""

from __future__ import annotations

from typing import Final

from nicegui import ui

#: Matches the inbox's ``lg:flex-nowrap`` breakpoint: narrower than this, the list sits above the reader.
STACKED: Final = '(max-width: 1023.98px)'
SCROLL_DELAY_MS: Final = 150
_MOTION: Final = "matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'"


def _when_stacked(body: str) -> str:
    # After a short delay, so the refreshed reader (and the inbox tab, from the entity explorer) is laid out.
    return (
        f"setTimeout(() => {{ if (matchMedia('{STACKED}').matches) {{ const behavior = {_MOTION}; {body} }} "
        f'}}, {SCROLL_DELAY_MS});'
    )


SHOW_READER: Final = _when_stacked(
    "document.querySelector('.document-reader')?.scrollIntoView({behavior, block: 'start'});"
)
SHOW_LIST: Final = _when_stacked(
    "document.querySelector('.document-list-pane')?.scrollIntoView({behavior, block: 'start'});"
    "const list = document.querySelector('.document-list');"
    "const card = list?.querySelector('.source-selected');"
    'if (list && card) list.scrollTop += card.getBoundingClientRect().top - list.getBoundingClientRect().top;'
)


def show_reader() -> None:
    """Bring the report reader into view on a phone (after a report was opened)."""
    ui.run_javascript(SHOW_READER)


def show_list() -> None:
    """Back to the document list on a phone, with the open report's card in view."""
    ui.run_javascript(SHOW_LIST)


def back_to_list_button() -> None:
    """At the top of the reader while the list is stacked above it; hidden where both are side by side."""
    ui.button('← Back to list', on_click=show_list).props('flat dense no-caps').classes(
        'lg:hidden self-start text-sm'
    ).mark('back-to-list')

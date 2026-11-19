"""Real headings for the workspace (WCAG 1.3.1, 2.4.6, 2.4.10).

Screen readers and read-aloud tools list and jump between headings; a ``div`` that only *looks* like a heading
is invisible to them. :class:`Heading` is a NiceGUI label rendered as ``<h1>``-``<h3>``.
"""

from __future__ import annotations

from typing import Final, Literal

from nicegui import ui

Level = Literal[1, 2, 3]
#: The visual style of each level (see ``styles.py``).
NEW_TAB: Final = ' (opens in a new tab)'
HEADING_CLASSES: Final[dict[int, str]] = {1: 'page-title', 2: 'section-title', 3: 'subsection-title'}


class Heading(ui.label):
    """A label rendered as an HTML heading."""

    def __init__(self, text: str, level: Level) -> None:
        super().__init__(text)
        self.tag = f'h{level}'


def heading(text: str, level: Level, style: str | None = None) -> Heading:
    """A heading of ``level``, styled for that level unless ``style`` (a CSS class) is given."""
    return Heading(text, level).classes(style or HEADING_CLASSES[level])


def new_tab_link(text: str, target: str) -> ui.link:
    """A link that opens a new tab and says so (screen readers read the arrow as "north east arrow")."""
    return (
        ui.link(f'{text} ↗', target, new_tab=True)
        .props(f'aria-label="{text}{NEW_TAB}"')
        .classes('target-link')
    )

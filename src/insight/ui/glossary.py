"""Plain-language explanations of the words and abbreviations the workspace uses (WCAG 3.1.3, 3.1.4; COGA).

Threat-intelligence work is full of jargon. Every abbreviation shown in the interface must be explained here
(``tests/unit/test_plain_language.py`` checks it); each explanation is written to be read at about age 12-14.
"""

from __future__ import annotations

from nicegui import ui

from .glossary_infrastructure import INFRASTRUCTURE_GLOSSARY
from .glossary_terms import GLOSSARY as BASE_GLOSSARY
from .typography import heading

__all__ = ['GLOSSARY', 'open_glossary']
GLOSSARY = BASE_GLOSSARY + INFRASTRUCTURE_GLOSSARY


def open_glossary() -> None:
    """A dialog listing every term, with a heading and a name for assistive technology."""
    title = 'What the words mean'
    with (
        ui.dialog().props(f'aria-label="{title}"') as dialog,
        ui.card().classes('panel dialog-card w-[42rem] max-w-full p-6 gap-3'),
    ):
        heading(title, 2)
        ui.label('Words and abbreviations used in Insight, in plain language.').classes('muted prose')
        with ui.element('dl').classes('glossary w-full'):
            for term, explanation in GLOSSARY:
                ui.label(term).tag = 'dt'
                ui.label(explanation).tag = 'dd'
        ui.button('Close', on_click=dialog.close).props('flat')
    dialog.open()

"""Share: every way intelligence leaves Insight, in one place.

Insight never sends anything by itself. The IOC export is in the workspace; the TAXII feed, API keys and MISP
are set up on the host, so this section says how, instead of hiding them in the documentation.
"""

from __future__ import annotations

from typing import Final

from nicegui import ui

from .ioc_export import open_ioc_export_dialog
from .typography import heading, new_tab_link
from .workspace import Workspace

DOCS: Final = 'https://github.com/andrewjscott88/insight/blob/main/docs'


def _card(title: str, text: str) -> ui.column:
    with ui.column().classes('share-card gap-2 p-4 min-w-0') as card:
        heading(title, 2, 'subsection-title')  # under the section's h1 (axe: heading-order)
        ui.label(text).classes('prose')
    return card


def build_share(ws: Workspace) -> None:
    heading('Share', 1)
    ui.label(
        'Insight never sends intelligence by itself. Every export keeps its TLP label, and the label decides '
        'who may receive it.'
    ).classes('muted prose')
    with ui.element('div').classes('share-grid w-full gap-4 mt-4'):
        with _card(
            'Download indicators',
            'Pick reports and indicators, then download an Insight JSON file or a STIX 2.1 bundle.',
        ):
            ui.button('Choose what to export', on_click=lambda: open_ioc_export_dialog(ws)).props(
                'outline'
            ).classes('self-start')
        with _card(
            'TAXII 2.1 feed',
            'SIEMs and threat-intelligence platforms can poll /taxii2/ on this site with an API key. It '
            'serves your reviewed indicators, ATT&CK techniques, actors and campaigns, and the CISA KEV '
            'catalog.',
        ):
            new_tab_link('How to connect a client', f'{DOCS}/TAXII.md')
        with _card(
            'API keys',
            'Create a key on the host with insight api-key create --name NAME. It is read-only unless you '
            'say otherwise, and --max-tlp GREEN hides stricter reports from it.',
        ):
            new_tab_link('API guide', f'{DOCS}/API.md#api-key-scripts-and-siem')
        with _card(
            'MISP',
            'Send or fetch one MISP event on the host with insight misp-export or insight misp-import, as a '
            'file or with your MISP instance.',
        ):
            new_tab_link('MISP guide', f'{DOCS}/MISP.md')

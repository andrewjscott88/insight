"""IOC export dialog: choose what to include, then download the cross-report JSON export.

The download goes through the authenticated API route (``/api/iocs/export``), exactly like the per-report
export link in the inbox, so the API, workspace and CLI share one implementation and one audit event.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final
from urllib.parse import urlencode

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..schemas import (
    DEFAULT_EXPORT_REVIEW_STATUSES,
    INDICATOR_KINDS,
    REVIEW_STATUSES,
    TLP_LEVELS,
    IocExportQuery,
)
from .messages import problem_area
from .typography import heading
from .workspace import ALL_STATUSES, ALL_TLP, Workspace, WorkspaceState

EXPORT_ROUTE: Final = '/api/iocs/export'
TITLE: Final = 'Export indicators of compromise (IOCs)'
NO_TLP_LIMIT: Final = 'No limit'
KIND_LABELS: Final = {
    'cve': 'CVE',
    'url': 'URL',
    'domain': 'Domain',
    'ip': 'IP address',
    'cidr': 'Network range (CIDR)',
    'email': 'E-mail address',
    'md5': 'MD5',
    'sha1': 'SHA-1',
    'sha256': 'SHA-256',
    'sha512': 'SHA-512',
}


def _inbox_params(inbox: WorkspaceState) -> list[tuple[str, str]]:
    """The inbox search and filters as export parameters (empty value: filter not set)."""
    return [
        ('q', inbox.q.strip()[: services.MAX_QUERY_LENGTH]),
        ('status', '' if inbox.status == ALL_STATUSES else inbox.status),
        ('tlp', '' if inbox.tlp == ALL_TLP else inbox.tlp),
        ('include_superseded', 'true' if inbox.include_superseded else ''),
    ]


def export_url(
    *,
    kinds: Sequence[str],
    review_statuses: Sequence[str],
    max_tlp: str = NO_TLP_LIMIT,
    defang: bool = False,
    inbox: WorkspaceState | None = None,
    evidence: bool = True,
) -> str:
    """The download URL for these choices; ``inbox`` also applies the inbox search and filters."""
    optional = [
        ('max_tlp', '' if max_tlp == NO_TLP_LIMIT else max_tlp),
        ('defang', 'true' if defang else ''),
        ('evidence', '' if evidence else 'false'),
    ]
    if inbox is not None:
        optional += _inbox_params(inbox)
    params = [('kind', kind) for kind in kinds]
    params += [('review_status', status) for status in review_statuses]
    params += [(name, value) for name, value in optional if value]
    return f'{EXPORT_ROUTE}?{urlencode(params)}' if params else EXPORT_ROUTE


def export_query(
    *, kinds: Sequence[str], review_statuses: Sequence[str], max_tlp: str, inbox: WorkspaceState | None
) -> IocExportQuery:
    """The same choices as :func:`export_url`, as a validated query (raises ``ValidationError``)."""
    filters = dict(_inbox_params(inbox)) if inbox is not None else {}
    return IocExportQuery.model_validate(
        {
            'kinds': list(kinds),
            'review_statuses': list(review_statuses),
            'max_tlp': None if max_tlp == NO_TLP_LIMIT else max_tlp,
            'q': filters.get('q', ''),
            'status': filters.get('status') or None,
            'tlp': filters.get('tlp') or None,
            'include_superseded': bool(filters.get('include_superseded')),
        }
    )


def preview_text(counts: dict[str, int]) -> str:
    """What the download will contain, or why there is nothing to download."""
    if counts['mentions'] > services.MAX_EXPORT_MENTIONS:
        return (
            f'Too large: {counts["mentions"]:,} mentions match (at most {services.MAX_EXPORT_MENTIONS:,}). '
            'Narrow the filters.'
        )
    if not counts['iocs']:
        return 'Nothing matches these filters.'
    return (
        f'Will export {_plural(counts["iocs"], "indicator")} from {_plural(counts["documents"], "report")} '
        f'({_plural(counts["mentions"], "mention")}).'
    )


def _plural(count: int, noun: str) -> str:
    return f'{count:,} {noun}' if count == 1 else f'{count:,} {noun}s'


def open_ioc_export_dialog(ws: Workspace) -> None:
    """Build the dialog on demand (like the enrichment dialog), so every export starts from the defaults."""
    if not ws.authorized():
        return
    with (
        ui.dialog().props(f'aria-label="{TITLE}"') as dialog,
        ui.card().classes('panel dialog-card w-[40rem] max-w-full p-6 gap-4'),
    ):
        ui.label('Export from your workspace').classes('eyebrow')
        heading(TITLE, 2)
        ui.label(
            'You get one file (JSON) that lists each indicator once. For each one it shows the reports that '
            'mention it, the words around it, and the TLP label.'
        ).classes('muted prose')
        kinds_input = (
            ui.select(
                {kind: KIND_LABELS.get(kind, kind) for kind in INDICATOR_KINDS},
                value=list(INDICATOR_KINDS),
                multiple=True,
                label='Indicator types',
            )
            .props('outlined use-chips')
            .classes('w-full')
        )
        review_input = (
            ui.select(
                list(REVIEW_STATUSES),
                value=list(DEFAULT_EXPORT_REVIEW_STATUSES),
                multiple=True,
                label='Observation review status',
            )
            .props('outlined use-chips')
            .classes('w-full')
        )
        ui.label(
            'Accepted means someone checked that the value was copied correctly. '
            'It does not mean the value is harmful.'
        ).classes('muted text-sm prose -mt-3')
        max_tlp_input = (
            ui.select(
                [NO_TLP_LIMIT, *TLP_LEVELS], value=NO_TLP_LIMIT, label='Most restrictive TLP to include'
            )
            .props('outlined')
            .classes('w-full')
        )
        inbox_input = ui.checkbox('Only reports matching the current inbox search and filters')
        defang_input = ui.checkbox('Defang values so they cannot be clicked (hxxps://, example[.]com)')
        evidence_input = ui.checkbox(
            'Include evidence excerpts: the words around each indicator. '
            'Untick this before you share the file.',
            value=True,
        )
        ui.label(
            'Check for personal data before sharing. You can leave e-mail out of the list of types. '
            'Addresses may still appear in titles and quotes from reports.'
        ).classes('text-warn text-sm prose')
        ui.label(
            'The file gets the strictest TLP label of the reports in it. Exports keep TLP labels. '
            'They do not give permission to share. The file is not in the STIX format.'
        ).classes('muted text-sm prose')
        preview = ui.label().classes('text-primary prose').props('role=status')

        def counts() -> dict[str, int] | None:
            """Counts for the current choices, or None (with a message) if the choices are incomplete."""
            try:
                query = export_query(
                    kinds=list(kinds_input.value or []),
                    review_statuses=list(review_input.value or []),
                    max_tlp=max_tlp_input.value or NO_TLP_LIMIT,
                    inbox=ws.state if inbox_input.value else None,
                )
            except ValidationError:
                preview.set_text('Choose at least one indicator type and one review status.')
                return None
            with ws.read() as db:
                found = services.ioc_export_counts(db, query)
            preview.set_text(preview_text(found))
            return found

        def refresh_preview() -> None:
            if ws.authorized():
                counts()

        for control in (kinds_input, review_input, max_tlp_input, inbox_input):
            control.on_value_change(refresh_preview)
        refresh_preview()

        def download() -> None:
            if not ws.authorized():
                return
            kinds = list(kinds_input.value or [])
            statuses = list(review_input.value or [])
            if not kinds or not statuses:
                problem.set_text('Choose at least one indicator type and one review status.')
                return
            found = counts()
            if found is None or not found['iocs'] or found['mentions'] > services.MAX_EXPORT_MENTIONS:
                problem.set_text(f'Nothing to download. {preview.text}')
                return
            url = export_url(
                kinds=kinds,
                review_statuses=statuses,
                max_tlp=max_tlp_input.value or NO_TLP_LIMIT,
                defang=bool(defang_input.value),
                inbox=ws.state if inbox_input.value else None,
                evidence=bool(evidence_input.value),
            )
            ui.navigate.to(url, new_tab=True)
            dialog.close()

        problem = problem_area()
        with ui.row().classes('w-full justify-end'):
            ui.button('Cancel', on_click=dialog.close).props('flat')
            ui.button('Download JSON ↓', on_click=download)
    dialog.open()

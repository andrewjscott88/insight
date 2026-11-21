"""The report reader: one report, its extracted observations, its ATT&CK techniques and the analyst's notes.

Written for readability (ADR 0017): real headings (report title ``h2``, sections ``h3``), the report text in a
readable column instead of a box with its own scroll bar, plain-language explanations, and links that say they
open a new tab.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..extraction import EVIDENCE_CONTEXT
from ..schemas import DOCUMENT_STATUSES, NoteInput
from .actors import render_report_groups
from .enrichment import open_enrichment_dialog
from .messages import tell
from .mobile import back_to_list_button
from .rules import render_report_rules
from .techniques import render_report_techniques
from .theme import tlp_badge
from .typography import heading, new_tab_link
from .verdicts import Indicator, VerdictView, flag_badges, render_verdict
from .workspace import Workspace


@dataclass(frozen=True, slots=True)
class ReaderActions:
    """What the reader can ask the inbox to do."""

    choose: Callable[[str], None]
    review_document: Callable[[str, str], None]
    review_observation: Callable[[str, str], None]
    refresh: Callable[[], Any]


def render_empty() -> None:
    with ui.column().classes('w-full min-h-[350px] p-4 sm:p-8 gap-2 justify-center'):
        ui.label('✳').classes('text-5xl text-primary').props('aria-hidden=true')
        heading('Your intelligence, connected.', 2)
        ui.label('Choose a report from the list to read it and check what Insight found in it.').classes(
            'muted prose'
        )


def render_report(ws: Workspace, data: dict[str, Any], actions: ReaderActions) -> None:
    back_to_list_button()
    tlp_badge(data['tlp'])
    heading(data['title'], 2, 'report-title break-value w-full')
    if data['truncated']:
        ui.label(
            'Only part of this report was saved. The publisher’s text was longer than the summary Insight '
            'keeps, so the full report may have more indicators. Open the original to read all of it.'
        ).classes('text-warn prose')
    ui.label(f'{data["source_name"]} · {data["created_at"][:10]}').classes(
        'muted text-sm prose break-value w-full'
    )
    if data['source_url']:
        new_tab_link('Open the original report', data['source_url'])
    _render_revisions(data, actions)
    ui.select(
        list(DOCUMENT_STATUSES),
        value=data['status'],
        label='Document review',
        on_change=lambda event: actions.review_document(data['id'], event.value),
    ).props('outlined').classes('w-60 max-w-full')
    heading('Report text', 3, 'subsection-title mt-3')
    ui.label(data['body']).classes('source-body panel p-4 w-full').props(
        'role=region aria-label="Report text"'
    )
    heading(f'Extracted observations ({len(data["observations"])})', 3, 'subsection-title mt-4')
    ui.label(
        'Insight found these values automatically. Check the words around each one before you accept it.'
    ).classes('muted prose')
    if not data['observations']:
        ui.label('Insight found no indicators in this report.').classes('muted')
    verdicts = data.get('verdicts', {})
    for obs in data['observations']:
        _render_observation(
            ws, obs, actions, data['tlp'], verdicts.get(obs['entity_id']), data.get('cve_scores', {})
        )
    render_report_techniques(ws, data['id'], data.get('techniques', []), actions.refresh)
    render_report_groups(ws, data['id'], actions.refresh)
    render_report_rules(ws, data['id'], data['tlp'], actions.refresh)
    with ui.row().classes('gap-x-6 gap-y-0'):
        new_tab_link('Download this report as JSON', f'/api/documents/{data["id"]}/export')
        new_tab_link("Export this report's IOCs", f'/api/iocs/export?document_id={data["id"]}')
    ui.label('Exports keep the TLP label. They do not give permission to share.').classes('muted prose')
    if any(obs['kind'] == 'email' for obs in data['observations']):
        ui.label('This report includes e-mail addresses. Check who may receive them before sharing.').classes(
            'text-warn prose'
        )
    _render_notes(ws, data, actions)
    with ui.expansion('Where this report came from').classes('w-full muted'):
        ui.label('Fingerprint (SHA-256): ' + data['content_hash']).classes('break-value font-mono text-sm')
        ui.label('Extraction rules: ' + data['extractor_version']).classes('text-sm')
        if data['source_key']:
            ui.label(f'Source item: {data["source_key"]} / {data["external_id"]}').classes(
                'break-value text-sm'
            )


def _render_revisions(data: dict[str, Any], actions: ReaderActions) -> None:
    if not data['is_current']:
        current = next((r for r in data['revisions'] if r['is_current']), None)
        with ui.row().classes('w-full items-center gap-3 panel p-3'):
            ui.label(
                'Superseded revision. This is an old version: the publisher has changed this report since.'
            ).classes('text-warn prose')
            if current is not None:
                ui.button(
                    'Open current revision', on_click=lambda doc_id=current['id']: actions.choose(doc_id)
                ).props('flat dense no-caps')
    if len(data['revisions']) > 1:
        with ui.expansion(f'Revisions · {len(data["revisions"])}').classes('w-full muted'):
            for rev in data['revisions']:
                marker = ' · current' if rev['is_current'] else ''
                here = ' · viewing' if rev['id'] == data['id'] else ''
                ui.button(
                    f'{rev["created_at"][:16].replace("T", " ")}{marker}{here}',
                    on_click=lambda doc_id=rev['id']: actions.choose(doc_id),
                ).props('flat dense no-caps align=left')


def _render_observation(
    ws: Workspace,
    obs: dict[str, Any],
    actions: ReaderActions,
    report_tlp: str,
    verdict: VerdictView | None,
    cve_scores: dict[str, str],
) -> None:
    with ui.column().classes('panel w-full p-4 gap-2'):
        with ui.row().classes('items-center w-full'):
            ui.badge(obs['kind']).props('outline')
            ui.label(obs['value']).classes('font-mono break-value flex-1 min-w-0')
        flag_badges(obs['kind'], obs['value'])
        if obs['kind'] in ('cidr', 'email'):
            # The excerpt starts at most EVIDENCE_CONTEXT characters before the exact source span.
            start = min(obs['start_offset'], EVIDENCE_CONTEXT)
            end = start + obs['end_offset'] - obs['start_offset']
            evidence = obs['evidence']
            with ui.element('div').classes('evidence text-sm w-full'):
                ui.label(evidence[:start]).tag = 'span'
                ui.label(evidence[start:end]).tag = 'mark'
                ui.label(evidence[end:]).tag = 'span'
        else:
            ui.label(obs['evidence']).classes('evidence text-sm w-full')
        ui.label(
            f'Position {obs["start_offset"]}–{obs["end_offset"]} in the text · {obs["review_status"]}'
        ).classes('muted text-sm')
        if kev := obs.get('kev'):
            ui.label(
                'On the CISA list of Known Exploited Vulnerabilities (KEV) · '
                f'added {kev["date_added"]} · fix by {kev["due_date"]}'
            ).classes('text-warn text-sm prose')
            if kev.get('ransomware_use') == 'Known':
                ui.label('CISA knows of ransomware campaigns that use it.').classes('text-warn text-sm prose')
            if kev.get('vulnerability_name'):
                ui.label(kev['vulnerability_name']).classes('text-sm prose break-value')
            ui.label(kev['required_action']).classes('muted text-sm prose')
        if obs['kind'] == 'cve':
            if scores := cve_scores.get(obs['value']):
                ui.label(scores).classes('text-sm prose')
            ui.button(
                'Look up this CVE',
                icon='travel_explore',
                on_click=lambda cve=obs['value']: open_enrichment_dialog(ws, cve),
            ).props('flat dense no-caps')
        indicator = Indicator(obs['entity_id'], obs['kind'], obs['value'], report_tlp)
        render_verdict(ws, indicator, verdict, on_saved=actions.refresh)
        with ui.row().classes('gap-2'):
            for value, label in (('accepted', 'Accept'), ('rejected', 'Reject'), ('unreviewed', 'Reset')):
                current = obs['review_status'] == value
                ui.button(
                    label,
                    on_click=lambda oid=obs['id'], status=value: actions.review_observation(oid, status),
                ).props(f'dense {"" if current else "outline"} aria-pressed={str(current).lower()}')


def _render_notes(ws: Workspace, data: dict[str, Any], actions: ReaderActions) -> None:
    state = ws.state
    heading('Analyst notes', 3, 'subsection-title mt-4')
    for note in data['notes']:
        with ui.column().classes('panel p-3 w-full gap-1'):
            ui.label(note['body']).classes('whitespace-pre-wrap break-value prose')
            ui.label(note['created_at'][:16].replace('T', ' ')).classes('muted text-sm')
    doc_id = data['id']
    note_input = (
        ui.textarea(
            'Add a note',
            placeholder='What do you think? What should happen next?',
            value=state.note_drafts.get(doc_id, ''),
            on_change=lambda e: state.note_drafts.__setitem__(doc_id, e.value or ''),
        )
        .props('outlined autogrow maxlength=10000')
        .classes('w-full prose')
    )

    def save_note() -> None:
        if not ws.authorized():
            return
        try:
            item = NoteInput(body=note_input.value or '')
        except ValidationError:
            note_input.error = 'Write a note first (up to 10,000 characters).'
            tell('Write a note first (up to 10,000 characters).', 'warning')
            return
        with ws.write() as db:
            saved = services.add_note(db, doc_id, item.body) is not None
        if not saved:
            tell('This item no longer exists.', 'warning')
            return
        state.note_drafts.pop(doc_id, None)
        actions.refresh()
        tell('Note saved.', 'success')

    ui.button('Save note', on_click=save_note).props('outline')

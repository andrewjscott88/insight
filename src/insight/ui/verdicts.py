"""Verdicts and warning flags in the workspace (review Design 1).

Accept and Reject say whether Insight copied a value correctly. A **verdict** says what the value
means: unknown, benign, suspicious or malicious. **Warning flags** say why a value should never be
blocked, whatever its verdict; they are worked out from the value itself (``insight.flags``), never
stored. Only a malicious value with an accepted mention and no warning flag reaches the blocklist
(``GET /api/iocs/blocklist``).

The verdict's reason carries its own TLP label, because it may quote a restricted report. The dialog
suggests the more restrictive of AMBER and the report's own label, within what this instance may store.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Final

from nicegui import ui
from pydantic import ValidationError
from sqlalchemy.orm import Session

from .. import services
from ..flags import Flag, flags
from ..permissions import Permission
from ..schemas import TLP_LEVELS, AssessmentInput, Verdict
from .messages import tell
from .typography import heading
from .workspace import Workspace

VERDICT_LABELS: Final[dict[Verdict, str]] = {
    'unknown': 'Unknown',
    'benign': 'Benign',
    'suspicious': 'Suspicious',
    'malicious': 'Malicious',
}
#: Plain names for the flags; each is a glossary term (``tests/ui/test_verdicts.py`` checks it).
FLAG_LABELS: Final[dict[Flag, str]] = {
    'non-routable': 'Private or reserved address',
    'documentation': 'Example address',
    'reserved-name': 'Reserved name',
    'common-benign': 'Common vendor site',
    'personal-data': 'Personal data',
}


@dataclass(frozen=True, slots=True)
class VerdictView:
    """A recorded verdict, copied out of the session so it can be shown after the session closes."""

    verdict: Verdict
    reason: str
    tlp: str
    valid_until: str | None
    decided_at: str
    actor: str


@dataclass(frozen=True, slots=True)
class Indicator:
    """The entity a verdict is about, and the label of the report it is being read in (if any)."""

    entity_id: str
    kind: str
    value: str
    report_tlp: str | None = None


def load_verdicts(db: Session, entity_ids: Iterable[str]) -> dict[str, VerdictView]:
    """Recorded verdicts on these entities, by entity ID (the operator sees every label)."""
    return {
        entity_id: VerdictView(
            verdict=row.verdict,  # type: ignore[arg-type]  # only VERDICTS are ever stored
            reason=row.reason,
            tlp=row.tlp,
            valid_until=row.valid_until,
            decided_at=row.decided_at,
            actor=row.actor,
        )
        for entity_id, row in services.visible_assessments(db, entity_ids).items()
    }


def suggested_tlp(report_tlp: str | None, permitted: list[str]) -> str:
    """AMBER, or the report's label when that is more restrictive, but never above what may be stored."""
    wanted = 'AMBER'
    if report_tlp in TLP_LEVELS and TLP_LEVELS.index(report_tlp) > TLP_LEVELS.index(wanted):
        wanted = report_tlp
    return wanted if wanted in permitted else permitted[-1]


def verdict_summary(view: VerdictView | None) -> str:
    if view is None:
        return 'Verdict: Unknown'
    parts = [f'Verdict: {VERDICT_LABELS[view.verdict]}']
    if view.valid_until:
        parts.append(f'until {view.valid_until[:10]}')
    parts.append(f'TLP:{view.tlp}')
    parts.append(f'set by {view.actor} on {view.decided_at[:10]}')
    return ' · '.join(parts)


def flag_badges(kind: str, value: str) -> tuple[Flag, ...]:
    """Show a badge for each warning flag on this value, and return the flags."""
    found = flags(kind, value)
    if found:
        with ui.row().classes('gap-2'):
            for flag in found:
                ui.label(FLAG_LABELS[flag]).classes('flag-badge text-warn text-xs rounded px-2 py-1')
    return found


def render_verdict(
    ws: Workspace, target: Indicator, view: VerdictView | None, on_saved: Callable[[], Any]
) -> None:
    """The verdict line, its reason and the button that changes it."""
    found = flags(target.kind, target.value)
    ui.label(verdict_summary(view)).classes('verdict-summary text-sm')
    if view is not None and view.reason:
        ui.label(view.reason).classes('muted text-sm prose break-value whitespace-pre-wrap')
    if view is not None and view.verdict == 'malicious' and found:
        ui.label('Kept off the blocklist because of its warning.').classes('text-warn text-sm prose')
    ui.button(
        'Change verdict' if view else 'Set verdict',
        icon='gavel',
        on_click=lambda: open_verdict_dialog(ws, target, view, on_saved),
    ).props('flat dense no-caps')


def open_verdict_dialog(
    ws: Workspace, target: Indicator, view: VerdictView | None, on_saved: Callable[[], Any]
) -> None:
    if not ws.authorized():
        return
    max_tlp = ws.app.state.settings.max_tlp
    permitted = services.permitted_tlp_levels(max_tlp)
    with (
        ui.dialog().props('aria-label="Verdict on this indicator"') as dialog,
        ui.card().classes('w-full max-w-xl gap-3'),
    ):
        heading('Verdict on this indicator', 2)
        ui.label(target.value).classes('font-mono break-value')
        ui.label(
            'Accept only says Insight copied the value right. The verdict says what it means. '
            'Only malicious values with no warning go on the blocklist.'
        ).classes('muted prose')
        choice = ui.radio(dict(VERDICT_LABELS), value=view.verdict if view else 'malicious').props(
            'inline aria-label=Verdict'
        )
        reason = (
            ui.textarea(
                'Reason',
                placeholder='Why? For example: the March report names it as a command server.',
                value=view.reason if view else '',
            )
            .props('outlined autogrow maxlength=2000')
            .classes('w-full prose')
        )
        current_tlp = view.tlp if view and view.tlp in permitted else None
        label = ui.select(
            permitted,
            value=current_tlp or suggested_tlp(target.report_tlp, permitted),
            label='TLP label for the reason',
        ).props('outlined')
        until = ui.input(
            'Valid until (leave empty for no end date)', value=(view.valid_until or '')[:10] if view else ''
        ).props('outlined stack-label type=date')

        def save() -> None:
            if not ws.allowed(Permission.REVIEW):
                return
            try:
                payload = AssessmentInput(
                    verdict=choice.value,
                    reason=reason.value or '',
                    tlp=label.value,
                    valid_until=until.value or None,
                )
            except ValidationError as error:
                fields = {str(e['loc'][0]) for e in error.errors() if e['loc']}
                if 'valid_until' in fields:
                    until.error = 'Pick today or a later date, or leave it empty.'
                    tell('Pick today or a later date, or leave the end date empty.', 'warning')
                else:
                    tell('Check the verdict and the reason (up to 2,000 characters).', 'warning')
                return
            try:
                with ws.write(Permission.REVIEW) as db:
                    services.assess_entity(db, target.entity_id, payload, max_tlp=max_tlp)
            except LookupError:
                tell('This item no longer exists.', 'warning')
                return
            except services.TlpNotPermitted:
                tell('This instance cannot store a verdict with that label.', 'warning')
                return
            dialog.close()
            on_saved()
            tell('Verdict cleared.' if payload.verdict == 'unknown' else 'Verdict saved.', 'success')

        with ui.row().classes('gap-2'):
            ui.button('Save verdict', on_click=save)
            ui.button('Cancel', on_click=dialog.close).props('flat')
    dialog.open()

"""Confidence and source reliability in the workspace (TIP 4.2, ADR 0033): an indicator's confidence with the
sources behind it, a report's credibility, and the Source reliability panel in Settings."""

from __future__ import annotations

from typing import Final

from nicegui import ui
from pydantic import ValidationError

from .. import services
from ..schemas import CredibilityInput, SourceRatingInput
from .messages import tell
from .typography import heading
from .workspace import Workspace

BAND_TEXT: Final = {'high': 'High', 'medium': 'Medium', 'low': 'Low', 'none': 'None'}
AGEING: Final = {0: 'Default for the type', 7: '7 days', 30: '30 days', 90: '90 days', 365: '1 year'}


def render_confidence(found: services.Confidence) -> None:
    """One line, and the sources behind it when opened."""
    count = len(found.sources)
    sources = 'source' if count == 1 else 'sources'
    line = f'Confidence {found.score} ({BAND_TEXT[found.band].lower()}): {count} {sources} you can see'
    with ui.expansion(line).classes('w-full').props('dense').mark('entity-confidence'):
        for source in found.sources:
            ui.label(
                f'{source.source_name} · reliability {source.reliability} · {source.reports} report(s), '
                f'newest {source.newest_at[:10]} · adds {source.weight}'
            ).classes('text-sm break-value')
        ageing = (
            f'Reports lose half their weight every {found.half_life_days} days.'
            if found.half_life_days
            else 'This kind of indicator does not age.'
        )
        ui.label(f'{ageing} Grade sources in Settings and reports in the reader to sharpen this.').classes(
            'muted text-sm prose'
        )


def render_credibility(ws: Workspace, document_id: str, value: int) -> None:
    """The credibility select in the reader."""
    limit = ws.app.state.settings.max_tlp

    def save(chosen: int) -> None:
        if not ws.authorized() or chosen == value:
            return
        try:
            with ws.write() as db:
                services.set_credibility(db, document_id, CredibilityInput(credibility=chosen), max_tlp=limit)
        except (LookupError, ValidationError):
            tell('That could not be saved.', 'warning')
            return
        tell('Credibility saved. Confidence in its indicators follows.', 'success')

    options = {grade: f'{grade} · {text}' for grade, text in services.CREDIBILITY.items()}
    ui.select(
        options, value=value, label='How believable is this report?', on_change=lambda e: save(e.value)
    ).props('outlined').classes('w-72 max-w-full').mark('report-credibility')


def build_source_ratings(ws: Workspace) -> None:
    """Settings: Source reliability: grade each source and see what it adds."""

    def save(name: str, grade: str, ageing: int) -> None:
        if not ws.authorized():
            return
        payload = SourceRatingInput(source_name=name, reliability=grade, half_life_days=ageing or None)
        with ws.write() as db:
            services.rate_source(db, payload)
        tell(f'{name}: reliability {grade}.', 'success')

    @ui.refreshable
    def table() -> None:
        if not ws.authorized():
            return
        with ws.read() as db:
            stats = services.source_statistics(db, max_tlp=ws.app.state.settings.max_tlp)
        if not stats:
            ui.label('No reports yet.').classes('muted')
            return
        grades = {g: f'{g} · {text}' for g, text in services.RELIABILITY.items()}
        for s in stats:
            with (
                ui.row().classes('w-full items-center gap-3 panel p-2').mark(f'source-rating-{s.source_name}')
            ):
                ui.label(s.source_name).classes('font-semibold break-value prose min-w-40')
                grade = ui.select(grades, value=s.reliability, label='Reliability').props('outlined dense')
                ageing = ui.select(AGEING, value=s.half_life_days or 0, label='Ageing').props(
                    'outlined dense'
                )
                rejected = (
                    f'{round(100 * s.rejected / s.reviewed)}% rejected' if s.reviewed else 'none reviewed'
                )
                ui.label(
                    f'{s.reports} report(s) · {s.indicators} indicator(s), {s.unique_indicators} only here · '
                    f'{rejected}'
                ).classes('muted text-sm')
                grade.on_value_change(lambda e, n=s.source_name, a=ageing: save(n, e.value, a.value))
                ageing.on_value_change(lambda e, n=s.source_name, g=grade: save(n, g.value, e.value))

    heading('Source reliability', 2)
    ui.label(
        'Grade how far you trust each source, from A (completely reliable) to F (cannot be judged). '
        'Grades and ageing shape the confidence of every indicator.'
    ).classes('muted prose')
    ws.on_refresh(table.refresh)
    with ui.column().classes('w-full gap-2 mt-2'):
        table()

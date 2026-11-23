"""The product in a case (TIP 4.4, ADR 0036): bottom line up front, key judgements, analysis and gaps.

Rendered inside the case dialog (``case_detail``), which owns the ``write`` helper: every change goes through
it, so errors and refreshes are handled in one place.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from nicegui import ui

from .. import services
from ..product_markdown import LIKELIHOOD
from ..schemas import CaseUpdate, GapInput, JudgementInput
from .theme import tlp_badge
from .typography import heading

Write = Callable[[Callable[[Any], object], str], None]
PRODUCT_TYPES: Final = {
    'assessment': 'Assessment: what we judge, and why',
    'alert': 'Alert: a short, urgent warning',
    'profile': 'Profile: one threat group, campaign or tool',
    'summary': 'Summary: a regular round-up',
}
LIKELIHOOD_CHOICES: Final = {key: f'{words} ({odds})' for key, (words, odds) in LIKELIHOOD.items()}
CONFIDENCE_CHOICES: Final = {
    'low': 'Low confidence',
    'moderate': 'Moderate confidence',
    'high': 'High confidence',
}
KINDS: Final = {'document': 'Report', 'indicator': 'Indicator', 'actor': 'Actor', 'campaign': 'Campaign'}


def render_bottom_line(view: services.CaseView, write: Write, limit: str | None, editable: bool) -> None:
    heading('Bottom line up front', 3)
    if not editable:
        ui.label(view.bluf or 'Not written.').classes('prose break-value')
        return
    ui.label(
        'The answer first, in two or three sentences. Readers who stop here should still know it.'
    ).classes('muted prose')
    bluf = (
        ui.textarea(value=view.bluf)
        .props('outlined maxlength=2000 aria-label="Bottom line up front"')
        .mark('product-bluf')
    )
    kind = ui.select(PRODUCT_TYPES, value=view.product_type, label='Kind of product').props('outlined')
    audience = ui.input('Who is it for?', value=view.audience).props('outlined maxlength=200')

    def save() -> None:
        def action(db: Any) -> object:
            payload = CaseUpdate(
                bluf=bluf.value or '', product_type=kind.value, audience=audience.value or ''
            )
            return services.update_case(db, view.id, payload, max_tlp=limit)

        write(action, 'Saved.')

    ui.button('Save', on_click=save).props('outline').classes('self-start').mark('product-bluf-save')


def _evidence_names(view: services.CaseView) -> dict[str, str]:
    return {i.id: f'{KINDS[i.kind]} · {i.name or i.target_id}' for i in view.items if i.kind != 'note'}


def render_judgements(
    view: services.CaseView, parts: services.ProductParts, write: Write, limit: str | None, editable: bool
) -> None:
    heading('Key judgements', 3)
    names = _evidence_names(view)
    if not parts.judgements:
        ui.label('None yet. A product needs at least one, with its evidence.').classes('muted')
    for judgement in parts.judgements:
        words, odds = LIKELIHOOD[judgement.likelihood]
        with ui.column().classes('gap-0 w-full').mark(f'product-judgement-{judgement.position}'):
            with ui.row().classes('items-center gap-2'):
                ui.label(
                    f'{judgement.position}. {words} ({odds}), {CONFIDENCE_CHOICES[judgement.confidence]}'
                ).classes('font-semibold')
                tlp_badge(judgement.tlp)
            ui.label(judgement.statement).classes('prose break-value')
            cited = '; '.join(names.get(i, i) for i in judgement.evidence) or 'none yet'
            ui.label(f'Evidence: {cited}').classes('muted text-sm break-value prose')
            if editable:
                ui.button(
                    'Remove',
                    on_click=lambda j=judgement: write(
                        lambda db: services.remove_judgement(db, view.id, j.id, max_tlp=limit),
                        'Key judgement removed. The product keeps its label.',
                    ),
                ).props('flat dense no-caps').classes('self-start')
    if not editable:
        return
    statement = ui.textarea('New key judgement').props('outlined maxlength=1000').mark('product-judgement')
    with ui.row().classes('gap-2 w-full'):
        likelihood = ui.select(LIKELIHOOD_CHOICES, value='likely', label='How likely').props('outlined')
        confidence = ui.select(CONFIDENCE_CHOICES, value='moderate', label='How sure').props('outlined')
    evidence = (
        ui.select(names, multiple=True, value=[], label='Evidence from this product')
        .props('outlined use-chips')
        .classes('w-full')
        .mark('product-judgement-evidence')
    )

    def add() -> None:
        def action(db: Any) -> object:
            payload = JudgementInput(
                statement=statement.value or ' ',
                likelihood=likelihood.value,
                confidence=confidence.value,
                evidence=list(evidence.value or []),
            )
            return services.add_judgement(db, view.id, payload, max_tlp=limit)

        write(action, 'Key judgement added.')

    ui.button('Add key judgement', on_click=add).props('outline').classes('self-start').mark(
        'product-judgement-add'
    )


def render_analysis(view: services.CaseView, write: Write, limit: str | None, editable: bool) -> None:
    heading('Analysis', 3)
    if not editable:
        ui.label(view.summary or 'Not written.').classes('prose break-value')
        return
    analysis = (
        ui.textarea(value=view.summary)
        .props('outlined autogrow maxlength=30000 aria-label="Analysis"')
        .classes('w-full')
        .mark('product-analysis')
    )

    def save() -> None:
        def action(db: Any) -> object:
            return services.update_case(db, view.id, CaseUpdate(summary=analysis.value or ''), max_tlp=limit)

        write(action, 'Saved.')

    ui.button('Save', on_click=save).props('outline').classes('self-start').mark('product-analysis-save')


def render_gaps(
    view: services.CaseView, parts: services.ProductParts, write: Write, limit: str | None, editable: bool
) -> None:
    heading('Intelligence gaps', 3)
    if not parts.gaps:
        ui.label('None recorded. Write down what you could not find out.').classes('muted')
    for gap in parts.gaps:
        with ui.row().classes('items-center gap-2 w-full').mark('product-gap'):
            ui.label(gap.question).classes('prose break-value')
            tlp_badge(gap.tlp)
            if gap.requirement_id:
                ui.label('Asked as a request for information').classes('muted text-sm')
            elif editable:
                ui.button(
                    'Ask as a request',
                    on_click=lambda g=gap: write(
                        lambda db: services.ask_gap(db, view.id, g.id, max_tlp=limit),
                        'Asked. Find the request in Settings, under Intelligence questions.',
                    ),
                ).props('flat dense no-caps').mark('product-gap-ask')
            if editable:
                ui.button(
                    'Remove',
                    on_click=lambda g=gap: write(
                        lambda db: services.remove_gap(db, view.id, g.id, max_tlp=limit), 'Gap removed.'
                    ),
                ).props('flat dense no-caps')
    if editable:
        question = (
            ui.input('What could you not find out?').props('outlined maxlength=300').mark('product-gap-new')
        )

        def add() -> None:
            def action(db: Any) -> object:
                return services.add_gap(db, view.id, GapInput(question=question.value or ''), max_tlp=limit)

            write(action, 'Gap added.')

        ui.button('Add gap', on_click=add).props('outline').classes('self-start').mark('product-gap-add')

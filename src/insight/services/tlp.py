"""TLP levels and visibility: the security core. Kept tiny; imports nothing from its siblings."""

from __future__ import annotations

import logging

from sqlalchemy import ColumnElement

from ..models import (
    Document,
)
from ..schemas import (
    TLP_LEVELS,
    DocumentInput,
    most_restrictive,
    tlp_markings,
)

log = logging.getLogger('insight.tlp')


def apply_tlp_policy(item: DocumentInput) -> DocumentInput:
    """Raise the label to the most restrictive ``TLP:`` marking in the title or body. Never lowers it."""
    effective = most_restrictive(item.tlp, *tlp_markings(f'{item.title}\n{item.body}'))
    return item if effective == item.tlp else item.model_copy(update={'tlp': effective})


class TlpNotPermitted(ValueError):
    """The label (after ``apply_tlp_policy``) is above what this instance stores (``INSIGHT_MAX_TLP``)."""


def tlp_permitted(label: str, max_tlp: str) -> bool:
    return TLP_LEVELS.index(label) <= TLP_LEVELS.index(max_tlp)


def permitted_tlp_levels(max_tlp: str) -> list[str]:
    """Labels a submitter may choose, least restrictive first."""
    return [label for label in TLP_LEVELS if tlp_permitted(label, max_tlp)]


def _refuse_above(submitted: str, effective: str, max_tlp: str) -> None:
    if tlp_permitted(effective, max_tlp):
        return
    limit = f'This instance stores reports up to TLP:{max_tlp} (INSIGHT_MAX_TLP).'
    if effective == submitted:
        message = f'TLP:{effective} reports cannot be stored here. {limit}'
    else:
        message = (
            f'Refused: the text carries a TLP:{effective} marking, so the report counts as TLP:{effective} '
            f'(submitted as TLP:{submitted}). {limit} If the text only mentions that label, reword it.'
        )
    log.warning('Refused a TLP:%s report (submitted as TLP:%s; limit TLP:%s)', effective, submitted, max_tlp)
    raise TlpNotPermitted(message)


def visible_levels(max_tlp: str | None) -> tuple[str, ...]:
    """Labels a reader limited to ``max_tlp`` may see (all of them for ``None``)."""
    return TLP_LEVELS if max_tlp is None else TLP_LEVELS[: TLP_LEVELS.index(max_tlp) + 1]


def stricter_limit(*limits: str | None) -> str | None:
    """The most restrictive of several optional TLP limits (``None`` means unlimited)."""
    given = [limit for limit in limits if limit is not None]
    return min(given, key=TLP_LEVELS.index) if given else None


def _visible(max_tlp: str | None) -> list[ColumnElement[bool]]:
    """SQL condition restricting ``Document`` rows to a reader's TLP limit (none when unlimited)."""
    return [] if max_tlp is None else [Document.tlp.in_(visible_levels(max_tlp))]

"""Sector names for brief search, using Insight's existing, cited industry taxonomy."""

from __future__ import annotations

import re

from .industries import INDUSTRIES


def industry_choices(query: str = '') -> list[tuple[str, str]]:
    """Search names, scope and source aliases; sector and industry mean the same focus here."""
    terms = [term for term in re.findall(r'\w+', query.casefold()) if term not in {'sector', 'industry'}]
    return [
        (industry.key, industry.name)
        for industry in sorted(INDUSTRIES, key=lambda item: item.name)
        if all(
            term in ' '.join((industry.key, industry.name, industry.covers, *industry.labels)).casefold()
            for term in terms
        )
    ]

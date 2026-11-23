"""MITRE ATT&CK® domain catalogs and precision-first technique finding (ADRs 0019 and 0042).

The catalogs (``data/attack-*.json``, regenerated with ``scripts/update_attack.py``) hold every
current Enterprise, Mobile and ICS technique with its tactics. MITRE ATT&CK is reproduced and distributed
with the permission of The MITRE Corporation; see ``NOTICE``.

:func:`find_techniques` only reports technique IDs written in the text (``T1059``, ``T1059.001``) that exist
in the catalog: the report's own author mapped them. Insight never guesses a technique from prose, a product
name or a CVE, and never infers an actor from techniques.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from typing import Final, Literal

Domain = Literal['enterprise', 'mobile', 'ics']
DOMAINS: Final[dict[Domain, str]] = {
    'enterprise': 'Enterprise',
    'mobile': 'Mobile',
    'ics': 'Industrial control systems',
}

#: Characters of context kept on each side of a technique ID, as for indicators.
EVIDENCE_CONTEXT: Final = 90
#: At most this many distinct techniques are recorded from one report.
MAX_TECHNIQUES: Final = 500
TECHNIQUE_ID: Final = re.compile(r'^T\d{4}(?:\.\d{3})?$')
# Uppercase T only; not part of a longer word, version, path segment or number (T1059.0012, XT1059, T1059-2).
_FINDER: Final = re.compile(r'(?<![\w.\-])T\d{4}(?:\.\d{3})?(?![\w\-]|\.\d)')


@dataclass(frozen=True, slots=True)
class Tactic:
    id: str
    shortname: str
    name: str


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]  # tactic shortnames, in matrix order
    parent_name: str | None = None  # the parent technique's name, for sub-techniques
    domain: Domain = 'enterprise'

    @property
    def kill_chain(self) -> str:
        return 'mitre-attack' if self.domain == 'enterprise' else f'mitre-{self.domain}-attack'

    @property
    def is_subtechnique(self) -> bool:
        return '.' in self.id

    @property
    def full_name(self) -> str:
        """``Command and Scripting Interpreter: PowerShell`` for a sub-technique, the name otherwise."""
        return f'{self.parent_name}: {self.name}' if self.parent_name else self.name

    @property
    def url(self) -> str:
        return f'https://attack.mitre.org/techniques/{self.id.replace(".", "/")}/'


@dataclass(frozen=True, slots=True)
class Catalog:
    version: str
    notice: str
    terms: str
    tactics: tuple[Tactic, ...]
    techniques: dict[str, Technique]
    domain: Domain = 'enterprise'

    def tactic_names(self, technique: Technique) -> tuple[str, ...]:
        names = {t.shortname: t.name for t in self.tactics}
        return tuple(names[s] for s in technique.tactics if s in names)


@dataclass(frozen=True, slots=True)
class TechniqueMention:
    """A technique ID written in a report: where it is, and the text around it."""

    technique_id: str
    start: int
    end: int
    evidence: str


@cache
def catalog(domain: Domain = 'enterprise') -> Catalog:
    """A bundled ATT&CK domain, loaded once; Enterprise remains the default."""
    if domain not in DOMAINS:
        raise ValueError('Unknown ATT&CK domain')
    raw = json.loads(files('insight').joinpath(f'data/attack-{domain}.json').read_text(encoding='utf-8'))
    order = [t['shortname'] for t in raw['tactics']]
    names = {t['id']: t['name'] for t in raw['techniques']}
    techniques = {
        t['id']: Technique(
            id=t['id'],
            name=t['name'],
            tactics=tuple(sorted(t['tactics'], key=order.index)),
            parent_name=names.get(t['id'].split('.')[0]) if '.' in t['id'] else None,
            domain=domain,
        )
        for t in raw['techniques']
    }
    return Catalog(
        version=raw['version'],
        notice=raw['notice'],
        terms=raw['terms'],
        tactics=tuple(Tactic(t['id'], t['shortname'], t['name']) for t in raw['tactics']),
        techniques=techniques,
        domain=domain,
    )


@cache
def all_techniques() -> dict[str, Technique]:
    """The three catalogs, refusing ambiguous IDs rather than silently picking a domain."""
    combined: dict[str, Technique] = {}
    for domain in DOMAINS:
        for key, value in catalog(domain).techniques.items():
            if key in combined:
                raise ValueError('ATT&CK technique ID appears in multiple domains')
            combined[key] = value
    return combined


def technique(technique_id: str) -> Technique | None:
    return all_techniques().get(technique_id.strip().upper())


def search(query: str, limit: int = 50, *, domain: Domain = 'enterprise') -> list[Technique]:
    """Techniques whose ID starts with, or whose full name contains, ``query`` (case-insensitive), by ID."""
    q = query.strip().casefold()
    found = [
        t
        for t in catalog(domain).techniques.values()
        if not q or t.id.casefold().startswith(q) or q in t.full_name.casefold()
    ]
    return found[: max(1, limit)]


def find_techniques(text: str) -> list[TechniqueMention]:
    """Technique IDs written in ``text`` that exist in the catalog: the first mention of each, in order."""
    known = all_techniques()
    found: dict[str, TechniqueMention] = {}
    for match in _FINDER.finditer(text):
        technique_id = match.group()
        if technique_id in found or technique_id not in known:
            continue
        start, end = match.span()
        evidence = text[max(0, start - EVIDENCE_CONTEXT) : end + EVIDENCE_CONTEXT]
        found[technique_id] = TechniqueMention(technique_id, start, end, evidence)
        if len(found) >= MAX_TECHNIQUES:
            break
    return list(found.values())

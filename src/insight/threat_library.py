"""The threat library: ATT&CK groups/software and sourced MISP aliases/claims (ADR 0025, ADR 0038).

Two editions, versioned format (``insight.threat_library_build``; format 1 is still readable):

* **bundled**: ``data/actors.json``, shipped with Insight and regenerated with ``scripts/update_actors.py``.
  Every current ATT&CK group, its aliases, techniques, software, campaigns and industry claims, and for each
  technique its ATT&CK mitigations and detection strategies (data components, log sources). Descriptions are
  shortened and ATT&CK analytics and procedure examples are left out, to keep the repository small.
  Every current malware/tool is included, even without a group; aliases retain their catalog provenance.
* **full**: ``<INSIGHT_DATA_DIR>/threat-library.json``, written by ``insight threat-library-sync`` from the
  same pinned releases (``insight.threat_library_sync``). Adds whole descriptions, procedure examples, ATT&CK
  analytics and every reference. Used instead of the bundled edition when present and valid.

Both are read-only catalog data: a group in the library is not a claim that it is in the analyst's reports,
and nothing here attributes activity to anyone. MITRE ATT&CK is reproduced under MITRE's terms (``NOTICE``).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from functools import cache
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

from .attack import catalog
from .industries import BY_KEY

log = logging.getLogger('insight.threat_library')

FORMAT: Final = 'insight-threat-library-2'
LEGACY_FORMAT: Final = 'insight-threat-library-1'
SYNCED_NAME: Final = 'threat-library.json'


@dataclass(frozen=True, slots=True)
class Citation:
    name: str
    url: str


@dataclass(frozen=True, slots=True)
class Claim:
    """A source naming industries a group targeted, with the words it uses."""

    industries: tuple[str, ...]
    source: str  # 'attack' or 'misp-galaxy' (catalogs); 'analyst' for the analyst's own (services)
    evidence: str
    url: str
    citations: tuple[Citation, ...] = ()
    match: str = ''

    @property
    def source_name(self) -> str:
        return SOURCE_NAMES.get(self.source, self.source)


SOURCE_NAMES: Final[dict[str, str]] = {
    'attack': 'MITRE ATT&CK',
    'misp-galaxy': 'MISP galaxy',
    'analyst': 'Your own mapping',
}


@dataclass(frozen=True, slots=True)
class Campaign:
    id: str
    name: str
    first_seen: str
    last_seen: str

    @property
    def url(self) -> str:
        return f'https://attack.mitre.org/campaigns/{self.id}/'


@dataclass(frozen=True, slots=True)
class AliasSource:
    """The catalog that supplies an alias; MISP also records its entry and the exact ATT&CK name match."""

    name: str
    source: str
    url: str
    entry: str = ''
    entry_id: str = ''
    matched_name: str = ''


@dataclass(frozen=True, slots=True)
class Group:
    id: str
    name: str
    aliases: tuple[str, ...]
    description: str
    url: str
    modified: str
    techniques: tuple[str, ...]
    software: tuple[str, ...]
    claims: tuple[Claim, ...]
    regions: tuple[str, ...]
    campaigns: tuple[Campaign, ...]
    references: tuple[Citation, ...]
    procedures: dict[str, str] = field(default_factory=dict)
    alias_sources: tuple[AliasSource, ...] = ()

    @property
    def names(self) -> tuple[str, ...]:
        return (self.name, *self.aliases)

    @property
    def last_activity(self) -> Campaign | None:
        """The ATT&CK campaign attributed to the group that was seen most recently, if any."""
        dated = [c for c in self.campaigns if c.last_seen]
        return max(dated, key=lambda c: c.last_seen) if dated else None

    def claims_for(self, industry: str) -> tuple[Claim, ...]:
        return tuple(c for c in self.claims if industry in c.industries)

    @property
    def industries(self) -> tuple[str, ...]:
        keys = {k for c in self.claims for k in c.industries}
        return tuple(i for i in BY_KEY if i in keys)


@dataclass(frozen=True, slots=True)
class Analytic:
    id: str
    platforms: tuple[str, ...]
    description: str
    log_sources: tuple[tuple[str, str, str], ...]  # (data component ID, log source, channel)


@dataclass(frozen=True, slots=True)
class Detection:
    """An ATT&CK detection strategy for a technique (``DET0560``) and the telemetry it needs."""

    id: str
    name: str
    platforms: tuple[str, ...]
    components: tuple[str, ...]  # data component IDs (``DC0032``)
    log_sources: tuple[str, ...]
    analytics: tuple[Analytic, ...] = ()

    @property
    def url(self) -> str:
        return f'https://attack.mitre.org/detectionstrategies/{self.id}/'


@dataclass(frozen=True, slots=True)
class TechniqueContext:
    mitigations: tuple[str, ...]
    detections: tuple[Detection, ...]


@dataclass(frozen=True, slots=True)
class Software:
    id: str
    name: str
    type: str  # 'malware' or 'tool'
    aliases: tuple[str, ...] = ()
    description: str = ''
    platforms: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()

    @property
    def names(self) -> tuple[str, ...]:
        return (self.name, *self.aliases)

    @property
    def url(self) -> str:
        return f'https://attack.mitre.org/software/{self.id}/'


@dataclass(frozen=True, slots=True)
class Library:
    edition: str
    notice: str
    sources: dict[str, dict[str, str]]
    groups: dict[str, Group]
    techniques: dict[str, TechniqueContext]
    mitigations: dict[str, str]
    software: dict[str, Software]
    data_components: dict[str, str]
    path: str

    @property
    def attack_version(self) -> str:
        return self.sources.get('attack', {}).get('version', 'unknown')

    def group(self, group_id: str) -> Group | None:
        return self.groups.get(group_id.strip().upper())

    def groups_for(self, industry: str) -> list[Group]:
        return [g for g in self.groups.values() if g.claims_for(industry)]

    def search(self, query: str, limit: int = 50) -> list[Group]:
        """Groups whose ID starts with, or any of whose names contains, ``query`` (case-insensitive)."""
        q = query.strip().casefold()
        found = [
            g
            for g in sorted(self.groups.values(), key=lambda g: g.name.casefold())
            if not q or g.id.casefold().startswith(q) or any(q in n.casefold() for n in g.names)
        ]
        return found[: max(1, limit)]


def _claims(raw: list[dict[str, Any]], url: str, misp_url: str) -> tuple[Claim, ...]:
    return tuple(
        Claim(
            industries=tuple(k for k in c['industries'] if k in BY_KEY),
            source=c['source'],
            evidence=c['evidence'],
            url=url if c['source'] == 'attack' else misp_url,
            citations=tuple(Citation(x['name'], x['url']) for x in c.get('citations', [])),
            match=c.get('match', ''),
        )
        for c in raw
    )


def _alias_sources(group: dict[str, Any], misp_url: str, legacy: bool) -> tuple[AliasSource, ...]:
    if legacy:
        sources = {name: [{'source': 'attack'}] for name in group.get('aliases', [])}
    else:
        references = group['alias_references']
        sources = {}
        for name, indices in group['alias_sources'].items():
            if any(type(index) is not int or not 0 <= index < len(references) for index in indices):
                raise ValueError('Invalid alias source reference')
            sources[name] = [references[index] for index in indices]
    return tuple(
        AliasSource(
            name=name,
            source=source['source'],
            url=group.get('url', '') if source['source'] == 'attack' else misp_url,
            entry=source.get('entry', ''),
            entry_id=source.get('entry_id', ''),
            matched_name=source.get('matched_name', ''),
        )
        for name, evidence in sources.items()
        for source in evidence
    )


def _software(software_id: str, raw: dict[str, Any], legacy: bool) -> Software:
    if raw['type'] not in ('malware', 'tool'):
        raise ValueError('Library software must be malware or tool')
    if legacy:
        return Software(software_id, raw['name'], raw['type'])
    return Software(
        id=software_id,
        name=raw['name'],
        type=raw['type'],
        aliases=tuple(raw['aliases']),
        description=raw['description'],
        platforms=tuple(raw['platforms']),
        techniques=tuple(raw['techniques']),
        groups=tuple(raw['groups']),
    )


def parse(raw: dict[str, Any], path: str) -> Library:
    """A :class:`Library` from the JSON of either edition (``ValueError`` for anything else)."""
    if raw.get('format') not in (FORMAT, LEGACY_FORMAT):
        raise ValueError(f'Not an Insight threat library ({FORMAT})')
    legacy = raw['format'] == LEGACY_FORMAT
    misp_url = raw['sources'].get('misp-galaxy', {}).get('url', 'https://github.com/MISP/misp-galaxy')
    groups = {}
    for g in raw['groups']:
        regions = tuple(n for r in g.get('regions', []) for n in r.get('names', []))
        groups[g['id']] = Group(
            id=g['id'],
            name=g['name'],
            aliases=tuple(g.get('aliases', [])),
            description=g.get('description', ''),
            url=g.get('url', ''),
            modified=g.get('modified', ''),
            techniques=tuple(g.get('techniques', [])),
            software=tuple(g.get('software', [])),
            claims=_claims(g.get('industries', []), g.get('url', ''), misp_url),
            regions=regions,
            campaigns=tuple(Campaign(**c) for c in g.get('campaigns', [])),
            references=tuple(Citation(r['name'], r['url']) for r in g.get('references', [])),
            procedures=dict(g.get('procedures', {})),
            alias_sources=_alias_sources(g, misp_url, legacy),
        )
    techniques = {
        tid: TechniqueContext(
            mitigations=tuple(t.get('mitigations', [])),
            detections=tuple(
                Detection(
                    id=d['id'],
                    name=d['name'],
                    platforms=tuple(d.get('platforms', [])),
                    components=tuple(d.get('components', [])),
                    log_sources=tuple(d.get('log_sources', [])),
                    analytics=tuple(
                        Analytic(
                            id=a['id'],
                            platforms=tuple(a.get('platforms', [])),
                            description=a.get('description', ''),
                            log_sources=tuple((s[0], s[1], s[2]) for s in a.get('log_sources', [])),
                        )
                        for a in d.get('analytics', [])
                    ),
                )
                for d in t.get('detections', [])
            ),
        )
        for tid, t in raw['techniques'].items()
    }
    return Library(
        edition=raw.get('edition', 'bundled'),
        notice=raw.get('notice', ''),
        sources=raw['sources'],
        groups=groups,
        techniques=techniques,
        mitigations=dict(raw.get('mitigations', {})),
        software={sid: _software(sid, s, legacy) for sid, s in raw.get('software', {}).items()},
        data_components=dict(raw.get('data_components', {})),
        path=path,
    )


def synced_path(environ: dict[str, str] | None = None) -> Path:
    """Where ``insight threat-library-sync`` writes the full edition (next to the default database)."""
    env = os.environ if environ is None else environ
    return Path(env.get('INSIGHT_DATA_DIR', 'data')) / SYNCED_NAME


def _bundled() -> Library:
    resource = files('insight').joinpath('data/actors.json')
    return parse(json.loads(resource.read_text(encoding='utf-8')), 'bundled')


@cache
def library() -> Library:
    """The full edition if it was synced and is valid, otherwise the bundled one (loaded once per process)."""
    path = synced_path()
    if path.is_file():
        try:
            return parse(json.loads(path.read_text(encoding='utf-8')), str(path))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log.warning('Ignoring %s (%s); using the bundled threat library', path, exc)
    return _bundled()


def reload() -> Library:
    """Forget the loaded library (after a sync) and load it again."""
    library.cache_clear()
    return library()


def technique_name(technique_id: str) -> str:
    found = catalog().techniques.get(technique_id)
    return found.full_name if found else technique_id

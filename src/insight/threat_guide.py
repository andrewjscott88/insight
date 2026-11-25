"""Actor threat guides: compose the threat library and the analyst's data into one guide (TIP 2.10, ADR 0025).

Pure functions, no database: :func:`compose` takes :class:`insight.services.GuideData` (what this instance
knows, already limited to the reader's TLP) and the threat library, and returns a :class:`ThreatGuide`.
:func:`guide_json`, :func:`navigator_layer` and :func:`sweep_csv` export it;
:mod:`insight.threat_guide_markdown` writes the Markdown.

Hunt hypotheses are *starting hypotheses* built from ATT&CK's own detection strategies and data components
for each technique; they are not detections and no AI writes them. They are ordered by what is current in the
analyst's reports, then by what the analyst linked to the group, then by ATT&CK coverage.
"""

from __future__ import annotations

import csv
import io
from collections import Counter
from dataclasses import dataclass
from typing import Any, Final

from . import __version__
from .attack import catalog, technique
from .industries import BY_KEY
from .services.actor_timeline import timeline_json
from .services.threat_guides import GuideData, SweepEntry
from .software_navigator import software_techniques
from .threat_library import Detection, Library, technique_name

FORMAT: Final = 'insight-threat-guide-1'
SWEEP_FORMAT: Final = 'insight-sweep-v1'
NAVIGATOR_VERSION: Final = '5.0.0'
LAYER_FORMAT: Final = '4.5'
HYPOTHESIS_LABEL: Final = (
    'Starting hypotheses from ATT&CK detection strategies and data components. They are not detections: '
    'check each against your own data and adapt it.'
)
SWEEP_COLUMNS: Final = (
    'kind',
    'value',
    'verdict',
    'verdict_until',
    'first_seen',
    'last_seen',
    'via',
    'tlp',
    'reports',
)


@dataclass(frozen=True, slots=True)
class TechniqueRow:
    id: str
    name: str
    tactics: tuple[str, ...]  # tactic names, matrix order
    in_attack: bool  # ATT&CK lists the group using it
    in_reports: int  # linked reports tagged with it
    trending: int  # the reader's reports in the last 90 days tagged with it
    procedure: str  # ATT&CK's procedure text (full edition only)


@dataclass(frozen=True, slots=True)
class Hypothesis:
    technique_id: str
    technique_name: str
    statement: str
    data_components: tuple[str, ...]
    log_sources: tuple[str, ...]
    detections: tuple[Detection, ...]
    from_parent: bool  # ATT&CK has no strategy for the sub-technique; these are its parent's
    why_first: str


@dataclass(frozen=True, slots=True)
class ThreatGuide:
    data: GuideData
    library: Library
    techniques: tuple[TechniqueRow, ...]
    hypotheses: tuple[Hypothesis, ...]
    mitigations: tuple[tuple[str, str, tuple[str, ...]], ...]  # (M ID, name, technique IDs)

    @property
    def tlp(self) -> str:
        return self.data.tlp

    @property
    def name(self) -> str:
        return self.data.subject.name


def _techniques(data: GuideData, lib: Library) -> list[TechniqueRow]:
    group = data.subject.catalog
    ids = {*(group.techniques if group else ()), *data.report_techniques}
    order = {t.shortname: i for i, t in enumerate(catalog().tactics)}
    rows, first = [], {}
    for tid in ids:
        found = technique(tid)
        if found is None:
            continue
        first[found.id] = min((order.get(t, 99) for t in found.tactics), default=99)
        rows.append(
            TechniqueRow(
                id=found.id,
                name=technique_name(found.id),
                tactics=catalog(found.domain).tactic_names(found),
                in_attack=bool(group and found.id in group.techniques),
                in_reports=data.report_techniques.get(found.id, 0),
                trending=data.trending.get(found.id, 0),
                procedure=(group.procedures.get(found.id, '') if group else ''),
            )
        )
    return sorted(rows, key=lambda r: (first[r.id], r.id))


def _detections(tid: str, lib: Library) -> tuple[tuple[Detection, ...], bool]:
    own = lib.techniques.get(tid)
    if own is not None and own.detections:
        return own.detections, False
    parent = lib.techniques.get(tid.split('.')[0])
    if '.' in tid and parent is not None and parent.detections:
        return parent.detections, True
    return (), False


def _hypothesis(row: TechniqueRow, name: str, lib: Library) -> Hypothesis:
    detections, from_parent = _detections(row.id, lib)
    components = tuple(dict.fromkeys(lib.data_components.get(c, c) for d in detections for c in d.components))
    sources = tuple(dict.fromkeys(s for d in detections for s in d.log_sources))
    if detections:
        look = ', '.join(components) or 'the data ATT&CK names'
        where = f' ({", ".join(sources)})' if sources else ''
        behaviour = '; '.join(d.name for d in detections[:3])
        statement = (
            f'If {name} is active here, expect {row.name} ({row.id}). Look in {look}{where} for: {behaviour}.'
        )
    else:
        statement = (
            f'If {name} is active here, expect {row.name} ({row.id}). ATT&CK {lib.attack_version} has no '
            'detection strategy for it: start from the technique page and your own telemetry.'
        )
    reasons = []
    if row.trending:
        reasons.append(f'in {row.trending} of your reports in the last 90 days')
    if row.in_reports:
        reasons.append(f'tagged on {row.in_reports} report(s) linked to this group')
    if row.in_attack:
        reasons.append('ATT&CK lists the group using it')
    why = '; '.join(reasons)
    return Hypothesis(
        row.id,
        row.name,
        statement,
        components,
        sources,
        detections,
        from_parent,
        why[:1].upper() + why[1:],  # not str.capitalize(): it would lower-case "ATT&CK"
    )


def _mitigations(rows: list[TechniqueRow], lib: Library) -> list[tuple[str, str, tuple[str, ...]]]:
    found: dict[str, list[str]] = {}
    for row in rows:
        context = lib.techniques.get(row.id)
        for mid in context.mitigations if context else ():
            found.setdefault(mid, []).append(row.id)
    out = [(mid, lib.mitigations.get(mid, mid), tuple(sorted(t))) for mid, t in found.items()]
    return sorted(out, key=lambda m: (-len(m[2]), m[0]))


def compose(data: GuideData, lib: Library) -> ThreatGuide:
    rows = _techniques(data, lib)
    ranked = sorted(rows, key=lambda r: (-r.trending, -r.in_reports, not r.in_attack, r.id))
    hypotheses = tuple(_hypothesis(r, data.subject.name, lib) for r in ranked)
    return ThreatGuide(data, lib, tuple(rows), hypotheses, tuple(_mitigations(rows, lib)))


def industry_claims(guide: ThreatGuide) -> list[dict[str, Any]]:
    """Every industry claim in the guide with its source: catalog claims not removed, then the analyst's."""
    removed = {industry for industry, _, _ in guide.data.removed}
    group = guide.data.subject.catalog
    out: list[dict[str, Any]] = []
    for claim in group.claims if group else ():
        kept = [k for k in claim.industries if k not in removed]
        if kept:
            out.append(
                {
                    'industries': kept,
                    'source': claim.source_name,
                    'evidence': claim.evidence,
                    'url': claim.url,
                    'citations': [{'name': c.name, 'url': c.url} for c in claim.citations],
                    'match': claim.match,
                }
            )
    for industry, url, reason, tlp in guide.data.added:
        out.append(
            {
                'industries': [industry],
                'source': 'Your own mapping',
                'evidence': reason,
                'url': url,
                'tlp': tlp,
            }
        )
    return out


def _rule(entry: Any) -> dict[str, Any]:
    rule = entry.rule
    return {
        'id': rule.id,
        'kind': rule.kind,
        'name': rule.name,
        'source_url': rule.source_url,
        'licence': rule.licence,
        'sha256': rule.content_hash,
        'tlp': entry.tlp,
        'linked_to': [{'kind': k, 'id': i} for k, i in entry.links],
        'body': rule.body,
    }


def sweep_rows(entries: tuple[SweepEntry, ...]) -> list[dict[str, Any]]:
    return [
        {
            'kind': e.kind,
            'value': e.value,
            'verdict': e.verdict,
            'verdict_until': e.verdict_until,
            'first_seen': e.first_seen,
            'last_seen': e.last_seen,
            'via': e.via,
            'tlp': e.tlp,
            'reports': list(e.reports),
        }
        for e in entries
    ]


def sweep_scope(linked_only: bool) -> str:
    """Which reports a sweep list's indicators come from, in one sentence."""
    if linked_only:
        return 'Indicators from reports an analyst linked to this group.'
    return 'Indicators from reports linked to this group and from reports that only name it.'


def sweep_json(guide: ThreatGuide) -> dict[str, Any]:
    data = guide.data
    return {
        'format': SWEEP_FORMAT,
        'group': {'ref': data.subject.ref, 'name': data.subject.name},
        'generated': data.generated,
        'tlp': guide.tlp,
        'note': sweep_scope(data.sweep_linked_only) + ' To search for. Not attribution.',
        'linked_only': data.sweep_linked_only,
        'truncated': data.sweep_truncated,
        'indicators': sweep_rows(data.sweep),
    }


def sweep_csv(guide: ThreatGuide) -> str:
    """The sweep list as CSV: a ``# TLP:`` comment line first, then a header row."""
    out = io.StringIO()
    scope = 'linked reports only' if guide.data.sweep_linked_only else 'linked reports and reports naming it'
    out.write(f'# TLP:{guide.tlp} - indicators to search for, not attribution ({scope}). {guide.name}\n')
    writer = csv.DictWriter(out, fieldnames=SWEEP_COLUMNS, lineterminator='\n')
    writer.writeheader()
    for row in sweep_rows(guide.data.sweep):
        row['reports'] = ' '.join(row['reports'])
        row['verdict_until'] = row['verdict_until'] or ''
        writer.writerow({k: _safe_cell(str(v)) for k, v in row.items()})
    return out.getvalue()


def _safe_cell(value: str) -> str:
    """Stop spreadsheet formula injection (a cell starting with ``=``, ``+``, ``-``, ``@``)."""
    return f"'{value}" if value[:1] in ('=', '+', '-', '@', '\t', '\r') else value


def guide_json(guide: ThreatGuide) -> dict[str, Any]:
    data, lib, subject = guide.data, guide.library, guide.data.subject
    group = subject.catalog
    return {
        'format': FORMAT,
        'generated': data.generated,
        'generator': f'Insight {__version__}',
        'tlp': guide.tlp,
        'reader_limit': data.max_tlp,
        'timeline': timeline_json(data.timeline) if data.timeline else None,
        'group': {
            'ref': subject.ref,
            'kind': subject.kind,
            'name': subject.name,
            'aliases': list(subject.aliases),
            'description': subject.description,
            'attack_group': None if group is None else {'id': group.id, 'name': group.name, 'url': group.url},
        },
        'industries': industry_claims(guide),
        'removed_industries': [{'industry': i, 'reason': r, 'tlp': t} for i, r, t in data.removed],
        'regions': {
            'source': 'MISP galaxy (cfr-suspected-victims)',
            'names': list(group.regions if group else ()),
        },
        'campaigns': [
            {'id': c.id, 'name': c.name, 'first_seen': c.first_seen, 'last_seen': c.last_seen, 'url': c.url}
            for c in (group.campaigns if group else ())
        ],
        'techniques': [
            {
                'id': r.id,
                'name': r.name,
                'tactics': list(r.tactics),
                'in_attack': r.in_attack,
                'linked_reports': r.in_reports,
                'recent_reports': r.trending,
                **({'procedure': r.procedure} if r.procedure else {}),
            }
            for r in guide.techniques
        ],
        'software': [
            {'id': s.id, 'name': s.name, 'type': s.type, 'url': s.url}
            for s in (lib.software[sid] for sid in (group.software if group else ()) if sid in lib.software)
        ],
        'mitigations': [{'id': m, 'name': n, 'techniques': list(t)} for m, n, t in guide.mitigations],
        'reports': [
            {
                'id': r.document_id,
                'title': r.title,
                'tlp': r.tlp,
                'added': r.created_at,
                'source': r.source_name,
                'via': r.via,
                'evidence': r.evidence,
            }
            for r in data.reports
        ],
        'reports_naming_group': data.named_total,
        'hunt': {
            'label': HYPOTHESIS_LABEL,
            'hypotheses': [
                {
                    'technique': h.technique_id,
                    'statement': h.statement,
                    'why_first': h.why_first,
                    'data_components': list(h.data_components),
                    'log_sources': list(h.log_sources),
                    'detection_strategies': [
                        {'id': d.id, 'name': d.name, 'url': d.url} for d in h.detections
                    ],
                    'from_parent_technique': h.from_parent,
                }
                for h in guide.hypotheses
            ],
            'sweep': sweep_json(guide),
            'rules': [_rule(r) for r in data.rules],
            'records': [
                {
                    'id': h.hunt.id,
                    'title': h.hunt.title,
                    'status': h.hunt.status,
                    'summary': h.hunt.summary,
                    'tlp': h.hunt.effective_tlp,
                    'started': h.hunt.created_at,
                    'updated': h.hunt.updated_at,
                    'checks': {
                        t: {'result': c[0], 'data_checked': c[1], 'from': c[2], 'to': c[3], 'notes': c[4]}
                        for t, c in h.checks.items()
                    },
                }
                for h in data.hunts
            ],
        },
        'sources': {
            'library': {'edition': lib.edition, **lib.sources},
            'references': [{'name': c.name, 'url': c.url} for c in (group.references if group else ())],
            'notice': lib.notice,
        },
    }


def navigator_layer(guide: ThreatGuide) -> dict[str, Any]:
    """An ATT&CK Navigator layer (format 4.5): 1 if ATT&CK lists the technique, plus 1 per linked report."""
    # This actor/software library is Enterprise-only; never mislabel Mobile/ICS report tags in its layer.
    enterprise = catalog().techniques
    counts = Counter({r.id: int(r.in_attack) + r.in_reports for r in guide.techniques if r.id in enterprise})
    top = max(counts.values(), default=1)
    name = guide.name
    group = guide.data.subject.catalog
    software_sources = software_techniques(
        guide.library, (*(group.software if group else ()), *guide.data.linked_software)
    )
    software_only = {
        tid: names for tid, names in software_sources.items() if tid not in counts and tid in enterprise
    }
    return {
        'name': f'{name}: techniques (Insight threat guide)',
        'versions': {
            'attack': guide.library.attack_version,
            'navigator': NAVIGATOR_VERSION,
            'layer': LAYER_FORMAT,
        },
        'domain': 'enterprise-attack',
        'description': (
            f'TLP:{guide.tlp}. Techniques for {name}: from MITRE ATT&CK and from reports the analyst '
            'linked to it. '
            'Score: 1 if ATT&CK lists it, plus the number of linked reports tagged with it. '
            'Software-only techniques have score 0 and are not direct group observations.'
        ),
        'layout': {'layout': 'side', 'showID': True, 'showName': True, 'expandedSubtechniques': 'annotated'},
        'gradient': {'colors': ['#fff3e0', '#e65100'], 'minValue': 0, 'maxValue': max(1, top)},
        'techniques': [
            {
                'techniqueID': r.id,
                'score': counts[r.id],
                'comment': '; '.join(
                    x
                    for x in (
                        'ATT&CK' if r.in_attack else '',
                        f'{r.in_reports} linked report(s)' if r.in_reports else '',
                    )
                    if x
                ),
                'enabled': True,
            }
            for r in guide.techniques
            if r.id in enterprise
        ]
        + [
            {
                'techniqueID': tid,
                'score': 0,
                'enabled': True,
                'comment': 'Software only (explicit group software association; ATT&CK software technique): '
                + ', '.join(names)
                + '. Not a direct group technique or analyst attribution.',
            }
            for tid, names in sorted(software_only.items())
        ],
        'metadata': [
            {'name': 'TLP', 'value': f'TLP:{guide.tlp}'},
            {'name': 'Generated by', 'value': f'Insight {__version__}'},
            {'name': 'ATT&CK', 'value': guide.library.notice},
        ],
    }


def industry_name(key: str) -> str:
    return BY_KEY[key].name if key in BY_KEY else key

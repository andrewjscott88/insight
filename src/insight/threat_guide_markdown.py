"""An actor threat guide as Markdown: TLP first, who the group targets with evidence, then the hunt.

Text from reports and catalogs is escaped (:func:`insight.briefing.escape`), so it cannot add links,
headings or HTML. Links are only those the sources give, written so that a bracket in a URL cannot break out.
"""

from __future__ import annotations

from typing import Final

from . import __version__
from .briefing import escape
from .threat_guide import HYPOTHESIS_LABEL, ThreatGuide, industry_claims, industry_name

MAX_SWEEP_LINES: Final = 50
#: Every technique in the guide gets its hypothesis (TIP 2.10 acceptance); this only bounds odd actors.
MAX_HYPOTHESES: Final = 600
RESULT_WORDS: Final = {
    'not-checked': 'Not checked',
    'nothing-found': 'Nothing found',
    'suspicious': 'Suspicious',
    'confirmed': 'Confirmed',
}


def link(label: str, url: str) -> str:
    """A Markdown link when ``url`` is an https/http or in-app address; otherwise the escaped label only."""
    if not url.startswith(('https://', 'http://', '/?')):
        return escape(label)
    safe = (
        url.replace(' ', '%20')
        .replace('(', '%28')
        .replace(')', '%29')
        .replace('<', '%3C')
        .replace('>', '%3E')
    )
    return f'[{escape(label)}]({safe})'


def _header(guide: ThreatGuide) -> list[str]:
    data, subject = guide.data, guide.data.subject
    group = subject.catalog
    kind = 'MITRE ATT&CK group' if subject.kind == 'catalog' else 'Actor you track'
    out = [
        f'**TLP:{guide.tlp}**',
        '',
        f'# Threat guide: {escape(subject.name)}',
        '',
        f'Made by Insight {__version__} on {data.generated[:16].replace("T", " ")} UTC. '
        f'Built from data up to TLP:{guide.tlp}: share it no wider. Not written by AI.',
        '',
        f'- {kind}: {escape(subject.ref)}',
    ]
    if subject.aliases:
        out.append(f'- Also called: {", ".join(escape(a) for a in subject.aliases)}')
    if group is not None:
        out.append(f'- In MITRE ATT&CK: {link(f"{group.id} {group.name}", group.url)}')
    out += ['', escape(subject.description) or 'No description.', '']
    return out


def _targets(guide: ThreatGuide) -> list[str]:
    out = ['## Who it targets', '']
    claims = industry_claims(guide)
    if not claims:
        out += ['No source names an industry for this group.', '']
    for claim in claims:
        names = ', '.join(industry_name(k) for k in claim['industries'])
        cites = ''.join(f' {link(c["name"], c["url"])}' for c in claim.get('citations', []))
        source = link(claim['source'], claim['url'])
        out.append(f'- **{names}**: "{escape(claim["evidence"])}" ({source}){cites}')
    for industry, reason, _ in guide.data.removed:
        out.append(f'- Removed by you: {industry_name(industry)}. {escape(reason)}')
    group = guide.data.subject.catalog
    if group is not None and group.regions:
        out += [
            '',
            'Countries named as victims (MISP galaxy, cfr-suspected-victims): '
            f'{escape(", ".join(group.regions))}.',
        ]
    if group is not None and group.campaigns:
        out += ['', '### Latest public activity', '']
        out += [
            f'- {link(f"{c.id} {c.name}", c.url)}: {c.first_seen} to {c.last_seen}'
            for c in group.campaigns[:5]
        ]
    return [*out, '']


def _techniques(guide: ThreatGuide) -> list[str]:
    out = ['## ATT&CK techniques', '', '| Tactic | Technique | From |', '| --- | --- | --- |']
    for row in guide.techniques:
        where = ', '.join(
            x
            for x in (
                'ATT&CK' if row.in_attack else '',
                f'{row.in_reports} linked report(s)' if row.in_reports else '',
            )
            if x
        )
        out.append(f'| {escape(", ".join(row.tactics))} | {row.id} {escape(row.name)} | {where} |')
    if not guide.techniques:
        out.append('| | No technique is known for this group yet. | |')
    out += ['', 'The Navigator layer export shows these on the ATT&CK matrix.', '']
    lib, group = guide.library, guide.data.subject.catalog
    software = [lib.software[s] for s in (group.software if group else ()) if s in lib.software]
    if software:
        out += ['## Tools and malware', '']
        out += [f'- {link(f"{s.id} {s.name}", s.url)} ({s.type})' for s in software]
        out.append('')
    if guide.mitigations:
        out += ['## Mitigations', '', 'ATT&CK mitigations for these techniques, most techniques first:', '']
        out += [
            f'- {link(f"{m} {name}", f"https://attack.mitre.org/mitigations/{m}/")}: {len(t)} technique(s)'
            for m, name, t in guide.mitigations[:20]
        ]
        out.append('')
    return out


def _reports(guide: ThreatGuide) -> list[str]:
    data = guide.data
    out = ['## Your reports', '']
    if not data.reports:
        out += ['None of your reports is linked to or names this group.', '']
        return out
    out += [
        f'{len([r for r in data.reports if r.via == "linked"])} linked by an analyst; '
        f'{data.named_total} name the group (a literal match of its names, not attribution).',
        '',
    ]
    for r in data.reports:
        how = 'linked' if r.via == 'linked' else 'names it'
        out.append(
            f'- {r.created_at[:10]} [TLP:{r.tlp}] {link(r.title, f"/?report={r.document_id}")} ({how})'
        )
    return [*out, '']


def _hunt(guide: ThreatGuide) -> list[str]:
    data = guide.data
    out = ['## Threat hunt', '', '### Hypotheses', '', f'_{HYPOTHESIS_LABEL}_', '']
    for h in guide.hypotheses[:MAX_HYPOTHESES]:
        why = f' Why first: {escape(h.why_first)}.' if h.why_first else ''
        out.append(f'- **{h.technique_id}**: {escape(h.statement)}{why}')
    if len(guide.hypotheses) > MAX_HYPOTHESES:
        out.append(f'- And {len(guide.hypotheses) - MAX_HYPOTHESES} more in the JSON export.')
    out += ['', '### Indicator sweep list', '']
    scope = (
        'reports an analyst linked to the group (reports that only name it are left out)'
        if data.sweep_linked_only
        else 'the reports above, including reports that only name the group'
    )
    out.append(
        f'{len(data.sweep)} accepted indicator(s) from {scope}, to search for in your logs. '
        'Not attribution: a report naming a group can name other things too.'
    )
    out.append('')
    for e in data.sweep[:MAX_SWEEP_LINES]:
        out.append(
            f'- `{e.kind}` {escape(e.value)} ({e.verdict}; seen {e.first_seen[:10]} to {e.last_seen[:10]})'
        )
    if len(data.sweep) > MAX_SWEEP_LINES:
        out.append(f'- And {len(data.sweep) - MAX_SWEEP_LINES} more in the sweep export (CSV or JSON).')
    out += ['', '### Detection rules', '']
    if not data.rules:
        out.append('No YARA or Sigma rule is linked to this group or its techniques.')
    for r in data.rules:
        source = link('source', r.rule.source_url) if r.rule.source_url else 'no source'
        out.append(
            f'- {r.rule.kind.upper()} {escape(r.rule.name)} [TLP:{r.rule.tlp}] ({source}; '
            f'licence: {escape(r.rule.licence) or "not given"}; SHA-256 {r.rule.content_hash[:16]}…)'
        )
    out += ['', '### Hunt records', '']
    if not data.hunts:
        out.append('No hunt recorded yet.')
    for record in data.hunts:
        out.append(
            f'- **{escape(record.hunt.title)}** [TLP:{record.hunt.tlp}] {record.hunt.status}, '
            f'started {record.hunt.created_at[:10]}'
        )
        if record.hunt.summary:
            out.append(f'  - Summary: {escape(record.hunt.summary)}')
        for tid, (result, checked, start, end, notes) in record.checks.items():
            period = f', {start} to {end}' if start or end else ''
            detail = f' Data: {escape(checked)}.' if checked else ''
            note = f' {escape(notes)}' if notes else ''
            out.append(f'  - {tid}: {RESULT_WORDS.get(result, result)}{period}.{detail}{note}')
    return [*out, '']


def _sources(guide: ThreatGuide) -> list[str]:
    lib, group = guide.library, guide.data.subject.catalog
    out = ['## Sources', '']
    for source in lib.sources.values():
        name = link(source.get('name', ''), source.get('url', ''))
        line = f'- {name} version {escape(source.get("version", ""))}'
        out.append(line + (f', {escape(source["licence"])}' if 'licence' in source else ''))
    out.extend(f'- {link(ref.name, ref.url)}' for ref in (group.references if group else ()))
    out += ['', escape(lib.notice), '', f'**TLP:{guide.tlp}**', '']
    return out


def to_markdown(guide: ThreatGuide) -> str:
    parts = (
        _header(guide)
        + _targets(guide)
        + _techniques(guide)
        + _reports(guide)
        + _hunt(guide)
        + _sources(guide)
    )
    return '\n'.join(parts)

"""A threat landscape as a Markdown briefing to share or paste: TLP first, the summary, then the evidence.

The briefing says what the workspace says, nothing more. Report titles and other text from reports are
escaped, so a title cannot add links, headings or HTML to the briefing.
"""

from __future__ import annotations

import re
from typing import Final

from .brief import count_of
from .landscape import NEW, NO_HISTORY, QUIETER, RISING, STEADY, Landscape, usual_text

#: How each trend label reads in the workspace and in the briefing.
LABELS: Final[dict[str, str]] = {
    RISING: 'Rising',
    NEW: 'New',
    STEADY: 'As usual',
    QUIETER: 'Quieter',
    NO_HISTORY: 'No history yet',
}
#: Characters that format Markdown or start HTML. Brackets are escaped, so parentheses cannot make links.
_SPECIAL: Final = re.compile(r'([\\`*_{}\[\]<>#|~])')


def escape(text: str) -> str:
    """Text from reports, with Markdown and HTML characters made literal."""
    return _SPECIAL.sub(r'\\\1', ' '.join(text.split()))


def to_markdown(landscape: Landscape, *, generated: str, version: str) -> str:
    days = landscape.days
    tlp = f'**TLP:{landscape.tlp}**'
    out = [
        tlp,
        '',
        f'# Threat landscape: the last {count_of(days, "day")}',
        '',
        f'Made by Insight {version} on {generated[:16].replace("T", " ")} UTC from '
        f'{count_of(landscape.reports, "report")} from {count_of(landscape.sources, "source")}. '
        f'Built from reports up to TLP:{landscape.tlp}: share it no wider. Not written by AI.',
        '',
        '## Executive summary',
        '',
        *(f'- {escape(line)}' for line in landscape.summary),
        '',
        '## Trending threats',
        '',
    ]
    if not landscape.threats:
        out += ['No report in this period names a common kind of threat.', '']
    for threat in landscape.threats:
        usual = usual_text(threat.change, days)
        out += [
            f'### {threat.name}: {LABELS[threat.change.label]}',
            '',
            f'- In this period: {count_of(threat.change.current, "report")} from '
            f'{count_of(threat.sources, "source")}' + (f' ({usual})' if usual else '') + '.',
            f'- What it is: {threat.what}',
            f'- Why it matters: {threat.impact}',
            f'- What to check: {threat.check}',
            *(f'- Report: {escape(item.text)}' for item in threat.reports),
            '',
        ]
    if landscape.quieter:
        out += ['## Quieter than usual', '']
        out += [
            f'- {t.name}: {count_of(t.change.current, "report")} ({usual_text(t.change, days)})'
            for t in landscape.quieter
        ]
        out.append('')
    out += ['## What attackers are doing (MITRE ATT&CK)', '']
    if not landscape.tactics:
        out.append('No report in this period has ATT&CK techniques.')
    for tactic in landscape.tactics:
        usual = usual_text(tactic.change, days)
        techniques = '; '.join(f'{t} {escape(name)} ({n})' for t, name, n in tactic.techniques)
        out.append(
            f'- **{tactic.plain.capitalize()}** ({tactic.name}): {count_of(tactic.change.current, "report")}'
            + (f', {usual}' if usual else '')
            + f'. {LABELS[tactic.change.label]}. Techniques: {techniques}.'
        )
    out.append('')
    for section in landscape.brief.sections:
        out += [f'## {section.title}', '']
        out += [f'- {escape(item.text)}' for item in section.items] or [section.empty]
        out.append('')
    out += ['## How to read this', '', *(f'- {line}' for line in landscape.caveats), '', tlp, '']
    return '\n'.join(out)

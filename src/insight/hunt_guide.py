"""A hunt plan to read or download. Plain text in; no model, queries or rule execution."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from .ioc_export import defang_text
from .pdf_writer import BOLD, Block, heading, paragraph, printable, render


@dataclass(frozen=True, slots=True)
class GuideSection:
    title: str
    lines: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HuntGuide:
    kind: str
    ref: str
    title: str
    summary: str
    tlp: str
    created_at: str
    sections: tuple[GuideSection, ...]


def bounded(guide: HuntGuide) -> HuntGuide:
    """Cap all feed-derived text and the full plan; keep the label even when evidence is shortened."""
    remaining, shortened = 40_000, False
    sections = []
    for section in guide.sections[:24]:
        lines = []
        for line in section.lines[:150]:
            clean = ' '.join(line.split())
            capped = clean[: min(1_200, remaining)]
            shortened |= len(capped) != len(clean)
            if capped:
                lines.append(capped)
                remaining -= len(capped)
        shortened |= len(section.lines) > 150
        sections.append(GuideSection(section.title[:120], tuple(lines)))
    shortened |= len(guide.sections) > 24 or len(guide.title) > 300 or len(guide.summary) > 1_200
    if shortened:
        sections.append(
            GuideSection(
                'Guide size limit',
                (
                    'Some text was shortened to keep this guide small. '
                    'Open the source report or profile for more.',
                ),
            )
        )
    return replace(guide, title=guide.title[:300], summary=guide.summary[:1_200], sections=tuple(sections))


def _markdown(text: str) -> str:
    # User and feed text stays text: it cannot add HTML, links or Markdown sections.
    escaped = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return re.sub(r'([\\`*_{}\[\]()#+!|~])', r'\\\1', escaped).replace('\n', ' ')


def to_markdown(guide: HuntGuide) -> str:
    lines = [
        f'# {_markdown(defang_text(guide.title))}',
        '',
        f'TLP:{guide.tlp} | Created: {_markdown(guide.created_at)}',
        '',
        _markdown(defang_text(guide.summary)),
    ]
    for section in guide.sections:
        lines += ['', f'## {_markdown(defang_text(section.title))}', '']
        lines += [f'- {_markdown(defang_text(line))}' for line in section.lines]
    lines += ['', 'Built by Insight from saved intelligence and fixed guidance. No AI wrote this guide.', '']
    return '\n'.join(lines)


def to_pdf(guide: HuntGuide) -> bytes:
    blocks = [
        Block('H1', [(BOLD, defang_text(guide.title))], size=18, leading=23, before=0),
        paragraph(f'Created: {guide.created_at} | TLP:{guide.tlp}', grey=True),
        paragraph(defang_text(guide.summary)),
    ]
    for section in guide.sections:
        blocks.append(heading(defang_text(section.title)))
        blocks += [paragraph(defang_text(line)) for line in section.lines]
    blocks.append(
        paragraph(
            'Network indicators use [.] and hxxp so they are not opened by mistake. '
            'Built by Insight from saved intelligence and fixed guidance. No AI wrote this guide.',
            grey=True,
        )
    )
    if not all(printable(text) for block in blocks for _, text in block.runs):
        blocks.append(
            paragraph('Some characters cannot be shown here and print as "?". The Markdown keeps them.')
        )
    return render(
        blocks,
        title=defang_text(guide.title),
        subject=f'Threat hunt guide, TLP:{guide.tlp}',
        tlp=guide.tlp,
        when=guide.created_at,
    )

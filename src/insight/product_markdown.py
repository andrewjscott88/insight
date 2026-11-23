"""An intelligence product (``insight-product-1``, TIP 4.4) as Markdown: the TLP label first and last, the
bottom line up front, key judgements in ICD 203's estimative language with confidence and sources, the
analysis, intelligence gaps, then the sources with their Admiralty grades.

All text is escaped (:func:`insight.briefing.escape`), so it cannot add links, headings or HTML; paragraphs in
the analysis are kept. Links are only those the sources give.
"""

from __future__ import annotations

import re
from typing import Any, Final

from . import __version__
from .briefing import escape
from .threat_guide_markdown import link

PRODUCT_TYPES: Final = {
    'assessment': 'Assessment',
    'alert': 'Alert',
    'profile': 'Profile',
    'summary': 'Summary',
}
LIKELIHOOD: Final = {
    'almost-no-chance': ('Almost no chance', '1-5%'),
    'very-unlikely': ('Very unlikely', '5-20%'),
    'unlikely': ('Unlikely', '20-45%'),
    'roughly-even-chance': ('Roughly even chance', '45-55%'),
    'likely': ('Likely', '55-80%'),
    'very-likely': ('Very likely', '80-95%'),
    'almost-certain': ('Almost certain', '95-99%'),
}
CONFIDENCE: Final = {'low': 'low confidence', 'moderate': 'moderate confidence', 'high': 'high confidence'}
SOURCE_KINDS: Final = {
    'document': 'Report',
    'indicator': 'Indicator',
    'actor': 'Threat actor',
    'campaign': 'Campaign',
}


def paragraphs(text: str) -> list[str]:
    """Escaped paragraphs (separated by blank lines), each on one line."""
    return [escape(p) for p in re.split(r'\n\s*\n', text.strip()) if p.strip()]


def cited(numbers: list[int]) -> str:
    return ' '.join(f'[{n}]' for n in numbers) if numbers else 'no source'


def source_line(source: dict[str, Any]) -> str:
    n, kind, name = source['n'], source['kind'], source.get('name') or source['id']
    if kind == 'document':
        grade = f'{source.get("reliability", "F")}{source.get("credibility", 6)}'
        title = link(name, source['url']) if source.get('url') else escape(name)
        return (
            f'{n}. [{grade}] {title}, {escape(source.get("source_name", ""))}, added '
            f'{str(source.get("added_at", ""))[:10]} [TLP:{source["tlp"]}]'
        )
    if kind == 'indicator':
        return (
            f'{n}. Indicator ({source.get("indicator_kind", "")}) {escape(name)}: confidence '
            f'{source.get("confidence", 0)} ({source.get("band", "none")}) [TLP:{source["tlp"]}]'
        )
    return f'{n}. {SOURCE_KINDS.get(kind, kind)}: {escape(name)} [TLP:{source["tlp"]}]'


def to_markdown(product: dict[str, Any]) -> str:
    tlp = f'**TLP:{product["tlp"]}**'
    kind = PRODUCT_TYPES.get(product['product_type'], 'Product')
    if product.get('version'):
        status = f'Version {product["version"]}, published {str(product["published_at"])[:10]}'
    else:
        status = f'Draft, not published (made {str(product["generated_at"])[:10]})'
    out = [tlp, '', f'# {escape(product["title"])}', '', f'{kind}. {status}.']
    if product.get('audience'):
        out += ['', f'For: {escape(product["audience"])}']
    out += ['', '## Bottom line up front', '']
    out += paragraphs(product['bluf']) or ['Not written yet.']
    out += ['', '## Key judgements', '']
    if not product['judgements']:
        out.append('None yet.')
    for i, judgement in enumerate(product['judgements'], start=1):
        words, odds = LIKELIHOOD[judgement['likelihood']]
        out.append(
            f'{i}. **{words}** ({odds}), {CONFIDENCE[judgement["confidence"]]}: '
            f'{escape(judgement["statement"])} {cited(judgement["sources"])}'
        )
    if product.get('analysis', '').strip():
        out += ['', '## Analysis', '']
        out += [line for p in paragraphs(product['analysis']) for line in (p, '')][:-1]
    out += ['', '## Intelligence gaps', '']
    if not product['gaps']:
        out.append('None recorded.')
    for gap in product['gaps']:
        asked = ' (asked as a request for information)' if gap.get('rfi') else ''
        out.append(f'- {escape(gap["question"])}{asked}')
    out += ['', '## Sources', '']
    out += [source_line(s) for s in product['sources']] or ['None.']
    out += [
        '',
        'Likelihood uses the expressions of ICD 203 (Analytic Standards); confidence says how well the '
        "evidence supports a judgement. A report's grade is its source's reliability (A to F) and its own "
        'credibility (1 to 6).',
        '',
        f'Made with Insight {__version__}. Not written by AI. Built from data up to TLP:{product["tlp"]}: '
        'share it no wider.',
        '',
        tlp,
        '',
    ]
    return '\n'.join(out)

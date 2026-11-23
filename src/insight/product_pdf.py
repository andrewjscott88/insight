"""An intelligence product (``insight-product-1``, TIP 4.4) as a PDF, with the same content as the Markdown
export, laid out by :mod:`insight.pdf_writer`: the TLP label on every page, the bottom line up front, key
judgements in ICD 203's estimative language with confidence and sources, the analysis, intelligence gaps, then
the sources with their Admiralty grades.

The PDF is for reading, so network indicators in its text are defanged (``evil[.]example``, ``hxxps://``) and
no reader opens one by accident. The publishers' links in the sources stay as stored, as in the IOC export
(:mod:`insight.ioc_export`). The Markdown and STIX exports keep values as written.
"""

from __future__ import annotations

import re
from typing import Any, Final

from . import __version__
from .ioc_export import NETWORK_KINDS, defang, defang_text
from .pdf_writer import BOLD, REGULAR, Block, Run, heading, items, paragraph, printable, render
from .product_markdown import CONFIDENCE, LIKELIHOOD, PRODUCT_TYPES, SOURCE_KINDS, cited

NOTE: Final[dict[str, Any]] = {'size': 9, 'leading': 12, 'before': 6, 'grey': True}


def _paragraphs(text: str) -> list[str]:
    parts = re.split(r'\n\s*\n', defang_text(text).strip())
    return [part.strip() for part in parts if part.strip()]


def _source(source: dict[str, Any]) -> str:
    kind, name, tlp = source['kind'], str(source.get('name') or source['id']), source['tlp']
    if kind == 'document':
        grade = f'{source.get("reliability", "F")}{source.get("credibility", 6)}'
        added = str(source.get('added_at', ''))[:10]
        text = f'[{grade}] {defang_text(name)}, {source.get("source_name", "")}, added {added} [TLP:{tlp}]'
        return f'{text} {source["url"]}' if source.get('url') else text  # the publisher's link, as stored
    if kind == 'indicator':
        value_kind = str(source.get('indicator_kind', ''))
        value = defang(value_kind, name) if value_kind in NETWORK_KINDS else defang_text(name)
        score, band = source.get('confidence', 0), source.get('band', 'none')
        return f'Indicator ({value_kind}) {value}: confidence {score} ({band}) [TLP:{tlp}]'
    return f'{SOURCE_KINDS.get(kind, kind)}: {defang_text(name)} [TLP:{tlp}]'


def _judgement(judgement: dict[str, Any]) -> list[Run]:
    words, odds = LIKELIHOOD[judgement['likelihood']]
    rest = f' ({odds}), {CONFIDENCE[judgement["confidence"]]}: {defang_text(judgement["statement"])}'
    return [(BOLD, words), (REGULAR, f'{rest} {cited(judgement["sources"])}')]


def _gap(gap: dict[str, Any]) -> list[Run]:
    asked = ' (asked as a request for information)' if gap.get('rfi') else ''
    return [(REGULAR, defang_text(gap['question']) + asked)]


def blocks(product: dict[str, Any]) -> list[Block]:
    """The product's headings, paragraphs and lists, in reading order."""
    kind = PRODUCT_TYPES.get(product['product_type'], 'Product')
    if product.get('version'):
        status = f'Version {product["version"]}, published {str(product["published_at"])[:10]}'
    else:
        status = f'Draft, not published (made {str(product["generated_at"])[:10]})'
    out = [Block('H1', [(BOLD, defang_text(product['title']))], size=18, leading=23, before=0)]
    out.append(paragraph(f'{kind}. {status}.', before=4))
    if product.get('audience'):
        out.append(paragraph(f'For: {defang_text(product["audience"])}', before=2))
    out.append(heading('Bottom line up front'))
    out += [paragraph(p) for p in _paragraphs(product['bluf'])] or [paragraph('Not written yet.')]
    out.append(heading('Key judgements'))
    judgements = [(f'{i}.', _judgement(j)) for i, j in enumerate(product['judgements'], start=1)]
    out += items(judgements, 1) or [paragraph('None yet.')]
    if analysis := _paragraphs(product.get('analysis', '')):
        out += [heading('Analysis'), *(paragraph(p) for p in analysis)]
    out.append(heading('Intelligence gaps'))
    out += items([('•', _gap(gap)) for gap in product['gaps']], 2) or [paragraph('None recorded.')]
    out.append(heading('Sources'))
    sources = [(f'{s["n"]}.', [(REGULAR, _source(s))]) for s in product['sources']]
    out += items(sources, 3) or [paragraph('None.')]
    out.append(
        paragraph(
            'Likelihood uses the expressions of ICD 203 (Analytic Standards); confidence says how well the '
            "evidence supports a judgement. A report's grade is its source's reliability (A to F) and its "
            'own credibility (1 to 6). Network indicators are defanged ([.] and hxxp) so that no one opens '
            'one by accident.',
            **(NOTE | {'before': 18}),
        )
    )
    if not all(printable(text) for block in out for _, text in block.runs):
        out.append(
            paragraph(
                'Some characters cannot be shown here and print as "?". The Markdown keeps them.', **NOTE
            )
        )
    out.append(
        paragraph(
            f'Made with Insight {__version__}. Not written by AI. Built from data up to '
            f'TLP:{product["tlp"]}: share it no wider.',
            **NOTE,
        )
    )
    return out


def to_pdf(product: dict[str, Any]) -> bytes:
    kind = PRODUCT_TYPES.get(product['product_type'], 'Product')
    when = product.get('published_at') if product.get('version') else product.get('generated_at')
    return render(
        blocks(product),
        title=defang_text(product['title']),
        subject=f'{kind}, TLP:{product["tlp"]}',
        tlp=product['tlp'],
        when=when,
    )

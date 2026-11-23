"""An intelligence product (``insight-product-1``, TIP 4.4) as a STIX 2.1 bundle. No database or network.

One ``report`` carries the title, the bottom line up front and the analysis; each key judgement is a
``note`` about the report and the evidence behind it, with the analyst's confidence on STIX's 0-100 scale
(STIX 2.1 Appendix A: low 15, moderate 50, high 85) and the ICD 203 likelihood in its abstract; each
intelligence gap is a ``note`` too. Cited indicators, CVEs, actors and campaigns are objects the report
refers to; cited reports are external references only, so their text never leaves. Every object carries the
product's TLP marking.

A published version has IDs derived from the product, its version and the item, so exporting it again gives
the same objects; a draft gets new IDs every time.
"""

from __future__ import annotations

from typing import Any, Final
from uuid import uuid4

from .product_markdown import CONFIDENCE, LIKELIHOOD, PRODUCT_TYPES
from .stix_export import TLP_MARKINGS, _pattern, stable_id, stix_timestamp, tlp_marking

STIX_CONFIDENCE: Final = {'low': 15, 'moderate': 50, 'high': 85}


def to_stix(product: dict[str, Any]) -> dict[str, Any]:
    """``ValueError`` if there is nothing for the report to refer to yet."""
    marking = TLP_MARKINGS[product['tlp']]
    version = product.get('version')
    stamp = stix_timestamp(product.get('published_at') or product['generated_at'])

    def object_id(kind: str, *parts: str) -> str:
        if version:
            return stable_id(kind, 'insight-product', '|'.join((product['id'], str(version), *parts)))
        return f'{kind}--{uuid4()}'

    def common(kind: str, *parts: str) -> dict[str, Any]:
        return {'type': kind, 'spec_version': '2.1', 'id': object_id(kind, *parts), 'created': stamp,
                'modified': stamp, 'object_marking_refs': [marking]}  # fmt: skip

    report_id = object_id('report')
    objects: list[dict[str, Any]] = []
    by_number: dict[int, str] = {}
    references: list[dict[str, Any]] = [{'source_name': 'Insight product', 'external_id': product['id']}]
    for source in product['sources']:
        number, kind, name = source['n'], source['kind'], source.get('name') or source['id']
        if kind == 'document':
            reference = {
                'source_name': source.get('source_name') or 'report',
                'external_id': source['id'],
                'description': f'{name} [{source.get("reliability", "F")}{source.get("credibility", 6)}]',
            }
            if source.get('url'):
                reference['url'] = source['url']
            references.append(reference)
            continue
        if kind == 'indicator' and source.get('indicator_kind') == 'cve':
            obj = common('vulnerability', str(number))
            obj.update(name=name, external_references=[{'source_name': 'cve', 'external_id': name}])
        elif kind == 'indicator':
            obj = common('indicator', str(number))
            obj.update(name=name, pattern_type='stix', pattern_version='2.1',
                       pattern=_pattern(source['indicator_kind'], name), valid_from=stamp)  # fmt: skip
        else:
            obj = common('threat-actor' if kind == 'actor' else 'campaign', str(number))
            obj['name'] = name
        by_number[number] = obj['id']
        objects.append(obj)
    for i, judgement in enumerate(product['judgements'], start=1):
        words, odds = LIKELIHOOD[judgement['likelihood']]
        note = common('note', 'judgement', str(i))
        note.update(
            abstract=f'Key judgement {i}: {words} ({odds}), {CONFIDENCE[judgement["confidence"]]}',
            content=judgement['statement'],
            object_refs=[report_id, *(by_number[n] for n in judgement['sources'] if n in by_number)],
            confidence=STIX_CONFIDENCE[judgement['confidence']],
            labels=['key-judgement'],
            x_insight_likelihood=judgement['likelihood'],
            x_insight_analytic_confidence=judgement['confidence'],
        )
        objects.append(note)
    for i, gap in enumerate(product['gaps'], start=1):
        note = common('note', 'gap', str(i))
        note.update(abstract=f'Intelligence gap {i}', content=gap['question'], object_refs=[report_id],
                    labels=['intelligence-gap'])  # fmt: skip
        objects.append(note)
    if not objects:
        raise ValueError('Nothing to export yet: add evidence, a key judgement or a gap first.')
    report = common('report')
    report.update(
        name=product['title'],
        description='\n\n'.join(
            part for part in (product['bluf'], product.get('analysis', '')) if part.strip()
        ),
        published=stamp,
        report_types=['threat-report'],
        object_refs=[obj['id'] for obj in objects],
        external_references=references,
        labels=[PRODUCT_TYPES.get(product['product_type'], 'Product').lower()],
    )
    if not report['description']:
        del report['description']
    return {
        'type': 'bundle',
        'id': f'bundle--{uuid4()}',
        'objects': [tlp_marking(product['tlp']), report, *objects],
    }

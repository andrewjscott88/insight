"""Plain-language findings and data limits for the executive brief, using stored facts only."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta

from .brief_facts import (
    SECTION_ITEMS,
    VENDOR_LINE,
    _count,
    _day,
    _Facts,
    _names,
    _product,
    _source,
    _time,
    is_demo,
    published,
)
from .brief_types import BriefHighlight, BriefItem
from .services import BriefData, BriefDocument


def _impact(doc: BriefDocument, cve: str) -> str:
    """Explain an explicitly named weakness, without inferring one from a CVSS number."""
    line = next((line for line in doc.body.splitlines() if line.startswith(f'- {cve}, CVSS ')), '')
    description = line.partition(':')[2].strip()
    meanings = (
        ('remote code execution', 'let an attacker run code on an affected system'),
        ('arbitrary code execution', 'let an attacker run code on an affected system'),
        ('denial of service', 'interrupt a service on an affected system'),
        ('authentication bypass', 'let an attacker skip sign-in checks on an affected system'),
    )
    for phrase, meaning in meanings:
        if re.search(r'\b' + re.escape(phrase) + r'\b', description, re.I) and not re.search(
            r"\b(?:no|not|never|without|cannot|can't|doesn't|isn't|prevent\w*|mitigat\w*|avoid\w*)\b",
            description,
            re.I,
        ):
            return f'The source describes {phrase}. This could {meaning}. '
    if description:
        # Quote the source when its weakness does not have a precise built-in explanation.
        excerpt = description[:180].rstrip()
        if len(description) > 180:
            excerpt += '…'
        return f'The source describes it as: “{excerpt}” '
    return 'Read the advisory for what the flaw could let an attacker do. '


def _evidence(documents: list[BriefDocument]) -> tuple[BriefItem, ...]:
    """Unique current reports, newest received first; titles remain attributed source text."""
    unique = {doc.id: doc for doc in documents}
    newest = sorted(unique.values(), key=lambda doc: (doc.created_at, doc.id), reverse=True)
    return tuple(BriefItem(doc.title, doc.id) for doc in newest[:SECTION_ITEMS])


def highlights(data: BriefData, facts: _Facts, as_of: datetime) -> tuple[BriefHighlight, ...]:
    result = []
    by_id = {doc.id: doc for doc in facts.fresh}
    known = {kev.cve: kev for kev in facts.kev_added}
    known.update((kev.cve, kev) for kev, _, _, _ in facts.kev_mentioned)
    if known:
        evidence = [
            BriefItem(f'{kev.cve} · {_product(kev)}', kev.document_id)
            for kev in known.values()
            if kev.document_id
        ]
        evidence += [
            BriefItem(f'{kev.cve} · {_product(kev)}', doc)
            for kev, _, doc, _ in facts.kev_mentioned
            if not kev.document_id
        ]
        products = _names([_product(kev) for kev in known.values()])
        result.append(
            BriefHighlight(
                'Known exploitation deserves attention',
                f'{_count(len(known), "flaw")} in this brief {_verb(len(known), "is", "are")} on '
                f"CISA's known exploited list. Products include {products}. "
                'This is evidence of past or present use by attackers. '
                'It does not prove an attack on your business.',
                'If you use these products, ask IT to check exposure. Follow the linked fix guidance first.',
                tuple(evidence[:SECTION_ITEMS]),
            )
        )

    mentioned: dict[str, set[str]] = defaultdict(set)
    for doc_id, kind, value in data.mentions:
        if kind == 'cve' and doc_id in by_id:
            mentioned[value].add(doc_id)
    repeated = sorted(
        ((cve, ids) for cve, ids in mentioned.items() if len(ids) >= 2),
        key=lambda pair: (-len(pair[1]), pair[0]),
    )
    if repeated:
        cve, ids = repeated[0]
        docs = [by_id[doc_id] for doc_id in ids]
        sources = len({_source(doc) for doc in docs})
        result.append(
            BriefHighlight(
                'A recurring topic in the reports',
                f'{cve} appears in {_count(len(ids), "report")} from {_count(sources, "source")}. '
                'It is the most-mentioned flaw in this brief. More mentions do not mean more attacks.',
                'Ask IT whether this flaw affects a product you use. Read the reports for context.',
                _evidence(docs),
            )
        )
    elif facts.vendors:
        name, _ = facts.vendors[0]
        related = [
            doc
            for doc in facts.fresh
            if name.casefold()
            in {
                ' '.join(vendor.split()).casefold()
                for line in VENDOR_LINE.findall(doc.body)
                for vendor in line.split(',')
            }
        ]
        vendor_evidence = list(_evidence(related))
        vendor_evidence += [
            BriefItem(f'{kev.cve} · {_product(kev)}', kev.document_id)
            for kev in facts.kev_added
            if kev.document_id and ' '.join(kev.vendor.split()).casefold() == name.casefold()
        ]
        result.append(
            BriefHighlight(
                'Products to check against your own',
                f'{name} is among the most-named vendors in the advisories and new CISA listings. '
                'A vendor name alone does not mean every product or version is affected.',
                'Ask IT to compare the named products and versions with your systems.',
                tuple({item.document_id: item for item in vendor_evidence}.values())[:SECTION_ITEMS],
            )
        )

    if facts.severe:
        score, cve, title, doc_id = facts.severe[0]
        listed = (
            cve in data.kev
            and (added := _day(data.kev[cve].date_added)) is not None
            and added <= as_of.date()
        )
        result.append(
            BriefHighlight(
                'Highest reported severity',
                f'{cve} has the highest listed base score: {score:g} out of 10. '
                f'Advisory: {title.split(" · ", 1)[-1]}. '
                + _impact(by_id[doc_id], cve)
                + 'This score rates the flaw, not the chance of an attack. '
                + (
                    "It is also on CISA's known exploited list."
                    if listed
                    else 'This brief has no confirmed CISA match; that does not rule out attacks.'
                ),
                "If the product is in use, ask IT to review the impact and the vendor's fix guidance.",
                (BriefItem(title, doc_id),),
            )
        )

    if facts.watch:
        terms = _names([term for term, _ in facts.watch])
        ids = set().union(*(data.watch[term] for term, _ in facts.watch)) & by_id.keys()
        result.append(
            BriefHighlight(
                'Possible relevance to your organization',
                f'{_count(facts.watch_reports, "report")} {_verb(facts.watch_reports, "matches", "match")} '
                f'your watch terms: {terms}. '
                'A text match is a clue, not proof that your systems are exposed.',
                'Ask the owner of these systems to confirm the product, version and any action needed.',
                _evidence([by_id[doc_id] for doc_id in ids]),
            )
        )

    recent = [
        doc
        for doc in facts.fresh
        if (received := _time(doc.created_at)) is not None
        and as_of - timedelta(hours=24) <= received <= as_of
    ]
    result.append(
        BriefHighlight(
            'Received in the last 24 hours',
            f'{_count(len(recent), "report")} in this brief {_verb(len(recent), "was", "were")} received '
            'in the last 24 hours. This is collection time, not when a flaw or attack first appeared.',
            'Open the latest reports to see what changed and whether it matters to your systems.'
            if recent
            else 'Check the source status below. No new reports does not mean no risk.',
            _evidence(recent),
        )
    )
    return tuple(result)


def _verb(count: int, singular: str, plural: str) -> str:
    return singular if count == 1 else plural


def coverage(data: BriefData, facts: _Facts, as_of: datetime) -> tuple[str, ...]:
    notes = [
        'Counts cover the reports in this brief, not all threats. '
        'Repeated mentions do not measure a rise in attacks.',
        'The 24-hour count uses receipt time for the current report version. '
        'A received report may be an update.',
        'CISA dates have day-level precision. '
        'Other reports use receipt time when no publisher date is stored.',
        'The CISA list shows known exploitation. It does not show whether attacks are happening today.',
    ]
    if data.truncated:
        notes.append('This brief reached its report limit. Counts and topic rankings are partial.')
    invalid = [
        doc
        for doc in data.documents
        if not is_demo(doc)
        and (
            (received := _time(doc.created_at)) is None
            or received > as_of
            or (released := _day(published(doc))) is None
            or released > as_of.date()
        )
    ]
    if invalid:
        notes.append('Reports with invalid or future dates were left out of the brief.')
    if any(
        _day(kev.date_added) is None or kev.date_added > as_of.date().isoformat() for kev in data.kev.values()
    ):
        notes.append('CISA entries with invalid or future listing dates were left out.')
    if not facts.fresh and not facts.kev_added:
        notes.append(
            'No recent evidence is available here. This does not establish that your systems are safe.'
        )
    if not data.source_checks:
        notes.append('No source checks are recorded. We cannot tell if the feeds are up to date.')
    for _, name, attempt, status, success in data.source_checks:
        latest, checked = _time(attempt), _time(success)
        if checked is None or checked > as_of:
            notes.append(f'{name}: no successful check is recorded for this period.')
            continue
        when = checked.strftime('%d %b %Y at %H:%M UTC')
        if latest is not None and latest <= as_of and status != 'success':
            notes.append(f'{name}: the latest check failed. Last successful check: {when}.')
        elif checked < as_of - timedelta(hours=24):
            notes.append(f'{name}: no successful check in the last 24 hours. Last checked: {when}.')
        else:
            notes.append(f'{name}: last successful check {when}.')
    return tuple(notes)

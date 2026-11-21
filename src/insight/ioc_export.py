"""Cross-report indicator-of-compromise export (``insight-ioc-v1``): pure formatting, no database access.

``services.export_iocs`` loads the matching mentions and calls :func:`build_export`. Keeping this module free
of SQL makes the output format easy to test and keeps ``insight.services`` the only query layer (ADR 0003).

Output rules:

* one entry per canonical indicator (``kind``, ``value``), listing every report that mentions it;
* each indicator carries the most restrictive TLP of its source reports, and the export as a whole carries the
  most restrictive TLP of every report it includes (labels are only ever raised, never lowered, ADR 0009);
* an unknown label counts as more restrictive than RED (fail safe);
* defanging applies to indicator values, report titles and evidence excerpts. Source URLs are the publisher's
  link (provenance) and stay exactly as stored.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from . import __version__
from .extraction import AMBIGUOUS_TLDS, EMAIL_SEPARATOR, extract
from .flags import flags
from .schemas import DEFAULT_TLP, REVIEW_STATUSES, TLP_LEVELS

FORMAT: Final = 'insight-ioc-v1'
HANDLING_NOTICE: Final = (
    'Local export only. Preserve TLP and publisher restrictions. Not STIX. '
    'Extraction is not a maliciousness verdict: "accepted" means an analyst confirmed the extraction is '
    'accurate, not that the indicator is malicious.'
)
#: Kinds that can be clicked, resolved or connected to by accident, and are therefore defanged on request.
NETWORK_KINDS: Final = frozenset({'url', 'domain', 'ip', 'cidr', 'email'})

_BARE_DOT = re.compile(r'(?<![\[({])\.(?![\])}])')  # a dot that is not already defanged as [.] (.) {.}
_BARE_COLON = re.compile(r'(?<!\[):(?!\])')  # a colon that is not already defanged as [:]
_LIVE_SCHEME = re.compile(r'\bhttp(s?)(?=://)', re.IGNORECASE)
# Network-shaped text the extractor deliberately does not report as an indicator, but which mail clients and
# ticket systems can still turn into links. Defanged text must not leave them live.
_EMAIL_DOMAIN = re.compile(r'(?<=@)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,63}\b', re.IGNORECASE)
_IPV4_CIDR = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d)')
_IPV6_CIDR = re.compile(r'(?<![\w:.])(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}/\d{1,3}(?!\d)', re.IGNORECASE)
_FILE_EXTENSION_TLDS = '|'.join(sorted(AMBIGUOUS_TLDS, key=len, reverse=True))
_FILE_LIKE_NAME = re.compile(
    r'(?<![\w@.\-])[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.'
    r'(?:' + _FILE_EXTENSION_TLDS + r')(?![\w-]|\.[a-z0-9])',
    re.IGNORECASE,
)
_EDGE_TOKEN = re.compile(r'\A\S+|\S+\Z')
_INNER_DOT = re.compile(r'(?<=\w)\.(?=\w)')


@dataclass(frozen=True, slots=True)
class IocMention:
    """One observation of an indicator in one report, with the provenance the export needs."""

    entity_id: str
    kind: str
    value: str
    review_status: str
    evidence: str
    document_id: str
    title: str
    source_name: str
    source_url: str
    tlp: str
    status: str
    created_at: str
    is_current: bool
    kev: Mapping[str, str] | None = None
    extractor_version: str = ''
    #: The report's publisher allows metadata only: its words (the evidence) stay in Insight (ADR 0021).
    metadata_only: bool = False
    #: When the mention was last reviewed ('' if never, or before reviews were timed). TAXII versions use it.
    reviewed_at: str = ''


@dataclass(frozen=True)
class Assessment:
    """The verdict an export may show for one indicator (already checked against the reader's TLP limit)."""

    verdict: str
    valid_until: str | None = None


UNKNOWN: Final = Assessment('unknown')


# --------------------------------------------------------------------------- defanging


def _defang_span(kind: str, text: str) -> str:
    if kind not in NETWORK_KINDS:
        return text
    if kind == 'email':
        separator = EMAIL_SEPARATOR.search(text)
        domain_start = separator.end() if separator else 0
        return text[:domain_start] + _BARE_DOT.sub('[.]', text[domain_start:])
    text = _BARE_DOT.sub('[.]', text)
    if kind in ('ip', 'cidr'):
        text = _BARE_COLON.sub('[:]', text)
    if kind == 'url':
        text = _LIVE_SCHEME.sub(lambda match: 'hxxp' + match.group(1).lower(), text)
    return text


def defang(kind: str, value: str) -> str:
    """Defang a canonical indicator value so it cannot be clicked or resolved by accident.

    ``https://evil.example/a.php`` → ``hxxps://evil[.]example/a[.]php``,
    ``evil.example`` → ``evil[.]example``, ``203.0.113.9`` → ``203[.]0[.]113[.]9`` and
    ``2001:db8::1`` → ``2001[:]db8[:][:]1``. CVEs and hashes are returned unchanged. Insight's own
    extractor refangs every one of these forms back to the original value.
    """
    return _defang_span(kind, value)


def _defang_matches(pattern: re.Pattern[str], kind: str, text: str) -> str:
    return pattern.sub(lambda match: _defang_span(kind, match.group()), text)


def defang_text(text: str) -> str:
    """Defang network indicators in free text (titles, evidence excerpts).

    Covers what the extractor reports plus network-shaped text it skips: e-mail domains in partial addresses,
    CIDR-like text with host bits set and two-label names with file-extension TLDs
    (``update.zip``). Any remaining ``http(s)://`` scheme is defanged as well. Version numbers that merely
    look like IPv4 addresses (``firmware 10.2.9.1``) are left as written.
    """
    spans = sorted(
        ((m.start, m.end, m.kind) for m in extract(text) if m.kind in NETWORK_KINDS),
        key=lambda span: (span[0], -span[1]),
    )
    parts: list[str] = []
    position = 0
    for start, end, kind in spans:
        if start < position:
            continue  # inside a span already handled, e.g. the host of a URL
        parts.append(text[position:start])
        parts.append(_defang_span(kind, text[start:end]))
        position = end
    parts.append(text[position:])
    result = ''.join(parts)
    result = _defang_matches(_EMAIL_DOMAIN, 'domain', result)
    result = _defang_matches(_IPV4_CIDR, 'ip', result)
    result = _defang_matches(_IPV6_CIDR, 'ip', result)
    result = _defang_matches(_FILE_LIKE_NAME, 'domain', result)
    return _LIVE_SCHEME.sub(lambda match: 'hxxp' + match.group(1).lower(), result)


def defang_excerpt(text: str) -> str:
    """:func:`defang_text` for an evidence excerpt, which is cut at fixed character positions.

    A URL or name cut off at either edge (``…ttps://relay.example.org/a.php``, ``exfil.examp…``) is no longer
    recognisable as an indicator, so dots inside the first and last words are defanged too.
    """
    return _EDGE_TOKEN.sub(lambda match: _INNER_DOT.sub('[.]', match.group()), defang_text(text))


# --------------------------------------------------------------------------- TLP


def _restrictiveness(level: str) -> int:
    return TLP_LEVELS.index(level) if level in TLP_LEVELS else len(TLP_LEVELS)


def most_restrictive_label(levels: Iterable[str], default: str = DEFAULT_TLP) -> str:
    """The most restrictive label in ``levels`` (``default`` when empty); unknown labels win (fail safe)."""
    return max(levels, key=_restrictiveness, default=default)


# --------------------------------------------------------------------------- export document


def export_filename(generated_at: str) -> str:
    """``insight-iocs-20261113T101500Z.json`` for an ISO-8601 UTC ``generated_at``."""
    return f'insight-iocs-{datetime.fromisoformat(generated_at).strftime("%Y%m%dT%H%M%SZ")}.json'


def _evidence(mention: IocMention, defanged: bool, include: bool) -> str | None:
    if not include or mention.metadata_only:
        return None
    return defang_excerpt(mention.evidence) if defanged else mention.evidence


def _source_view(mentions: list[IocMention], defanged: bool, evidence: bool) -> dict[str, Any]:
    first = mentions[0]
    return {
        'document_id': first.document_id,
        'title': defang_text(first.title) if defanged else first.title,
        'source_name': first.source_name,
        'source_url': first.source_url,
        'tlp': first.tlp,
        'status': first.status,
        'created_at': first.created_at,
        'is_current': first.is_current,
        'extractor_version': first.extractor_version,
        'mentions': len(mentions),
        'evidence': _evidence(first, defanged, evidence),
    }


def _review_order(status: str) -> int:
    return REVIEW_STATUSES.index(status) if status in REVIEW_STATUSES else len(REVIEW_STATUSES)


def _ioc_view(
    mentions: list[IocMention], defanged: bool, evidence: bool, assessment: Assessment = UNKNOWN
) -> dict[str, Any]:
    first = mentions[0]
    by_document: dict[str, list[IocMention]] = {}
    for mention in mentions:
        by_document.setdefault(mention.document_id, []).append(mention)
    sources = sorted(
        (_source_view(group, defanged, evidence) for group in by_document.values()),
        key=lambda source: (source['created_at'], source['document_id']),
    )
    statuses = [mention.review_status for mention in mentions]
    return {
        'kind': first.kind,
        'value': defang(first.kind, first.value) if defanged else first.value,
        'entity_id': first.entity_id,
        'tlp': most_restrictive_label(source['tlp'] for source in sources),
        'first_ingested_at': sources[0]['created_at'],
        'last_ingested_at': sources[-1]['created_at'],
        'review_statuses': {
            status: statuses.count(status) for status in sorted(set(statuses), key=_review_order)
        },
        'kev': dict(first.kev) if first.kev is not None else None,
        'verdict': assessment.verdict,
        'verdict_valid_until': assessment.valid_until,
        'flags': list(flags(first.kind, first.value)),
        'sources': sources,
    }


def build_export(
    mentions: Iterable[IocMention],
    *,
    filters: Mapping[str, Any],
    defanged: bool,
    export_id: str,
    generated_at: str,
    include_evidence: bool = True,
    assessments: Mapping[str, Assessment] | None = None,
) -> dict[str, Any]:
    """Group ``mentions`` into one entry per indicator and wrap them with handling metadata.

    Mentions of one indicator within one report are counted; the first one (in the order given, normally
    by position in the report) supplies the evidence excerpt, or ``None`` when ``include_evidence`` is off.
    ``assessments`` maps entity IDs to the verdicts this reader may see; every other indicator is ``unknown``.
    Warning flags are computed from each canonical value, whether or not the export is defanged.
    """
    by_entity: dict[str, list[IocMention]] = {}
    document_tlp: dict[str, str] = {}
    total = 0
    for mention in mentions:
        by_entity.setdefault(mention.entity_id, []).append(mention)
        document_tlp[mention.document_id] = mention.tlp
        total += 1
    known = assessments or {}
    iocs = sorted(
        (
            _ioc_view(group, defanged, include_evidence, known.get(entity_id, UNKNOWN))
            for entity_id, group in by_entity.items()
        ),
        key=lambda ioc: (ioc['kind'], ioc['value'], ioc['entity_id']),
    )
    by_kind: dict[str, int] = {}
    for ioc in iocs:
        by_kind[ioc['kind']] = by_kind.get(ioc['kind'], 0) + 1
    return {
        'format': FORMAT,
        'export_id': export_id,
        'generated_at': generated_at,
        'generator': f'insight {__version__}',
        'handling_notice': HANDLING_NOTICE,
        # With nothing included the workspace default applies: an empty export is never labelled CLEAR.
        'tlp': most_restrictive_label(document_tlp.values()),
        'defanged': defanged,
        'filters': dict(filters),
        'counts': {
            'iocs': len(iocs),
            'documents': len(document_tlp),
            'mentions': total,
            'by_kind': dict(sorted(by_kind.items())),
        },
        'iocs': iocs,
    }

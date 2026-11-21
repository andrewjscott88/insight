"""Import one trusted MISP JSON event with typed, unreviewed indicators and a stable revision history."""

from __future__ import annotations

import json
from datetime import date
from typing import Any, Final
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy.orm import Session

from . import services
from .extraction import EVIDENCE_CONTEXT, MAX_MENTIONS, Kind, Mention, canonical
from .models import Document
from .schemas import DEFAULT_TLP, TLP_LEVELS, DocumentInput, most_restrictive, tlp_markings
from .services.tlp import apply_tlp_policy

MAX_MISP_BYTES: Final = 8_000_000
_TYPES: Final[dict[str, Kind]] = {
    'domain': 'domain',
    'hostname': 'domain',
    'url': 'url',
    'ip-src': 'ip',
    'ip-dst': 'ip',
    'email-src': 'email',
    'email-dst': 'email',
    'email': 'email',
    'vulnerability': 'cve',
    'md5': 'md5',
    'sha1': 'sha1',
    'sha256': 'sha256',
    'sha512': 'sha512',
}
# A MISP sharing-group ID identifies a particular recipient list. No Insight TLP label can express that.
_DISTRIBUTION_FLOOR: Final = {'0': 'AMBER+STRICT', '1': 'GREEN', '2': 'GREEN', '3': 'CLEAR'}


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('A MISP object contains a duplicate field.')
        result[key] = value
    return result


def _handling(record: dict[str, Any], *, event: bool) -> str:
    """Combine explicit TLP markings and distribution, treating all active attributes as one report."""
    distribution = str(record.get('distribution', '0' if event else '5'))
    if (
        distribution == '4'
        or record.get('sharing_group_id', '0') not in ('0', 0, None)
        or record.get('SharingGroup')
    ):
        raise ValueError('MISP sharing groups cannot be represented in Insight.')
    floor = 'CLEAR' if distribution == '5' and not event else _DISTRIBUTION_FLOOR.get(distribution)
    if floor is None:
        raise ValueError('Invalid MISP distribution setting.')
    tags = record.get('Tag', [])
    if not isinstance(tags, list) or len(tags) > 256 or record.get('AttributeTag') or record.get('EventTag'):
        raise ValueError('Invalid MISP tags. Expected a Tag list.')
    levels: list[str] = []
    for tag in tags:
        if not isinstance(tag, dict) or not isinstance(name := tag.get('name'), str):
            raise ValueError('A MISP tag must have a name.')
        namespace, separator, label = name.upper().partition(':')
        if separator and namespace.strip() == 'TLP':
            level = label.strip()
            if level == 'WHITE':
                level = 'CLEAR'
            if level not in TLP_LEVELS:
                raise ValueError('Unknown MISP TLP tag.')
            levels.append(level)
    if event and not levels:
        levels.append(DEFAULT_TLP)
    if _enabled(record, 'disable_correlation'):
        raise ValueError('Insight cannot import a MISP record that forbids correlation.')
    # Attribute comments can carry inline handling labels even when the comment itself is omitted.
    if 'comment' in record:
        comment = record['comment']
        if not isinstance(comment, str):
            raise ValueError('Invalid MISP comment.')
        levels.extend(tlp_markings(comment))
    return most_restrictive(floor, *levels)


def _enabled(record: dict[str, Any], field: str) -> bool:
    """MISP exports boolean fields as booleans, integer flags, or their string equivalents."""
    value = str(record.get(field, False)).lower()
    if value in ('0', 'false'):
        return False
    if value in ('1', 'true'):
        return True
    raise ValueError(f'Invalid MISP {field} flag.')


def _attribute(row: dict[str, Any]) -> tuple[str, Kind, str]:
    wire_type, raw = row.get('type'), row.get('value')
    if not isinstance(wire_type, str) or wire_type not in _TYPES or row.get('data'):
        raise ValueError('Unsupported MISP attribute. Import only supported indicator types.')
    if (
        not isinstance(raw, str)
        or not 0 < len(raw) <= 8192
        or not raw.isprintable()
        or any(ch.isspace() for ch in raw)
    ):
        raise ValueError('Invalid MISP indicator value.')
    kind = _TYPES[wire_type]
    if kind == 'ip' and '/' in raw:
        kind = 'cidr'
    try:
        value = canonical(kind, raw)
    except ValueError:
        raise ValueError(f'Invalid value for a MISP {wire_type} attribute.') from None
    return wire_type, kind, value


def _report(event: dict[str, Any], event_id: str) -> tuple[DocumentInput, list[Mention]]:
    title = event.get('info')
    if not isinstance(title, str) or not title.strip() or not title.isprintable() or len(title) > 300:
        raise ValueError('A MISP event needs an info title of up to 300 characters.')
    if any(event.get(key) for key in ('Object', 'EventReport', 'ShadowAttribute')):
        raise ValueError('Only flat MISP events with an Attribute list are supported.')
    attributes = event.get('Attribute')
    if not isinstance(attributes, list) or len(attributes) > MAX_MENTIONS:
        raise ValueError(f'A MISP event needs an Attribute list of up to {MAX_MENTIONS} entries.')
    tlp = _handling(event, event=True)
    indicators: set[tuple[str, Kind, str]] = set()
    for row in attributes:
        if not isinstance(row, dict):
            raise ValueError('A MISP attribute must be an object.')
        if _enabled(row, 'deleted'):
            continue
        tlp = most_restrictive(tlp, _handling(row, event=False))
        indicators.add(_attribute(row))

    # The event UUID participates in the document fingerprint, even for two otherwise identical events.
    lines = [f'MISP event {event_id}']
    if 'date' in event:
        raw_date = event['date']
        if not isinstance(raw_date, str) or len(raw_date) != 10:
            raise ValueError('Invalid MISP event date.')
        try:
            lines.append('Event date: ' + date.fromisoformat(raw_date).isoformat())
        except ValueError:
            raise ValueError('Invalid MISP event date.') from None
    offset = sum(len(line) + 1 for line in lines)
    spans = []
    for wire_type, kind, value in sorted(indicators):
        prefix = f'{wire_type}: '
        line = prefix + value
        start = offset + len(prefix)
        spans.append((kind, value, start, start + len(value)))
        lines.append(line)
        offset += len(line) + 1
    try:
        report = DocumentInput.model_validate(
            {'title': title, 'body': '\n'.join(lines), 'source_name': 'MISP event', 'tlp': tlp}
        )
    except ValidationError:
        # Pydantic includes sampled report content in its exception text, which may carry restricted data.
        raise ValueError('The MISP event exceeds Insight report limits.') from None
    mentions = [
        Mention(
            kind, value, start, end, report.body[max(0, start - EVIDENCE_CONTEXT) : end + EVIDENCE_CONTEXT]
        )
        for kind, value, start, end in spans
    ]
    return report, mentions


def parse_misp_event(
    payload: bytes, *, expected_uuid: str | None = None
) -> tuple[str, DocumentInput, list[Mention]]:
    """Read one native event or PyMISP Event wrapper. All attribute validation happens before any write."""
    if len(payload) > MAX_MISP_BYTES:
        raise ValueError('MISP event exceeds the 8 MB file limit.')
    try:
        data = json.loads(payload, object_pairs_hook=_unique_keys)
    except (ValueError, RecursionError):
        raise ValueError('Invalid MISP event JSON.') from None
    if not isinstance(data, dict) or not isinstance(event := data.get('Event', data), dict):
        raise ValueError('Expected a single MISP event object.')
    try:
        raw_uuid = event.get('uuid')
        if not isinstance(raw_uuid, str):
            raise ValueError('Missing UUID')
        event_uuid = UUID(raw_uuid)
        if not event_uuid.int:
            raise ValueError('Nil UUID')
        event_id = str(event_uuid)
    except ValueError:
        raise ValueError('A MISP event must have a valid UUID.') from None
    if expected_uuid is not None and UUID(expected_uuid) != event_uuid:
        raise ValueError('MISP returned a different event UUID than requested.')
    report, mentions = _report(event, event_id)
    return event_id, report, mentions


def import_misp_event(
    db: Session, payload: bytes, *, max_tlp: str, allow_red: bool = False, expected_uuid: str | None = None
) -> tuple[Document, bool]:
    """Import one validated snapshot through the normal transactional revision and TLP path."""
    if max_tlp not in TLP_LEVELS:
        raise ValueError('Invalid maximum TLP.')
    event_id, report, mentions = parse_misp_event(payload, expected_uuid=expected_uuid)
    if apply_tlp_policy(report).tlp == 'RED' and not allow_red:
        raise ValueError('TLP:RED import requires explicit permission (--allow-red).')
    doc, created = services.ingest(
        db,
        report,
        ref=services.SourceRef('misp', event_id),
        max_tlp=max_tlp,
        structured=services.StructuredObservations(version='misp-event-v1', mentions=mentions),
    )
    if (doc.source_key, doc.external_id) != ('misp', event_id):
        # The shared fingerprint index also covers manual submissions. Preserve both provenance and types.
        raise ValueError('This MISP snapshot matches a report already stored under a different source.')
    return doc, created

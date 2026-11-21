"""Build an unpublished MISP event from reviewed Insight observations."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from itertools import groupby
from typing import Any, Final
from urllib.parse import unquote
from uuid import UUID, uuid5

from sqlalchemy.orm import Session

from . import services
from .extraction import EMAIL_SEPARATOR
from .ioc_export import IocMention, defang_excerpt, most_restrictive_label
from .schemas import INDICATOR_KINDS, TLP, IocExportQuery

#: MISP treats a range (including its prefix) as an ip-src/ip-dst attribute.
_ATTRIBUTE_TYPES: Final = {'cve': 'vulnerability', 'ip': 'ip-dst', 'cidr': 'ip-dst', 'email': 'email-dst'}
_DISTRIBUTION: Final = {'CLEAR': '3', 'GREEN': '1', 'AMBER': '0', 'AMBER+STRICT': '0', 'RED': '0'}
_NAMESPACE: Final = UUID('9a76302a-9a17-418c-97d5-2362a37ade9b')


def _attribute(group: list[IocMention], *, evidence: bool, personal_data: bool) -> dict[str, Any]:
    first = group[0]
    tags = [{'name': 'tlp:' + most_restrictive_label(m.tlp for m in group).lower()}]
    if first.kind == 'email':
        tags.append({'name': 'insight:personal-data'})
    category = 'Network activity'
    if first.kind == 'cve':
        category = 'External analysis'
    elif first.kind in {'md5', 'sha1', 'sha256', 'sha512'}:
        category = 'Payload delivery'
    attr: dict[str, Any] = {
        'type': _ATTRIBUTE_TYPES.get(first.kind, first.kind),
        'category': category,
        'value': first.value,
        'to_ids': False,
        'distribution': '5',
        'Tag': tags,
    }
    if evidence:
        for mention in group:
            if mention.metadata_only:
                continue
            if not personal_data and EMAIL_SEPARATOR.search(unquote(mention.evidence)):
                continue
            attr['comment'] = defang_excerpt(mention.evidence)
            break
    return attr


def export_misp_event(
    db: Session,
    *,
    max_tlp: TLP,
    allow_red: bool = False,
    document_ids: Sequence[str] = (),
    include_unreviewed: bool = False,
    include_evidence: bool = False,
    include_personal_data: bool = False,
) -> dict[str, Any]:
    """Select one snapshot. Stable event/attribute UUIDs allow the receiver to recognise repeated sends."""
    query = IocExportQuery(
        max_tlp='AMBER+STRICT' if max_tlp == 'RED' and not allow_red else max_tlp,
        document_ids=tuple(document_ids),
        review_statuses=('accepted', 'unreviewed') if include_unreviewed else ('accepted',),
        kinds=tuple(k for k in INDICATOR_KINDS if k != 'email' or include_personal_data),
    )
    mentions = services.ioc_mentions(db, query)
    if not include_personal_data:
        # A URL path or query can carry a mailbox without a separate e-mail observation.
        mentions = [m for m in mentions if m.kind != 'url' or not EMAIL_SEPARATOR.search(unquote(m.value))]
    if not mentions:
        raise ValueError('No eligible indicators match the MISP export filters')
    attributes = [
        _attribute(list(group), evidence=include_evidence, personal_data=include_personal_data)
        for _, group in groupby(mentions, key=lambda m: (m.kind, m.value))
    ]
    label = most_restrictive_label(m.tlp for m in mentions)
    reports = sorted({m.document_id for m in mentions})
    date = max(m.created_at for m in mentions)[:10]
    # A new snapshot of the same reports needs new attribute UUIDs too: MISP attributes belong to one event.
    snapshot = json.dumps([reports, date, attributes], sort_keys=True, separators=(',', ':')).encode()
    event_uuid = uuid5(_NAMESPACE, hashlib.sha256(snapshot).hexdigest())
    for attr in attributes:
        attr['uuid'] = str(uuid5(event_uuid, f'{attr["type"]}:{attr["value"]}'))
    services.audit(db, 'misp.export', str(event_uuid), f'{len(attributes)} attributes; TLP:{label}')
    return {
        'Event': {
            'uuid': str(event_uuid),
            'info': 'Indicators from Insight',
            'date': date,
            'analysis': '0',
            'threat_level_id': '4',
            'distribution': _DISTRIBUTION[label],
            'published': False,
            'Tag': [{'name': 'tlp:' + label.lower()}],
            'Attribute': attributes,
        }
    }

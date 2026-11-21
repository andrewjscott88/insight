"""Read a bounded STIX 2.1 bundle offline. Only simple, representable objects become observations."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Final, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from .attack import technique
from .extraction import EVIDENCE_CONTEXT, MAX_MENTIONS, Kind, Mention, canonical
from .schemas import DEFAULT_TLP, TLP, DocumentInput, most_restrictive, tlp_markings
from .stix_export import TLP_EXTENSION, TLP_MARKINGS
from .stix_validation import validate_stix_bundle

MAX_BUNDLE_BYTES: Final = 2_000_000
MAX_OBJECTS: Final = 2_000
MAX_REPORTS: Final = 200
MAX_REFERENCES: Final = 10_000
_TLP1 = {  # Predefined STIX 2.1 TLP 1.0 marking IDs, in addition to the TLP 2.0 IDs used by Insight.
    'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9': 'CLEAR',
    'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da': 'GREEN',
    'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82': 'AMBER',
    'marking-definition--5e57c739-391a-4eb3-b6cf-5e9ed4ae2baa': 'RED',
}
_OBSERVABLE_TYPES = {'indicator', 'vulnerability', 'attack-pattern'}
_SUPPORTED = _OBSERVABLE_TYPES | {'report', 'identity', 'marking-definition'}
_PATTERN = re.compile(
    r"\[\s*(ipv[46]-addr|file|domain-name|url|email-addr):"
    r"(value|hashes\.(?:'[^']{1,12}'|MD5))\s*=\s*'((?:[^'\\]|\\['\\])*)'\s*\]"
)
_KINDS: dict[str, Kind] = {'domain-name': 'domain', 'url': 'url', 'email-addr': 'email'}
_HASHES: dict[str, Kind] = {'MD5': 'md5', 'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-512': 'sha512'}
Object = dict[str, Any]


@dataclass(frozen=True)
class ImportedReport:
    source_id: str
    initial_id: str
    item: DocumentInput
    mentions: list[Mention]
    metadata_only: bool
    technique_ids: frozenset[str]


@dataclass(frozen=True)
class ImportedBundle:
    bundle_id: str
    sha256: str
    reports: list[ImportedReport]


def _object(pairs: list[tuple[str, Any]]) -> Object:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError('Duplicate JSON key in STIX bundle')
    return result


def _uuid(stix_id: str, kind: str) -> str:
    prefix, sep, value = stix_id.partition('--')
    if prefix != kind or not sep or str(UUID(value)) != value:
        raise ValueError('Invalid STIX object ID')
    return value


def _read(data: bytes) -> Object:
    if not data or len(data) > MAX_BUNDLE_BYTES:
        raise ValueError('Choose a STIX JSON file of up to 2 MB')
    try:
        bundle = json.loads(data.decode('utf-8'), object_pairs_hook=_object)
        # Enforce UTF-8 and finite numbers for JSON escape sequences as well as the input file itself.
        json.dumps(bundle, ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (ValueError, RecursionError) as exc:
        raise ValueError('Invalid UTF-8 JSON in STIX bundle') from exc
    pending = [(bundle, 0)]
    visited = 0
    while pending:
        node, depth = pending.pop()
        visited += 1
        if visited > 100_000 or (isinstance(node, (dict, list)) and len(node) > MAX_REFERENCES):
            raise ValueError('STIX bundle structure exceeds the import limit')
        if depth > 24:
            raise ValueError('STIX bundle is nested too deeply')
        if isinstance(node, dict):
            pending.extend((k, depth + 1) for k in node)
            pending.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            pending.extend((v, depth + 1) for v in node)
        elif isinstance(node, str) and '\x00' in node:
            raise ValueError('STIX text contains a null character')
    if not isinstance(bundle, dict) or bundle.get('type') != 'bundle' or not isinstance(bundle.get('id'), str):
        raise ValueError('Expected a STIX bundle with an ID')
    _uuid(bundle['id'], 'bundle')
    objects = bundle.get('objects')
    if not isinstance(objects, list) or not 1 <= len(objects) <= MAX_OBJECTS:
        raise ValueError(f'A STIX bundle must contain 1 to {MAX_OBJECTS} objects')
    return bundle


def _indicator(obj: Object) -> tuple[Kind, str]:
    if obj.get('pattern_type') != 'stix' or not isinstance(obj.get('pattern'), str) or len(obj['pattern']) > 8192:
        raise ValueError('Expected a single STIX equality pattern')
    match = _PATTERN.fullmatch(obj['pattern'])
    if not match:
        raise ValueError('Only a single equality on a supported indicator is accepted')
    observable, prop, literal = match.groups()
    value = re.sub(r"\\(['\\])", r'\1', literal)
    if observable == 'file' and prop.startswith('hashes.'):
        kind = _HASHES.get(prop[7:].strip("'"))
    elif prop == 'value' and observable in ('ipv4-addr', 'ipv6-addr'):
        network = ipaddress.ip_network(value, strict=True)
        if network.version != int(observable[3]):
            raise ValueError('STIX address family does not match its value')
        kind = 'cidr' if '/' in value else 'ip'
    else:
        kind = _KINDS.get(observable) if prop == 'value' else None
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Invalid control character in indicator')
    if kind is None:
        raise ValueError('Unsupported STIX observable property')
    normalized = canonical(kind, value)
    if len(normalized.encode()) > 2000:
        raise ValueError('STIX indicator exceeds the value limit')
    return kind, normalized


def _reference(obj: Object, source: str) -> str:
    matches = {entry.get('external_id') for entry in obj.get('external_references', []) if entry.get('source_name', '').lower() == source}
    if len(matches) != 1 or not isinstance(value := matches.pop(), str):
        raise ValueError(f'Expected one {source} external ID')
    return value


def _value(obj: Object) -> tuple[Kind | None, str]:
    if obj['type'] == 'indicator':
        return _indicator(obj)
    if obj['type'] == 'vulnerability':
        name = obj.get('name', '')
        value = _reference(obj, 'cve') if any(r.get('source_name', '').lower() == 'cve' for r in obj.get('external_references', [])) else name
        return 'cve', canonical('cve', value)
    attack_id = _reference(obj, 'mitre-attack')
    if not technique(attack_id):
        raise ValueError('This ATT&CK technique is outside the bundled Enterprise catalog')
    return None, attack_id


def _labels(objects: dict[str, Object], max_tlp: str) -> dict[str, str]:
    standard = {stix_id: label for label, stix_id in TLP_MARKINGS.items()} | _TLP1
    labels: dict[str, str] = {}
    for object_id, obj in objects.items():
        if obj['type'] == 'marking-definition':
            if object_id not in standard:
                raise ValueError('Unsupported marking definition in STIX bundle')
            label = standard[object_id]
            if object_id in _TLP1 and obj.get('extensions'):
                raise ValueError('Unsupported marking extension')
            if object_id in _TLP1:
                old_label = 'white' if label == 'CLEAR' else label.lower()
                if obj.get('definition_type') != 'tlp' or obj.get('definition') != {'tlp': old_label}:
                    raise ValueError('Marking definition does not match its standard ID')
            elif obj.get('name') != f'TLP:{label}' or obj.get('extensions') != {
                TLP_EXTENSION: {'extension_type': 'property-extension', 'tlp_2_0': label.lower()}
            } or 'definition' in obj or 'definition_type' in obj:
                raise ValueError('Marking definition does not match its standard ID')
            if obj.get('object_marking_refs') or obj.get('granular_markings'):
                raise ValueError('Nested markings are unsupported')
            continue
        if obj.get('granular_markings') or obj.get('extensions') or obj.get('revoked'):
            raise ValueError('Granular markings, extensions and revoked STIX records are unsupported')
        refs = obj.get('object_marking_refs', [])
        if any(ref not in standard for ref in refs):
            raise ValueError('Unrecognized STIX marking reference')
        declared = [standard[ref] for ref in refs] or [DEFAULT_TLP]
        words = [obj.get('name', ''), obj.get('description', ''), *obj.get('labels', [])]
        labels[object_id] = most_restrictive(*declared, *tlp_markings('\n'.join(words)))
        if most_restrictive(labels[object_id], max_tlp) != max_tlp:
            raise ValueError('A STIX object exceeds the permitted TLP level')
    return labels


def _render_report(
    report: Object, refs: list[str], values: dict[str, tuple[Kind | None, str]],
    labels: dict[str, str], objects: dict[str, Object],
) -> ImportedReport:
    source_id = str(report['id'])
    initial_id = _uuid(source_id, 'report') if report['type'] == 'report' else str(uuid5(NAMESPACE_URL, source_id))
    publisher = next(iter(report.get('external_references', [])), {})
    author = objects.get(report.get('created_by_ref', ''), {})
    marking = most_restrictive(labels.get(source_id, 'CLEAR'), *(labels[r] for r in refs))
    if author:
        marking = most_restrictive(marking, labels[author['id']])
    lines = [f'STIX source: {source_id}']
    metadata_only = report.get('x_insight_metadata_only', False)
    if not isinstance(metadata_only, bool):
        raise ValueError('Invalid metadata-only handling flag')
    if report.get('description') and not metadata_only:
        lines.append(report['description'].replace('\r\n', '\n').replace('\r', '\n'))
    offsets: list[tuple[Kind, str, int, int]] = []
    length = sum(map(len, lines)) + len(lines) - 1
    ordered = sorted({values[r] for r in refs}, key=lambda pair: (pair[0] or '', pair[1]))
    for kind, value in ordered:
        label = kind or 'ATT&CK technique'
        start = length + len(label) + 3
        lines.append(f'{label}: {value}')
        length = start + len(value)
        if kind is not None:
            offsets.append((kind, value, start, length))
        if length > 200_000 or len(offsets) > MAX_MENTIONS:
            raise ValueError('STIX report exceeds the document or observation limit')
    body = '\n'.join(lines)
    item = DocumentInput(
        title=report['name'], body=body, source_name=publisher.get('source_name') or author.get('name') or 'STIX import',
        source_url=publisher.get('url', ''), tlp=cast(TLP, marking),
    )
    mentions = [Mention(kind, value, start, end, body[max(start-EVIDENCE_CONTEXT, 0):end+EVIDENCE_CONTEXT]) for kind,value,start,end in offsets]
    return ImportedReport(source_id, initial_id, item, mentions, metadata_only,
                          frozenset(value for kind, value in ordered if kind is None))


def parse_stix(data: bytes, max_tlp: str) -> ImportedBundle:
    """Validate every member and reference before building any database records."""
    bundle = _read(data)
    objects: dict[str, Object] = {}
    total_refs = report_count = 0
    for obj in bundle['objects']:
        if not isinstance(obj, dict) or not isinstance(obj.get('type'), str) or obj['type'] not in _SUPPORTED or not isinstance(obj.get('id'), str):
            raise ValueError('Unsupported or invalid object in STIX bundle')
        _uuid(obj['id'], obj['type'])
        if obj['id'] in objects or obj.get('spec_version') != '2.1':
            raise ValueError('Expected unique, version 2.1 STIX objects')
        for field in ('object_refs', 'object_marking_refs'):
            refs = obj.get(field, [])
            if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
                raise ValueError('Invalid STIX references')
            total_refs += len(refs)
        report_count += obj['type'] == 'report'
        if total_refs > MAX_REFERENCES or report_count > MAX_REPORTS:
            raise ValueError('Too many STIX reports or references')
        if obj['type'] != 'marking-definition' and (obj.get('extensions') or obj.get('granular_markings')):
            raise ValueError('Unsupported STIX extensions or granular markings')
        if obj['type'] == 'indicator':
            if obj.get('pattern_version', '2.1') != '2.1' or 'valid_until' in obj:
                raise ValueError('Unsupported pattern version or time-limited indicator')
            _indicator(obj)  # Bound the supported pattern grammar before calling the general validator.
        objects[obj['id']] = obj
    # Only predefined object types and simple patterns reach the packaged OASIS schemas.
    try:
        validate_stix_bundle(bundle)
    except (KeyError, IndexError, TypeError, RecursionError) as exc:
        raise ValueError('Invalid STIX 2.1 object') from exc
    labels = _labels(objects, max_tlp)
    values = {key: _value(obj) for key, obj in objects.items() if obj['type'] in _OBSERVABLE_TYPES}
    reports: list[ImportedReport] = []
    used: set[str] = set()
    total_chars = 0
    for obj in objects.values():
        creator = obj.get('created_by_ref')
        if creator and obj['type'] != 'marking-definition' and objects.get(creator, {}).get('type') != 'identity':
            raise ValueError('Unresolved creator identity')
        if creator and obj['type'] == 'identity' and creator != obj['id']:
            raise ValueError('Nested STIX publisher identities are unsupported')
        if creator in labels and obj['id'] in labels:
            labels[obj['id']] = most_restrictive(labels[obj['id']], labels[creator])
    for obj in objects.values():
        if obj['type'] != 'report':
            continue
        refs = obj['object_refs']
        if not refs or any(ref not in values for ref in refs):
            raise ValueError('Every report reference must resolve to a supported observable or technique in the bundle')
        used.update(refs)
        imported = _render_report(obj, refs, values, labels, objects)
        total_chars += len(imported.item.body)
        if total_chars > 2 * MAX_BUNDLE_BYTES:
            raise ValueError('Expanded reports exceed the STIX import limit')
        reports.append(imported)
    orphaned = [key for key in values if key not in used]
    if any(values[key][0] is None for key in orphaned):
        raise ValueError('An ATT&CK technique must be referenced by its report')
    if orphaned:
        standalone = {'id': bundle['id'], 'name': 'Imported STIX indicators', 'type': 'bundle'}
        reports.append(_render_report(standalone, orphaned, values, labels, objects))
    if not reports:
        raise ValueError('No supported reports or observations in STIX bundle')
    return ImportedBundle(bundle['id'], hashlib.sha256(data).hexdigest(), reports)

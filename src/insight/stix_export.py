"""Project a policy-filtered IOC export into a STIX 2.1 bundle, without database or network access."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any, Final
from uuid import uuid4

# OASIS CTI common objects, TLP 2.0 marking definitions (2022-10-01). Recipients can distinguish
# AMBER+STRICT from AMBER. These identifiers and the extension payloads are fixed by the specification.
TLP_EXTENSION: Final = 'extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d'
TLP_MARKINGS: Final = {
    'CLEAR': 'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487',
    'GREEN': 'marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb',
    'AMBER': 'marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421',
    'AMBER+STRICT': 'marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003',
    'RED': 'marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1',
}

_PATHS: Final = {
    'domain': 'domain-name:value',
    'email': 'email-addr:value',
    'url': 'url:value',
    'md5': "file:hashes.'MD5'",
    'sha1': "file:hashes.'SHA-1'",
    'sha256': "file:hashes.'SHA-256'",
    'sha512': "file:hashes.'SHA-512'",
}


def stix_timestamp(value: str) -> str:
    """Use a UTC timestamp with at least millisecond precision, including for legacy SQLite rows."""
    stamp = datetime.fromisoformat(value)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.astimezone(UTC).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _marking(label: str) -> dict[str, Any]:
    return {
        'type': 'marking-definition',
        'spec_version': '2.1',
        'id': TLP_MARKINGS[label],
        'created': '2022-10-01T00:00:00.000Z',
        'name': f'TLP:{label}',
        'extensions': {TLP_EXTENSION: {'extension_type': 'property-extension', 'tlp_2_0': label.lower()}},
    }


def _pattern(kind: str, value: str) -> str:
    if kind in {'ip', 'cidr'}:
        family = ipaddress.ip_address(value.split('/')[0]).version
        path = f'ipv{family}-addr:value'
    else:
        path = _PATHS[kind]
    literal = value.replace('\\', '\\\\').replace("'", "\\'")
    return f"[{path} = '{literal}']"


def _indicator(ioc: dict[str, Any], modified: str) -> dict[str, Any]:
    kind, value = ioc['kind'], ioc['value']
    created = stix_timestamp(ioc['first_ingested_at'])
    object_type = 'vulnerability' if kind == 'cve' else 'indicator'
    result: dict[str, Any] = {
        'type': object_type,
        'spec_version': '2.1',
        'id': f'{object_type}--{uuid4()}',
        'name': value,
        'created': created,
        'modified': modified,
        'object_marking_refs': [TLP_MARKINGS[ioc['tlp']]],
    }
    if kind == 'cve':
        result['external_references'] = [{'source_name': 'cve', 'external_id': value}]
        if ioc['kev']:
            result['description'] = f'CISA added this CVE to KEV on {ioc["kev"]["date_added"]}.'
            result['external_references'].append(
                {
                    'source_name': 'CISA KEV',
                    'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                }
            )
    else:
        result.update(
            pattern_type='stix', pattern_version='2.1', pattern=_pattern(kind, value), valid_from=created
        )
    return result


def _report(source: dict[str, Any], modified: str, metadata_only: bool) -> dict[str, Any]:
    published = stix_timestamp(source['created_at'])
    provenance = {'source_name': source['source_name'], 'external_id': source['document_id']}
    if source['source_url']:
        provenance['url'] = source['source_url']
    return {
        'type': 'report',
        'spec_version': '2.1',
        'id': f'report--{source["document_id"]}',
        'created': published,
        'modified': modified,
        'published': published,
        'name': source['title'],
        'report_types': ['threat-report'],
        'external_references': [provenance],
        'object_marking_refs': [TLP_MARKINGS[source['tlp']]],
        'object_refs': [],
        'x_insight_metadata_only': metadata_only,
    }


def build_stix_bundle(export: dict[str, Any], metadata_only_ids: set[str]) -> dict[str, Any]:
    """Use only selected reports/indicators and permitted excerpts. Report references retain membership."""
    bundle: dict[str, Any] = {'type': 'bundle', 'id': 'bundle--' + export['export_id']}
    if not export['iocs']:
        return bundle
    modified = stix_timestamp(export['generated_at'])
    reports: dict[str, dict[str, Any]] = {}
    excerpts: dict[str, dict[str, None]] = {}
    objects = []
    labels: set[str] = set()
    for ioc in export['iocs']:
        indicator = _indicator(ioc, modified)
        objects.append(indicator)
        labels.add(ioc['tlp'])
        for source in ioc['sources']:
            doc_id = source['document_id']
            if doc_id not in reports:
                reports[doc_id] = _report(source, modified, doc_id in metadata_only_ids)
            reports[doc_id]['object_refs'].append(indicator['id'])
            labels.add(source['tlp'])
            if source['evidence'] and doc_id not in metadata_only_ids:
                excerpts.setdefault(doc_id, {})[source['evidence']] = None
    for doc_id, quotes in excerpts.items():
        reports[doc_id]['description'] = '\n\n'.join(quotes)
    bundle['objects'] = (
        [_marking(label) for label in TLP_MARKINGS if label in labels] + objects + list(reports.values())
    )
    return bundle

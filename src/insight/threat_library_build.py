"""Build Insight's group/software library from MITRE ATT&CK and MISP galaxy (ADR 0025, ADR 0038).

Pure functions: a parsed Enterprise ATT&CK STIX bundle and a parsed MISP galaxy ``threat-actor`` cluster go
in, the library Insight reads (``insight.threat_library``) comes out. Used by ``scripts/update_actors.py`` for
the bundled edition and by ``insight threat-library-sync`` for the full one. No network, no database.

Every industry claim carries its source:

* **ATT&CK prose.** ATT&CK has no structured industry field. A group is linked to an industry only when a
  sentence of its ATT&CK description says it targeted that industry (``insight.industries``); the sentence is
  kept, with the citations it carries, as the evidence. ``REVIEWED_EXCLUSIONS`` lists matches a person read
  and rejected.
* **MISP galaxy.** The ``cfr-target-category`` and ``targeted-sector`` labels of the MISP entry with *exactly*
  the same name as the ATT&CK group or one of its aliases, and only when that name points to one group.
  MISP's "similar" links are not used: they join groups that ATT&CK keeps apart.

Nothing is inferred from indicators, techniques or co-occurrence.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from typing import Any, Final
from urllib.parse import urlsplit

from .industries import industries_in, industry_for_label, plain, sentences
from .threat_library_aliases import add_aliases, misp_index, misp_matches

FORMAT: Final = 'insight-threat-library-2'
ATTACK_TERMS: Final = 'https://attack.mitre.org/resources/legal-and-branding/terms-of-use/'
#: MISP ``cfr-target-category`` labels come from the CFR Cyber Operations Tracker, cited for them.
CFR_HOST: Final = 'cfr.org'
MISP_LICENCE: Final = 'CC0-1.0 or BSD-2-Clause (dual-licensed; https://github.com/MISP/misp-galaxy)'
#: Matches a person read and rejected: ``(group ID, industry) -> why``. Kept in the library as a record.
REVIEWED_EXCLUSIONS: Final[dict[tuple[str, str], str]] = {
    (
        'G0018',
        'finance',
    ): 'The sentence names organisations working on financial and trade policy, not finance firms.',
}
#: The bundled edition keeps descriptions short and leaves out analytics, procedures and most references.
BUNDLED_DESCRIPTION: Final = 700
BUNDLED_REFERENCES: Final = 6
BUNDLED_SOFTWARE_DESCRIPTION: Final = 200


def _attack_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack' and ref.get('external_id'):
            return str(ref['external_id'])
    return None


def _attack_url(obj: dict[str, Any]) -> str:
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack' and ref.get('url'):
            return str(ref['url'])
    return ''


def _current(obj: dict[str, Any]) -> bool:
    return not obj.get('revoked') and not obj.get('x_mitre_deprecated')


def _shorten(text: str, limit: int) -> str:
    """At most ``limit`` characters, cut at a sentence (or word) boundary, with an ellipsis when cut."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    end = max(cut.rfind('. '), cut.rfind('.\n'))
    if end > limit // 2:
        return cut[: end + 1]
    return cut.rsplit(' ', 1)[0] + ' …'


def _citations(text: str, references: dict[str, str]) -> list[dict[str, str]]:
    """The ``(Citation: name)`` markers in ``text`` that the object's references resolve to a URL."""
    names = dict.fromkeys(part.split(')')[0] for part in text.split('(Citation: ')[1:])
    return [{'name': name, 'url': references[name]} for name in names if name in references]


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class _Bundle:
    """Indexes over one ATT&CK bundle."""

    def __init__(self, bundle: dict[str, Any]) -> None:
        objects = bundle.get('objects')
        if bundle.get('type') != 'bundle' or not isinstance(objects, list):
            raise ValueError('Not a STIX bundle')
        self.collection = next((o for o in objects if o.get('type') == 'x-mitre-collection'), None)
        if self.collection is None:
            raise ValueError('Not an ATT&CK bundle (collection missing)')
        self.by_id: dict[str, dict[str, Any]] = {o['id']: o for o in objects if 'id' in o}
        self.uses: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.mitigates: dict[str, list[str]] = defaultdict(list)
        self.detects: dict[str, list[str]] = defaultdict(list)
        self.attributed: dict[str, list[str]] = defaultdict(list)
        for rel in objects:
            if rel.get('type') != 'relationship' or not _current(rel):
                continue
            kind, source, target = rel.get('relationship_type'), rel['source_ref'], rel['target_ref']
            if kind == 'uses':
                self.uses[source].append(rel)
            elif kind == 'mitigates':
                self.mitigates[target].append(source)
            elif kind == 'detects':
                self.detects[target].append(source)
            elif kind == 'attributed-to':
                self.attributed[target].append(source)

    def current(self, stix_type: str) -> Iterable[dict[str, Any]]:
        return (o for o in self.by_id.values() if o.get('type') == stix_type and _current(o))

    def ref(self, stix_id: str) -> dict[str, Any] | None:
        obj = self.by_id.get(stix_id)
        return obj if obj is not None and _current(obj) else None


def _citation_host(url: str) -> str:
    """Return the HTTPS publisher hostname for a usable reference, or an empty string."""
    try:
        parts = urlsplit(url)
        if parts.scheme == 'https' and parts.username is None and parts.port in (None, 443):
            return parts.hostname or ''
    except ValueError:
        pass
    return ''


def is_cfr_url(url: str) -> bool:
    """Whether an HTTPS reference belongs to the CFR publisher."""
    host = _citation_host(url)
    return host == CFR_HOST or host.endswith('.' + CFR_HOST)


def _misp_claims(group_id: str, name: str, entry: dict[str, Any]) -> list[dict[str, Any]]:
    """One claim per MISP field that names industries, with the labels it lists and what they map to."""
    meta = entry.get('meta', {}) if isinstance(entry.get('meta'), dict) else {}
    refs = [r for r in meta.get('refs', []) if isinstance(r, str) and _citation_host(r)]
    claims = []
    for field in ('cfr-target-category', 'targeted-sector'):
        labels = (
            [x for x in meta.get(field, []) if isinstance(x, str)]
            if isinstance(meta.get(field), list)
            else []
        )
        mapped = {label: key for label in labels if (key := industry_for_label(label))}
        keys = [k for k in dict.fromkeys(mapped.values()) if (group_id, k) not in REVIEWED_EXCLUSIONS]
        if not keys:
            continue
        cited = [r for r in refs if is_cfr_url(r)] if field.startswith('cfr-') else []
        claims.append(
            {
                'industries': keys,
                'source': 'misp-galaxy',
                'evidence': f'MISP galaxy entry "{entry["value"]}", {field}: {"; ".join(labels)}.',
                'match': f'"{name}" is the name of this MISP entry and a name of {group_id} in ATT&CK.',
                'citations': [{'name': 'CFR Cyber Operations Tracker', 'url': r} for r in cited[:3]]
                or [{'name': 'MISP galaxy reference', 'url': r} for r in refs[:3]],
            }
        )
    return claims


def _misp_regions(entry: dict[str, Any]) -> list[str]:
    meta = entry.get('meta', {}) if isinstance(entry.get('meta'), dict) else {}
    victims = meta.get('cfr-suspected-victims', [])
    return (
        sorted({v.strip() for v in victims if isinstance(v, str) and v.strip()})
        if isinstance(victims, list)
        else []
    )


def _detections(atk: _Bundle, technique: dict[str, Any], full: bool) -> list[dict[str, Any]]:
    components = {o['id']: _attack_id(o) for o in atk.current('x-mitre-data-component')}
    out = []
    for det_ref in atk.detects.get(technique['id'], []):
        strategy = atk.ref(det_ref)
        if strategy is None or strategy.get('type') != 'x-mitre-detection-strategy':
            continue
        analytics = [
            a for ref in strategy.get('x_mitre_analytic_refs', []) if (a := atk.ref(ref)) is not None
        ]
        sources = [s for a in analytics for s in a.get('x_mitre_log_source_references', [])]
        detection: dict[str, Any] = {
            'id': _attack_id(strategy) or '',
            'name': strategy.get('name', ''),
            'platforms': sorted({p for a in analytics for p in a.get('x_mitre_platforms', [])}),
            'components': sorted(
                {c for s in sources if (c := components.get(s.get('x_mitre_data_component_ref', '')))}
            ),
            'log_sources': sorted({s.get('name', '') for s in sources if s.get('name')}),
        }
        if full:
            detection['analytics'] = [
                {
                    'id': _attack_id(a) or '',
                    'platforms': list(a.get('x_mitre_platforms', [])),
                    'description': ' '.join(a.get('description', '').split()),
                    'log_sources': [
                        [
                            components.get(s.get('x_mitre_data_component_ref', ''), '') or '',
                            s.get('name', ''),
                            s.get('channel', ''),
                        ]
                        for s in a.get('x_mitre_log_source_references', [])
                    ],
                }
                for a in analytics
            ]
        out.append(detection)
    return sorted(out, key=lambda d: d['id'])


def _software(atk: _Bundle, groups: list[dict[str, Any]], full: bool) -> dict[str, dict[str, Any]]:
    """All current software, including items with no group; relationships are explicit ATT&CK uses only."""
    users: dict[str, set[str]] = defaultdict(set)
    for group in groups:
        for software_id in group['software']:
            users[software_id].add(group['id'])
    out: dict[str, dict[str, Any]] = {}
    for kind in ('malware', 'tool'):
        for obj in atk.current(kind):
            if (software_id := _attack_id(obj)) is None:
                continue
            techniques = {
                tid
                for rel in atk.uses.get(obj['id'], [])
                if (target := atk.ref(rel['target_ref'])) is not None
                and target.get('type') == 'attack-pattern'
                and (tid := _attack_id(target)) is not None
            }
            description = plain(obj.get('description', ''))
            out[software_id] = {
                'name': obj['name'],
                'type': kind,
                'aliases': sorted({a for a in obj.get('x_mitre_aliases', []) if a != obj['name']}),
                'description': description if full else _shorten(description, BUNDLED_SOFTWARE_DESCRIPTION),
                'platforms': sorted(set(obj.get('x_mitre_platforms', []))),
                'techniques': sorted(techniques),
                'groups': sorted(users[software_id]),
            }
    return dict(sorted(out.items()))


def build(
    bundle: dict[str, Any],
    cluster: dict[str, Any] | None,
    *,
    full: bool = False,
    attack_source: dict[str, str] | None = None,
    misp_source: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The library as a JSON-ready dict. ``full`` keeps whole descriptions, procedures and every reference."""
    atk = _Bundle(bundle)
    collection = atk.collection or {}
    groups: list[dict[str, Any]] = []
    used_techniques: set[str] = set()
    for obj in atk.current('intrusion-set'):
        group_id = _attack_id(obj)
        if group_id is None:
            continue
        references = {
            r['source_name']: r['url']
            for r in obj.get('external_references', [])
            if r.get('url') and r.get('source_name') != 'mitre-attack'
        }
        description = obj.get('description', '')
        techniques: dict[str, str] = {}
        tools: set[str] = set()
        for rel in atk.uses.get(obj['id'], []):
            target = atk.ref(rel['target_ref'])
            if target is None or (target_id := _attack_id(target)) is None:
                continue
            if target['type'] == 'attack-pattern':
                techniques.setdefault(target_id, plain(rel.get('description', '')))
            elif target['type'] in ('malware', 'tool'):
                tools.add(target_id)
        used_techniques.update(techniques)
        by_sentence: dict[str, list[str]] = {}
        for key, sentence in industries_in(description).items():
            if (group_id, key) not in REVIEWED_EXCLUSIONS:
                by_sentence.setdefault(sentence, []).append(key)
        industries = [
            {
                'industries': keys,
                'source': 'attack',
                'evidence': plain(sentence),
                'citations': _citations(sentence, references),
            }
            for sentence, keys in by_sentence.items()
        ]
        campaigns = []
        for campaign_ref in atk.attributed.get(obj['id'], []):
            campaign = atk.ref(campaign_ref)
            if campaign is not None:
                campaigns.append(
                    {
                        'id': _attack_id(campaign) or '',
                        'name': campaign.get('name', ''),
                        'first_seen': str(campaign.get('first_seen', ''))[:10],
                        'last_seen': str(campaign.get('last_seen', ''))[:10],
                    }
                )
        text = plain(description)
        cited = _citations(description, references)
        extra = [{'name': n, 'url': u} for n, u in references.items() if all(c['name'] != n for c in cited)]
        group = {
            'id': group_id,
            'name': obj['name'],
            'aliases': sorted({a for a in obj.get('aliases', []) if a != obj['name']}),
            'description': text if full else _shorten(text, BUNDLED_DESCRIPTION),
            'url': _attack_url(obj),
            'modified': str(obj.get('modified', ''))[:10],
            'techniques': sorted(techniques),
            'software': sorted(tools),
            'industries': industries,
            'regions': [],
            'campaigns': sorted(campaigns, key=lambda c: (c['last_seen'], c['id']), reverse=True),
            'references': (cited + extra) if full else cited[:BUNDLED_REFERENCES],
        }
        if full:
            group['procedures'] = {t: p for t, p in sorted(techniques.items()) if p}
        groups.append(group)
    groups.sort(key=lambda g: g['id'])
    index = misp_index(cluster)
    for group_id, (name, entry) in misp_matches(groups, index).items():
        group = next(g for g in groups if g['id'] == group_id)
        group['industries'] += _misp_claims(group_id, name, entry)
        if regions := _misp_regions(entry):
            group['regions'] = [{'source': 'misp-galaxy', 'field': 'cfr-suspected-victims', 'names': regions}]
    add_aliases(groups, index)
    software = _software(atk, groups, full)
    used_techniques.update(t for item in software.values() for t in item['techniques'])
    techniques_out: dict[str, Any] = {}
    mitigations: dict[str, str] = {}
    for obj in atk.current('attack-pattern'):
        technique_id = _attack_id(obj)
        if technique_id is None or (not full and technique_id not in used_techniques):
            continue
        mitigation_ids = []
        for ref in atk.mitigates.get(obj['id'], []):
            mitigation = atk.ref(ref)
            if mitigation is not None and (mid := _attack_id(mitigation)) and mid.startswith('M'):
                mitigations[mid] = mitigation['name']
                mitigation_ids.append(mid)
        techniques_out[technique_id] = {
            'mitigations': sorted(set(mitigation_ids)),
            'detections': _detections(atk, obj, full),
        }
    components = {cid: o['name'] for o in atk.current('x-mitre-data-component') if (cid := _attack_id(o))}
    year = str(collection.get('modified', ''))[:4] or 'unknown'
    return {
        'format': FORMAT,
        'edition': 'full' if full else 'bundled',
        'notice': (
            f'© {year} The MITRE Corporation. '
            'This work is reproduced and distributed with the permission of The MITRE Corporation.'
        ),
        'sources': {
            'attack': {
                'name': 'MITRE ATT&CK Enterprise',
                'version': str(collection.get('x_mitre_version', 'unknown')),
                'terms': ATTACK_TERMS,
                **(attack_source or {}),
            },
            'misp-galaxy': {
                'name': 'MISP galaxy threat-actor cluster',
                'version': str((cluster or {}).get('version', 'none')),
                'licence': MISP_LICENCE,
                **(misp_source or {}),
            },
        },
        'reviewed_exclusions': [
            {'group': g, 'industry': i, 'reason': reason}
            for (g, i), reason in sorted(REVIEWED_EXCLUSIONS.items())
        ],
        'data_components': dict(sorted(components.items())),
        'mitigations': dict(sorted(mitigations.items())),
        'software': software,
        'techniques': dict(sorted(techniques_out.items())),
        'groups': groups,
    }


def check_sentences(library: dict[str, Any], bundle: dict[str, Any]) -> list[str]:
    """Problems with ATT&CK evidence: each quoted sentence must be in the group's pinned description."""
    atk = _Bundle(bundle)
    descriptions = {
        _attack_id(o): {plain(s) for s in sentences(o.get('description', ''))}
        for o in atk.current('intrusion-set')
    }
    return [
        f'{group["id"]} {claim["industries"]}: evidence not in the ATT&CK description'
        for group in library['groups']
        for claim in group['industries']
        if claim['source'] == 'attack' and claim['evidence'] not in descriptions.get(group['id'], set())
    ]

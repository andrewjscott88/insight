"""Sourced group aliases from pinned catalogs, never analyst attribution (ADR 0038).

Only an entry's primary name can establish a MISP match. Imported synonyms never seed another match,
and a new synonym claimed by more than one group is omitted. ATT&CK's own names remain unchanged.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def misp_index(cluster: dict[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    """MISP entries by their case-folded primary name; duplicate entries remain ambiguous."""
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for value in (cluster or {}).get('values', []):
        if isinstance(value, dict) and isinstance(value.get('value'), str) and value['value'].strip():
            index[value['value'].strip().casefold()].append(value)
    return index


def _claims(groups: list[dict[str, Any]]) -> dict[str, set[str]]:
    claims: dict[str, set[str]] = defaultdict(set)
    for group in groups:
        for name in [group['name'], *group['aliases']]:
            claims[name.strip().casefold()].add(group['id'])
    return claims


def _matches(
    groups: list[dict[str, Any]], index: dict[str, list[dict[str, Any]]]
) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    claims = _claims(groups)
    matches: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for group in groups:
        seen: set[str] = set()
        for name in [group['name'], *group['aliases']]:
            key = name.strip().casefold()
            entries = index.get(key, [])
            if len(claims[key]) == 1 and len(entries) == 1 and key not in seen:
                matches[group['id']].append((name, entries[0]))
                seen.add(key)
    return matches


def misp_matches(
    groups: list[dict[str, Any]], index: dict[str, list[dict[str, Any]]]
) -> dict[str, tuple[str, dict[str, Any]]]:
    """Keep the existing industry rule: the first unique primary-name/ATT&CK-alias match per group."""
    return {gid: entries[0] for gid, entries in _matches(groups, index).items()}


def add_aliases(groups: list[dict[str, Any]], index: dict[str, list[dict[str, Any]]]) -> None:
    """Add unambiguous MISP synonyms and provenance, using only the original ATT&CK names to match."""
    claims = _claims(groups)
    candidates: dict[str, list[tuple[str, dict[str, str]]]] = defaultdict(list)
    for gid, matches in _matches(groups, index).items():
        for matched, entry in matches:
            meta = entry.get('meta')
            synonyms = meta.get('synonyms', []) if isinstance(meta, dict) else []
            if not isinstance(synonyms, list):
                continue
            for synonym in synonyms:
                if not isinstance(synonym, str) or not (name := synonym.strip()):
                    continue
                source = {'source': 'misp-galaxy', 'entry': entry['value'], 'matched_name': matched}
                if isinstance(entry.get('uuid'), str):
                    source['entry_id'] = entry['uuid']
                candidates[gid].append((name, source))
                claims[name.casefold()].add(gid)
    # Apply only after every candidate has been checked against every group's original and proposed names.
    for group in groups:
        names = {name.casefold(): name for name in group['aliases']}
        sources = {name: [{'source': 'attack'}] for name in group['aliases']}
        for name, source in candidates[group['id']]:
            key = name.casefold()
            if key == group['name'].casefold() or len(claims[key]) != 1:
                continue
            alias = names.setdefault(key, name)
            evidence = sources.setdefault(alias, [])
            if source not in evidence:
                evidence.append(source)
        group['aliases'] = sorted(sources)
        # Many synonyms share one MISP entry. Keep its evidence once, with explicit per-alias references.
        references: list[dict[str, str]] = []
        by_alias: dict[str, list[int]] = {}
        for name in group['aliases']:
            by_alias[name] = []
            for source in sources[name]:
                if source not in references:
                    references.append(source)
                by_alias[name].append(references.index(source))
        group['alias_sources'] = by_alias
        group['alias_references'] = references

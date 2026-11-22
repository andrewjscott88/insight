"""Pinned IANA bootstrap routing and a contact-free RDAP projection (ADR 0037)."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from functools import lru_cache
from importlib.resources import files
from typing import Any
from urllib.parse import urlsplit

from . import pivot_data


@lru_cache(maxsize=3)
def _bootstrap(kind: str) -> dict[str, Any]:
    root = files('insight').joinpath('data')
    manifest = json.loads(root.joinpath('rdap-bootstrap-pins.json').read_bytes())
    raw = root.joinpath(f'rdap-{kind}.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest[kind]['sha256']:
        raise ValueError('RDAP bootstrap integrity check failed')
    return pivot_data.object_data(raw)


def _https(url: str) -> bool:
    parts = urlsplit(url)
    return bool(
        parts.scheme == 'https'
        and parts.hostname
        and not parts.username
        and not parts.password
        and parts.port in (None, 443)
        and not parts.query
        and not parts.fragment
    )


def destination(value: str) -> tuple[str, frozenset[str]]:
    """Select the longest bootstrap match; never guess an HTTPS endpoint for an HTTP-only registry."""
    kind, _ = pivot_data.subject(value)
    address = ipaddress.ip_address(value) if kind == 'ip' else None
    bootstrap = _bootstrap(f'ipv{address.version}' if address else 'dns')
    matches: list[tuple[int, str]] = []
    hosts: set[str] = set()
    for keys, urls in bootstrap['services']:
        secure = [u for u in urls if isinstance(u, str) and _https(u)]
        hosts.update(urlsplit(u).hostname or '' for u in secure)
        for key in keys:
            if address is not None:
                network = ipaddress.ip_network(key)
                if address in network:
                    matches.extend((network.prefixlen, u) for u in secure)
            elif value == key or value.endswith('.' + key):
                matches.extend((len(key), u) for u in secure)
    if not matches:
        raise ValueError('No pinned HTTPS RDAP service covers this value')
    # Stable first choice among equally specific services. No automatic referral or fallback disclosure.
    base = sorted(matches, key=lambda item: (-item[0], item[1]))[0][1]
    return base.rstrip('/') + ('/ip/' if address else '/domain/') + value, frozenset(hosts)


def parse(raw: bytes, value: str) -> dict[str, Any]:
    """Whitelist registration metadata, never retain entities, vCards, links, remarks or notices."""
    data = pivot_data.object_data(raw)
    kind, _ = pivot_data.subject(value)
    result: dict[str, Any] = {'found': True, 'nodes': []}
    if kind == 'domain':
        if data.get('objectClassName') != 'domain' or pivot_data.name(data.get('ldhName')) != value:
            raise ValueError('RDAP answered for another domain')
        nameservers = data.get('nameservers', [])
        if not isinstance(nameservers, list) or len(nameservers) > pivot_data.MAX_ROWS:
            raise ValueError('Invalid name servers')
        names = sorted({pivot_data.name(row['ldhName']) for row in nameservers})
        result['name_servers'] = names
        result['nodes'] = [{'type': 'name_server', 'value': n} for n in names]
        # Registrar's public IANA identifier is sufficient; do not retain ANY entity contact details.
        registrars: set[str] = set()
        for entity in data.get('entities', []):
            if 'registrar' not in entity.get('roles', []):
                continue
            for identifier in entity.get('publicIds', []):
                if identifier.get('type') == 'IANA Registrar ID':
                    number = pivot_data.text(identifier.get('identifier'), 10)
                    if number.isascii() and number.isdecimal():
                        registrars.add(number)
        result['registrar_ids'] = sorted(registrars)[:20]
    else:
        address = ipaddress.ip_address(value)
        first, last = (ipaddress.ip_address(data[key]) for key in ('startAddress', 'endAddress'))
        if (
            data.get('objectClassName') != 'ip network'
            or not first.version == address.version == last.version
            or not int(first) <= int(address) <= int(last)
        ):
            raise ValueError('RDAP answered for another network')
        result.update(
            network_name=pivot_data.text(data.get('name', '')),
            handle=pivot_data.text(data.get('handle', '')),
            start_address=str(first),
            end_address=str(last),
            country=pivot_data.text(data.get('country', ''), 2),
        )
    statuses = data.get('status', [])
    if not isinstance(statuses, list) or len(statuses) > 50:
        raise ValueError('Invalid status')
    result['status'] = [pivot_data.text(s, 80) for s in statuses]
    dates: dict[str, str] = {}
    actions = {'registration': 'created', 'last changed': 'changed', 'expiration': 'expires'}
    events = data.get('events', [])
    if not isinstance(events, list) or len(events) > 100:
        raise ValueError('Invalid events')
    for event in events:
        if event.get('eventAction') in actions:
            dates[actions[event['eventAction']]] = pivot_data.date(event['eventDate'])
    result['dates'] = dates
    return result

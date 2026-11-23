"""Outbound connections to the addresses Insight checked (code review L1, TIP 0.4).

Insight resolves a host name once, checks every address, then connects to a checked address. The host name
is kept for TLS (SNI and the certificate check, through httpcore's ``sni_hostname`` extension) and in the
``Host`` header, so the server sees an ordinary request. Before, the check and the connection looked the
name up separately, and a DNS answer that changed in between (DNS rebinding) could reach loopback, a private
network or a cloud metadata address. An egress firewall rule remains the backstop (docs/SECURITY.md).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


# Some clouds also serve instance or container metadata outside IPv4/IPv6 link-local space.
_METADATA = frozenset(
    ipaddress.ip_address(value)
    for value in (
        '100.100.100.200',
        '168.63.129.16',
        'fd00:ec2::254',
        'fd20:ce::254',
    )
)


def effective(address: IPAddress) -> IPAddress:
    """The IPv4 address an IPv4-mapped IPv6 address (``::ffff:127.0.0.1``) reaches, else ``address``.

    Checked explicitly instead of relying on how each Python patch level classifies mapped addresses.
    """
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def never_allowed(address: IPAddress) -> bool:
    """Never reachable: link-local (cloud metadata), multicast, unspecified and reserved addresses."""
    real = effective(address)
    return (
        real in _METADATA
        or real.is_link_local
        or real.is_multicast
        or real.is_unspecified
        or real.is_reserved
    )


def is_public(address: IPAddress) -> bool:
    real = effective(address)
    return real.is_global and not never_allowed(address)


def is_private_network(address: IPAddress) -> bool:
    """A private-network address an operator may opt in to (a MISP instance on the LAN): not public, and not
    loopback or one of the :func:`never_allowed` addresses."""
    real = effective(address)
    return not real.is_global and not real.is_loopback and not never_allowed(address)


async def resolve(hostname: str, port: int) -> list[IPAddress]:
    """Every address ``hostname`` resolves to, IPv4 first (containers often have no IPv6 route)."""
    infos = await asyncio.to_thread(socket.getaddrinfo, hostname, port, 0, socket.SOCK_STREAM)
    found = dict.fromkeys(ipaddress.ip_address(str(info[4][0]).split('%', 1)[0]) for info in infos)
    return sorted(found, key=lambda a: a.version)


@dataclass(frozen=True, slots=True)
class Pinned:
    """A request for ``url`` sent to one checked address."""

    url: str
    headers: dict[str, str] = field(default_factory=dict)
    extensions: dict[str, str] = field(default_factory=dict)


def pin(url: str, address: IPAddress) -> Pinned:
    """``url`` with ``address`` in place of its host, plus the ``Host`` header and SNI name it needs."""
    parts = urlsplit(url)
    host = (parts.hostname or '').lower()
    port = parts.port
    literal = f'[{address}]' if address.version == 6 else str(address)
    netloc = literal + (f':{port}' if port else '')
    default = {'https': 443, 'http': 80}.get(parts.scheme)
    host_header = host + (f':{port}' if port and port != default else '')
    return Pinned(
        url=urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment)),
        headers={'Host': host_header},
        extensions={'sni_hostname': host},
    )

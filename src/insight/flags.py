"""Warning flags: values that must never reach a blocklist. Computed from the value alone, never stored.

A report mentions a victim's internal address, a documentation example or a vendor's own domain as often as an
attacker's server. Accepting the mention ("copied correctly") is right; blocking it would break things. Flags
say why a value is unsafe to block, so the blocklist leaves it out whatever its verdict (review finding C1).

* ``non-routable``: private, loopback, link-local, shared (CGNAT), multicast, reserved or unspecified
  addresses, which a firewall at the internet edge never sees as a remote peer.
* ``documentation``: the RFC 5737, RFC 3849 and RFC 9637 example ranges.
* ``reserved-name``: special-use and internal names (``.test``, ``.local``, ``example.com``).
* ``common-benign``: a short list of vendor domains that reports cite constantly; blocking them would cut off
  updates or e-mail. User-content platforms (``github.io``, cloud storage) are deliberately not on it.

Pure functions, no SQL, no network.
"""

from __future__ import annotations

import ipaddress
from typing import Final, Literal, get_args
from urllib.parse import urlsplit

from .extraction import SPECIAL_USE_TLDS

Flag = Literal['non-routable', 'documentation', 'reserved-name', 'common-benign']
FLAGS: Final[tuple[Flag, ...]] = get_args(Flag)

DOCUMENTATION_NETWORKS: Final = tuple(
    ipaddress.ip_network(network)
    for network in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32', '3fff::/20')
)
SHARED_ADDRESS_SPACE: Final = ipaddress.ip_network('100.64.0.0/10')  # RFC 6598 carrier-grade NAT
#: Whole blocks with a single special use. A larger range may contain public hosts too.
NON_ROUTABLE_NETWORKS: Final = tuple(
    ipaddress.ip_network(value)
    for value in (
        str(SHARED_ADDRESS_SPACE),
        '0.0.0.0/8',
        '10.0.0.0/8',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '224.0.0.0/4',
        '240.0.0.0/4',
        'fc00::/7',
        'fe80::/10',
        'ff00::/8',
    )
)

#: Tor onion names stay unflagged: a ransomware leak site's address is a useful indicator, and a DNS
#: blocklist entry for it is harmless.
RESERVED_TLDS: Final = SPECIAL_USE_TLDS - {'onion'}
RESERVED_DOMAINS: Final = frozenset({'example.com', 'example.net', 'example.org', 'home.arpa'})

#: Vendor-controlled domains that advisories cite as context (update servers, documentation, sign-in).
#: Keep it short; anything not here is judged by its verdict.
COMMON_BENIGN: Final = frozenset(
    {
        'microsoft.com',
        'windows.com',
        'windowsupdate.com',
        'office.com',
        'microsoftonline.com',
        'live.com',
        'google.com',
        'apple.com',
        'cloudflare.com',
        'mozilla.org',
        'cisa.gov',
        'nist.gov',
        'mitre.org',
        'first.org',
        'virustotal.com',
    }
)


def _within(name: str, domains: frozenset[str]) -> bool:
    return any(name == domain or name.endswith('.' + domain) for domain in domains)


def ip_flags(value: str) -> frozenset[Flag]:
    try:
        address = ipaddress.ip_address(value.strip('[]'))
    except ValueError:
        return frozenset()
    if any(address in network for network in DOCUMENTATION_NETWORKS if network.version == address.version):
        return frozenset({'documentation'})
    unroutable = (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
        or (isinstance(address, ipaddress.IPv4Address) and address in SHARED_ADDRESS_SPACE)
    )
    return frozenset({'non-routable'}) if unroutable else frozenset()


def domain_flags(value: str, *, include_benign: bool = True) -> frozenset[Flag]:
    name = value.strip().rstrip('.').lower()
    if not name:
        return frozenset()
    found: set[Flag] = set()
    if name.rsplit('.', 1)[-1] in RESERVED_TLDS or _within(name, RESERVED_DOMAINS):
        found.add('reserved-name')
    if include_benign and _within(name, COMMON_BENIGN):
        found.add('common-benign')
    return frozenset(found)


def cidr_flags(value: str) -> frozenset[Flag]:
    try:
        network = ipaddress.ip_network(value)
    except ValueError:
        return frozenset()
    if network.num_addresses == 1:
        return ip_flags(str(network.network_address))
    first, last = network.network_address, network.broadcast_address
    if any(first in block and last in block for block in DOCUMENTATION_NETWORKS):
        return frozenset({'documentation'})
    if any(first in block and last in block for block in NON_ROUTABLE_NETWORKS):
        return frozenset({'non-routable'})
    return frozenset()


def url_flags(value: str) -> frozenset[Flag]:
    """A URL is judged by its host. A vendor domain alone does not flag it: blocking one path is precise."""
    try:
        host = urlsplit(value).hostname or ''
    except ValueError:
        return frozenset()
    flagged = ip_flags(host)
    return flagged if flagged else domain_flags(host, include_benign=False)


def flags(kind: str, value: str) -> tuple[Flag, ...]:
    """The warning flags for one indicator, in ``FLAGS`` order (stable for exports). Hashes and CVEs: none."""
    if kind == 'ip':
        found = ip_flags(value)
    elif kind == 'cidr':
        found = cidr_flags(value)
    elif kind == 'domain':
        found = domain_flags(value)
    elif kind == 'url':
        found = url_flags(value)
    else:
        found = frozenset()
    return tuple(flag for flag in FLAGS if flag in found)

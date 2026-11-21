"""Warning flags (review Design 1): values that must never reach a blocklist."""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from insight.flags import DOCUMENTATION_NETWORKS, FLAGS, flags

NON_ROUTABLE_NETWORKS = [
    ipaddress.ip_network(network)
    for network in (
        '0.0.0.0/8',  # "this network"
        '10.0.0.0/8',
        '100.64.0.0/10',  # shared address space (CGNAT)
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '198.18.0.0/15',  # benchmarking
        '224.0.0.0/4',  # multicast
        '240.0.0.0/4',  # reserved
        '::1/128',
        'fc00::/7',  # unique local
        'fe80::/10',
        'ff00::/8',
    )
]


def addresses_in(networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> st.SearchStrategy[str]:
    return st.sampled_from(networks).flatmap(
        lambda network: st.integers(0, network.num_addresses - 1).map(lambda i: str(network[i]))
    )


@given(addresses_in(list(DOCUMENTATION_NETWORKS)))
def test_every_documentation_address_is_flagged_as_documentation(address: str) -> None:
    assert flags('ip', address) == ('documentation',)


@given(addresses_in(NON_ROUTABLE_NETWORKS))
def test_every_special_purpose_address_is_flagged_non_routable(address: str) -> None:
    assert flags('ip', address) == ('non-routable',)


@pytest.mark.parametrize('address', ['93.184.216.34', '8.8.8.8', '45.33.32.156', '2606:4700::1111'])
def test_public_addresses_carry_no_flag(address: str) -> None:
    assert flags('ip', address) == ()


@pytest.mark.parametrize(
    ('value', 'expected'),
    [
        ('203.0.113.0/25', ('documentation',)),
        ('2001:db8::/32', ('documentation',)),
        ('10.1.0.0/16', ('non-routable',)),
        ('fd12:3456::/32', ('non-routable',)),
        ('100.64.0.0/12', ('non-routable',)),
        ('::1/128', ('non-routable',)),
        ('8.8.8.0/24', ()),
        ('203.0.112.0/23', ()),  # only half is reserved for examples
        ('0.0.0.0/0', ()),
        ('invalid', ()),
    ],
)
def test_range_warnings_apply_to_the_whole_range(value: str, expected: tuple[str, ...]) -> None:
    assert flags('cidr', value) == expected


@pytest.mark.parametrize(
    ('value', 'expected'),
    [
        ('printer.corp', ('reserved-name',)),
        ('dc01.internal', ('reserved-name',)),
        ('www.example.com', ('reserved-name',)),
        ('example.org', ('reserved-name',)),
        ('router.home.arpa', ('reserved-name',)),
        ('login.microsoftonline.com', ('common-benign',)),
        ('microsoft.com', ('common-benign',)),
        ('cisa.gov', ('common-benign',)),
        # A look-alike is not the vendor: matching is per label, not a string suffix.
        ('evil-microsoft.com', ()),
        ('microsoft.com.evil.net', ()),
        # Onion services and user-content platforms are judged by their verdict, not flagged.
        ('leaksite3kq7vxm2.onion', ()),
        ('attacker.github.io', ()),
        ('evil-updates.net', ()),
    ],
)
def test_domain_flags(value: str, expected: tuple[str, ...]) -> None:
    assert flags('domain', value) == expected


@pytest.mark.parametrize(
    ('value', 'expected'),
    [
        ('http://10.0.0.5/payload', ('non-routable',)),
        ('https://[2001:db8::1]/x', ('documentation',)),
        ('http://intranet.corp/login', ('reserved-name',)),
        # Blocking one path on a vendor's host is precise, so the vendor list does not flag URLs.
        ('https://github.com/attacker/tool/releases/x.zip', ()),
        ('https://update.microsoft.com/fake', ()),
        ('https://evil-updates.net/a', ()),
    ],
)
def test_urls_are_judged_by_their_host(value: str, expected: tuple[str, ...]) -> None:
    assert flags('url', value) == expected


@pytest.mark.parametrize('kind', ['md5', 'sha1', 'sha256', 'sha512', 'cve'])
def test_hashes_and_cves_carry_no_flags(kind: str) -> None:
    assert flags(kind, '10.0.0.1') == ()


def test_flags_come_in_a_fixed_order() -> None:
    assert FLAGS == ('non-routable', 'documentation', 'reserved-name', 'common-benign', 'personal-data')
    assert flags('domain', 'mail.corp') == ('reserved-name',)


@pytest.mark.parametrize('value', ['someone@example.org', 'incoming+reports@security.example'])
def test_every_email_address_is_marked_as_personal_data(value: str) -> None:
    assert flags('email', value) == ('personal-data',)

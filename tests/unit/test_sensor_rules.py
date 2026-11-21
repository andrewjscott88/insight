"""Sensor rule output uses exact matches and only canonical, reviewed values."""

from __future__ import annotations

import re

import pytest

from insight.sensor_rules import sensor_rules


def test_engine_specific_exact_dns_rules() -> None:
    # Reserved synthetic domain used directly at the formatter boundary, without network access.
    name = 'mail.example.org'
    suricata = sensor_rules('suricata', 'domain', [name])
    assert 'alert dns any any -> any any' in suricata
    assert 'dns.query; content:"mail.example.org"; nocase; bsize:16;' in suricata
    snort = sensor_rules('snort', 'domain', [name])
    assert 'alert udp any any -> any 53' in snort
    assert 'byte_test:1,<,8,2; byte_test:2,>,0,4;' in snort
    assert (
        'content:"|04 6d 61 69 6c 07 65 78 61 6d 70 6c 65 03 6f 72 67 00|",nocase,offset 12,depth 18;'
        in snort
    )


def test_ip_rules_have_repeatable_sids_cover_both_directions_and_deduplicate() -> None:
    addresses = ['2001:db8::a', '192.0.2.1', '2001:db8::a']
    first = sensor_rules('snort', 'ip', addresses)
    assert first == sensor_rules('snort', 'ip', reversed(addresses))
    assert 'alert ip any any <> 2001:db8::a any' in first
    assert 'alert ip any any <> 192.0.2.1 any' in first
    sids = re.findall(r'sid:(\d+);', first)
    assert len(set(sids)) == len(sids) == 2
    assert sids[1] in sensor_rules('snort', 'ip', [addresses[0]])


@pytest.mark.parametrize(
    ('kind', 'values'),
    [
        ('domain', []),
        ('url', ['https://example.org']),
        ('domain', ['example.org";']),
        ('ip', ['any']),
        ('ip', ['2001:db8::1%untrusted-interface']),
        ('domain', [('a' * 63 + '.') * 4 + 'org']),
    ],
)
def test_empty_unsupported_or_unsafe_rule_input_is_refused(kind: str, values: list[str]) -> None:
    with pytest.raises(
        ValueError, match=r'No eligible indicators|only kind=ip or kind=domain|represented safely'
    ):
        sensor_rules('suricata', kind, values)

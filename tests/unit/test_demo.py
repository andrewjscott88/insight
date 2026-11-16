"""The synthetic demo must be idempotent and must never reference live infrastructure."""

from __future__ import annotations

import ipaddress

from sqlalchemy.orm import Session

from insight.demo import REPORTS, seed
from insight.extraction import extract

DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32')
]


def test_seed_is_idempotent(db: Session) -> None:
    assert seed(db) == len(REPORTS)
    assert seed(db) == 0


def test_every_report_is_labelled_synthetic() -> None:
    for _title, _source, body, _tlp in REPORTS:
        assert 'synthetic training data' in body


def test_demo_uses_reserved_documentation_namespaces_only() -> None:
    for _title, _source, body, _tlp in REPORTS:
        for mention in extract(body):
            if mention.kind == 'ip':
                address = ipaddress.ip_address(mention.value)
                assert any(address in net for net in DOCUMENTATION_NETWORKS), mention.value
            elif mention.kind in {'domain', 'url'}:
                assert 'example.' in mention.value, mention.value

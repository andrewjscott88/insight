"""Metadata-only abuse.ch response fixtures. All network indicators use documentation addresses."""

from __future__ import annotations

import json

import pytest

from insight.abusech import parse_abusech
from insight.extraction import extract
from insight.feed_items import MAX_FEED_ITEMS, FeedItem
from insight.source_registry import Source


def source(key: str) -> Source:
    return Source(key, key, 'https://publisher.example/', 'rss', 'Fixture')


def parse(key: str, *rows: object) -> list[FeedItem]:
    field = 'urls' if key == 'urlhaus' else 'data'
    payload = json.dumps({'query_status': 'ok', field: rows}).encode()
    return parse_abusech(payload, source(key))


def test_urlhaus_keeps_defanged_evidence_and_fixed_publisher_link() -> None:
    row = {
        'id': '72',
        'url': 'https://demo.example/one.exe',
        'urlhaus_reference': 'https://other.example/',
        'date_added': '2026-10-17 15:01:09 UTC',
        'url_status': 'offline',
        'reporter': 'nobody@example.org',
        'tags': ['https://other.example/untrusted'],
    }
    (item,) = parse('urlhaus', row)
    doc = item.document
    assert (item.external_id, doc.source_url, doc.tlp) == ('72', 'https://urlhaus.abuse.ch/url/72/', 'CLEAR')
    assert doc.body.splitlines() == [
        'Reported URL: hxxps://demo[.]example/one[.]exe',
        'First seen (UTC): 2026-10-17 15:01:09',
        'Status reported by URLhaus: offline',
    ]
    assert {(o.kind, o.value) for o in extract(doc.body)} == {
        ('url', 'https://demo.example/one.exe'),
        ('domain', 'demo.example'),
    }
    assert 'demo' not in doc.title


@pytest.mark.parametrize(
    ('kind', 'raw', 'expected'),
    [
        ('ip:port', '192.0.2.3:443', ('ip', '192.0.2.3')),
        ('ip:port', '[2001:DB8::8]:443', ('ip', '2001:db8::8')),
        ('domain', 'Demo.EXAMPLE', ('domain', 'demo.example')),
        ('url', 'https://demo.example/a', ('url', 'https://demo.example/a')),
        ('sha256_hash', 'a1' * 32, ('sha256', 'a1' * 32)),
    ],
)
def test_threatfox_parses_typed_indicators(kind: str, raw: str, expected: tuple[str, str]) -> None:
    (item,) = parse(
        'threatfox',
        {
            'id': 9,
            'ioc': raw,
            'ioc_type': kind,
            'confidence_level': 80,
            'reference': 'https://other.example/',
        },
    )
    assert (item.external_id, item.document.source_url) == ('9', 'https://threatfox.abuse.ch/ioc/9/')
    assert expected in {(o.kind, o.value) for o in extract(item.document.body)}
    assert 'Confidence reported by ThreatFox: 80%' in item.document.body
    assert 'other.example' not in item.document.body
    if kind == 'ip:port':
        assert 'Port: 443' in item.document.body


def test_an_unknown_threatfox_indicator_does_not_hide_later_supported_rows() -> None:
    (row,) = parse(
        'threatfox', {'ioc_type': 'other'}, {'id': 7, 'ioc_type': 'domain', 'ioc': 'relay.example'}
    )
    assert row.external_id == '7'


def test_malwarebazaar_uses_hash_identity_and_allowlisted_metadata() -> None:
    sha256, sha1, md5 = 'cd' * 32, 'ab' * 20, 'ef' * 16
    row = {
        'sha256_hash': sha256.upper(),
        'sha1_hash': sha1,
        'md5_hash': md5,
        'first_seen': '2026-10-17 14:01:02',
        'file_name': 'trap.example.exe',
        'download_url': 'https://untrusted.example/',
        'signature': 'CVE-2024-12345',
    }
    (item,) = parse('malwarebazaar', row)
    assert item.external_id == sha256
    assert item.document.source_url == f'https://bazaar.abuse.ch/sample/{sha256}/'
    assert {(o.kind, o.value) for o in extract(item.document.body)} == {
        ('sha256', sha256),
        ('sha1', sha1),
        ('md5', md5),
    }
    assert 'First seen (UTC): 2026-10-17 14:01:02' in item.document.body
    assert sha256 not in item.document.title


@pytest.mark.parametrize('key', ['urlhaus', 'threatfox', 'malwarebazaar'])
def test_empty_and_invalid_replies(key: str) -> None:
    assert parse(key) == []
    assert parse_abusech(b'{"query_status":"no_results"}', source(key)) == []
    for bad in (b'not json', b'[]', b'{"query_status":"secret-token"}', b'{"query_status":"ok"}'):
        with pytest.raises(ValueError, match=f'^{key} (?:returned invalid|did not return)') as error:
            parse_abusech(bad, source(key))
        assert 'secret-token' not in str(error.value)


@pytest.mark.parametrize(
    ('key', 'row'),
    [
        ('urlhaus', {'id': '../2', 'url': 'https://demo.example/'}),
        ('urlhaus', {'id': 2, 'url': 'https://demo.example/' + 'a' * 2000}),
        ('urlhaus', {'id': 2, 'url': 'file:///tmp/a'}),
        ('urlhaus', {'id': 2, 'url': 'https://demo.example/a\x00b'}),
        ('threatfox', {'id': 4, 'ioc_type': 'ip:port', 'ioc': '192.0.2.1:65536'}),
        ('threatfox', {'id': 4, 'ioc_type': 'ip:port', 'ioc': '192.0.2.1'}),
        ('threatfox', {'id': 4, 'ioc_type': 'domain', 'ioc': 'demo.example\nsurprise'}),
        ('malwarebazaar', {'sha256_hash': 'abc'}),
        ('malwarebazaar', None),
    ],
)
def test_invalid_metadata_has_a_fixed_error(key: str, row: object) -> None:
    with pytest.raises(ValueError, match=f'^{key} returned an invalid metadata record$'):
        parse(key, row)


def test_row_count_is_bounded() -> None:
    rows = [{'id': n, 'url': 'https://demo.example/file'} for n in range(MAX_FEED_ITEMS + 1)]
    assert [r.external_id for r in parse('urlhaus', *rows)] == [str(n) for n in range(MAX_FEED_ITEMS)]

"""RSS/Atom parsing: bounds, sanitisation, link safety and XML attack resistance."""

from __future__ import annotations

from xml.etree.ElementTree import ParseError

import pytest
from defusedxml.common import DefusedXmlException

from insight.connectors import MAX_BYTES, MAX_FEED_ITEMS, MAX_FEED_SUMMARY, SOURCES, parse_feed, text_only

SOURCE = SOURCES['sans-isc']


def rss(*items: str) -> bytes:
    return ('<rss><channel>' + ''.join(items) + '</channel></rss>').encode()


def test_rss_item_fields() -> None:
    (item,) = parse_feed(
        rss(
            '<item><title>Headline</title><link>https://isc.example/1</link>'
            '<description>Body text</description></item>'
        ),
        SOURCE,
    )
    doc = item.document
    assert item.external_id == 'https://isc.example/1'
    assert (doc.title, doc.source_url, doc.source_name, doc.tlp) == (
        'Headline',
        'https://isc.example/1',
        SOURCE.name,
        'CLEAR',
    )
    assert doc.body == 'Headline\n\nBody text'


def test_item_count_and_summary_are_bounded_and_html_is_stripped() -> None:
    item = '<item><title>H</title><description>&lt;b&gt;' + 'x' * 700 + '&lt;/b&gt;</description></item>'
    docs = [i.document for i in parse_feed(rss(*[item] * (MAX_FEED_ITEMS + 5)), SOURCE)]
    assert len(docs) == MAX_FEED_ITEMS
    assert '<b>' not in docs[0].body
    assert len(docs[0].body.split('\n\n')[1]) == MAX_FEED_SUMMARY


@pytest.mark.parametrize(
    'link', ['javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd', 'https://u:p@example.com/']
)
def test_dangerous_links_are_dropped_but_item_is_kept(link: str) -> None:
    (item,) = parse_feed(rss(f'<item><title>T</title><link>{link}</link><guid>g-1</guid></item>'), SOURCE)
    assert item.document.source_url == ''
    assert item.document.title == 'T'
    assert item.external_id == 'g-1'  # a rejected link is never used as the identity either


def test_untitled_item_gets_placeholder() -> None:
    (item,) = parse_feed(rss('<item><title>   </title></item>'), SOURCE)
    assert item.document.title == 'Untitled feed item'
    assert item.external_id is None


def test_long_title_is_truncated() -> None:
    (item,) = parse_feed(rss(f'<item><title>{"t" * 400}</title></item>'), SOURCE)
    assert len(item.document.title) == 300


def test_atom_entries_and_alternate_links() -> None:
    payload = b"""<feed xmlns="http://www.w3.org/2005/Atom">
      <entry><title>Atom title</title>
        <link rel="self" href="https://example.com/self"/>
        <link href="https://example.com/a"/>
        <summary>Summary</summary></entry>
      <entry><title>No link</title></entry>
    </feed>"""
    first_item, second_item = parse_feed(payload, SOURCE)
    first, second = first_item.document, second_item.document
    assert (first.title, first.source_url, first.body) == (
        'Atom title',
        'https://example.com/a',
        'Atom title\n\nSummary',
    )
    assert second.source_url == ''


@pytest.mark.parametrize(
    ('item', 'expected'),
    [
        # The link wins so documents imported by 0.1.0 (which stored only the link) keep matching.
        (
            '<item><title>T</title><link>https://a.example/1</link><guid>g-1</guid></item>',
            'https://a.example/1',
        ),
        ('<item><title>T</title><guid isPermaLink="false">g-1</guid></item>', 'g-1'),
        ('<item><title>T</title><guid>  spaced  </guid></item>', 'spaced'),
        ('<item><title>T</title></item>', None),
        (f'<item><title>T</title><guid>{"g" * 600}</guid></item>', 'g' * 500),
    ],
)
def test_external_identity(item: str, expected: str | None) -> None:
    (parsed,) = parse_feed(rss(item), SOURCE)
    assert parsed.external_id == expected


def test_atom_id_is_used_when_there_is_no_link() -> None:
    payload = b"""<feed xmlns="http://www.w3.org/2005/Atom">
      <entry><title>T</title><id>urn:uuid:1225c695</id></entry></feed>"""
    (item,) = parse_feed(payload, SOURCE)
    assert item.external_id == 'urn:uuid:1225c695'


def test_feed_without_items_yields_nothing() -> None:
    assert parse_feed(b'<rss><channel><title>Empty</title></channel></rss>', SOURCE) == []


def test_oversized_payload_rejected_before_parsing() -> None:
    with pytest.raises(ValueError, match='size'):
        parse_feed(b'x' * (MAX_BYTES + 1), SOURCE)


@pytest.mark.parametrize(
    'payload',
    [
        # External entity (XXE) - would read local files.
        b'<!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><rss><item><title>&xxe;</title></item></rss>',
        # Entity expansion ("billion laughs").
        b'<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
        b'<rss><item><title>&b;</title></item></rss>',
    ],
)
def test_xml_attacks_are_rejected(payload: bytes) -> None:
    with pytest.raises(DefusedXmlException):
        parse_feed(payload, SOURCE)


def test_malformed_xml_raises() -> None:
    with pytest.raises(ParseError):
        parse_feed(b'<rss><item>', SOURCE)


@pytest.mark.parametrize(
    ('raw', 'expected'),
    [
        (None, ''),
        ('', ''),
        ('<p>Hello &amp; <b>bye</b></p>', 'Hello &  bye'),
        ('  plain  ', 'plain'),
        ('a &lt; b', 'a < b'),
    ],
)
def test_text_only(raw: str | None, expected: str) -> None:
    assert text_only(raw) == expected


def test_payload_exactly_at_the_size_limit_is_parsed() -> None:
    document = rss('<item><title>T</title></item>')
    padded = document.replace(b'<rss>', b'<rss>' + b' ' * (MAX_BYTES - len(document)), 1)
    assert len(padded) == MAX_BYTES
    assert len(parse_feed(padded, SOURCE)) == 1

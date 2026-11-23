"""The PDF writer and the product PDF (TIP 4.4, ADR 0036): a well-formed file, the TLP label on every page,
text that fits, tags for screen readers, and defanged indicators."""

from __future__ import annotations

import io
import random
import re
import zlib
from typing import Any

import pytest

from insight.pdf_writer import BOLD, REGULAR, TLP_COLOURS, WIDTH, printable, width_of, wrap
from insight.product_pdf import to_pdf


def sample(**fields: Any) -> dict[str, Any]:
    product: dict[str, Any] = {
        'format': 'insight-product-1',
        'id': 'p1',
        'title': 'Edge appliance exploitation',
        'product_type': 'assessment',
        'audience': 'Security leaders',
        'tlp': 'AMBER',
        'version': 1,
        'published_at': '2026-11-22T12:00:00+00:00',
        'generated_at': '2026-11-22T12:30:00+00:00',
        'author': 'session',
        'bluf': 'Expect more edge appliance exploitation.\n\nPatch the VPN first.',
        'judgements': [
            {
                'statement': 'The crew will keep exploiting edge appliances.',
                'likelihood': 'likely',
                'confidence': 'moderate',
                'sources': [1, 2],
            }
        ],
        'analysis': 'First paragraph.\n\nSecond paragraph.',
        'gaps': [{'question': 'Which appliances in our estate are exposed?', 'rfi': 'r1'}],
        'sources': [
            {
                'n': 1,
                'kind': 'document',
                'id': 'd1',
                'tlp': 'GREEN',
                'name': 'Vendor advisory',
                'source_name': 'Vendor',
                'url': 'https://vendor.example/advisory',
                'added_at': '2026-11-20T08:00:00+00:00',
                'reliability': 'B',
                'credibility': 2,
            },
            {
                'n': 2,
                'kind': 'indicator',
                'id': 'e1',
                'tlp': 'AMBER',
                'name': 'relay.evil.example',
                'indicator_kind': 'domain',
                'confidence': 72,
                'band': 'high',
            },
        ],
    }
    return product | fields


def objects(pdf: bytes) -> dict[int, bytes]:
    """Every object, found through the cross-reference table, which this checks on the way."""
    start = int(pdf.rsplit(b'startxref\n', 1)[1].split()[0])
    table = pdf[start:].split(b'trailer\n', 1)[0].decode('ascii').split('\n')[:-1]
    assert table[:3] == ['xref', f'0 {len(table) - 2}', '0000000000 65535 f ']
    assert all(len(row) == 19 for row in table[2:]), 'each entry is 20 bytes with its end of line'
    offsets = [int(row[:10]) for row in table[3:]]
    ends = dict(zip(sorted(offsets), [*sorted(offsets)[1:], start], strict=True))
    found = {}
    for number, offset in enumerate(offsets, start=1):
        assert pdf[offset:].startswith(b'%d 0 obj\n' % number)
        found[number] = pdf[offset : ends[offset]]
    assert re.search(rb'/Size %d /Root 1 0 R /Info 5 0 R' % (len(offsets) + 1), pdf[start:])
    return found


def pages(pdf: bytes) -> list[bytes]:
    """Each page's contents, decompressed, in page order."""
    streams = []
    for body in objects(pdf).values():
        if b'/FlateDecode' in body:
            length = int(re.search(rb'/Length (\d+)', body).group(1))  # type: ignore[union-attr]
            data = body.split(b'stream\n', 1)[1]
            assert data[length:].startswith(b'\nendstream')
            streams.append(zlib.decompress(data[:length]))
    return streams


def test_the_file_is_well_formed_and_the_same_every_time() -> None:
    pdf = to_pdf(sample())
    assert pdf.startswith(b'%PDF-1.7\n')
    assert pdf.endswith(b'%%EOF\n')
    info = objects(pdf)[5]
    assert b'/CreationDate (D:20261122120000Z)' in info  # the published time, not the time of the export
    assert pdf == to_pdf(sample())
    assert pdf != to_pdf(sample(version=2, published_at='2026-11-23T08:00:00+00:00'))
    draft = to_pdf(sample(version=None, published_at=None))
    assert b'/CreationDate (D:20261122123000Z)' in objects(draft)[5]
    assert b'(Assessment. Draft, not published \\(made 2026-11-22\\).) Tj' in b''.join(pages(draft))


def test_every_page_carries_the_label_twice_in_12_point_type_and_its_number() -> None:
    long = '\n\n'.join(['Edge appliances were exploited again this week by the same crew. ' * 12] * 20)
    contents = pages(to_pdf(sample(analysis=long)))
    assert len(contents) >= 3
    for number, page in enumerate(contents, start=1):
        assert page.count(b'1 0.753 0 rg BT /F2 12 Tf') == 2  # amber on the black box, header and footer
        assert page.count(b'(TLP:AMBER) Tj') == 2
        assert page.count(b're f') == 2
        assert f'(Page {number} of {len(contents)}) Tj'.encode() in page


@pytest.mark.parametrize('tlp', list(TLP_COLOURS))
def test_each_label_has_its_tlp_2_colour(tlp: str) -> None:
    page = pages(to_pdf(sample(tlp=tlp)))[0]
    red, green, blue = TLP_COLOURS[tlp]
    colour = ' '.join(f'{c / 255:.3f}'.rstrip('0').rstrip('.') or '0' for c in (red, green, blue))
    assert page.count(f'{colour} rg BT /F2 12 Tf'.encode()) == 2
    assert page.count(f'(TLP:{tlp}) Tj'.encode()) == 2


def test_widths_are_adobe_helvetica_metrics() -> None:
    assert [width_of(c, REGULAR, 1000) for c in ('W', 'm', 'i', '@', 'é')] == [944, 833, 222, 1015, 556]
    assert [width_of(c, BOLD, 1000) for c in ('W', 'm', 'i', '@')] == [944, 889, 278, 975]
    assert width_of('ab', REGULAR, 10) == pytest.approx(11.12)


def test_lines_fit_and_long_words_are_cut_between_characters() -> None:
    chooser = random.Random(7)  # noqa: S311 - test data, not a secret
    words = [''.join(chooser.choices('abcdefghijklmnopWM', k=chooser.randint(1, 14))) for _ in range(400)]
    words.insert(50, 'x' * 300)  # longer than a line: a hash or a URL
    runs = [(BOLD, ' '.join(words[:20])), (REGULAR, ' ' + ' '.join(words[20:]))]
    lines = wrap(runs, 10.5, WIDTH)
    assert all(sum(width_of(text, font, 10.5) for font, text in line) <= WIDTH + 1e-9 for line in lines)
    assert ''.join(text for line in lines for _, text in line).replace(' ', '') == ''.join(words)
    assert wrap([(REGULAR, '')], 10.5, WIDTH) == [[]]
    assert wrap([(BOLD, 'Likely'), (REGULAR, ', moderate')], 10.5, WIDTH) == [
        [(BOLD, 'Likely'), (REGULAR, ', moderate')]
    ]


def test_text_is_escaped_and_unprintable_characters_are_noted() -> None:
    product = sample(title='Москва (east) \\ west', judgements=[])
    pdf = to_pdf(product)
    text = b''.join(pages(pdf))
    assert b'(?????? \\(east\\) \\\\ west) Tj' in text
    assert b'print as "?"' in text
    assert ('Москва'.encode('utf-16-be').hex().upper()).encode() in objects(pdf)[5]  # the title keeps them
    assert printable('Café – “quotes” • €')
    assert not printable('Москва')
    assert b'print as' not in b''.join(pages(to_pdf(sample())))


def test_network_indicators_are_defanged_but_publisher_links_are_not() -> None:
    judgement = {
        'statement': 'Seen at https://relay.evil.example/a.php from 203.0.113.9.',
        'likelihood': 'very-likely',
        'confidence': 'high',
        'sources': [2],
    }
    text = b''.join(pages(to_pdf(sample(judgements=[judgement], title='Relay at evil.example'))))
    assert b'hxxps://relay[.]evil[.]example/a[.]php' in text
    assert b'203[.]0[.]113[.]9' in text
    assert b'Relay at evil[.]example' in text
    assert b'Indicator \\(domain\\) relay[.]evil[.]example' in text
    assert b'https://vendor.example/advisory' in text  # the publisher's link, as stored
    assert b'evil.example' not in text


def test_it_is_tagged_for_screen_readers_with_a_bookmark_per_section() -> None:
    pdf = to_pdf(sample())
    found = objects(pdf)
    assert found[1].startswith(
        b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Lang (en-US) /MarkInfo << /Marked true >>'
    )
    kinds = re.findall(rb'/Type /StructElem /S /(\w+)', pdf)
    assert {b'Document', b'H1', b'H2', b'P', b'L', b'LI', b'LBody'} == set(kinds)
    parents = re.search(rb'/ParentTree << /Nums \[(.*?)\] >>', found[6], re.DOTALL).group(1)  # type: ignore[union-attr]
    owned = [len(re.findall(rb'\d+ 0 R', arr)) for arr in re.findall(rb'\d+ \[(.*?)\]', parents)]
    assert owned == [page.count(b'/MCID') for page in pages(pdf)]
    assert all(page.count(b'BDC') == page.count(b'EMC') for page in pages(pdf))
    titles = re.findall(rb'/Title <FEFF([0-9A-F]+)> /Parent 7 0 R', pdf)
    assert [bytes.fromhex(t.decode()).decode('utf-16-be') for t in titles] == [
        'Bottom line up front',
        'Key judgements',
        'Analysis',
        'Intelligence gaps',
        'Sources',
    ]


def test_an_empty_draft_says_what_is_missing() -> None:
    draft = sample(version=None, published_at=None, bluf='', judgements=[], analysis='', gaps=[], sources=[])
    text = b''.join(pages(to_pdf(draft)))
    for missing in (b'(Not written yet.)', b'(None yet.)', b'(None recorded.)', b'(None.)'):
        assert missing in text
    assert b'(Analysis)' not in text


def test_a_pdf_library_reads_the_text_and_pages() -> None:
    pypdf = pytest.importorskip('pypdf')
    long = '\n\n'.join(['The crew returns to the same gateways. ' * 20] * 12)
    pdf = to_pdf(sample(analysis=long))
    reader = pypdf.PdfReader(io.BytesIO(pdf))
    assert len(reader.pages) == len(pages(pdf))
    first = reader.pages[0].extract_text()
    for expected in ('Edge appliance exploitation', 'TLP:AMBER', 'Bottom line up front'):
        assert expected in first
    whole = ' '.join(page.extract_text() for page in reader.pages)
    assert 'The crew will keep exploiting edge appliances.' in ' '.join(whole.split())

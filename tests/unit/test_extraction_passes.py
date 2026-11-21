"""The individual extraction passes and predicates, tested in isolation.

``extract()`` is a fixed sequence of passes over one ``_Mentions`` collector (URLs, then domains, IPs,
hashes and CVEs). These tests pin each pass's own rule, so a failure points at the responsible step rather
than at the pipeline as a whole. End-to-end behaviour stays covered by ``test_extraction.py`` and the
labelled corpus.
"""

from __future__ import annotations

import pytest

from insight import extraction
from insight.extraction import (
    _add_cves,
    _add_domains,
    _add_hashes,
    _add_ips,
    _add_urls,
    _is_ambiguous_name,
    _is_fragment,
    _Mentions,
    _within,
)


def found(mentions: _Mentions) -> set[tuple[str, str]]:
    return {(m.kind, m.value) for m in mentions.in_order()}


# --------------------------------------------------------------------------- predicates


@pytest.mark.parametrize(
    ('spans', 'start', 'end', 'expected'),
    [
        ([(0, 10)], 2, 5, True),
        ([(0, 10)], 0, 10, True),  # boundaries are inclusive
        ([(0, 10)], 5, 11, False),  # overlapping is not "inside"
        ([(0, 3), (8, 12)], 9, 11, True),
        ([], 0, 1, False),
    ],
)
def test_within(spans: list[tuple[int, int]], start: int, end: int, expected: bool) -> None:
    assert _within(spans, start, end) is expected


@pytest.mark.parametrize(
    ('name', 'expected'),
    [
        ('update.zip', True),
        ('setup.py', True),
        ('setup.py.', True),
        ('files.example.zip', False),
        ('a.com', False),
    ],
)
def test_is_ambiguous_name(name: str, expected: bool) -> None:
    assert _is_ambiguous_name(f' {name} ', 1, 1 + len(name)) is expected


def test_is_fragment_detects_a_non_ascii_neighbour() -> None:
    work = 'ex\u0430mple-login.com'  # U+0430 CYRILLIC SMALL LETTER A before the ASCII tail
    tail = work.index('mple')
    assert _is_fragment(work, tail, len(work))
    assert not _is_fragment(' mple-login.com ', 1, 15)


# --------------------------------------------------------------------------- collector


def test_add_maps_back_to_the_original_text_and_deduplicates() -> None:
    mentions = _Mentions('see evil[.]example now')
    start = mentions.work.index('evil')
    assert mentions.work == 'see evil.example now'
    assert mentions.add('domain', start, start + len('evil.example'))
    assert mentions.add('domain', start, start + len('evil.example'))  # same span: recorded once
    (mention,) = mentions.in_order()
    assert (mention.value, mention.start, mention.end) == ('evil.example', 4, 18)  # offsets in the original
    assert mentions.text[mention.start : mention.end] == 'evil[.]example'


def test_add_rejects_invalid_values() -> None:
    mentions = _Mentions('999.1.1.1')
    assert not mentions.add('ip', 0, 9)
    assert mentions.in_order() == []


def test_add_enforces_the_mention_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extraction, 'MAX_MENTIONS', 1)
    mentions = _Mentions('192.0.2.1 192.0.2.2')
    assert mentions.add('ip', 0, 9)
    with pytest.raises(ValueError, match='split it into smaller documents'):
        mentions.add('ip', 10, 19)


# --------------------------------------------------------------------------- passes


def test_url_pass_records_the_url_and_its_host_and_returns_the_span() -> None:
    text = 'Beacon https://evil.example/a.php.'
    mentions = _Mentions(text)
    spans = _add_urls(mentions)
    assert spans == [(7, 33)]  # trailing sentence dot trimmed
    assert found(mentions) == {('url', 'https://evil.example/a.php'), ('domain', 'evil.example')}


def test_domain_pass_skips_names_inside_urls_and_file_like_names() -> None:
    mentions = _Mentions('https://a.example/x.example then b.example, update.zip')
    _add_domains(mentions, [(0, 27)])
    assert found(mentions) == {('domain', 'b.example')}


def test_ip_pass_ignores_version_numbers() -> None:
    mentions = _Mentions('firmware 10.2.9.1 talks to 192.0.2.8 and 2001:db8::1')
    _add_ips(mentions, [])
    assert found(mentions) == {('ip', '192.0.2.8'), ('ip', '2001:db8::1')}


def test_hash_pass_joins_unevenly_wrapped_digests_only() -> None:
    digest = 'ab' * 32
    wrapped = _Mentions(f'{digest[:40]}\n{digest[40:]}')
    _add_hashes(wrapped)
    assert found(wrapped) == {('sha256', digest)}
    even_split = _Mentions(f'{"c" * 32}\n{"d" * 32}')  # two MD5s, not one SHA256
    _add_hashes(even_split)
    assert found(even_split) == {('md5', 'c' * 32), ('md5', 'd' * 32)}


def test_cve_pass_canonicalises_case() -> None:
    mentions = _Mentions('see cve-2021-44228')
    _add_cves(mentions)
    assert found(mentions) == {('cve', 'CVE-2021-44228')}

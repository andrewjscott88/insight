"""Deterministic extraction: per-kind positives/negatives, canonicalisation, offsets and invariants."""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from insight.extraction import EVIDENCE_CONTEXT, MAX_MENTIONS, Mention, canonical, extract, refang


def values(text: str, kind: str) -> list[str]:
    return [m.value for m in extract(text) if m.kind == kind]


# --------------------------------------------------------------------------- per-kind detection


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('CVE-2024-12345', ['CVE-2024-12345']),
        ('cve-2024-3400 lower case', ['CVE-2024-3400']),
        ('seven digits CVE-2021-4428812', ['CVE-2021-4428812']),
        ('(CVE-2023-34362)', ['CVE-2023-34362']),
        ('too short CVE-2024-123', []),
        ('embedded XCVE-2024-12345', []),
    ],
)
def test_cve(text: str, expected: list[str]) -> None:
    assert values(text, 'cve') == expected


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('at 192.0.2.8 today', ['192.0.2.8']),
        ('list: 192.0.2.8, 198.51.100.7', ['192.0.2.8', '198.51.100.7']),
        # Regression: IPv4 at the end of a sentence was previously not extracted.
        ('Beacon to 192.0.2.8.', ['192.0.2.8']),
        # Regression: IPv4 with a port was previously not extracted.
        ('Beacon to 192.0.2.8:443 now', ['192.0.2.8']),
        ('invalid octet 999.1.2.3', []),
        ('version string 1.2.3.4.5', []),
        ('embedded v192.0.2.8', []),
        ('IPv6 2001:0DB8:0000:0000:0000:0000:0000:0001', ['2001:db8::1']),
        ('IPv6 2001:db8::42.', ['2001:db8::42']),
        ('loopback ::1 here', ['::1']),
        ('clock 12:30:45 is not an address', []),
        # ASCII-only: Unicode digits must never produce an address.
        ('arabic-indic ١٩٢.٠.٢.٨', []),
    ],
)
def test_ip(text: str, expected: list[str]) -> None:
    assert values(text, 'ip') == expected


@pytest.mark.parametrize(
    ('raw', 'expected'),
    [
        ('203[.]0[.]113[.]0/24', '203.0.113.0/24'),
        ('2001[:]0DB8:0000:0000::/48', '2001:db8::/48'),
        ('::ffff:c000:0200/120', '::ffff:192.0.2.0/120'),
        ('::ffff:192.0.2.0/120', '::ffff:192.0.2.0/120'),
        ('192.0.2.7/32', '192.0.2.7/32'),
        ('2001:db8::7/128', '2001:db8::7/128'),
        ('128.0.0.0/1', '128.0.0.0/1'),
        ('8000::/1', '8000::/1'),
    ],
)
def test_cidr_keeps_full_raw_span_and_canonical_network(raw: str, expected: str) -> None:
    text = f'📄 Range ({raw}).'
    (mention,) = extract(text)
    assert (mention.kind, mention.value) == ('cidr', expected)
    assert text[mention.start : mention.end] == raw
    assert raw in mention.evidence
    assert canonical('cidr', raw) == expected


@pytest.mark.parametrize(
    'raw',
    [
        '203.0.113.0/33',
        '2001:db8::/129',
        '2001:db8::/-1',
        '192.0.2.0/+24',
        '203.0.113.7/24',
        '2001:db8::7/64',
        '999.0.0.0/8',
        '2001:db8:::1/128',
        '192.0.2.0/24x',
        '192.0.2.0/2.4',
        'x192.0.2.0/24',
        'é192.0.2.0/24',
        '192.0.2.0/24é',
        '192.0.2.0/24/32',
        'firmware 1.2.3.0/24',
        '::ffff:192.0.2.7/120',
    ],
)
def test_invalid_or_embedded_ranges_do_not_yield_partial_addresses(raw: str) -> None:
    assert extract(raw) == []


def test_regression_every_address_is_not_an_indicator() -> None:
    """Cloud reports often say a rule allowed 0.0.0.0/0; that range is every address, not an indicator."""
    text = 'The security group allowed SSH from 0.0.0.0/0 and ::/0; the scans came from 198.51.100.0/24.'
    assert values(text, 'cidr') == ['198.51.100.0/24']
    assert values(text, 'ip') == []


def test_cidr_skips_url_paths_and_leaves_bare_ips_alone() -> None:
    text = (
        'hxxps://example[.]org/net/192.0.2.0/24 or https://192.0.2.0/24. Range 192.0.2.0/24; host 192.0.2.1.'
    )
    assert values(text, 'cidr') == ['192.0.2.0/24']
    assert values(text, 'ip') == ['192.0.2.1']


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('see https://Example.COM/Path?q=1.', ['https://example.com/Path?q=1']),
        ('(http://example.org/a)', ['http://example.org/a']),
        ('quoted "https://example.net/x" ok', ['https://example.net/x']),
        ('https://[2001:0DB8::1]:8443/p', ['https://[2001:db8::1]:8443/p']),
        ('credentials https://user:pw@example.com/ are stripped', ['https://example.com/']),
        ('bad port https://example.com:99999/ dropped', []),
        ('ftp://example.com/ is not extracted', []),
    ],
)
def test_url(text: str, expected: list[str]) -> None:
    assert values(text, 'url') == expected


@pytest.mark.parametrize(
    ('kind', 'length'),
    [('md5', 32), ('sha1', 40), ('sha256', 64)],
)
def test_hashes_are_classified_by_length(kind: str, length: int) -> None:
    digest = 'AB' * (length // 2)
    found = extract(f'hash {digest} end')
    assert [(m.kind, m.value) for m in found] == [(kind, digest.lower())]


def test_sha512_and_runs_of_other_lengths() -> None:
    assert [(m.kind, m.value) for m in extract('a' * 128)] == [('sha512', 'a' * 128)]
    assert extract('a' * 100) == []  # not a known digest length: never truncated into a shorter "hash"


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('Visit Example.COM.', ['example.com']),
        ('sub.domain.example.org', ['sub.domain.example.org']),
        ('mail someone@example.com', []),
        # Regression: the local part of an e-mail address was extracted as a "domain".
        ('mail first.last@example.com', []),
        ('no tld localhost', []),
        ('numeric tld 10.0.0.1', []),
    ],
)
def test_domain(text: str, expected: list[str]) -> None:
    assert values(text, 'domain') == expected


def test_invalid_candidate_does_not_stop_later_matches() -> None:
    """Found by mutation testing: ``continue`` -> ``break`` after an invalid candidate survived."""
    text = '999.1.2.3 then 192.0.2.8; ftp://bad.example/ then https://good.example/'
    assert values(text, 'ip') == ['192.0.2.8']
    assert values(text, 'url') == ['https://good.example/']


def test_url_host_is_also_a_domain_pivot() -> None:
    kinds = {(m.kind, m.value) for m in extract('https://relay.example.org/beacon')}
    assert kinds == {('url', 'https://relay.example.org/beacon'), ('domain', 'relay.example.org')}


# --------------------------------------------------------------------------- canonicalisation


@pytest.mark.parametrize(
    ('kind', 'raw', 'expected'),
    [
        ('cve', 'cve-2024-1234', 'CVE-2024-1234'),
        ('ip', '2001:0db8:0:0:0:0:0:1', '2001:db8::1'),
        ('ip', '192.0.2.8', '192.0.2.8'),
        ('url', 'HTTPS://Example.COM:443/Path?q=VALUE#Frag', 'https://example.com:443/Path?q=VALUE#Frag'),
        ('url', 'https://[2001:0DB8::1]/path', 'https://[2001:db8::1]/path'),
        ('url', 'https://bücher.example/x', 'https://xn--bcher-kva.example/x'),
        ('domain', 'Example.COM', 'example.com'),
        ('sha256', 'A' * 64, 'a' * 64),
    ],
)
def test_canonical(kind: str, raw: str, expected: str) -> None:
    assert canonical(kind, raw) == expected


@pytest.mark.parametrize(
    ('kind', 'raw'),
    [
        ('ip', '999.1.2.3'),
        ('url', 'https://'),
        ('url', 'https://example.com:bad/'),
        ('url', 'ftp://example.com/'),
        ('cve', 'CVE-24-1'),
        ('domain', 'svchost.exe'),
        ('ip', '010.1.2.3'),
        ('cidr', '192.0.2.1'),
        ('cidr', '192.0.2.0/255.255.255.0'),
        ('cidr', 'fe80::%eth0/64'),
        ('cidr', '0.0.0.0/0'),
        ('cidr', '::/0'),
    ],
)
def test_canonical_rejects_invalid(kind: str, raw: str) -> None:
    with pytest.raises(ValueError):  # noqa: PT011 - the public contract is "ValueError", no message.
        canonical(kind, raw)


def test_url_without_host_has_a_clear_message() -> None:
    with pytest.raises(ValueError, match=r'^Invalid URL$'):
        canonical('url', 'https://')


def test_url_credentials_are_never_stored() -> None:
    assert (
        canonical('url', 'https://collector:s3cr3t@drop.example.org/upload')
        == 'https://drop.example.org/upload'
    )


# --------------------------------------------------------------------------- offsets, ordering, limits


def test_offsets_evidence_and_sorting() -> None:
    text = '  Unicode ☃: cve-2024-12345 at EXAMPLE.COM; cve-2024-12345 again.\n'
    found = extract(text)
    assert [m.kind for m in found] == ['cve', 'domain', 'cve']
    assert [m.start for m in found] == sorted(m.start for m in found)
    for mention in found:
        raw = text[mention.start : mention.end]
        assert canonical(mention.kind, raw) == mention.value
        assert raw in mention.evidence


def test_evidence_window_is_bounded() -> None:
    text = 'x' * 500 + ' CVE-2024-12345 ' + 'y' * 500
    (mention,) = extract(text)
    assert len(mention.evidence) == EVIDENCE_CONTEXT + len('CVE-2024-12345') + EVIDENCE_CONTEXT


def test_mention_limit_boundary() -> None:
    # Regression: exactly MAX_MENTIONS used to raise although the message says "exceeds".
    assert len(extract('CVE-2024-12345 ' * MAX_MENTIONS)) == MAX_MENTIONS
    with pytest.raises(ValueError, match='exceeds'):
        extract('CVE-2024-12345 ' * (MAX_MENTIONS + 1))


def test_mention_is_immutable() -> None:
    mention = extract('CVE-2024-12345')[0]
    with pytest.raises(AttributeError):
        mention.value = 'changed'  # type: ignore[misc]


# --------------------------------------------------------------------------- property-based invariants

observable_fragments = st.sampled_from(
    [
        'CVE-2024-12345',
        '192.0.2.8',
        '2001:db8::1',
        '192.0.2.0/24',
        '2001:0DB8::/32',
        'https://example.com/a?b=c',
        'example.org',
        'a' * 32,
        'b' * 40,
        'c' * 64,
        'user@example.com',
        '1.2.3.4.5',
        '☃',
        ' ',
        '.',
        ':',
        '\n',
    ]
)
texts = st.one_of(
    st.text(max_size=300),
    st.lists(st.one_of(observable_fragments, st.text(max_size=8)), max_size=40).map(''.join),
)


@given(texts)
@example('Beacon to 192.0.2.8.')
# Example counts come from the Hypothesis profile (conftest.py): 300 on every push, 5,000 nightly. Do not set
# max_examples here; a per-test value silently overrides the nightly profile (found by running the pipeline).
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_extraction_invariants(text: str) -> None:
    """For any input: never crash, offsets are valid, spans re-canonicalise, and output is sorted."""
    found = extract(text)
    assert all(isinstance(m, Mention) for m in found)
    assert found == sorted(found, key=lambda m: (m.start, m.kind))
    for mention in found:
        assert 0 <= mention.start < mention.end <= len(text)
        raw = text[mention.start : mention.end]
        assert canonical(mention.kind, raw) == mention.value
        assert raw in mention.evidence
        if mention.kind == 'url':
            # Paths are preserved verbatim as evidence, but the host is always IDNA/ASCII.
            assert (urlsplit(mention.value).hostname or '').isascii()
        else:
            assert mention.value.isascii()


@given(texts)
def test_extraction_is_deterministic(text: str) -> None:
    assert extract(text) == extract(text)


# ------------------------------------------------------------------- rules driven by the synthetic reports
# Each case below reproduces a defect found with tests/corpus/reports/*. "Wrong" indicators (fragments of a
# larger token, a different address) are treated as worse than missed ones.


@pytest.mark.parametrize(
    ('text', 'kind', 'expected'),
    [
        ('hxxp://198.51.100[.]77/a.ps1', 'url', ['http://198.51.100.77/a.ps1']),
        ('hxxps://files.example[.]net/u/8f3a', 'url', ['https://files.example.net/u/8f3a']),
        ('hXXps[:]//evil(.)example/x', 'url', ['https://evil.example/x']),
        ('update-check[.]example[.]org', 'domain', ['update-check.example.org']),
        ('192.0.2[.]15 and 198[.]51[.]100[.]3', 'ip', ['192.0.2.15', '198.51.100.3']),
        ('evil{.}example[dot]org', 'domain', ['evil.example.org']),
    ],
)
def test_defanged_indicators_are_refanged(text: str, kind: str, expected: list[str]) -> None:
    found = [m for m in extract(text) if m.kind == kind]
    assert [m.value for m in found] == expected
    for mention in found:  # offsets still point at the defanged source text
        assert canonical(kind, text[mention.start : mention.end]) == mention.value


def test_refang_is_idempotent_on_ordinary_text() -> None:
    text = 'Plain [text] with (parentheses) and a list [1, 2].'
    assert refang(text) == text


@pytest.mark.parametrize(
    ('text', 'expected', 'never'),
    [
        ('site ex\u0430mple-login.com here', 'xn--exmple-login-y9j.com', 'mple-login.com'),  # Cyrillic a
        ('cdn exam\u200bple.com here', 'example.com', 'ple.com'),  # zero-width space
        ('page cafe\u0301-login.example here', 'xn--caf-login-d4a.example', 'login.example'),  # NFD accent
        ('see b\u00fccher.example now', 'xn--bcher-kva.example', 'cher.example'),
    ],
)
def test_international_and_obfuscated_names_are_never_truncated(text: str, expected: str, never: str) -> None:
    domains = values(text, 'domain')
    assert domains == [expected]
    assert never not in domains


@pytest.mark.parametrize(
    'text',
    [
        'Hunt for svchost.exe, update.bin, loader.bin, relaysvc.dll, report.docx and setup.msi.',
        'IEX (New-Object Net.WebClient) and [System.Net.Sockets.TcpClient]::new(); os.path.join()',
        'Scripts update.zip, setup.py, build.sh, readme.md, subprocess.run and git config user.name.',
    ],
)
def test_file_names_and_code_are_not_domains(text: str) -> None:
    assert values(text, 'domain') == []


def test_ambiguous_tld_is_accepted_as_a_url_host() -> None:
    found = {(m.kind, m.value) for m in extract('Lure at https://invoice.zip/pay now.')}
    assert ('domain', 'invoice.zip') in found


def test_url_paths_do_not_produce_domains() -> None:
    text = 'https://mail.example.org/owa/logon.aspx?x=1 and https://psirt.example.com/a/ms-relay.html'
    assert values(text, 'domain') == ['mail.example.org', 'psirt.example.com']


def test_url_host_of_a_credential_url_is_still_a_domain() -> None:
    found = {(m.kind, m.value) for m in extract('Posted to https://user:pw@drop.example.org/upload today.')}
    assert found == {('url', 'https://drop.example.org/upload'), ('domain', 'drop.example.org')}


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('firmware 10.2.9.1 and version 9.0.0.1, build: 7.1.0.2', []),
        ('connected to 10.2.9.1 twice', ['10.2.9.1']),
        ('scanned 203.0.113.0/24 and 2001:db8::/32', []),
        ('IPv4-mapped ::ffff:203.0.113.9 beacon', ['203.0.113.9']),
        ('padded 192.000.002.033 in the log', ['192.0.2.33']),
        ('ambiguous 010.1.2.03 left alone', []),
        ('link-local fe80::1%eth0 host', ['fe80::1']),
        ('bracketed [2001:db8:dead:beef::1]:8443', ['2001:db8:dead:beef::1']),
        ('share \\\\198.51.100.5\\payload$', ['198.51.100.5']),
    ],
)
def test_address_context_rules(text: str, expected: list[str]) -> None:
    assert values(text, 'ip') == expected


def test_ipv4_mapped_address_is_never_truncated_into_another_address() -> None:
    assert '::ffff:203' not in values('form ::ffff:203.0.113.9 seen', 'ip')


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('TXT at _dmarc.example.com', ['_dmarc.example.com']),
        ('SRV _sip._tcp.example.com', ['_sip._tcp.example.com']),
        ('FQDN exfil.example.net. noted', ['exfil.example.net']),
        ('Hidden service abcdefghijklmnop.onion', ['abcdefghijklmnop.onion']),
        ('IDN TLD example.xn--p1ai', ['example.xn--p1ai']),
        ('mixed CDN.EXAMPLE.ORG', ['cdn.example.org']),
    ],
)
def test_domain_forms(text: str, expected: list[str]) -> None:
    assert values(text, 'domain') == expected


def test_unknown_tlds_are_rejected() -> None:
    assert values('notes.docx backup.invalidtld config.yaml', 'domain') == []


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('see https://en.wikipedia.org/wiki/Foo_(bar) now', ['https://en.wikipedia.org/wiki/Foo_(bar)']),
        ('(see https://x.example/a).', ['https://x.example/a']),
        ('[advisory](https://psirt.example.com/a.html),', ['https://psirt.example.com/a.html']),
    ],
)
def test_url_trailing_punctuation_and_brackets(text: str, expected: list[str]) -> None:
    assert values(text, 'url') == expected


def test_unevenly_wrapped_hash_is_joined() -> None:
    digest = '0123456789abcdef' * 4  # sha256
    text = f'SHA-256 {digest[:48]}\n   {digest[48:]} (wrapped by the PDF export)'
    assert [(m.kind, m.value) for m in extract(text)] == [('sha256', digest)]
    (mention,) = extract(text)
    assert canonical('sha256', text[mention.start : mention.end]) == digest


def test_one_hash_per_line_lists_are_never_merged() -> None:
    """An even 32 + 32 split is indistinguishable from two MD5 lines, the far more common case."""
    text = 'MD5 list:\n' + 'a' * 32 + '\n' + 'b' * 32 + '\n'
    assert [(m.kind, m.value) for m in extract(text)] == [('md5', 'a' * 32), ('md5', 'b' * 32)]


# --------------------------------------------------------------- gaps found by mutation testing (0.2.0 run)


def test_wrap_where_one_part_is_a_valid_length_is_joined_not_split() -> None:
    """40 + 24 hex chars is one SHA-256; the 40-char half must not also be reported as a SHA-1."""
    digest = 'fedcba9876543210' * 4
    text = f'hash {digest[:40]}\n{digest[40:]} end'
    assert [(m.kind, m.value) for m in extract(text)] == [('sha256', digest)]


@pytest.mark.parametrize(
    ('text', 'domains'),
    [
        ('https://a.example/redirect/evil.com', ['a.example']),  # a name ending exactly where the URL ends
        ('https://cdn.example.org/user@foo.example/x', ['cdn.example.org']),  # '@' in the path, not userinfo
        ('https://a.example/x//b.example/y', ['a.example']),  # '//' in the path
        ('https://exfil.example.net./x', ['exfil.example.net']),  # trailing-dot host
    ],
)
def test_url_host_is_taken_from_the_authority_only(text: str, domains: list[str]) -> None:
    assert values(text, 'domain') == domains


def test_trailing_dot_url_host_is_canonicalised() -> None:
    assert values('see https://exfil.example.net./x now', 'url') == ['https://exfil.example.net/x']


@pytest.mark.parametrize(
    'text',
    [
        'example.com\u00e9 is one token',  # followed by a non-ASCII letter
        'visit example.comé now',
        'x \u00f1ame.zip',  # international name with an ambiguous (file-extension) TLD
    ],
)
def test_fragments_and_ambiguous_international_names_are_rejected(text: str) -> None:
    assert values(text, 'domain') == []


def test_domain_at_the_start_of_text_ending_in_a_non_ascii_letter() -> None:
    assert values('example.com was named in a report from Zürich, café', 'domain') == ['example.com']


def test_bracketed_scheme_separator_is_refanged() -> None:
    assert values('payload at hxxps[://]evil.example/p', 'url') == ['https://evil.example/p']


@pytest.mark.parametrize(('kind', 'raw'), [('md5', 'z' * 32), ('sha1', 'g' * 40), ('sha256', 'x' * 64)])
def test_non_hex_strings_of_hash_length_are_rejected(kind: str, raw: str) -> None:
    with pytest.raises(ValueError, match='digest'):
        canonical(kind, raw)


def test_internal_underscores_are_rejected_but_leading_ones_kept() -> None:
    assert values('hosts my_host.example.com and _srv._tcp.example.com', 'domain') == [
        '_srv._tcp.example.com'
    ]

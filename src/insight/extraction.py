"""Deterministic mention extraction. Never attributes maliciousness or actors.

Pipeline (see docs/EXTRACTION.md):

1. **Refang** a working copy of the text (``hxxp``→``http``, ``[.]``→``.``, ``[:]``→``:``) while keeping a map
   back to the original character positions, so offsets and evidence always refer to the text as submitted.
2. **Match** candidates per kind on the working copy.
3. **Validate and canonicalise** (real IP syntax, known TLDs, hash lengths, IDNA for international names).
4. **Apply context rules** that prevent *wrong* indicators, which are worse than missed ones: no partial
   tokens (a match must not be a fragment of a larger word, e.g. of a homoglyph domain), no domains from URL
   paths, no CIDR network addresses or version numbers as IPs, no file names with ambiguous TLDs as domains.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Final, Literal
from urllib.parse import urlsplit, urlunsplit

Kind = Literal['cve', 'url', 'sha512', 'sha256', 'sha1', 'md5', 'ip', 'domain', 'cidr', 'email']

EXTRACTOR_VERSION: Final = 'regex-v4'
MAX_MENTIONS: Final = 2000
EVIDENCE_CONTEXT: Final = 90

_ASCII_I = re.IGNORECASE | re.ASCII
ZERO_WIDTH: Final = frozenset('\u200b\u200c\u200d\u2060\ufeff\u00ad')
HASH_KINDS: Final[dict[int, Kind]] = {128: 'sha512', 64: 'sha256', 40: 'sha1', 32: 'md5'}

#: Special-use and internal names that are not in the public TLD list but matter in intrusion reports
#: (RFC 2606/6761 documentation names, Tor onion services, common internal zones).
SPECIAL_USE_TLDS: Final = frozenset(
    {
        'example',
        'test',
        'invalid',
        'localhost',
        'onion',
        'local',
        'internal',
        'lan',
        'corp',
        'home',
        'intranet',
    }
)
#: Real TLDs that are also common file extensions or code members. A bare two-label name with one of these
#: (``update.zip``, ``setup.py``, ``app.run``, ``user.name``) is far more likely a file or identifier than a
#: domain, so it is only accepted when it is the host of a URL.
AMBIGUOUS_TLDS: Final = frozenset(
    {
        'zip',
        'mov',
        'py',
        'sh',
        'pl',
        'pm',
        'rs',
        'md',
        'so',
        'ai',
        'cc',
        'one',
        'ps',
        'run',
        'app',
        'mobi',
        'name',
    }
)

# --------------------------------------------------------------------------- patterns

_DEFANG = re.compile(
    r'(?P<scheme>\bh(?:xx|\*\*)p(?P<s>s?)(?=(?:\[:\]|:)//|\[://\]))'
    r'|(?P<dot>\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))'
    r'|(?P<sep>\[://\])'
    r'|(?P<colon>\[:\])',
    re.IGNORECASE,
)
_CVE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', _ASCII_I)
_URL = re.compile(r'\bhttps?://[^\s<>"\'`|]+', re.IGNORECASE)
_HEX = re.compile(r'\b[0-9a-f]{32,128}\b', _ASCII_I)
# A hash wrapped onto the next line (PDF/e-mail export): first part ends a line, second part starts the next.
_WRAPPED_HEX = re.compile(r'\b([0-9a-f]{8,124})[ \t]*\r?\n[ \t]*([0-9a-f]{4,124})\b', _ASCII_I)
_IPV4 = re.compile(r'(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\w|/[+-]?\d)', re.ASCII)
_IPV6 = re.compile(
    r'(?<![\w:.])(?:[0-9a-f]{0,4}:){2,}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{0,4})(?![\w:]|\.\w|/[+-]?\d)',
    _ASCII_I,
)
# 45 characters covers an IPv6 address with a dotted IPv4 tail. Validate the full candidate with ip_network.
_CIDR = re.compile(r'(?<![\w.:/@%-])[0-9a-f:.]{2,45}/[0-9]{1,3}(?![\w/%+-]|[.:][\w:])', _ASCII_I)
_LABEL = r'_?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
_TLD = r'(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})'
_DOMAIN = re.compile(rf'(?<![\w@.\-])(?:{_LABEL}\.)+{_TLD}(?![\w-]|\.[a-z0-9])(?!@)', _ASCII_I)
_DOMAIN_FULL = re.compile(rf'(?:{_LABEL}\.)+{_TLD}', _ASCII_I)
_WORDISH = r'\w\u0300-\u036f\u200b-\u200d\u2060\ufeff\u00ad'
_IDN = re.compile(rf'(?<![{_WORDISH}@.\-])(?:[{_WORDISH}-]+\.)+[{_WORDISH}-]{{2,63}}(?![{_WORDISH}-])')
# Accept common unquoted mailboxes; the wider left boundary prevents taking the tail of an unsupported one.
_EMAIL = re.compile(
    rf"(?<![{_WORDISH}.!#$%&'*+/=?^`{{|}}~@\\-])(?<!\[@\])(?P<local>[A-Za-z0-9_.'%+-]{{1,65}})"
    rf'(?:@|\[@\])(?P<host>[{_WORDISH}-]+(?:\.[{_WORDISH}-]+)+)(?![{_WORDISH}@-]|\[@\]|\.+[{_WORDISH}-])'
)
_EMAIL_LOCAL = re.compile(r"[A-Za-z0-9_%+-]+(?:[.'][A-Za-z0-9_%+-]+)*")
# Scan URI tokens and bare mailboxes in one pass: userinfo, query strings and paths are not recipients.
_URI_OR_EMAIL = re.compile(
    r'(?P<uri>\b(?:(?P<mailto>(?i:mailto:))|[A-Za-z][A-Za-z0-9+.\-]{0,31}://)[^\s<>"`|]+)|' + _EMAIL.pattern
)
_IPV4_SHAPE = re.compile(r'\d{1,3}(?:\.\d{1,3}){3}', re.ASCII)
_VERSION_CONTEXT = re.compile(
    r'(?:\b(?:version|ver|firmware|fw|build|release|agent|patch|section|chapter|step)\.?'
    r'|\bv)\s*[:=#]?\s*$',
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class Mention:
    kind: Kind
    value: str
    start: int
    end: int
    evidence: str


@lru_cache(maxsize=1)
def known_tlds() -> frozenset[str]:
    """ICANN top-level domains (bundled snapshot, see ``data/tlds.txt``) plus special-use names."""
    text = resources.files('insight').joinpath('data/tlds.txt').read_text(encoding='utf-8')
    listed = {line.strip() for line in text.splitlines() if line.strip() and not line.startswith('#')}
    return frozenset(listed) | SPECIAL_USE_TLDS


# --------------------------------------------------------------------------- refanging with an offset map


@dataclass(frozen=True, slots=True)
class _View:
    """The refanged text plus, for each of its characters, the span it came from in the original."""

    text: str
    starts: tuple[int, ...] | None = None  # None: identical to the original
    ends: tuple[int, ...] | None = None

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        if self.starts is None or self.ends is None:
            return start, end
        return self.starts[start], self.ends[end - 1]


def _replacement(match: re.Match[str]) -> str:
    if match.group('scheme'):
        return 'http' + match.group('s').lower()
    if match.group('dot'):
        return '.'
    if match.group('sep'):
        return '://'
    return ':'


def _refang_view(text: str) -> _View:
    if not _DEFANG.search(text):
        return _View(text)
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    position = 0
    for match in _DEFANG.finditer(text):
        for index in range(position, match.start()):
            chars.append(text[index])
            starts.append(index)
            ends.append(index + 1)
        for char in _replacement(match):
            chars.append(char)
            starts.append(match.start())
            ends.append(match.end())
        position = match.end()
    for index in range(position, len(text)):
        chars.append(text[index])
        starts.append(index)
        ends.append(index + 1)
    return _View(''.join(chars), tuple(starts), tuple(ends))


def refang(text: str) -> str:
    """``hxxps://evil[.]example[:]8443`` → ``https://evil.example:8443``. Idempotent on ordinary text."""
    return _refang_view(text).text


# --------------------------------------------------------------------------- canonical forms


def _strip_zero_width(value: str) -> str:
    return ''.join(char for char in value if char not in ZERO_WIDTH)


def _canonical_domain(value: str) -> str:
    cleaned = unicodedata.normalize('NFC', _strip_zero_width(refang(value))).rstrip('.')
    if '_' in cleaned.replace('._', '.').lstrip('_'):
        raise ValueError('Underscores are only allowed at the start of a label')
    ascii_name = cleaned.encode('idna').decode('ascii').lower()
    if not _DOMAIN_FULL.fullmatch(ascii_name):
        raise ValueError('Not a domain name')
    if ascii_name.rsplit('.', 1)[-1] not in known_tlds():
        raise ValueError('Unknown top-level domain')
    return ascii_name


def _canonical_email(value: str) -> str:
    match = _EMAIL.fullmatch(refang(value))
    if not match:
        raise ValueError('Invalid e-mail address')
    local, host = match.group('local', 'host')
    if len(local) > 64 or not _EMAIL_LOCAL.fullmatch(local) or '_' in host:
        raise ValueError('Invalid e-mail address')
    address = f'{local}@{_canonical_domain(host)}'
    if len(address) > 254:
        raise ValueError('E-mail address is too long')
    return address


def _canonical_url(value: str) -> str:
    parts = urlsplit(_strip_zero_width(refang(value)))
    if parts.scheme.lower() not in ('http', 'https') or not parts.hostname:
        raise ValueError('Invalid URL')
    host = unicodedata.normalize('NFC', parts.hostname).rstrip('.').encode('idna').decode('ascii').lower()
    if ':' in host:
        host = f'[{ipaddress.ip_address(host).compressed}]'
    port = parts.port
    authority = host + (f':{port}' if port is not None else '')
    # Credentials (userinfo) are never stored; path, query, fragment and explicit port are evidence.
    return urlunsplit((parts.scheme.lower(), authority, parts.path, parts.query, parts.fragment))


def _canonical_ip(value: str) -> str:
    candidate = refang(value).strip('[]')
    if _IPV4_SHAPE.fullmatch(candidate):
        octets = candidate.split('.')
        if any(len(octet) > 1 and octet.startswith('0') for octet in octets):
            # Fixed-width decimal padding (log formats) is unambiguous; other leading zeros may mean octal.
            if not all(len(octet) == 3 for octet in octets):
                raise ValueError('Ambiguous zero-padded IPv4 address')
            candidate = '.'.join(str(int(octet)) for octet in octets)
    address = ipaddress.ip_address(candidate)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)  # ::ffff:203.0.113.9 is 203.0.113.9: pivot on one entity
    return address.compressed


def _canonical_hash(kind: str, value: str) -> str:
    digest = ''.join(value.split()).lower()
    if HASH_KINDS.get(len(digest)) != kind or not re.fullmatch(r'[0-9a-f]+', digest):
        raise ValueError(f'Not a {kind} digest')
    return digest


def canonical(kind: str, value: str) -> str:
    """Canonical form used to de-duplicate entities. ``value`` may be the raw (even defanged) source text.

    Raises ``ValueError`` (or ``UnicodeError``) if ``value`` is not a valid instance of ``kind``.
    """
    if kind == 'cve':
        if not _CVE.fullmatch(value):
            raise ValueError('Invalid CVE identifier')
        return value.upper()
    if kind == 'ip':
        return _canonical_ip(value)
    if kind == 'cidr':
        candidate = refang(value)
        if not _CIDR.fullmatch(candidate):
            raise ValueError('Expected a network address and numeric prefix length')
        network = ipaddress.ip_network(candidate, strict=True)
        if network.prefixlen == 0:
            # 0.0.0.0/0 and ::/0 mean every address (firewall and cloud rules): never an indicator.
            raise ValueError('A /0 range covers every address')
        address = network.network_address
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            # Python versions differ on how they print mapped IPv6; keep one stable entity across upgrades.
            return f'::ffff:{address.ipv4_mapped}/{network.prefixlen}'
        return str(network)
    if kind == 'url':
        return _canonical_url(value)
    if kind == 'domain':
        return _canonical_domain(value)
    if kind == 'email':
        return _canonical_email(value)
    if kind in HASH_KINDS.values():
        return _canonical_hash(kind, value)
    raise ValueError(f'Unknown kind: {kind}')


# --------------------------------------------------------------------------- extraction


def _trim_url(url: str) -> str:
    """Drop sentence punctuation and unbalanced closing brackets (``(see https://x/a).`` → ``https://x/a``)."""
    previous = None
    while url != previous:
        previous = url
        url = url.rstrip('.,;:!?\'"*')
        for opener, closer in ('()', '[]', '{}'):
            if url.endswith(closer) and url.count(opener) < url.count(closer):
                url = url[:-1]
    return url


def _host_span(url: str) -> tuple[int, int] | None:
    """Offsets of a domain host inside ``url`` (None for IP literals and hosts without a dot)."""
    authority_start = url.index('//') + 2
    authority_end = len(url)
    for separator in '/?#':
        found = url.find(separator, authority_start)
        if found != -1:
            authority_end = min(authority_end, found)
    host_start = url.rfind('@', authority_start, authority_end) + 1 or authority_start
    host_start = max(host_start, authority_start)
    if url.startswith('[', host_start):
        return None
    colon = url.find(':', host_start, authority_end)
    host_end = colon if colon != -1 else authority_end
    host = url[host_start:host_end]
    if '.' not in host.strip('.') or _IPV4_SHAPE.fullmatch(host):
        return None
    return host_start, host_end


def _is_word_char(char: str) -> bool:
    return char.isalnum() or char in ZERO_WIDTH or unicodedata.category(char).startswith('M')


Span = tuple[int, int]


def _within(spans: list[Span], start: int, end: int) -> bool:
    """True if ``[start, end)`` lies entirely inside one of ``spans``."""
    return any(s <= start and end <= e for s, e in spans)


def _is_fragment(work: str, start: int, end: int) -> bool:
    """True if the match is part of a larger token (e.g. the ASCII tail of a homoglyph domain)."""
    before = work[start - 1] if start > 0 else ' '
    after = work[end] if end < len(work) else ' '
    return (not before.isascii() and _is_word_char(before)) or (not after.isascii() and _is_word_char(after))


def _is_ambiguous_name(work: str, start: int, end: int) -> bool:
    """A bare two-label name whose TLD is also a common file extension (``update.zip``, ``setup.py``)."""
    labels = work[start:end].rstrip('.').lower().split('.')
    return len(labels) == 2 and labels[-1] in AMBIGUOUS_TLDS


class _Mentions:
    """Collects validated mentions of one text, keyed by kind and original span.

    Matching runs on the refanged working copy (``work``); :meth:`add` maps each match back to the original
    text, canonicalises it and records it once, with evidence taken from the text as submitted.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.view = _refang_view(text)
        self.work = self.view.text
        self.found: dict[tuple[str, int, int], Mention] = {}

    def add(self, kind: Kind, start: int, end: int) -> bool:
        """Record ``work[start:end]`` as ``kind``. False if it is not a valid instance of that kind."""
        original_start, original_end = self.view.original_span(start, end)
        raw = self.text[original_start:original_end]
        try:
            value = canonical(kind, raw)
        except (ValueError, UnicodeError):
            return False
        key = (kind, original_start, original_end)
        if key not in self.found:
            evidence = self.text[max(0, original_start - EVIDENCE_CONTEXT) : original_end + EVIDENCE_CONTEXT]
            self.found[key] = Mention(kind, value, original_start, original_end, evidence)
            if len(self.found) > MAX_MENTIONS:
                raise ValueError(
                    f'Document exceeds {MAX_MENTIONS:,} extracted mentions; split it into smaller documents.'
                )
        return True

    def in_order(self) -> list[Mention]:
        return sorted(self.found.values(), key=lambda m: (m.start, m.kind))


def _add_urls(mentions: _Mentions) -> list[Span]:
    """URLs, plus the domain host of each URL. Returns the URL spans (domains inside them are not re-read)."""
    url_spans: list[Span] = []
    for match in _URL.finditer(mentions.work):
        url = _trim_url(match.group())
        start, end = match.start(), match.start() + len(url)
        if mentions.add('url', start, end):
            url_spans.append((start, end))
            host = _host_span(url)
            if host is not None:
                mentions.add('domain', start + host[0], start + host[1])  # the only domain a URL contributes
    return url_spans


def _add_emails(mentions: _Mentions) -> None:
    """Record a whole mailbox once, then mask it so later passes cannot extract any of its parts."""
    if '@' not in mentions.work:
        return

    def record(match: re.Match[str]) -> str:
        start, end = match.span()
        if match.group('mailto'):
            start = match.end('mailto')
            recipient = mentions.work[start:end].partition('?')[0].rstrip(".,;:!')}]")
            if recipient:
                mentions.add('email', start, start + len(recipient))
        elif match.group('uri'):
            return match.group()  # Leave HTTP(S) URLs for the URL pass.
        else:
            if mentions.work[start] == "'" and mentions.work[end : end + 1] == "'":
                start += 1  # Prose quotes are outside the evidence span.
            mentions.add('email', start, end)
        # Mask even malformed mailbox tokens so later passes cannot misread a part as a different indicator.
        return '\0' * len(match.group())

    mentions.work = _URI_OR_EMAIL.sub(record, mentions.work)


def _add_domains(mentions: _Mentions, url_spans: list[Span]) -> None:
    """ASCII and international domain names outside URLs, skipping fragments and file-like names."""
    work = mentions.work
    for match in _DOMAIN.finditer(work):
        start, end = match.span()
        if (
            not _within(url_spans, start, end)
            and not _is_fragment(work, start, end)
            and not _is_ambiguous_name(work, start, end)
        ):
            mentions.add('domain', start, end)
    for match in _IDN.finditer(work):
        start, end = match.span()
        if match.group().isascii() or _within(url_spans, start, end):
            continue  # pure-ASCII names are handled (more strictly) above
        if not _is_ambiguous_name(work, start, end):
            mentions.add('domain', start, end)


def _add_ips(mentions: _Mentions, url_spans: list[Span]) -> None:
    """IPv4 and IPv6 addresses and standalone CIDR networks."""
    work = mentions.work
    for match in _CIDR.finditer(work):
        start, end = match.span()
        if (
            not _within(url_spans, start, end)
            and not _is_fragment(work, start, end)
            and not _VERSION_CONTEXT.search(work[max(0, start - 24) : start])
        ):
            mentions.add('cidr', start, end)
    for match in _IPV4.finditer(work):
        start, end = match.span()
        if not _VERSION_CONTEXT.search(work[max(0, start - 24) : start]):
            mentions.add('ip', start, end)
    for match in _IPV6.finditer(work):
        mentions.add('ip', *match.span())


def _add_hashes(mentions: _Mentions) -> None:
    """MD5/SHA1/SHA256/SHA512 digests, including digests wrapped onto the next line."""
    joined: list[Span] = []
    for match in _WRAPPED_HEX.finditer(mentions.work):
        first, second = len(match.group(1)), len(match.group(2))
        kind = HASH_KINDS.get(first + second)
        # An even split into two valid lengths (e.g. 32 + 32) is indistinguishable from a list of two hashes.
        if (
            kind is not None
            and not (first in HASH_KINDS and second in HASH_KINDS)
            and mentions.add(kind, *match.span())
        ):
            joined.append(match.span())
    for match in _HEX.finditer(mentions.work):
        start, end = match.span()
        kind = HASH_KINDS.get(end - start)
        if kind is not None and not _within(joined, start, end):
            mentions.add(kind, start, end)


def _add_cves(mentions: _Mentions) -> None:
    for match in _CVE.finditer(mentions.work):
        mentions.add('cve', *match.span())


def extract(text: str) -> list[Mention]:
    """Extract observable mentions with exact offsets into ``text``, sorted by position.

    Raises ``ValueError`` if the text yields more than :data:`MAX_MENTIONS` mentions. The passes run in a
    fixed order (mailboxes first to protect their components, then URLs before standalone names).
    """
    mentions = _Mentions(text)
    _add_emails(mentions)
    url_spans = _add_urls(mentions)
    _add_domains(mentions, url_spans)
    _add_ips(mentions, url_spans)
    _add_hashes(mentions)
    _add_cves(mentions)
    return mentions.in_order()

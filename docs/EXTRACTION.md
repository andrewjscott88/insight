# Indicator extraction (`regex-v5`)

`insight/extraction.py` turns report text into **mentions**: kind, canonical value, exact character offsets and
surrounding evidence. It is deterministic. It never judges maliciousness or attributes activity; accepting an
observation means "this extraction is accurate", not "this is bad".

## Design rule: a wrong indicator is worse than a missed one

A missed indicator is visible in the evidence text. A *wrong* one, such as a truncated domain or a
neighbouring IP address, sends an analyst after the wrong infrastructure. Every rule below prefers dropping an
uncertain candidate over emitting something that was not in the source.

## Pipeline

1. **Refang.** A working copy replaces defanging with the real characters: `hxxp`/`hxxps`/`h**p` → `http(s)`;
   `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)` → `.`; `[:]` → `:`; `[://]` → `://`. A position map keeps every
   match tied to the **original** text, so offsets and evidence show what the author wrote.
   The URL pass also recognizes a bracketed web scheme such as `[https]://` at the start of a URL.
   Only the mailbox pass treats `[@]`, `[at]` or `(at)` as an at-sign.
2. **Match** candidates per kind (patterns are ASCII-only, except for international names).
3. **Validate and canonicalise** each candidate (table below). Invalid candidates are dropped.
4. **Context rules** (below) remove candidates that are fragments or misreadings.

Invariant, property-tested on random input: `canonical(kind, text[start:end]) == value` for every mention,
and the raw span always appears in its evidence.

In code, `extract()` creates one `_Mentions` collector (steps 1 and 3: the refanged view, the position map and
`add()`, which validates, canonicalises and records each candidate once) and runs one pass per family in a fixed
order. The e-mail pass records each mailbox and masks its span in the working copy. The URL, domain, IP,
hash and CVE passes see the surrounding text. This keeps an address such
as `CVE-2024-12345@example.org` together as one observation and preserves its original evidence.

## Kinds and canonical forms

| Kind | Matches | Canonical value |
| --- | --- | --- |
| `cve` | `CVE-YYYY-NNNN…` (4+ digits, any case) | Upper case |
| `url` | `http://` / `https://` up to whitespace, quotes, `<>`, `` ` ``, `\|` | Lower-case scheme and host, IDNA host, **credentials removed**, port/path/query/fragment kept verbatim |
| `domain` | Dotted names with a **known TLD**; international names | Lower case, punycode (`xn--…`), no trailing dot |
| `email` | Mailbox with a dotted domain, e.g. `Desk+Alert@EXAMPLE.org` | `Desk+Alert@example.org`. The mailbox name keeps its case. The domain uses the same lower-case IDNA form as domain indicators. |
| `ip` | IPv4, IPv6 (including embedded IPv4, bracketed, with ports or zone IDs) | Compressed; IPv4-mapped IPv6 → the IPv4 address |
| `cidr` | IPv4 or IPv6 network address and prefix length | Compressed network address with the prefix, e.g. `2001:db8::/32` |
| `md5`, `sha1`, `sha256`, `sha512` | Hex runs of exactly 32/40/64/128 characters | Lower case |

## Context rules

| Rule | Example | Result |
| --- | --- | --- |
| No fragments of a larger token | `exаmple-login.com` (Cyrillic а), `exam⁠ple.com` (zero-width space) | Whole name as punycode or cleaned: `xn--exmple-login-y9j.com`, `example.com`; never `mple-login.com` / `ple.com` |
| International names | `café-login.example` (NFC or NFD), `bücher.example` | NFC-normalised, then IDNA: `xn--caf-login-d4a.example` |
| Known TLD required | `svchost.exe`, `Net.WebClient`, `logon.aspx` | Not domains. TLDs come from the bundled ICANN list plus special-use names: `example`, `test`, `invalid`, `localhost`, `onion`, `local`, `internal`, `lan`, `corp`, `home`, `intranet`. |
| Ambiguous TLDs | `update.zip`, `setup.py`, `build.sh`, `subprocess.run`, `user.name` | Two-label names whose TLD is also a file extension or code member are accepted **only as URL hosts** (`https://invoice.zip/` → domain `invoice.zip`) |
| Domains come from URL hosts, not paths | `https://a.example/b.js` | Domain `a.example` only; `b.js` is not a domain |
| Service labels | `_dmarc.example.com`, `_sip._tcp.example.com` | Kept (leading underscore per label) |
| CIDR ranges | `203[.]0[.]113[.]0/24`, `2001:0DB8::/32` | Each produces one network range. Its evidence keeps the original spelling. |
| Invalid or ambiguous ranges | `203.0.113.0/33`, `203.0.113.17/24` | Skipped. The first prefix is too long for IPv4. The second address has host bits set, so interpreting it as a network would change the stated address. |
| Every address | `0.0.0.0/0`, `::/0` | Skipped. Reports use these in firewall and cloud rules ("allowed from 0.0.0.0/0"); they are not indicators. |
| Version context | `firmware 10.2.9.1`, `version 9.0.0.1`, `build: 7.1.0.2`, `section 1.2.3.4` | Not IPs. Keywords: version, ver, v, firmware, fw, build, release, agent, patch, section, chapter, step. |
| Zero padding | `192.000.002.033` | `192.0.2.33` when every octet has 3 digits (fixed-width logs); `010.1.2.03` is rejected as ambiguous (octal?) |
| IPv4-mapped IPv6 | `::ffff:203.0.113.9` | `203.0.113.9`: one entity to pivot on, never the truncated `::ffff:203` |
| Zone IDs | `fe80::1%eth0` | `fe80::1` (the zone is host-local context) |
| Wrapped hashes | 48 hex + newline + 16 hex | Joined into one SHA-256. An **even** split into two valid lengths (32 + 32) is kept as two hashes, because it cannot be told apart from the common one-hash-per-line list. |
| URL punctuation | `(see https://x/a).`, `https://en.wikipedia.org/wiki/Foo_(bar)` | Trailing punctuation and *unbalanced* closing brackets are trimmed; balanced ones are kept |
| E-mail addresses | `Analyst+Case@Example[.]org` | One `email` indicator, `Analyst+Case@example.org`, flagged as personal data. The original spelling stays in the evidence. |

E-mail extraction covers common unquoted ASCII mailbox names and dotted domains with a recognized suffix.
A `mailto:` link with a single explicit recipient contributes that recipient's address.
The extractor skips quoted mailbox names, IP-literal domains, and addresses embedded in web URLs.

Limits: at most 2,000 mentions per document (larger documents are rejected with a message to split them),
and 90 characters of evidence on each side.

## Offsets

`start_offset`/`end_offset` are **Unicode code-point** indices (Python string indices). JavaScript strings are
UTF-16, so after astral-plane characters such as emoji the same numbers point one character further on per
emoji. The API therefore also returns `start_offset_utf16`/`end_offset_utf16`. Use those with
`String.prototype.slice`.

## Measuring quality

`tests/corpus/extraction.json` holds labelled snippets and points to two full synthetic reports. Three snippets
quote U.S. government-authored advisories. Each carries its author, page, source URL and reuse basis.
The defanged examples are synthetic and use reserved names. The bracketed scheme follows the
[Safe-IOC Internet-Draft](https://www.ietf.org/archive/id/draft-grimminck-safe-ioc-sharing-14.html).

```sh
python scripts/benchmark_extraction.py                    # compare with benchmarks/extraction-baseline.json
python scripts/benchmark_extraction.py --report out.md    # Markdown report with every miss and false positive
python scripts/benchmark_extraction.py --update-baseline  # after a reviewed, intentional change
```

CI fails if any kind loses more than one point of precision or recall. If the corpus itself changed, it says
"corpus changed" instead of reporting false regressions. On the same 39 corpus entries, `regex-v4` scored
94.8% precision and 95.7% recall. `regex-v5` scored 98.3% precision and 99.1% recall.
Its remaining miss is the SHA-256 split across two table
rows in SALT MERIDIAN. The two halves appear as MD5 values. These scores describe this corpus.

## Maintaining the TLD list

`src/insight/data/tlds.txt` is derived from the Public Suffix List (MPL-2.0; see `NOTICE`). Refresh it a few
times a year:

```sh
curl -sSfO https://publicsuffix.org/list/public_suffix_list.dat
python scripts/update_tlds.py public_suffix_list.dat
python scripts/benchmark_extraction.py
```

## Adding or changing a rule

1. Add a failing case to `tests/unit/test_extraction.py`. If it comes from a real report, add a labelled
   snippet to `tests/corpus/extraction.json` too. A rule that belongs to one pass can also be pinned directly
   in `tests/unit/test_extraction_passes.py`.
2. Change the responsible pass or predicate in `extraction.py` and keep the invariant
   (`canonical(kind, raw) == value`).
3. Run the benchmark; if quality improved on purpose, update the baseline in the same pull request.
4. If canonical values change, bump `EXTRACTOR_VERSION` and note it in `CHANGELOG.md`. Stored observations keep
   the version that produced them.

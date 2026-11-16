# ADR 0007: Extraction: a wrong indicator is worse than a missed one

Status: accepted (0.2.0)

## Context
Synthetic reports showed the `regex-v1` extractor fabricating indicators:
- `mple-login.com` from a homoglyph domain;
- `::ffff:203` from `::ffff:203.0.113.9`;
- two MD5s from a wrapped SHA-256 (in the uneven case);
- domains from file names and URL paths.

## Decision
`regex-v2` refangs with an offset map, validates TLDs against a bundled ICANN list, rejects fragments of larger
tokens, extracts international names as punycode, takes domains only from URL hosts (not paths), and applies
context rules (CIDR, version numbers, ambiguous file-extension TLDs). Ambiguous cases, such as an even 32 + 32
hex split, keep the safe reading.

## Consequences
Corpus precision went from 67.8% to 97.9% and recall from 78.4% to 98.9%. Older documents keep `regex-v1`
observations. The TLD list needs periodic refreshes (`scripts/update_tlds.py`).

# ADR 0008: Search on a folded copy of the text

Status: accepted (0.2.0)

## Context
SQLite's `lower()` folds only ASCII, so `überwachung` and `istanbul` found nothing there but did on
PostgreSQL. Neither database matched NFC queries against NFD text.

## Decision
`documents.search_text` stores `fold(title, source, body)`: NFKD, strip combining marks and zero-width
characters, casefold, NFC. Queries are folded the same way and matched with `LIKE`. Watch terms use the same
function. Migration `0003` backfills it.

## Consequences
Search is identical on both databases and insensitive to case, accents, width and normal form. It is also
accent-insensitive (`cafe` finds `café`) and ignores Japanese voicing marks, a deliberate recall-over-precision
choice for search (not for indicators). Text storage roughly doubles.

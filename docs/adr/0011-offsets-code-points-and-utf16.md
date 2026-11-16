# ADR 0011: Evidence offsets: code points, plus UTF-16 for JavaScript

Status: accepted (0.2.0)

## Context
Offsets index Python strings (code points). After astral-plane characters (emoji) they are off by one per
character in JavaScript, where strings are UTF-16: 25-31 of ~50 highlights were wrong in a browser test.

## Decision
Stored offsets stay code points (stable, matching `body` in Python). The API adds computed
`start_offset_utf16`/`end_offset_utf16`.

## Consequences
No migration is needed. A browser test proves JavaScript slicing with the UTF-16 fields is exact.

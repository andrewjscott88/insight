# ADR 0009: TLP: default AMBER; markings can only raise the label

Status: accepted (0.2.0)

## Context
The API defaulted to TLP:CLEAR while the UI defaulted to AMBER. A report marked TLP:RED was stored as CLEAR (API)
or AMBER (UI).

## Decision
The default is AMBER everywhere. A `TLP:` marking in the title or body raises the label to the most restrictive
marking found; it never lowers it. The raise is audited, returned by the API (`tlp_raised_from`) and shown in the
UI. Connectors label public feeds CLEAR explicitly.

## Consequences
This fails safe: a text that merely *discusses* TLP:RED is over-restricted, and the warning explains why.
Clients that relied on the CLEAR default must now send `tlp` explicitly.

# ADR 0014: A TLP limit per API key, enforced in the service layer

Status: Accepted

## Context
The API key of ADR 0012 reads everything the instance stores. A SIEM or script rarely needs AMBER or
AMBER+STRICT material, and a leaked key exposes all of it. ADR 0003 makes `services` the only query layer.

## Decision
A key may carry `max_tlp` (`insight api-key create --max-tlp GREEN`). The API passes the caller's limit to
every service function that reads or changes reports (`max_tlp=`); `services` turns it into one SQL condition
on `Document.tlp`. Reports above the limit behave exactly like missing ones (absent from lists and counts,
`404` otherwise); entities seen only in such reports do not exist for the key; IOC exports use the stricter of
the requested and the key's `max_tlp`; the key cannot store a report above its limit. Routes that span all
reports and cannot be filtered meaningfully (the audit log, CVE enrichment's "is this CVE known" check) are
refused for limited keys. The operator's session is never limited.

## Consequences
A leaked GREEN key exposes GREEN and CLEAR reports only. Two tests guard it: a sweep of every API route for a
marker planted in an AMBER report, and an architecture test that fails when an API route (`insight/web/`, formerly `main.py`) calls a report query
without `max_tlp`. New report queries must accept the parameter. Watch terms and source-run messages are not
report data and stay visible.

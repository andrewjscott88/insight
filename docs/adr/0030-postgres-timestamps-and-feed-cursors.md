# ADR 0030: Native PostgreSQL timestamps and resumable OTX syncs

Status: accepted (unreleased)

## Context
Issue #11 (milestone M2) asked for three things: native datetime columns on PostgreSQL, cursor-based resume
for feeds tested with fake feeds, and a tighter PostgreSQL performance budget. Timestamps were ISO-8601 text on
both databases, which sorts correctly only because every writer uses `models.now()`, and PostgreSQL could not
compare, index or validate them as moments. SQLAlchemy's `DateTime(timezone=True)` drops the offset on SQLite
(docs/ARCHITECTURE.md), and hundreds of call sites read, slice and compare these values as strings.

## Decision
1. **`models.UtcTimestamp`.** A column type that is `timestamptz` on PostgreSQL and the same `VARCHAR(40)` on
   SQLite. Python always sees the ISO-8601 UTC string it saw before: values bound to it (including in
   comparisons such as `created_at >= since`) are read as moments, a string without an offset as UTC, and
   moments come back as `isoformat()` in UTC whatever the session time zone. No call site changes.
2. **Migration 0022** converts 48 timestamp columns on PostgreSQL in one transaction (`SET LOCAL TIME ZONE
   'UTC'`, `USING NULLIF(col, '')::timestamptz`); a value that is not a moment stops the upgrade and changes
   nothing. Downgrade writes the same text form back. SQLite is untouched. Two columns stay text because `''`
   means "never" there (`alerts.sent_at`, `alert_targets.last_sent_at`); converting them would mean rebuilding
   SQLite tables that other tables reference with cascading keys. Dates stay text (`kev_records.date_added`,
   `due_date`, hunt periods).
3. **Resumable OTX syncs (migration 0023, `fetch_state.cursor`).** OTX is the only paged feed. A sync reads up
   to four pages of 25 pulses from a saved cursor: `modified_since` plus the next page of the current pass.
   Each page is stored together with the cursor after it, so a failure or the page limit leaves the next sync
   to continue from the next page; when a pass reaches OTX's last page, the newest `modified` seen becomes
   `modified_since`. OTX's `next` link is only a signal and is never followed. A damaged cursor starts over.
   Other feeds are single documents and already skip unchanged downloads (ETag, `Last-Modified`, hash).
4. **A PostgreSQL budget.** The gate measures PostgreSQL against `benchmarks/performance-budget-postgres.json`:
   about three times the CI runner's results (ingest 20 s, search p95 80 ms, detail p95 25 ms for 1,000
   reports) instead of the general pilot ceilings (60 s, 250 ms, 100 ms).

## Consequences
- PostgreSQL deployments get real time columns: correct comparison across offsets, smaller indexes, and
  database-side checks that a timestamp is a moment.
- A PostgreSQL upgrade rewrites the converted tables once; back up first and expect a short lock on large
  `audit_events` and `observations` tables.
- OTX reads more than its first page and catches up on a backlog over several syncs instead of skipping it.
- Tests run on both databases; a PostgreSQL-only migration test covers offsets, `Z`, naive legacy values and a
  non-UTC session.

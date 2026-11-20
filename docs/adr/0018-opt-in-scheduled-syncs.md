# ADR 0018: Opt-in scheduled syncs with an in-process job runner

Status: accepted (unreleased)

## Context
Until now Insight went online only when someone pressed **Sync now** (or, since the landing-page work, **Sync
all sources**). That kept outbound traffic visible and predictable. However, the intel brief is only as fresh as
the last sync, and the operator expected Insight to "pull the feeds down" by itself. The 0.5.0 review found the
same gap (finding B1: no job model; Design 2).

Two constraints shape the answer:

- **One process.** NiceGUI keeps browser state in the server process (ADR 0003), so Insight runs one worker.
  A broker (Redis, Celery) would add a service to deploy, back up and secure, for four feeds.
- **No surprise traffic.** An instance that someone upgrades must not start contacting publishers on its own.

## Decision
1. **Schedules are off by default and opt-in per source.** The operator chooses *Off*, *Every hour*, *Every 6
   hours* or *Every day* in the Sources tab, with `insight schedule` on the host, or with `PUT
   /api/schedules/{key}` from a browser session. API keys may read schedules but never change them: how often
   Insight goes online by itself is the operator's decision, not a script's. Changes are audited
   (`schedule.update`).
2. **Jobs live in the database** (`jobs`, migration 0006). A partial unique index allows at most one queued or
   running job per `(kind, key)`. A job is claimed with a conditional update (`... WHERE status = 'queued'`), so
   two runners can never take the same job. On PostgreSQL with several workers, `FOR UPDATE SKIP LOCKED` would
   be the next step; one worker does not need it.
3. **One in-process runner** (`insight.jobs`), started with the app when `INSIGHT_RUN_JOBS=on` (the default for
   `insight serve`; settings built in code default to off, so tests and tools never start one). It wakes every
   15 seconds, queues due schedules, and runs jobs one at a time under the same lock as Sync now, so a schedule
   and a person never sync at the same moment. At start-up it takes back jobs that a stopped process left
   running.
4. **Retries with back-off.** A failed sync is tried again after 5, then 10 minutes, then marked `failed`. Every
   attempt is also a `SourceRun`, so *Recent sync activity* shows exactly what happened. A schedule's next run
   counts from when it ran, so a server that was off for days does not catch up with a burst.
5. **Fetch less.** `fetch_state` (also migration 0006) keeps each URL's `ETag`, `Last-Modified` and payload
   SHA-256. Syncs send `If-None-Match` / `If-Modified-Since`; a `304`, or the same bytes as last time, records
   `Unchanged since the last sync.` and writes nothing else. A new Insight version re-reads every source once,
   in case its parsing changed. State is saved only in the transaction that stored the data, and not when CISA
   advisories were skipped, so failures are always retried.

## Consequences
- Insight can now go online without a click, but only for sources the operator scheduled, only to the curated
  hosts, and visibly: the Sources tab shows the next sync, the log names every enabled schedule at start-up, and
  every run is recorded. Egress allow-lists need no new hosts.
- A schedule set on a server that runs with `INSIGHT_RUN_JOBS=off` is saved but does nothing; the workspace
  says so instead of pretending.
- Running several processes needs `INSIGHT_RUN_JOBS=off` in all but one (start-up recovery would otherwise take
  over jobs that another process is running).
- Manual syncs still run inline, so the person who pressed the button sees the result. Moving them onto the
  queue (`?wait=false` returning `202` and a job ID) can come later without a schema change.
- Finished jobs are pruned after 30 days.

# ADR 0001: Alembic owns the schema; datetime columns deferred

Status: accepted (0.2.0)

## Context
0.1.0 created tables with `create_all`, so no schema change could ship safely. Timestamps are ISO-8601 UTC
strings.

## Decision
Alembic migrations ship inside the package and run at every start-up. Revision `0001` reproduces the 0.1.0
schema exactly (verified against the original models on SQLite and PostgreSQL). Unversioned 0.1.0 databases are
stamped at `0001`, then upgraded. Migrations never import application code; they snapshot any logic they need.

Timestamps stay strings. Converting them pays off only with PostgreSQL's `timestamptz`, and SQLAlchemy's
`DateTime(timezone=True)` **silently drops UTC offsets on SQLite** (verified: `12:00+05:00` is read back as
`12:00`).

## Consequences
- CI proves that every revision is reversible, that models equal migrations, and that every released
  database upgrades.
- A future datetime migration needs a UTC-normalising `TypeDecorator` and a data migration.

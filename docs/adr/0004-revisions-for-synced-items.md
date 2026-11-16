# ADR 0004: Publisher edits become revisions, never edits or duplicates

Status: accepted (0.2.0)

## Context
A changed KEV description created a duplicate report. Editing stored bodies in place would invalidate the
exact evidence offsets.

## Decision
Synced items carry `(source_key, external_id)`. Changed content creates a new document that `supersedes` the
old one. A partial unique index allows one current revision per item. A revert re-activates the earlier
revision. Migration `0002` links existing duplicates.

## Consequences
The inbox shows current revisions; history stays available as evidence. Deleting a revision must repair the
chain (RUNBOOK §9).

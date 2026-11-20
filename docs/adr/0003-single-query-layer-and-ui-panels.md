# ADR 0003: One query layer; UI split into panel modules

Status: accepted (0.2.0). Since 0.6.0 the layer is the `insight.services` package, one module per domain, with the
same rule.

## Context
The API and UI each built their own SQL, and their search semantics drifted apart. `ui.py` was one ~600-line
function.

## Decision
`services.py` is the only SQL layer. `main.py` and `insight/ui/*` call it. The UI is one module per panel,
with typed per-tab state (`WorkspaceState`) and navigation hooks on `Workspace`. An architecture test
forbids SQL builders in front ends and ORM imports in the UI.

## Consequences
Behaviour (search, revisions, auditing, TLP policy) is identical across front ends. UI modules stay under 300
lines (tested).

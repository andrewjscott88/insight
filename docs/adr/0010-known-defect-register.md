# ADR 0010: Known defects as strict expected-failure tests

Status: accepted (0.2.0)

## Decision
Defects that are found but not yet fixed are written as tests marked `xfail(strict=True)` with a reason. CI
stays green; fixing a defect turns its test red until the marker is removed.

## Consequences
The register cannot drift from reality. In 0.2.0 all eight registered defects were fixed and their tests became
ordinary regression tests.

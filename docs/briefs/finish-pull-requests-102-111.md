# Brief: finish and merge pull requests #102–#111

Required for 1.0 (TIP 4.6, 4.7 and 4.8, plus two fixes). Read [AGENTS.md](../../AGENTS.md) first.

## Where things stand (22 November 2026)

Andrew had Claude review the ten pull requests. The work is good: thorough tests, no new dependencies, and nothing
weakens a security control. What stands between them and `main` is the list below. `main` moved on after they
were opened: #101 (TIP 4.4a, intelligence products) merged as `a0c08ed` and added migration `0028`. Eight of
the ten now conflict with `main` in small ways (the ADR index, test registries, `services/__init__.py`,
`web/app.py`, `ROADMAP.md`). #105 and #107 still merge cleanly.

| Pull request | Item | Before it can merge |
| --- | --- | --- |
| #107 | Descriptor under the Insight name | Nothing: checks pass |
| #105 | Login entry from external links (temporary open access) | Fix 3 (rerun) |
| #102, #104, #103 | TIP 4.7 parts 1–3 | Fix 1 (migrations), rebase |
| #111, #109 | TIP 4.8 parts 1–2 | Fix 2 (CodeQL), rebase |
| #106, #108, #110 | TIP 4.6 parts 1–3 | Fix 3 (rerun) for #106, rebase |

## Fixes

1. **Migration numbers (#104, #103).** Both use revision `0028`, which `main` now has
   (`0028_intelligence_products.py`). GitHub may still call them mergeable, but merging either one as it is
   gives Alembic two revisions with the same ID and breaks `main`. Renumber #104 to `0029` (`down_revision`
   `'0028'`), then #103 to `0030` (`down_revision` `'0029'`). Rename the files, fix the upgrade notes in
   `CHANGELOG.md`, and run the migration round trip on SQLite and PostgreSQL after each.
2. **CodeQL alert (#111, #109).** CodeQL reports "Information exposure through an exception" at
   `src/insight/web/routes/mcp.py:183`: `str(exc)` and `exc.data` from `MetadataError` go into the JSON-RPC
   error. The messages are fixed today, so nothing leaks, but the rule is no new alerts, and a later message
   could carry request input. Send constant messages chosen by the kind of error (for example a table keyed by
   a constant the exception carries, never its text), and build the unsupported-version `data` in the route
   from the validated request, not from the exception. Fix it once in the shared transport in #111 and carry
   it into #109. Do not dismiss the alert.
3. **Reruns.**
   - #106: `tests/ui/test_workspace.py::test_enrichment_dialog_requires_consent` failed on Python 3.11 only,
     in both CI and the milestone gate. It passes locally and looks like a timing flake. Rerun it. If it fails
     again, find out whether the pivot changes slow the enrichment dialog, and fix the cause with a
     `Regression:` test. Do not lengthen the test's wait.
   - #105: the Python 3.12 job reached its 20-minute limit at 93% of the tests. That was a slow runner, not a
     hang. Rerun it.
4. **Test time.** The test jobs take about 15 minutes against a 20-minute limit (`timeout-minutes: 20` on job
   `test` in `.github/workflows/ci.yml`), and these pull requests add several hundred tests. First, in a small
   pull request of its own, raise that limit to 30 minutes. Change no other job, and do not skip or deselect
   tests to save time.

## Merge order

The parts of each item were built independently, so the later parts carry their own copy of the shared code:
the pivot foundation in 4.6, the MCP transport in 4.8. Merge part 1, then rebase each later part onto the new
`main`. Keep one copy of the shared code and the **union** of every registry: providers and their kinds,
throttles and retention keys, MCP tools, routes, `PROTECTED` entries, GREEN-key sweep paths and planted AMBER
data, glossary terms, documentation sections and changelog lines. Taking one part's version of a registry
removes the other part's features: the combined code keeps every provider and every tool, with their tests.

1. The test-time pull request (fix 4).
2. #107, then #105.
3. TIP 4.7: #102, then #104 (migration `0029`), then #103 (migration `0030`). Keep both
   `Campaign.updated_at` and `ThreatLink.updated_at` in the STIX and TAXII projections, and keep all three
   sections of ADR 0038.
4. TIP 4.8: #111 (with fix 2), then #109 (one transport, all eight tools).
5. TIP 4.6: #106, then #108, then #110 (one pivot foundation; `rdap`, `asn`, `crtsh` and `circl` all
   registered; the credential check applies to `circl` only).

Before each merge, CI, the milestone gate and CodeQL ("No new alerts in code changed by this pull request")
must pass on the rebased head. Merge with a merge commit, and only if Andrew asked you to merge (AGENTS.md);
otherwise stop when the pull request is ready and say so. Never tag or start a release.

Claude is building TIP 4.4b (PDF export of intelligence products) at the same time. It touches the product
modules and the documentation; whichever lands second rebases.

## Done when

All ten are merged in the order above, or closed with a reason. After the last part of each item:

- mark it done in `ROADMAP.md`, `docs/ROADMAP-TIP.md` (the checklist too) and `README.md`;
- set its ADR's status to Accepted;
- delete its brief and its row in [README.md](README.md).

Then run the full SQLite and PostgreSQL suites and the milestone gate on `main`, and delete this brief and its
row in the same way.

# Releasing

Versioning is semantic. A release is one tag, `vX.Y.Z`. The release workflow runs the whole milestone gate on
that commit, then waits for your approval before it publishes anything. Release candidates (`vX.Y.Z-rc.N`) are
optional dry runs of the gate.

## 1. Prepare (pull request)

1. Bump `__version__` in `src/insight/__init__.py`. It is the single source: packaging reads it.
2. `CHANGELOG.md`: rename `## Unreleased` to `## X.Y.Z - YYYY-MM-DD`.
3. `docs/VALIDATION.md`: record what was validated for `X.Y.Z`.
4. Create the upgrade fixture for this version and commit it:
   ```sh
   python scripts/make_release_fixture.py        # writes tests/fixtures/releases/insight-X.Y.Z.sqlite3
   ```
   Without a local environment, run the **Release fixture** workflow (Actions → Release fixture → Run workflow)
   on the release branch instead: it runs the same script and commits the file.
   From now on, every future version's CI upgrades this database. A migration that would break it fails
   before release.
5. If the extractor improved on purpose, update the benchmark baseline:
   `python scripts/benchmark_extraction.py --update-baseline`.
6. Merge once Tier 1 is green.

## 2. Optional dry run

To see the gate's result before tagging, run it on `main` (or the release branch): **Actions → Milestone gate →
Run workflow**. A release-candidate tag (`git tag -s vX.Y.Z-rc.1 && git push origin vX.Y.Z-rc.1`) does the same
and also checks the release metadata. Neither is required.

## 3. Release

```sh
git tag -s vX.Y.Z && git push origin vX.Y.Z
```

`release.yml` runs, in one workflow run:

1. **Pre-release checks**: version, changelog, validation report, upgrade fixture, strict pins (a minute).
2. **Milestone gate**: Tier 1 on Python 3.11 to 3.15 and PostgreSQL, extraction benchmark, performance budget
   on both databases, backup drill, browser E2E with axe, signed-in OWASP ZAP, licences and SBOM (about 15
   minutes). Its reports are artifacts of this run.
3. **Approval**: publishing waits in the `release` environment until a required reviewer approves.
4. **Publish** (wheel, image with SBOM and provenance, cosign signature, attestations, GitHub Release), then
   **verify** the published image by digest.

Nothing is published before step 4. If the checks or the gate fail, delete the tag (`git push --delete origin
vX.Y.Z && git tag -d vX.Y.Z`), fix the problem on `main`, and tag again. The tag was never released, so reusing
it is safe; a dry run first avoids this.

## Checklist for the approver

- [ ] The milestone gate in this release run is green; benchmark and ZAP reports reviewed.
- [ ] `CHANGELOG.md` describes user-visible changes and any manual upgrade steps.
- [ ] New migrations were reviewed (data-preserving, reversible, tested on both databases).
- [ ] `docs/VALIDATION.md` is honest about what was *not* validated.

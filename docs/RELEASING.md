# Releasing

Versioning is semantic. A milestone ships as one or more release candidates (`vX.Y.Z-rc.N`) followed by the
final tag (`vX.Y.Z`). The final tag is only publishable for a commit that already passed the milestone gate as a
release candidate.

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

## 2. Release candidate

```sh
git tag -s vX.Y.Z-rc.1 && git push origin vX.Y.Z-rc.1
```

The milestone gate runs Tier 1 plus benchmarks, the backup drill, browser E2E, ZAP, licences and SBOM.
Fix anything it finds and tag `rc.2`, and so on.

## 3. Final release

```sh
git tag -s vX.Y.Z <same commit as the passing rc> && git push origin vX.Y.Z
```

`release.yml` verifies metadata, pins and the rc result, then **waits for approval** in the `release`
environment. After approval it builds, signs, attests and publishes, then verifies the published image by
digest.

## Checklist for the approver

- [ ] Milestone-gate run for this commit is green; benchmark and ZAP reports reviewed.
- [ ] `CHANGELOG.md` describes user-visible changes and any manual upgrade steps.
- [ ] New migrations were reviewed (data-preserving, reversible, tested on both databases).
- [ ] `docs/VALIDATION.md` is honest about what was *not* validated.

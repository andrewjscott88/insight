# Production deployment: Insight v0.8.0

Insight v0.8.0 was deployed to https://certifiedhacking.com at **2026-11-21 11:32:34 PM EST**.
The public HTTPS health check and authenticated version check passed after cutover.

## Release identity

- [Published release](https://github.com/andrewjscott88/insight/releases/tag/v0.8.0)
- Source commit: `6e3e52a5fa73eb8a1d718bc69aa19ac889f125fd`
- Published image: `ghcr.io/andrewjscott88/insight@sha256:cf8a7ce573858068d28aeb6647b3f243aba3b1323a85e3c2b8b9a522d69e1043`
- [Release workflow](https://github.com/andrewjscott88/insight/actions/runs/44979387444): all 18 jobs passed, including build,
  signature/attestation publication and verification of the published image. All 27 checks on the release
  commit passed. The release browser suite passed 55 tests; the ZAP gate reported 0 failures and 8 warnings.
- Previous production source: `57cb9c0cf0446f8625f6a4199a520281adf43d88` (0.6.0 with the executive brief updates).

## Database upgrade and data preservation

- Rehearsed migrations `0008` to `0018` against a consistent production database copy in an isolated
  container with networking disabled and the same 512 MiB / 0.75 CPU limits.
- Retained the original session secret for migration `0017` and future MFA pairing encryption.
- Ran the bundled ATT&CK technique backfill in rehearsal and production.
- Saved a fresh SQLite backup after stopping Insight and before migrating the live database.
- Preserved all **155 reports**, with the existing values in 15 evidence/configuration tables
  checked against the stopped backup. Existing report text, notes and review decisions remained intact.
- SQLite integrity and foreign-key checks passed. New schema: `0018`.

## Cutover and recovery controls

A temporary bridge rule blocked only proxy traffic to Insight while the database was migrated and private
acceptance ran. A public login probe and matching packet counter verified the gate before stopping the app.
The gate was removed only after the new version passed acceptance. Database restoration is prohibited after
public traffic resumes, so a later verification failure cannot discard new visitor writes.

The initial cutover attempt stopped before changing the application or database because this host does not
support bridge TCP-reset rejection. The replacement used a validated bridge DROP rule. Both attempt records
were retained on the host; the temporary rule and active maintenance marker were removed after success.

## Live verification

- Password-free browser entry, secure cookie flags, authenticated `/api/session` version `0.8.0`,
  anonymous API rejection and CSRF rejection passed. Verification sessions were revoked afterward.
- The seven-day executive brief contract, evidence highlights and last-24-hours field passed.
- Six Chromium configurations passed: 320 px with larger text, 390 px phone and 1440 px desktop,
  each in light and dark themes. The overview, prioritized CVEs and opened report were checked for
  horizontal overflow and accessibility violations; none were found by these checks.
- Public HTTPS health, the existing backup timer, network isolation and shared-host checks passed.
- Other application containers and shared proxy/firewall configuration remained unchanged.

## Runtime settings

Temporary password-free access remains enabled at the owner's request (`INSIGHT_DEV_NO_AUTH=on`).
MFA remains off and the new hardened-mode requirement remains off. The runtime environment file, session
secret, data volume, network, resource limits and other service settings were preserved. Restoring password
login requires setting `INSIGHT_DEV_NO_AUTH=off` and recreating Insight.

New optional source/enrichment switches remain disabled; no new feeds, alert destinations, schedules or
external AI service were enabled by this deployment. The upgrade reused the existing AWS host.

Private backups, environment files, host-specific execution evidence and temporary deployment tooling are
retained outside version control. No credentials or report contents are included in this record.


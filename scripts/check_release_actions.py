"""Release actions still accept what release.yml passes them, and the rehearsal runs the same versions.

CI never runs the release workflow, so a major-version bump of a release-only action could break the next
release unnoticed. The release rehearsal (`.github/workflows/release-rehearsal.yml`) runs the build, push,
signing and smoke-test steps for real against a throwaway local registry. This check covers the rest: it reads
each pinned action's `action.yml` at its exact commit and fails if `release.yml` passes an input the action no
longer declares, or leaves out one it requires. That includes the provenance attestations, which the rehearsal
cannot run without publishing.

python scripts/check_release_actions.py           # reads action.yml files from raw.githubusercontent.com
python scripts/check_release_actions.py --offline # only the pin agreement between the two workflows
"""

from __future__ import annotations

import argparse
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / '.github' / 'workflows'
RELEASE = WORKFLOWS / 'release.yml'
REHEARSAL = WORKFLOWS / 'release-rehearsal.yml'
RAW = 'https://raw.githubusercontent.com/{repo}/{sha}/{path}'

# Every action release.yml uses must be in exactly one of these. A new release action fails the check until
# someone decides whether the rehearsal can run it.
REHEARSED = (
    'docker/setup-buildx-action',
    'docker/login-action',
    'docker/metadata-action',
    'docker/build-push-action',
    'sigstore/cosign-installer',
)
NOT_REHEARSED = {
    'actions/checkout': 'every CI job runs it',
    'actions/setup-python': 'every CI job runs it',
    'actions/attest-build-provenance': 'it publishes an attestation; its inputs are checked instead',
}

Fetch = Callable[[str], str | None]


@dataclass(frozen=True)
class Step:
    job: str
    action: str  # owner/repo or owner/repo/path
    sha: str
    inputs: frozenset[str]


def steps(workflow: Path) -> list[Step]:
    """The remote actions a workflow uses, with the inputs each step passes."""
    data: dict[str, Any] = yaml.safe_load(workflow.read_text()) or {}
    found = []
    for job_name, job in (data.get('jobs') or {}).items():
        for step in job.get('steps') or []:
            uses = str(step.get('uses') or '')
            if not uses or uses.startswith(('./', 'docker://')) or '@' not in uses:
                continue
            action, sha = uses.split('@', 1)
            found.append(Step(job_name, action, sha, frozenset(step.get('with') or {})))
    return found


def fetch_url(url: str) -> str | None:
    """The text at `url`, or None if it does not exist."""
    if not url.startswith('https://raw.githubusercontent.com/'):
        raise ValueError(f'Refusing to fetch {url}')
    try:
        with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - host checked above
            text: str = response.read().decode()
            return text
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def declared_inputs(action: str, sha: str, fetch: Fetch) -> tuple[set[str], set[str]] | None:
    """(all inputs, required inputs without a default) from the action's metadata, or None if it has none."""
    owner, repo, *path = action.split('/')
    folder = '/'.join(path)
    for name in ('action.yml', 'action.yaml'):
        text = fetch(RAW.format(repo=f'{owner}/{repo}', sha=sha, path=f'{folder}/{name}' if folder else name))
        if text is None:
            continue
        inputs: dict[str, Any] = (yaml.safe_load(text) or {}).get('inputs') or {}
        required = {
            key
            for key, spec in inputs.items()
            if str((spec or {}).get('required', '')).lower() == 'true' and 'default' not in (spec or {})
        }
        return set(inputs), required
    return None


def pin_problems(release: Path = RELEASE, rehearsal: Path = REHEARSAL) -> list[str]:
    """Rehearsed actions run at the release's exact commit, and every release action is classified."""
    pins = {step.action: step.sha for step in steps(release)}
    rehearsed = {step.action: step.sha for step in steps(rehearsal)}
    found = []
    for action, sha in sorted(pins.items()):
        if action not in REHEARSED and action not in NOT_REHEARSED:
            found.append(
                f'{action} is new in release.yml: add it to the rehearsal (REHEARSED) or say why not '
                '(NOT_REHEARSED) in scripts/check_release_actions.py'
            )
        elif action in REHEARSED and rehearsed.get(action) != sha:
            found.append(f"release-rehearsal.yml must run {action} at the release's commit {sha[:12]}")
        elif action in rehearsed and rehearsed[action] != sha:
            found.append(f'release-rehearsal.yml runs {action} at a different commit than release.yml')
    return found


def input_problems(release: Path = RELEASE, fetch: Fetch = fetch_url) -> list[str]:
    """Inputs release.yml passes that the pinned action does not declare, and required ones it leaves out."""
    found = []
    checked: dict[tuple[str, str], tuple[set[str], set[str]] | None] = {}
    for step in steps(release):
        key = (step.action, step.sha)
        if key not in checked:
            checked[key] = declared_inputs(step.action, step.sha, fetch)
        declared = checked[key]
        if declared is None:
            found.append(f'{step.action}@{step.sha[:12]} has no action.yml at that commit')
            continue
        known, required = declared
        found += [
            f'release.yml ({step.job}): {step.action} has no input "{name}" at {step.sha[:12]}'
            for name in sorted(step.inputs - known)
        ]
        found += [
            f'release.yml ({step.job}): {step.action} requires the input "{name}"'
            for name in sorted(required - step.inputs)
        ]
    return found


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--offline', action='store_true', help='only check that the two workflows agree')
    args = parser.parse_args(argv)
    found = pin_problems() + ([] if args.offline else input_problems())
    for problem in found:
        print(f'::error::{problem}')
    if not found:
        print("Release actions accept their inputs, and the rehearsal runs the release's versions.")
    return 1 if found else 0


if __name__ == '__main__':
    raise SystemExit(main())

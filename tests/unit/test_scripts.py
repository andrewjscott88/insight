"""The CI/CD pipeline's own logic: a gate that silently passes is worse than no gate."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from scripts import (
    benchmark_extraction,
    benchmark_performance,
    check_forbidden_files,
    check_licenses,
    check_pins,
    check_release,
    check_release_actions,
    lock,
    make_ioc_example,
    make_release_fixture,
    release_notes,
    smoke,
    update_tlds,
)
from sqlalchemy import func, select

from insight import services
from insight.extraction import known_tlds
from insight.models import Base, Document, database

ROOT = Path(__file__).resolve().parent.parent.parent


# --------------------------------------------------------------------------- release metadata


@pytest.fixture
def release_root(tmp_path: Path) -> Path:
    (tmp_path / 'src/insight').mkdir(parents=True)
    (tmp_path / 'src/insight/__init__.py').write_text("__version__ = '1.2.0'\n")
    (tmp_path / 'docs').mkdir()
    (tmp_path / 'docs/VALIDATION.md').write_text('# Validation report · 1.2.0\n')
    (tmp_path / 'CHANGELOG.md').write_text('# Changelog\n\n## 1.2.0 - 2026-12-01\n\n- Things.\n\n## 1.1.0\n')
    (tmp_path / 'tests/fixtures/releases').mkdir(parents=True)
    (tmp_path / 'tests/fixtures/releases/insight-1.2.0.sqlite3').write_bytes(b'')
    return tmp_path


def test_consistent_release_passes(release_root: Path) -> None:
    assert check_release.problems('v1.2.0', release_root) == []
    assert check_release.problems('v1.2.0-rc.3', release_root) == []


@pytest.mark.parametrize('tag', ['1.2.0', 'v1.2', 'v1.2.0-beta', 'release-1.2.0', 'v1.2.0-rc'])
def test_malformed_tags_fail(release_root: Path, tag: str) -> None:
    assert check_release.problems(tag, release_root)


def test_version_changelog_validation_and_fixture_are_all_checked(release_root: Path) -> None:
    (release_root / 'tests/fixtures/releases/insight-1.2.0.sqlite3').unlink()
    (release_root / 'docs/VALIDATION.md').write_text('nothing')
    (release_root / 'CHANGELOG.md').write_text('## 1.1.0\n')
    found = check_release.problems('v1.3.0', release_root)
    assert len(found) == 4
    # A release candidate does not need the upgrade fixture yet.
    assert not any('fixture' in p for p in check_release.problems('v1.3.0-rc.1', release_root))


def test_repository_release_metadata_is_consistent() -> None:
    version = check_release.package_version()
    assert check_release.problems(f'v{version}') == []


def test_release_notes_extracts_one_section() -> None:
    changelog = '# Changelog\n\n## 1.2.0 - date\n\n- new\n\n## 1.1.0\n\n- old\n'
    assert release_notes.section(changelog, '1.2.0') == '- new'
    with pytest.raises(ValueError, match='no section'):
        release_notes.section(changelog, '9.9.9')


# --------------------------------------------------------------------------- pins


def test_pin_checker(tmp_path: Path) -> None:
    dockerfile = tmp_path / 'Dockerfile'
    dockerfile.write_text(
        'FROM python:3.13-slim AS build\nFROM build AS test\n'
        'FROM python:3.13-slim@sha256:' + 'a' * 64 + ' AS runtime\n'
    )
    assert check_pins.unpinned_images(dockerfile) == [
        'Dockerfile: base image python:3.13-slim is not pinned by digest'
    ]
    workflow = tmp_path / 'ci.yml'
    workflow.write_text(
        'steps:\n'
        '  - uses: actions/checkout@v5\n'
        f'  - uses: actions/setup-python@{"b" * 40} # v6\n'
        '  - uses: ./.github/actions/local\n'
        '    uses: docker://alpine:3\n'
    )
    assert check_pins.unpinned_actions(workflow) == [
        'ci.yml: actions/checkout@v5 is not pinned to a commit SHA'
    ]


DIGEST = 'sha256:' + 'f' * 64


def test_regression_l7_third_party_docker_run_images_must_be_pinned_by_digest(tmp_path: Path) -> None:
    """Review L7: gitleaks and ZAP ran from tags in CI, with the repository mounted or on the host network."""
    workflow = tmp_path / 'ci.yml'
    workflow.write_text(
        'steps:\n'
        '  - run: >-\n'
        '      docker run --rm -v "${PWD}:/repo" zricethezav/gitleaks:v8.18.4\n'
        '      detect --source /repo\n'
        '  - run: |\n'
        '      docker run --rm --network host -v "${PWD}/zap:/zap/wrk" \\\n'
        '        ghcr.io/zaproxy/zaproxy:stable \\\n'
        '        zap-baseline.py -t http://127.0.0.1:8080/\n'
        f'      docker run -d --name registry -p 127.0.0.1:5000:5000 registry:3@{DIGEST}\n'
        '      docker run -d --name insight --read-only -e A="$(openssl rand -hex 4)" insight:ci\n'
        '      docker run -d "${IMAGE}@${DIGEST}"\n'
    )
    assert check_pins.unpinned_run_images(workflow) == [
        'ci.yml: docker run image zricethezav/gitleaks:v8.18.4 is not pinned by digest',
        'ci.yml: docker run image ghcr.io/zaproxy/zaproxy:stable is not pinned by digest',
    ]


def test_every_workflow_image_in_this_repository_is_pinned_by_digest() -> None:
    assert [p for p in check_pins.problems() if 'docker run' in p] == []


def test_pin_checker_strict_mode_fails_on_this_repository_until_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Expected today (see docs/CI_CD.md "Inputs needed"); flip this test when everything is SHA-pinned.
    assert check_pins.main([]) == 0
    if check_pins.problems():
        assert check_pins.main(['--strict']) == 1


# --------------------------------------------------------------------------- release actions

SHA_A, SHA_B, SHA_C = 'a' * 40, 'b' * 40, 'c' * 40
RAW = 'https://raw.githubusercontent.com'
ACTION_METADATA = {
    f'{RAW}/docker/login-action/{SHA_A}/action.yml': (
        'inputs:\n  registry: {}\n  username: {}\n  password:\n    required: true\n'
        '  logout:\n    required: true\n    default: "true"\n'
    ),
    # Metadata in a sub-folder, under the other file name.
    f'{RAW}/github/codeql-action/{SHA_B}/init/action.yaml': 'inputs:\n  languages:\n    required: "true"\n',
}


def write_workflow(path: Path, *steps: str) -> Path:
    path.write_text('jobs:\n  publish:\n    steps:\n' + ''.join(steps))
    return path


def test_release_action_inputs_must_exist_at_the_pinned_commit(tmp_path: Path) -> None:
    release = write_workflow(
        tmp_path / 'release.yml',
        f'      - uses: docker/login-action@{SHA_A}\n'
        '        with: {registry: ghcr.io, username: me, password: secret, ecr: auto}\n',
        f'      - uses: docker/login-action@{SHA_A}\n        with: {{registry: ghcr.io}}\n',
        f'      - uses: github/codeql-action/init@{SHA_B}\n        with: {{languages: python}}\n',
        f'      - uses: docker/metadata-action@{SHA_C}\n',
        '      - uses: ./.github/actions/local\n      - run: echo hi\n',
    )
    assert check_release_actions.input_problems(release, ACTION_METADATA.get) == [
        f'release.yml (publish): docker/login-action has no input "ecr" at {SHA_A[:12]}',
        'release.yml (publish): docker/login-action requires the input "password"',
        f'docker/metadata-action@{SHA_C[:12]} has no action.yml at that commit',
    ]


def test_release_rehearsal_must_run_the_release_versions(tmp_path: Path) -> None:
    release = write_workflow(
        tmp_path / 'release.yml',
        f'      - uses: actions/checkout@{SHA_A}\n',
        f'      - uses: docker/login-action@{SHA_A}\n',
        f'      - uses: docker/build-push-action@{SHA_A}\n',
        f'      - uses: example/new-action@{SHA_A}\n',
    )
    rehearsal = write_workflow(
        tmp_path / 'release-rehearsal.yml',
        f'      - uses: actions/checkout@{SHA_B}\n',
        f'      - uses: docker/login-action@{SHA_B}\n',
    )
    assert check_release_actions.pin_problems(release, rehearsal) == [
        'release-rehearsal.yml runs actions/checkout at a different commit than release.yml',
        f"release-rehearsal.yml must run docker/build-push-action at the release's commit {SHA_A[:12]}",
        f"release-rehearsal.yml must run docker/login-action at the release's commit {SHA_A[:12]}",
        'example/new-action is new in release.yml: add it to the rehearsal (REHEARSED) or say why not '
        '(NOT_REHEARSED) in scripts/check_release_actions.py',
    ]
    agreed = (
        f'      - uses: actions/checkout@{SHA_A}\n',
        f'      - uses: docker/login-action@{SHA_A}\n',
        f'      - uses: docker/build-push-action@{SHA_A}\n',
    )
    write_workflow(rehearsal, *agreed)
    write_workflow(release, *agreed)
    assert check_release_actions.pin_problems(release, rehearsal) == []


def test_this_repositorys_rehearsal_runs_the_release_versions(capsys: pytest.CaptureFixture[str]) -> None:
    assert check_release_actions.pin_problems() == []
    assert check_release_actions.main(['--offline']) == 0
    assert "the rehearsal runs the release's versions" in capsys.readouterr().out


def test_release_action_metadata_is_only_read_from_github() -> None:
    with pytest.raises(ValueError, match='Refusing to fetch'):
        check_release_actions.fetch_url('https://example.com/action.yml')


# --------------------------------------------------------------------------- licences


@pytest.mark.parametrize(
    ('expression', 'allowed'),
    [
        ('MIT', True),
        ('GPL-3.0-only', False),
        ('MIT OR GPL-3.0-only', True),
        ('MIT AND GPL-3.0-only', False),
        ('MPL-2.0 AND (Apache-2.0 OR MIT)', True),
        ('(GPL-2.0-only OR AGPL-3.0-only) AND MIT', False),
        ('Apache-2.0 WITH LLVM-exception', True),
        ('MIT custom terms', False),
        ('MIT OR', False),
        ('MIT OR OR', False),
        ('(MIT OR GPL-3.0-only', False),
        ('MIT WITH AND', False),
    ],
)
def test_spdx_evaluation(expression: str, allowed: bool) -> None:
    assert check_licenses.evaluate_spdx(expression, lambda t: t in check_licenses.ALLOWED) is allowed


@pytest.mark.parametrize(
    ('fields', 'allowed', 'source'),
    [
        ({'license_expression': 'BSD-3-Clause'}, True, 'spdx'),
        ({'license': 'Apache 2.0'}, True, 'license-field'),
        ({'license': 'GPLv3'}, False, 'license-field'),
        ({'license': 'MIT OR AFL-2.1'}, True, 'license-field'),
        ({'license': 'MIT AND GPL-3.0-only'}, False, 'license-field'),
        ({'license': 'MIT WITH restrictions'}, False, 'license-field'),
        ({'license': 'UNKNOWN'}, False, 'none'),
        (
            {'license': 'UNKNOWN', 'classifier': ['License :: OSI Approved :: ISC License (ISCL)']},
            True,
            'classifiers',
        ),
        ({'license': 'UNKNOWN', 'classifier': ['License :: OSI Approved :: GPL']}, False, 'classifiers'),
        ({'classifier': ['License :: OSI Approved :: MIT License']}, True, 'classifiers'),
        (
            {'classifier': ['License :: OSI Approved :: GNU General Public License (GPL)']},
            False,
            'classifiers',
        ),
        ({}, False, 'none'),
    ],
)
def test_licence_verdicts(fields: dict[str, object], allowed: bool, source: str) -> None:
    verdict = check_licenses.verdict('pkg', SimpleNamespace(json=fields))
    assert (verdict.allowed, verdict.source) == (allowed, source)


def test_runtime_dependencies_pass_the_licence_policy() -> None:
    assert check_licenses.main([]) == 0


@pytest.mark.parametrize(
    ('package', 'version', 'licence', 'expression', 'allowed'),
    [
        ('cpe', '1.3.1', 'LGPLv3', '', True),
        ('cpe', '1.3.2', 'LGPLv3', '', False),
        ('other', '1.3.1', 'LGPLv3', '', False),
        ('cpe', '1.3.1', 'GPLv3', '', False),
        ('cpe', '1.3.1', 'LGPLv3', 'AGPL-3.0-only', False),
    ],
)
def test_cpe_licence_review_is_scoped_to_the_release(
    package: str, version: str, licence: str, expression: str, allowed: bool
) -> None:
    meta = SimpleNamespace(json={'version': version, 'license': licence, 'license_expression': expression})
    assert check_licenses.verdict(package, meta).allowed is allowed


def test_cpe_matching_source_and_licences_ship_as_resources() -> None:
    bundled = files('insight').joinpath('data', 'licenses')
    archive = bundled.joinpath('cpe-1.3.1.tar.gz').read_bytes()
    digest = 'f30a97881b6eb74a6d630552aebce03df22cddb7a587d632a13b4e14b66b95b0'
    assert hashlib.sha256(archive).hexdigest() == digest
    assert digest in (ROOT / 'requirements.lock').read_text()
    assert 'GNU LESSER GENERAL PUBLIC LICENSE' in bundled.joinpath('LGPL-3.0.txt').read_text()
    assert 'GNU GENERAL PUBLIC LICENSE' in bundled.joinpath('GPL-3.0.txt').read_text()


# --------------------------------------------------------------------------- forbidden files


@pytest.mark.parametrize(
    ('name', 'content', 'blocked'),
    [
        ('.env', 'X=1', True),
        ('.env.example', 'INSIGHT_PASSWORD=replace-with-a-long-unique-password', False),
        ('data/insight.db', '', True),
        ('tests/fixtures/releases/insight-9.9.9.sqlite3', '', False),
        ('keys/server.pem', '', True),
        ('notes.txt', '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----', True),  # split: don't trip the scanner
        ('config.sh', 'INSIGHT_SESSION_SECRET=abcdefghijklmnopqrstuvwxyz', True),
        ('readme.md', 'Set INSIGHT_PASSWORD= in your .env file', False),
        ('backups/backup-2026-01-01-120000.db', '', True),
        ('exports/iocs-2026-01-01-120000.json', '{}', True),  # TLP-labelled data from `make export-iocs`
        ('docs/exports/guide.md', 'text', False),
        ('docs/deployments/2026-01-01-host.md', '# A deployment record', True),  # deployments stay private
        ('docs/DEPLOYMENT.md', 'How to deploy', False),
        ('siem.conf', 'api_key = insk_0123456789ab_' + 'A' * 43, True),  # fake, built here gitleaks:allow
        ('docs/API.md', 'The key (`insk_<12-hex key ID>_<43-character secret>`)', False),
    ],
)
def test_forbidden_files(tmp_path: Path, name: str, content: str, blocked: bool) -> None:
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(content)
    assert bool(check_forbidden_files.problems([name], tmp_path)) is blocked


def test_repository_has_no_forbidden_files() -> None:
    inside = subprocess.run(
        ['git', 'rev-parse', '--is-inside-work-tree'], cwd=ROOT, capture_output=True, text=True, check=False
    )
    if shutil.which('git') is None or inside.stdout.strip() != 'true':
        pytest.skip('not a git work tree')
    assert check_forbidden_files.problems(check_forbidden_files.tracked_files()) == []


# --------------------------------------------------------------------------- locks


def test_lock_pin_parser_ignores_hashes_markers_and_comments() -> None:
    text = (
        'alembic==1.20.1 \\\n    --hash=sha256:abc\n'
        "uvloop==0.23.0 ; sys_platform != 'win32' \\\n    --hash=sha256:def\n"
        '    # via uvicorn\n'
    )
    assert lock.pins(text) == {'alembic==1.20.1', 'uvloop==0.23.0'}


def test_lock_commands_cover_every_lock_file() -> None:
    outputs = {entry.output for entry in lock.LOCKS}
    assert outputs == {p.name for p in ROOT.glob('requirements*.lock')}
    command = lock.compile_command(lock.LOCKS[1], Path('out'), upgrade=True)
    assert command[:3] == ['uv', 'pip', 'compile']
    assert {'--generate-hashes', '--universal', '--upgrade'} <= set(command)
    assert command[command.index('--extra') + 1] == 'dev'


@pytest.mark.slow
def test_lock_files_match_pyproject() -> None:
    if shutil.which('uv') is None:
        pytest.skip('uv not installed')
    assert lock.main(['--check']) == 0


# --------------------------------------------------------------------------- benchmarks


def test_extraction_metrics() -> None:
    documents: list[dict[str, object]] = [
        {
            'id': 'a',
            'text': 'CVE-2024-1111 and 192.0.2.1.',
            'expected': [['cve', 'CVE-2024-1111'], ['ip', '192.0.2.1']],
        },
        {'id': 'b', 'text': 'see example.org today', 'expected': []},
        {'id': 'c', 'text': 'nothing to find', 'expected': [['domain', 'missing.example']]},
    ]
    result = benchmark_extraction.evaluate(documents)
    scores = result.scores()
    assert scores['cve'] == {'precision': 1.0, 'recall': 1.0}
    assert scores['domain']['precision'] == 0.0  # example.org was not labelled
    assert scores['domain']['recall'] == 0.0
    assert result.misses == ['c: domain missing.example']
    assert 'b: domain example.org' in result.false_alarms


def test_extraction_regression_tolerance() -> None:
    baseline = {'ip': {'precision': 0.80, 'recall': 0.80}}
    assert benchmark_extraction.regressions({'ip': {'precision': 0.795, 'recall': 0.80}}, baseline) == []
    assert benchmark_extraction.regressions({'ip': {'precision': 0.78, 'recall': 0.80}}, baseline)


def test_extraction_quality_has_not_regressed() -> None:
    """Milestone-1 gate, also enforced on every push: the labelled corpus must not lose precision/recall."""
    assert benchmark_extraction.main([]) == 0


def test_extraction_baseline_covers_every_labelled_kind() -> None:
    corpus = benchmark_extraction.load_corpus(benchmark_extraction.CORPUS)
    kinds = {kind for doc in corpus for kind, _ in doc['expected']}  # type: ignore[attr-defined]
    assert kinds <= set(json.loads(benchmark_extraction.BASELINE.read_text())['scores'])


def test_extraction_gate_distinguishes_corpus_changes_from_regressions(tmp_path: Path) -> None:
    corpus = tmp_path / 'corpus.json'
    baseline = tmp_path / 'baseline.json'
    document = {'id': 'a', 'text': 'CVE-2024-1111', 'expected': [['cve', 'CVE-2024-1111']]}
    corpus.write_text(json.dumps({'documents': [document]}))
    args = ['--corpus', str(corpus), '--baseline', str(baseline)]
    assert benchmark_extraction.main([*args, '--update-baseline']) == 0
    assert benchmark_extraction.main(args) == 0
    harder = {'id': 'b', 'text': 'hxxp://x[.]example', 'expected': [['domain', 'x.example']]}
    corpus.write_text(json.dumps({'documents': [document, harder]}))
    report = tmp_path / 'report.md'
    assert benchmark_extraction.main([*args, '--report', str(report)]) == 1
    assert 'corpus changed since the baseline' in report.read_text()


def test_performance_budget_logic() -> None:
    budget = json.loads(benchmark_performance.BUDGET.read_text())
    ok = {'ingest_seconds': 1, 'search_p95_ms': 1, 'list_page_queries': 2, 'detail_p95_ms': 1}
    assert benchmark_performance.violations(ok, budget) == []
    slow = {**ok, 'list_page_queries': 201}
    assert benchmark_performance.violations(slow, budget) == ['list_page_queries = 201 exceeds budget 2']


def test_the_postgres_budget_is_complete_and_at_least_as_strict() -> None:
    """Issue #11: the gate measures PostgreSQL against its own, tighter ceilings."""
    general = json.loads(benchmark_performance.BUDGET.read_text())
    postgres = json.loads(
        (benchmark_performance.BUDGET.parent / 'performance-budget-postgres.json').read_text()
    )
    limits = {k for k in general if k.endswith('_max')}
    assert {k for k in postgres if k.endswith('_max')} == limits
    assert postgres['documents'] == general['documents']
    assert all(postgres[k] <= general[k] for k in limits)
    assert any(postgres[k] < general[k] for k in limits)
    workflow = (ROOT / '.github' / 'workflows' / 'milestone-gate.yml').read_text()
    assert '--budget benchmarks/performance-budget-postgres.json' in workflow


def test_performance_measurement_runs(tmp_path: Path) -> None:
    result = benchmark_performance.measure(f'sqlite:///{tmp_path / "perf.db"}', documents=25)
    assert result['documents'] == 25
    assert result['list_page_queries'] == 2


# --------------------------------------------------------------------------- smoke test and backup drill


def test_smoke_passes_against_the_real_stack(authed: TestClient) -> None:
    authed.cookies.clear()  # the smoke test signs in by itself
    stats = smoke.run(authed, 'longtestpassword', ui=False)  # the unit-test app runs without NiceGUI
    assert stats['documents'] >= 3


def test_smoke_refuses_version_disclosure_on_public_health(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(smoke, 'wait_until_healthy', lambda _: {'status': 'ok', 'version': '0.0.0'})
    with pytest.raises(smoke.SmokeFailure, match='public /health'):
        smoke.run(client, 'longtestpassword', ui=False)


def test_smoke_fails_with_the_wrong_password(client: TestClient) -> None:
    with pytest.raises(smoke.SmokeFailure, match='sign-in failed'):
        smoke.run(client, 'wrong-password', ui=False)


def test_smoke_detects_missing_security_headers(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(smoke, 'REQUIRED_HEADERS', (*smoke.REQUIRED_HEADERS, 'content-security-policy'))
    with pytest.raises(smoke.SmokeFailure, match='security headers missing'):
        smoke.run(client, 'longtestpassword', ui=False)


@pytest.mark.slow
def test_backup_restore_drill(tmp_path: Path) -> None:
    insight = shutil.which('insight', path=str(Path(sys.executable).parent))
    if insight is None:
        pytest.skip('insight console script not installed')
    result = subprocess.run(
        [sys.executable, str(ROOT / 'scripts/backup_restore_drill.py'), '--insight', insight],
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'Backup/restore drill passed' in result.stdout


@pytest.mark.skipif(
    sys.platform != 'linux', reason='The release fixture includes a real sandboxed PDF import'
)
def test_release_fixture_builder_produces_an_upgradeable_database(tmp_path: Path) -> None:
    path = tmp_path / 'fixture.sqlite3'
    make_release_fixture.build(path)
    engine, sessions = database(f'sqlite:///{path}')
    try:
        with sessions() as db:
            stats = services.stats(db)
            revisions = db.scalars(select(Document).where(Document.external_id == 'CVE-2024-3400')).all()
        assert stats['documents'] >= 6
        assert sorted(d.is_current for d in revisions) == [False, True]
        with engine.connect() as connection:
            empty = {
                name
                for name, table in Base.metadata.tables.items()
                if not connection.execute(select(func.count()).select_from(table)).scalar()
            }
        # Every table holds data, so future migrations are tested against it; MFA would commit a secret.
        assert empty == {'operator_mfa'}
    finally:
        engine.dispose()


def test_property_tests_do_not_override_the_hypothesis_profile() -> None:
    """Regression: a per-test ``max_examples`` made the nightly 5,000-example job silently run 300."""
    for path in (ROOT / 'tests').rglob('test_*.py'):
        if path.resolve() != Path(__file__).resolve():
            assert 'max_examples=' not in path.read_text(encoding='utf-8'), path


def test_tld_list_regeneration_round_trips(tmp_path: Path) -> None:
    psl = (
        '// VERSION: 2026-01-01\n// COMMIT: abc\n// ===BEGIN ICANN DOMAINS===\n'
        'com\n*.ck\n!www.ck\nco.uk\nрф\n'
        + '\n'.join(f'tld{i}' for i in range(1000))
        + '\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\nprivate.example\n'
    )
    tlds, version, commit = update_tlds.icann_tlds(psl)
    assert {'com', 'ck', 'uk', 'xn--p1ai'} <= set(tlds)
    assert 'example' not in tlds  # private section ignored
    assert (version, commit) == ('2026-01-01', 'abc')
    source = tmp_path / 'psl.dat'
    source.write_text(psl, encoding='utf-8')
    output = tmp_path / 'tlds.txt'
    assert update_tlds.main([str(source), '--output', str(output)]) == 0
    assert 'xn--p1ai' in output.read_text()


def test_bundled_tld_list_is_current_format_and_complete() -> None:
    assert len(known_tlds()) > 1400
    assert {'com', 'org', 'net', 'uk', 'zip', 'onion', 'example'} <= known_tlds()
    assert {'exe', 'dll', 'js', 'aspx', 'bin'}.isdisjoint(known_tlds())


def test_no_source_or_package_data_file_is_gitignored() -> None:
    """Regression: a `data/` ignore rule (meant for ./data) silently excluded src/insight/data/tlds.txt, so a
    fresh clone could not extract domains at all."""
    inside = subprocess.run(
        ['git', 'rev-parse', '--is-inside-work-tree'], cwd=ROOT, capture_output=True, text=True, check=False
    )
    if shutil.which('git') is None or inside.stdout.strip() != 'true':
        pytest.skip('not a git work tree')
    top = subprocess.run(
        ['git', 'rev-parse', '--show-toplevel'], cwd=ROOT, capture_output=True, text=True, check=False
    )
    if Path(top.stdout.strip()).resolve() != ROOT.resolve():
        pytest.skip('running from a copy inside another work tree (mutmut mutants/)')
    candidates = [str(p.relative_to(ROOT)) for p in (ROOT / 'src' / 'insight').rglob('*') if p.is_file()]
    candidates = [c for c in candidates if '__pycache__' not in c and not c.endswith('.pyc')]
    result = subprocess.run(
        ['git', 'check-ignore', '--stdin'],
        cwd=ROOT,
        input='\n'.join(candidates),
        capture_output=True,
        text=True,
    )
    assert result.stdout.split() == []


# --------------------------------------------------------------------------- IOC export example


def test_committed_ioc_example_is_current() -> None:
    """docs/IOC_EXPORT.md quotes this file: a format change must regenerate it (make_ioc_example.py)."""
    assert make_ioc_example.main(['--check']) == 0


def test_ioc_example_check_detects_drift_and_regenerates(tmp_path: Path) -> None:
    target = tmp_path / 'example.json'
    assert make_ioc_example.main(['--check'], target=target) == 1  # missing
    assert make_ioc_example.main([], target=target) == 0
    assert make_ioc_example.main(['--check'], target=target) == 0  # deterministic: same file again
    target.write_text(target.read_text().replace('"GREEN"', '"CLEAR"', 1))
    assert make_ioc_example.main(['--check'], target=target) == 1

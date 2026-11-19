"""The Makefile: every target documented; Docker targets run against a stand-in for `docker compose`, Python
targets against a stand-in virtualenv; and its safety properties (private files, no overwrites, prompts).
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
MAKEFILE = (ROOT / 'Makefile').read_text()
#: Records every call; `cp SERVICE:/data/x dest` creates `dest`; `mfa setup` fails when FAIL_SETUP is set.
FAKE_COMPOSE = """#!/bin/sh
echo "$*" >> calls.log
case "$1" in cp) echo "copied" > "$3" ;; esac
case "$*" in *"mfa setup"*) [ -n "$FAIL_SETUP" ] && exit 1 ;; esac
exit 0
"""
#: A stand-in for .venv/bin/<tool>: records its name, arguments and whether it received the password.
FAKE_TOOL = """#!/bin/sh
echo "$(basename "$0") $* password-in-env=${INSIGHT_PASSWORD:+yes}" >> calls.log
"""

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(shutil.which('make') is None, reason='make is not installed'),
]


def targets() -> dict[str, str]:
    """Documented targets and their help text."""
    return dict(re.findall(r'^([a-z0-9-]+):.*?## (.+)$', MAKEFILE, re.MULTILINE))


@pytest.fixture
def project(tmp_path: Path) -> Path:
    shutil.copy(ROOT / 'Makefile', tmp_path / 'Makefile')
    fake = tmp_path / 'fake-compose'
    fake.write_text(FAKE_COMPOSE)
    fake.chmod(0o755)
    venv = tmp_path / 'venv' / 'bin'
    venv.mkdir(parents=True)
    for tool in ('python', 'pytest', 'ruff', 'mypy', 'pip', 'insight', 'check-jsonschema', 'zizmor'):
        (venv / tool).write_text(FAKE_TOOL)
        (venv / tool).chmod(0o755)
    env = tmp_path / '.env'
    env.write_text(
        'INSIGHT_PASSWORD=secret-pass-123\nINSIGHT_MFA=off\nINSIGHT_SESSION_SECRET=abc'
    )  # no final \n
    env.chmod(0o600)
    return tmp_path


def make(project: Path, *args: str, stdin: str = '', **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ['make', '-s', *args, 'COMPOSE=./fake-compose', 'VENV=venv'],
        cwd=project,
        # Inherited INSIGHT_* variables (e.g. a developer's exported .env) must not change what make does.
        env={**{k: v for k, v in os.environ.items() if not k.startswith('INSIGHT_')}, **env},
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )


def calls(project: Path) -> list[str]:
    log = project / 'calls.log'
    return log.read_text().splitlines() if log.exists() else []


def env_lines(project: Path) -> list[str]:
    return (project / '.env').read_text().splitlines()


def ran(project: Path) -> list[str]:
    """Stand-in tool calls without the password marker."""
    return [call.replace('password-in-env=', '').strip() for call in calls(project)]


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# --------------------------------------------------------------------------- structure and documentation


def test_every_target_is_phony_documented_and_listed_by_help(project: Path) -> None:
    documented = targets()
    assert len(documented) >= 40
    phony = set(' '.join(re.findall(r'^\.PHONY: (.+)$', MAKEFILE, re.MULTILINE)).split())
    assert set(documented) <= phony
    listing = make(project, 'help').stdout
    for target in documented:
        assert f'make {target} ' in listing, target
    assert all(len(line) <= 105 for line in listing.splitlines()), 'keep help lines readable'
    for section in (
        'Run (Docker)',
        'Data (Docker)',
        'API key',
        'Sign-in MFA',
        'Appearance',
        'Develop',
        'CI gates',
    ):
        assert section in listing


def test_every_make_command_in_the_docs_exists() -> None:
    documents = [ROOT / 'README.md', ROOT / 'CONTRIBUTING.md', *sorted((ROOT / 'docs').rglob('*.md'))]
    mentioned = {
        target
        for document in documents
        for target in re.findall(r'`make ([a-z0-9-]+)', document.read_text(encoding='utf-8'))
    }
    assert mentioned, 'the docs should point at the Makefile'
    assert mentioned - set(targets()) == set()


def test_help_is_the_default_target(project: Path) -> None:
    assert 'make help' in make(project).stdout


# --------------------------------------------------------------------------- first run


def test_env_creates_private_strong_credentials_once(project: Path) -> None:
    (project / '.env').unlink()
    assert make(project, 'env').returncode == 0
    values = dict(line.split('=', 1) for line in env_lines(project))
    assert set(values) == {'INSIGHT_PASSWORD', 'INSIGHT_SESSION_SECRET'}
    assert len(values['INSIGHT_PASSWORD']) >= 20
    assert len(values['INSIGHT_SESSION_SECRET']) >= 48
    assert mode(project / '.env') == 0o600
    again = make(project, 'env')
    assert again.returncode != 0
    assert 'refusing to overwrite' in again.stderr
    assert dict(line.split('=', 1) for line in env_lines(project)) == values


def test_env_falls_back_to_openssl_without_python(project: Path, tmp_path: Path) -> None:
    if shutil.which('openssl') is None:
        pytest.skip('openssl is not installed')
    (project / '.env').unlink()
    tools = tmp_path / 'no-python-bin'
    tools.mkdir()
    for tool in ('make', 'sh', 'openssl', 'tr', 'cat', 'date', 'awk'):
        if found := shutil.which(tool):
            (tools / tool).symlink_to(found)
    assert make(project, 'env', PATH=str(tools)).returncode == 0
    values = dict(line.split('=', 1) for line in env_lines(project))
    assert len(values['INSIGHT_PASSWORD']) >= 20
    assert re.fullmatch(r'[A-Za-z0-9_-]{48,}', values['INSIGHT_SESSION_SECRET'])


@pytest.mark.parametrize(
    'target',
    ['up', 'version', 'backup', 'export-iocs', 'migrate', 'api-key-status', 'mfa-enable', 'smoke', 'theme'],
)
def test_targets_that_need_credentials_explain_a_missing_env_file(project: Path, target: str) -> None:
    (project / '.env').unlink()
    result = make(project, target)
    assert result.returncode != 0
    assert "No .env here: run 'make env' first" in result.stderr
    assert calls(project) == []


# --------------------------------------------------------------------------- run and data (Docker)


@pytest.mark.parametrize(
    ('target', 'expected'),
    [
        ('up', ['up --build -d']),
        ('down', ['down']),
        ('stop', ['stop']),
        ('restart', ['restart']),
        ('ps', ['ps']),
        ('logs', ['logs -f insight']),
        ('version', ['run --rm --no-deps insight insight --version']),
        ('migrate', ['run --rm insight insight migrate']),
        ('db-shell', ['run --rm --no-deps --entrypoint python insight -m sqlite3 /data/insight.db']),
    ],
)
def test_simple_docker_targets(project: Path, target: str, expected: list[str]) -> None:
    assert make(project, target).returncode == 0
    assert calls(project) == expected


def test_backup_copies_a_private_file_off_the_volume_and_cleans_up(project: Path) -> None:
    result = make(project, 'backup')
    assert result.returncode == 0, result.stderr
    backup, copy, remove = calls(project)
    name = re.fullmatch(r'exec -T insight insight backup /data/(backup-[\d-]+\.db)', backup)
    assert name is not None
    assert copy == f'cp insight:/data/{name[1]} backups/{name[1]}'
    assert remove == f'exec -T insight rm /data/{name[1]}'
    assert mode(project / 'backups') == 0o700
    assert mode(project / 'backups' / name[1]) == 0o600


def test_export_iocs_passes_filters_and_keeps_the_file_private(project: Path) -> None:
    result = make(project, 'export-iocs', 'EXPORT_ARGS=--max-tlp GREEN --defang')
    assert result.returncode == 0, result.stderr
    export, copy, remove = calls(project)
    assert re.fullmatch(
        r'exec -T insight insight export-iocs /data/iocs-[\d-]+\.json --max-tlp GREEN --defang', export
    )
    assert copy.startswith('cp insight:/data/iocs-')
    assert remove.startswith('exec -T insight rm /data/iocs-')
    exported = next((project / 'exports').iterdir())
    assert mode(exported) == 0o600


def test_restore_requires_a_backup_file(project: Path) -> None:
    assert 'usage: make restore BACKUP=' in make(project, 'restore').stderr
    assert 'No such backup' in make(project, 'restore', 'BACKUP=backups/missing.db').stderr
    assert calls(project) == []


@pytest.mark.parametrize('answer', ['n\n', '\n', 'yes please\n'])
def test_restore_asks_before_replacing_the_database(project: Path, answer: str) -> None:
    (project / 'old.db').write_text('backup')
    result = make(project, 'restore', 'BACKUP=old.db', stdin=answer)
    assert result.returncode != 0
    assert 'Cancelled; nothing changed.' in result.stdout
    assert calls(project) == []


@pytest.mark.parametrize(('args', 'stdin'), [(['CONFIRM=yes'], ''), ([], 'y\n')])
def test_restore_stops_copies_the_backup_in_and_starts(project: Path, args: list[str], stdin: str) -> None:
    (project / 'saved').mkdir()
    (project / 'saved' / 'backup-1.db').write_text('backup')
    result = make(project, 'restore', 'BACKUP=saved/backup-1.db', *args, stdin=stdin)
    assert result.returncode == 0, result.stderr
    assert calls(project) == [
        'stop',
        f'run --rm --no-deps -v {project / "saved"}:/restore:ro --entrypoint sh insight '
        '-c cp "/restore/backup-1.db" /data/insight.db',
        'up -d',
    ]


# --------------------------------------------------------------------------- API key


def test_api_key_create_needs_a_name(project: Path) -> None:
    result = make(project, 'api-key-create')
    assert result.returncode != 0
    assert 'usage: make api-key-create NAME=siem' in result.stderr
    assert calls(project) == []


@pytest.mark.parametrize(
    ('args', 'expected'),
    [
        (['api-key-create', 'NAME=siem'], 'run --rm insight insight api-key create --name siem'),
        (
            ['api-key-create', 'NAME=siem', 'ACCESS=read-write', 'MAX_TLP=GREEN', 'EXPIRES=30'],
            'run --rm insight insight api-key create --name siem --access read-write --max-tlp GREEN '
            '--expires-days 30',
        ),
        (['api-key-rotate'], 'run --rm insight insight api-key rotate'),
        (['api-key-rotate', 'MAX_TLP=RED'], 'run --rm insight insight api-key rotate --max-tlp RED'),
        (['api-key-status'], 'run --rm insight insight api-key status'),
        (['api-key-revoke'], 'run --rm insight insight api-key revoke'),
    ],
)
def test_api_key_targets(project: Path, args: list[str], expected: str) -> None:
    assert make(project, *args).returncode == 0
    assert [' '.join(call.split()) for call in calls(project)] == [expected]


# --------------------------------------------------------------------------- MFA


def test_mfa_enable_pairs_then_switches_on_then_restarts(project: Path) -> None:
    result = make(project, 'mfa-enable')
    assert result.returncode == 0, result.stderr
    assert calls(project) == [
        'run --rm insight insight migrate',
        'run --rm insight insight mfa setup',
        'up -d',
    ]
    assert env_lines(project) == [
        'INSIGHT_PASSWORD=secret-pass-123',
        'INSIGHT_SESSION_SECRET=abc',  # the last line had no newline: it is kept intact
        'INSIGHT_MFA=on',
    ]
    assert 'MFA is on' in result.stdout


def test_env_file_stays_private_and_no_temporary_file_remains(project: Path) -> None:
    assert make(project, 'mfa-enable').returncode == 0
    assert mode(project / '.env') == 0o600
    assert not [p.name for p in project.iterdir() if '.tmp.' in p.name]


def test_mfa_is_never_switched_on_when_pairing_fails(project: Path) -> None:
    result = make(project, 'mfa-enable', FAIL_SETUP='1')
    assert result.returncode != 0
    assert 'INSIGHT_MFA=off' in env_lines(project)
    assert 'up -d' not in calls(project)


def test_mfa_disable_switches_off_and_keeps_the_paired_app(project: Path) -> None:
    assert make(project, 'mfa-enable').returncode == 0
    (project / 'calls.log').unlink()
    assert make(project, 'mfa-disable').returncode == 0
    assert calls(project) == ['up -d']  # no `mfa reset`
    assert env_lines(project)[-1] == 'INSIGHT_MFA=off'
    assert sum(line.startswith('INSIGHT_MFA=') for line in env_lines(project)) == 1


def test_a_missing_mfa_switch_is_added(project: Path) -> None:
    (project / '.env').write_text('INSIGHT_PASSWORD=secret-pass-123\n')
    assert make(project, 'mfa-disable').returncode == 0
    assert env_lines(project) == ['INSIGHT_PASSWORD=secret-pass-123', 'INSIGHT_MFA=off']


@pytest.mark.parametrize(
    ('target', 'command'),
    [
        ('mfa-status', 'run --rm insight insight mfa status'),
        ('mfa-reset', 'run --rm insight insight mfa reset'),
    ],
)
def test_mfa_status_and_reset(project: Path, target: str, command: str) -> None:
    assert make(project, target).returncode == 0
    assert calls(project) == [command]
    assert 'INSIGHT_MFA=off' in env_lines(project)  # unchanged


def test_compose_passes_the_mfa_switch_through_with_off_as_default() -> None:
    assert 'INSIGHT_MFA: ${INSIGHT_MFA:-off}' in (ROOT / 'compose.yaml').read_text()


# --------------------------------------------------------------------------- appearance


@pytest.mark.parametrize('theme', ['system', 'light', 'dark'])
def test_theme_sets_the_default_and_restarts(project: Path, theme: str) -> None:
    result = make(project, 'theme', f'THEME={theme}')
    assert result.returncode == 0, result.stderr
    assert calls(project) == ['up -d']
    assert env_lines(project)[-1] == f'INSIGHT_THEME={theme}'
    assert f'Default theme: {theme}.' in result.stdout
    assert mode(project / '.env') == 0o600


def test_theme_replaces_the_previous_value(project: Path) -> None:
    assert make(project, 'theme', 'THEME=dark').returncode == 0
    assert make(project, 'theme', 'THEME=light').returncode == 0
    assert [line for line in env_lines(project) if line.startswith('INSIGHT_THEME=')] == [
        'INSIGHT_THEME=light'
    ]
    assert 'INSIGHT_PASSWORD=secret-pass-123' in env_lines(project)


@pytest.mark.parametrize('args', [[], ['THEME=drak'], ['THEME=auto'], ['THEME=dark;rm']])
def test_theme_refuses_anything_but_the_three_themes(project: Path, args: list[str]) -> None:
    before = env_lines(project)
    result = make(project, 'theme', *args)
    assert result.returncode != 0
    assert 'usage: make theme THEME=system|light|dark (current: system, the default)' in result.stderr
    assert calls(project) == []
    assert env_lines(project) == before


def test_theme_usage_shows_the_current_setting(project: Path) -> None:
    assert make(project, 'theme', 'THEME=dark').returncode == 0
    assert '(current: dark)' in make(project, 'theme').stderr


def test_up_can_set_the_theme_while_building(project: Path) -> None:
    result = make(project, 'up', 'THEME=light')
    assert result.returncode == 0, result.stderr
    assert calls(project) == ['up --build -d']
    assert env_lines(project)[-1] == 'INSIGHT_THEME=light'


def test_up_without_a_theme_leaves_the_env_file_alone(project: Path) -> None:
    before = env_lines(project)
    assert make(project, 'up').returncode == 0
    assert env_lines(project) == before


def test_up_refuses_an_invalid_theme_before_building(project: Path) -> None:
    result = make(project, 'up', 'THEME=neon')
    assert result.returncode != 0
    assert calls(project) == []


def test_compose_passes_the_theme_through_with_system_as_default() -> None:
    assert 'INSIGHT_THEME: ${INSIGHT_THEME:-system}' in (ROOT / 'compose.yaml').read_text()


# --------------------------------------------------------------------------- local Python (stand-in venv)


def test_smoke_passes_the_password_in_the_environment_not_the_command_line(project: Path) -> None:
    assert make(project, 'smoke').returncode == 0
    assert calls(project) == ['python scripts/smoke.py http://127.0.0.1:8080 --no-demo password-in-env=yes']
    assert 'secret-pass-123' not in calls(project)[0]


@pytest.mark.parametrize(
    ('target', 'expected'),
    [
        ('test', ['pytest']),
        ('test-fast', ['pytest tests/unit -q']),
        ('test-cov', ['pytest --cov --cov-report=term-missing --cov-fail-under=90']),
        ('lint', ['ruff check src tests scripts', 'ruff format --check src tests scripts']),
        ('format', ['ruff check --fix src tests scripts', 'ruff format src tests scripts']),
        ('typecheck', ['mypy']),
        ('serve', ['insight serve']),
        ('benchmark', ['python scripts/benchmark_extraction.py', 'python scripts/benchmark_performance.py']),
        ('drill', ['python scripts/backup_restore_drill.py']),
        ('locks', ['python scripts/lock.py']),
        ('locks-upgrade', ['python scripts/lock.py --upgrade']),
        ('ioc-example', ['python scripts/make_ioc_example.py']),
        ('release-fixture', ['python scripts/make_release_fixture.py']),
    ],
)
def test_python_targets_use_the_virtualenv(project: Path, target: str, expected: list[str]) -> None:
    assert make(project, target).returncode == 0
    assert ran(project) == expected


def test_check_runs_every_quality_gate_of_ci(project: Path) -> None:
    assert make(project, 'check').returncode == 0
    assert ran(project) == [
        'ruff check src tests scripts',
        'ruff format --check src tests scripts',
        'mypy',
        'pip check',
        'python scripts/lock.py --check',
        'python scripts/check_forbidden_files.py',
        'check-jsonschema --builtin-schema vendor.github-workflows .github/workflows/*.yml',
        'zizmor --offline --min-severity medium --config .github/zizmor.yml .github/workflows',
        'python scripts/check_pins.py',
    ]


def test_ci_matches_the_ci_workflow_quality_steps() -> None:
    """`make check` must not drift from CI's quality job."""
    workflow = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text()
    for command in (
        'ruff check src tests scripts',
        'ruff format --check src tests scripts',
        'python scripts/lock.py --check',
        'python scripts/check_forbidden_files.py',
        'zizmor --offline --min-severity medium --config .github/zizmor.yml .github/workflows',
        'python scripts/check_pins.py',
        '--cov-fail-under=90',
    ):
        assert command in workflow
        assert command in MAKEFILE


@pytest.mark.parametrize(
    ('args', 'message'),
    [
        (['test-postgres'], 'Set INSIGHT_TEST_DATABASE_URL='),
        (['release-check'], 'usage: make release-check TAG=vX.Y.Z'),
    ],
)
def test_targets_that_need_a_value_say_so(project: Path, args: list[str], message: str) -> None:
    result = make(project, *args, INSIGHT_TEST_DATABASE_URL='')
    assert result.returncode != 0
    assert message in result.stderr
    assert calls(project) == []


def test_test_postgres_passes_the_database_url(project: Path) -> None:
    url = 'postgresql+psycopg://postgres@localhost/postgres'
    assert make(project, 'test-postgres', INSIGHT_TEST_DATABASE_URL=url).returncode == 0
    assert ran(project) == ['pytest -m not slow']


def test_tools_come_from_path_without_a_virtualenv(project: Path) -> None:
    shutil.rmtree(project / 'venv')
    dry_run = make(project, '-n', 'test-fast')
    assert dry_run.stdout.strip() == 'pytest tests/unit -q'


def test_clean_never_touches_data_backups_exports_or_credentials(project: Path) -> None:
    for kept in ('data/insight.db', 'backups/backup-1.db', 'exports/iocs-1.json'):
        (project / kept).parent.mkdir(exist_ok=True)
        (project / kept).write_text('keep')
    for removed in ('.pytest_cache/x', '.mypy_cache/x', 'dist/insight.whl', 'htmlcov/index.html'):
        (project / removed).parent.mkdir(parents=True, exist_ok=True)
        (project / removed).write_text('cache')
    for directory in ('src', 'tests', 'scripts'):
        (project / directory / '__pycache__').mkdir(parents=True)
    assert make(project, 'clean').returncode == 0
    for kept in ('.env', 'data/insight.db', 'backups/backup-1.db', 'exports/iocs-1.json'):
        assert (project / kept).exists(), kept
    for removed in ('.pytest_cache', '.mypy_cache', 'dist', 'htmlcov', 'src/__pycache__'):
        assert not (project / removed).exists(), removed

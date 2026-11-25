"""``insight users``: people and their roles from the host, the break-glass (ADR 0046)."""

from __future__ import annotations

import io
import os
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import cli, services
from insight.models import AuditEvent, User, database


@pytest.fixture
def people(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[sessionmaker[Session]]:
    """A migrated SQLite database the CLI reads from ``INSIGHT_DATA_DIR``, and a way to plant people."""
    monkeypatch.chdir(tmp_path)
    data = tmp_path / 'data'
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATA_DIR': str(data)})
    assert cli.main(['migrate']) == 0
    engine, sessions = database(f'sqlite:///{data / "insight.db"}', migrate=False)
    yield sessions
    engine.dispose()


def plant(sessions: sessionmaker[Session], email: str, role: str | None = None) -> str:
    with sessions.begin() as db:
        user = User(issuer='https://idp.example.org', subject=email, email=email, display_name='', role=role)
        db.add(user)
        db.flush()
        services.start_operator_session(db, binding='b', at=datetime.now(UTC), user_id=user.id)
        return user.id


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = cli.main(['users', *argv])
    out, err = capsys.readouterr()
    return code, out, err


def test_list_says_when_nobody_has_signed_in(
    people: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(capsys, 'list') == (0, 'Nobody has signed in through the identity provider yet.\n', '')


def test_approve_change_disable_enable_and_sign_out(
    people: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    user_id = plant(people, 'new@example.org')
    code, out, _ = run(capsys, 'list')
    assert code == 0
    assert f'{user_id}  new@example.org  (waiting for approval;' in out
    assert '1 open session)' in out
    assert run(capsys, 'role', 'NEW@example.org', 'Analyst')[1] == (
        'new@example.org is now an analyst. 1 session ended.\n'
    )
    assert run(capsys, 'role', user_id, 'viewer')[1] == 'new@example.org is now a viewer.\n'
    assert run(capsys, 'disable', user_id)[1] == 'new@example.org is disabled.\n'
    assert 'disabled' in run(capsys, 'list')[1]
    assert run(capsys, 'enable', user_id)[1] == 'new@example.org is enabled.\n'
    assert run(capsys, 'sign-out', user_id)[1] == 'new@example.org is signed out.\n'
    assert (
        run(capsys, 'role', user_id, 'none')[1] == 'new@example.org has no role now and waits for approval.\n'
    )
    with people() as db:
        events = db.scalars(select(AuditEvent).where(AuditEvent.object_id == user_id)).all()
        assert {e.actor for e in events} == {'cli'}
        assert [e.action for e in events] == [
            'user.role',
            'user.role',
            'user.disable',
            'user.enable',
            'user.sign_out',
            'user.role',
        ]


def test_remove_asks_first(
    people: sessionmaker[Session], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    user_id = plant(people, 'gone@example.org', 'admin')
    monkeypatch.setattr(sys, 'stdin', io.StringIO('no\n'))
    assert run(capsys, 'remove', user_id)[1].endswith('Cancelled; nothing was removed.\n')
    monkeypatch.setattr(sys, 'stdin', io.StringIO('remove\n'))
    assert run(capsys, 'remove', user_id)[1].endswith('Removed gone@example.org. 1 session ended.\n')
    with people() as db:
        assert db.get(User, user_id) is None
    other = plant(people, 'quick@example.org')
    assert run(capsys, 'remove', other, '--yes')[1] == 'Removed quick@example.org. 1 session ended.\n'


@pytest.mark.parametrize(
    ('argv', 'message'),
    [
        (['role', 'nobody@example.org', 'viewer'], "nobody matches 'nobody@example.org'"),
        (['role', 'twin@example.org', 'viewer'], '2 people use that e-mail address'),
    ],
)
def test_unknown_or_ambiguous_people_are_refused(
    people: sessionmaker[Session], capsys: pytest.CaptureFixture[str], argv: list[str], message: str
) -> None:
    with people.begin() as db:
        for subject in ('a', 'b'):
            db.add(User(issuer='https://idp.example.org', subject=subject, email='twin@example.org'))
    code, _, err = run(capsys, *argv)
    assert code == 1
    assert message in err


def test_bad_arguments_are_usage_errors(
    people: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exit_code:
        cli.main(['users', 'role', 'someone', 'owner'])
    assert exit_code.value.code == 2
    assert 'invalid choice' in capsys.readouterr().err
    assert 'users ACTION' in cli.build_parser().format_help()

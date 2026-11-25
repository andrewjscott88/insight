"""People, their roles and their sessions (``services.users``, ADR 0046)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from insight import services
from insight.models import AuditEvent, OperatorSession, User

NOW = datetime(2026, 11, 25, 12, tzinfo=UTC)
BINDING = 'binding'


def add(db: Session, role: str | None = None, *, email: str = '', name: str = '') -> str:
    user = User(issuer='https://idp.example.org', subject=f'sub-{email or name or role}', role=role)
    user.email, user.display_name = email, name
    db.add(user)
    db.flush()
    return user.id


def session_for(db: Session, user_id: str | None, at: datetime = NOW) -> str:
    return services.start_operator_session(db, binding=BINDING, at=at, user_id=user_id)


def principal(db: Session, sid: str) -> services.SessionPrincipal | None:
    return services.session_principal(db, sid, binding=BINDING, at=NOW + timedelta(minutes=1))


def test_a_session_names_the_operator_or_the_person(db: Session) -> None:
    analyst = add(db, 'analyst', email='a@example.org')
    operator_sid, person_sid = session_for(db, None), session_for(db, analyst)
    assert (
        principal(db, operator_sid) == services.OPERATOR_PRINCIPAL == services.SessionPrincipal(None, 'admin')
    )
    assert principal(db, person_sid) == services.SessionPrincipal(analyst, 'analyst')
    assert principal(db, 'unknown') is None
    expired = session_for(db, analyst, at=NOW - services.SESSION_TTL - timedelta(minutes=5))
    assert principal(db, expired) is None


def test_waiting_people_have_no_role_and_disabled_people_no_session(db: Session) -> None:
    waiting = add(db, None, email='w@example.org')
    assert principal(db, session_for(db, waiting)) == services.SessionPrincipal(waiting, None)
    blocked = add(db, 'admin', email='b@example.org')
    sid = session_for(db, blocked)
    db.get(User, blocked).disabled = True  # type: ignore[union-attr]
    assert principal(db, sid) is None


def test_role_changes_end_sessions_and_are_audited_without_personal_data(db: Session) -> None:
    services.set_actor(db, 'cli')
    user_id = add(db, None, email='new@example.org', name='New Person')
    sid = session_for(db, user_id)
    assert services.set_user_role(db, user_id, 'analyst') == 1
    assert principal(db, sid) is None
    assert services.set_user_role(db, user_id, None) == 0
    event = db.scalars(select(AuditEvent).where(AuditEvent.action == 'user.role')).first()
    assert event is not None
    assert (event.object_id, event.actor) == (user_id, 'cli')
    assert event.detail == 'role: none -> analyst; 1 session(s) ended'
    details = ' '.join(e.detail for e in db.scalars(select(AuditEvent)))
    assert 'new@example.org' not in details
    assert 'New Person' not in details
    with pytest.raises(ValueError, match='Unknown role'):
        services.set_user_role(db, user_id, 'owner')  # type: ignore[arg-type]
    with pytest.raises(LookupError):
        services.set_user_role(db, 'missing', 'viewer')


def test_disable_enable_sign_out_and_remove(db: Session) -> None:
    user_id = add(db, 'viewer', email='v@example.org')
    other = add(db, 'viewer', email='other@example.org')
    session_for(db, user_id)
    session_for(db, user_id)
    kept = session_for(db, other)
    assert services.set_user_disabled(db, user_id, True) == 2
    assert services.set_user_disabled(db, user_id, False) == 0
    session_for(db, user_id)
    assert services.sign_out_user(db, user_id) == 1
    session_for(db, user_id)
    assert services.remove_user(db, user_id) == 1
    assert db.get(User, user_id) is None
    assert principal(db, kept) == services.SessionPrincipal(other, 'viewer')
    actions = [e.action for e in db.scalars(select(AuditEvent).order_by(AuditEvent.created_at))]
    assert actions == ['user.disable', 'user.enable', 'user.sign_out', 'user.remove']


def test_removing_a_person_cascades_to_their_sessions_in_the_database(db: Session) -> None:
    """The foreign key ends sessions even if a row is deleted directly (both databases)."""
    user_id = add(db, 'viewer', email='c@example.org')
    session_for(db, user_id)
    db.delete(db.get(User, user_id))
    db.flush()
    db.expire_all()
    assert db.scalars(select(OperatorSession).where(OperatorSession.user_id == user_id)).all() == []


def test_find_and_list_people(db: Session) -> None:
    first = add(db, 'admin', email='Ann@Example.org', name='Ann')
    add(db, None, email='zed@example.org')
    twin_a = add(db, 'viewer', email='twin@example.org', name='Twin A')
    add(db, 'viewer', email='TWIN@example.org', name='Twin B')
    session_for(db, first)
    found = services.find_user(db, 'ann@example.ORG', at=NOW)
    assert (found.id, found.label, found.sessions) == (first, 'Ann <Ann@Example.org>', 1)
    assert services.find_user(db, twin_a, at=NOW).display_name == 'Twin A'
    with pytest.raises(ValueError, match='2 people'):
        services.find_user(db, 'twin@example.org', at=NOW)
    with pytest.raises(LookupError):
        services.find_user(db, '  ', at=NOW)
    listed = services.list_users(db, at=NOW)
    assert listed[0].email == 'zed@example.org', 'people waiting for approval come first'
    assert [p.sessions for p in listed if p.id == first] == [1]


def test_signing_out_everywhere_is_per_person(db: Session) -> None:
    user_id = add(db, 'analyst', email='p@example.org')
    operator_sids = [session_for(db, None), session_for(db, None)]
    person_sid = session_for(db, user_id)
    assert services.sign_out(db, operator_sids[0], binding=BINDING, everywhere=True) == 2
    assert principal(db, person_sid) is not None
    assert services.sign_out(db, person_sid, binding=BINDING, everywhere=False) == 0
    assert principal(db, person_sid) is None
    assert services.sign_out(db, 'unknown', binding=BINDING, everywhere=True) == 0

"""People who sign in through the identity provider, their roles and their sessions (ADR 0046).

A person's first sign-in adds them. Unless the host maps provider groups to roles, they wait with no access
until an admin gives them a role (Settings, or ``insight users`` on the host). Changing a role, disabling a
person or removing them ends their sessions at once. Audit events name people by ID only, never by e-mail.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..models import OperatorSession, User
from ..permissions import Role, is_role
from .audit import audit
from .common import stamp


@dataclass(frozen=True, slots=True)
class UserView:
    id: str
    issuer: str
    subject: str
    email: str
    display_name: str
    #: ``None`` while waiting for an admin's approval.
    role: str | None
    #: Provider groups set the role at every sign-in.
    role_from_groups: bool
    disabled: bool
    first_sign_in_at: str
    last_sign_in_at: str
    #: Unexpired sessions.
    sessions: int

    @property
    def label(self) -> str:
        """How lists name the person: their name and e-mail, whichever the provider gave."""
        if self.display_name and self.email:
            return f'{self.display_name} <{self.email}>'
        return self.display_name or self.email or self.subject


def _view(user: User, sessions: int) -> UserView:
    return UserView(
        id=user.id,
        issuer=user.issuer,
        subject=user.subject,
        email=user.email,
        display_name=user.display_name,
        role=user.role if is_role(user.role) else None,
        role_from_groups=user.role_from_groups,
        disabled=user.disabled,
        first_sign_in_at=user.first_sign_in_at,
        last_sign_in_at=user.last_sign_in_at,
        sessions=sessions,
    )


def list_users(db: Session, *, at: datetime) -> list[UserView]:
    """Everyone who has signed in, people waiting for approval first, then by name."""
    open_sessions = dict(
        db.execute(
            select(OperatorSession.user_id, func.count())
            .where(OperatorSession.user_id.is_not(None), OperatorSession.expires_at > stamp(at))
            .group_by(OperatorSession.user_id)
        ).all()
    )
    users = db.scalars(select(User)).all()
    views = [_view(user, open_sessions.get(user.id, 0)) for user in users]
    return sorted(views, key=lambda v: (v.role is not None, v.label.casefold(), v.id))


def user_labels(db: Session, user_ids: Iterable[str]) -> dict[str, str]:
    """Each person's name and e-mail by ID, for audit trails that name people (admins only, ADR 0046)."""
    wanted = {user_id for user_id in user_ids if user_id}
    if not wanted:
        return {}
    found = db.scalars(select(User).where(User.id.in_(wanted))).all()
    return {user.id: _view(user, 0).label for user in found}


def find_user(db: Session, ref: str, *, at: datetime) -> UserView:
    """One person by ID, or by e-mail address (case-insensitive) when it names exactly one.

    Raises ``LookupError`` when nobody matches and ``ValueError`` when an e-mail matches several people.
    """
    ref = ref.strip()
    user = db.get(User, ref) if ref else None
    if user is None and ref:
        matches = db.scalars(select(User).where(func.lower(User.email) == ref.lower())).all()
        if len(matches) > 1:
            raise ValueError(f'{len(matches)} people use that e-mail address; use the ID instead')
        user = matches[0] if matches else None
    if user is None:
        raise LookupError('No such person')
    sessions = db.scalar(
        select(func.count())
        .select_from(OperatorSession)
        .where(OperatorSession.user_id == user.id, OperatorSession.expires_at > stamp(at))
    )
    return _view(user, sessions or 0)


def end_user_sessions(db: Session, user_id: str) -> int:
    """Sign one person out of every browser; returns how many sessions ended (not audited: callers are)."""
    owner = OperatorSession.user_id == user_id
    count = db.scalar(select(func.count()).select_from(OperatorSession).where(owner)) or 0
    db.execute(delete(OperatorSession).where(owner))
    return count


def sign_out_user(db: Session, user_id: str) -> int:
    """An admin signs one person out everywhere. Audited as ``user.sign_out``."""
    user = db.get(User, user_id)
    if user is None:
        raise LookupError('No such person')
    count = end_user_sessions(db, user.id)
    audit(db, 'user.sign_out', user.id, f'{count} session(s) ended')
    return count


def record_sign_in(
    db: Session,
    *,
    issuer: str,
    subject: str,
    email: str,
    display_name: str,
    group_role: Role | None,
    groups_mapped: bool,
    at: datetime,
) -> User:
    """Add or update the person behind a verified provider sign-in, and return them (ADR 0046).

    A new person gets the role their provider groups give (``group_role``), or none: they wait for an
    admin. When the host maps groups, every sign-in sets the role again, and a role that came from groups
    goes when the groups no longer give one; a role an admin gave stays. If the host stopped mapping groups,
    a role that came from them goes too. A role change ends the person's other sessions. Audited as the
    person (``user.add``, ``user.role``). A disabled person is returned as they are; the caller refuses them.
    """
    user = db.scalar(select(User).where(User.issuer == issuer, User.subject == subject))
    if user is None:
        user = User(
            issuer=issuer,
            subject=subject,
            role=group_role,
            role_from_groups=group_role is not None,
            first_sign_in_at=stamp(at),
            last_sign_in_at=stamp(at),
        )
        db.add(user)
        db.flush()
        db.info['actor'] = f'user:{user.id}'
        audit(db, 'user.add', user.id, f'role: {group_role or "none, waiting for approval"}')
    else:
        db.info['actor'] = f'user:{user.id}'
        previous = user.role
        if groups_mapped and group_role is not None:
            user.role, user.role_from_groups = group_role, True
        elif user.role_from_groups:  # The groups no longer give a role, or groups are no longer mapped.
            user.role, user.role_from_groups = None, False
        if user.role != previous:
            ended = end_user_sessions(db, user.id)
            change = f'role: {previous or "none"} -> {user.role or "none"} (provider groups)'
            audit(db, 'user.role', user.id, f'{change}; {ended} session(s) ended')
    user.email, user.display_name = email[:320], display_name[:200]
    user.last_sign_in_at = stamp(at)
    return user


def set_user_role(db: Session, user_id: str, role: Role | None) -> int:
    """Give a person a role, or take it away (``None``: back to waiting). Their sessions end, so the new
    role applies everywhere at once; returns how many ended. Audited as ``user.role``."""
    user = db.get(User, user_id)
    if user is None:
        raise LookupError('No such person')
    if role is not None and not is_role(role):
        raise ValueError(f'Unknown role {role!r}')
    previous = user.role
    user.role, user.role_from_groups = role, False
    ended = end_user_sessions(db, user.id)
    audit(
        db, 'user.role', user.id, f'role: {previous or "none"} -> {role or "none"}; {ended} session(s) ended'
    )
    return ended


def set_user_disabled(db: Session, user_id: str, disabled: bool) -> int:
    """Disable a person (they cannot sign in; their sessions end) or enable them again. Returns how many
    sessions ended. Audited as ``user.disable`` or ``user.enable``."""
    user = db.get(User, user_id)
    if user is None:
        raise LookupError('No such person')
    user.disabled = disabled
    ended = end_user_sessions(db, user.id) if disabled else 0
    audit(db, 'user.disable' if disabled else 'user.enable', user.id, f'{ended} session(s) ended')
    return ended


def remove_user(db: Session, user_id: str) -> int:
    """Remove a person and end their sessions; returns how many ended. Their audit events keep the ID. If
    they sign in again they come back as someone new, waiting for approval. Audited as ``user.remove``."""
    user = db.get(User, user_id)
    if user is None:
        raise LookupError('No such person')
    ended = end_user_sessions(db, user.id)
    db.delete(user)
    db.flush()
    audit(db, 'user.remove', user_id, f'{ended} session(s) ended')
    return ended

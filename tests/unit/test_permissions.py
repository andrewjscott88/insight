"""The role matrix (ADR 0046): three nested roles, and nothing for anyone without one."""

from __future__ import annotations

import pytest

from insight.permissions import MINIMUM_ROLE, ROLES, Permission, key_role, parse_role, role_allows


def test_roles_are_nested() -> None:
    assert ROLES == ('viewer', 'analyst', 'admin')
    for permission in Permission:
        allowed = [role for role in ROLES if role_allows(role, permission)]
        assert allowed == list(ROLES[ROLES.index(MINIMUM_ROLE[permission]) :]), permission


def test_every_permission_has_a_minimum_role() -> None:
    assert set(MINIMUM_ROLE) == set(Permission)


@pytest.mark.parametrize('role', [None, '', 'Admin', 'root', 'operator'])
def test_no_role_or_an_unknown_one_allows_nothing(role: str | None) -> None:
    assert not any(role_allows(role, permission) for permission in Permission)


def test_the_acceptance_criteria() -> None:
    """TIP 3.4: a viewer cannot ingest, sync or change schedules; an analyst triages but changes no
    settings."""
    for permission in (Permission.ADD_REPORTS, Permission.SYNC_SOURCES, Permission.SCHEDULES):
        assert not role_allows('viewer', permission)
    assert role_allows('analyst', Permission.REVIEW)
    for permission in (Permission.SOURCES, Permission.SCHEDULES, Permission.ALERTS, Permission.DEMO):
        assert not role_allows('analyst', permission)
        assert role_allows('admin', permission)


@pytest.mark.parametrize(
    ('access', 'role'),
    [
        ('read', 'viewer'),
        ('read-feedback', 'viewer'),
        ('read-write', 'analyst'),
        ('admin', 'viewer'),
        ('', 'viewer'),
    ],
)
def test_keys_are_never_admins(access: str, role: str) -> None:
    assert key_role(access) == role


def test_roles_parse_case_insensitively() -> None:
    assert parse_role(' Analyst ') == 'analyst'
    with pytest.raises(ValueError, match='viewer, analyst, admin'):
        parse_role('owner')

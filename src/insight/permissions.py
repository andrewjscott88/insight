"""Roles and what each may do (ADR 0046). Pure: no database, no framework.

Three fixed roles. Each may do everything the one before it may:

* **viewer**: read the workspace and the API; download exports, briefs, products and hunt guides.
* **analyst**: intelligence work: add and import reports; review indicators and verdicts; write notes and
  links; edit products, requirements, RFIs, watch terms and hunt packages; sync a source now; approve an
  outside lookup for a provider an admin has turned on.
* **admin**: settings: switch sources and lookup providers on or off; operator sources; schedules; alert
  destinations; demo reports; and, from TIP 3.4b, people and their roles.

The built-in **operator** (the password sign-in, with MFA) is an admin. API keys keep their own life cycle on
the host: a ``read`` or ``read-feedback`` key acts as a viewer and a ``read-write`` key as an analyst; no key
is ever an admin. Roles do not change TLP: everyone signed in reads up to the instance limit.

Each surface looks the permission up and refuses by default: the API by route
(``insight.web.route_permissions``) and the workspace by ``Workspace.write(permission)``.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Literal, TypeGuard, get_args

Role = Literal['viewer', 'analyst', 'admin']

#: Lowest first: a role may do everything the roles before it may.
ROLES: Final[tuple[Role, ...]] = get_args(Role)

#: What the built-in operator account (the password sign-in) acts as.
OPERATOR_ROLE: Final[Role] = 'admin'

NOT_PERMITTED: Final = 'Your role does not allow this.'


class Permission(StrEnum):
    """One action, or one family of actions, that a role may or may not take."""

    #: Read the workspace and the API; download exports, briefs, products and hunt guides.
    READ = 'read'
    #: Add a report, upload a PDF, import a STIX bundle.
    ADD_REPORTS = 'add-reports'
    #: Review reports and indicators; verdicts, assessments, credibility and source ratings.
    REVIEW = 'review'
    #: Notes, ATT&CK tags, threat groups, campaigns and the links between them and reports.
    NOTES_AND_LINKS = 'notes-and-links'
    #: Cases, judgements, gaps and published products.
    PRODUCTS = 'products'
    #: Intelligence requirements, RFIs, their evidence, and watch terms.
    REQUIREMENTS = 'requirements'
    #: Hunt packages, hunts, detection rules (stored as text) and sightings.
    HUNTING = 'hunting'
    #: Sync a source now (one or all).
    SYNC_SOURCES = 'sync-sources'
    #: Approve an outside lookup for a provider an admin has turned on.
    LOOKUPS = 'lookups'
    #: Switch sources and lookup providers on or off; add, change or remove operator sources.
    SOURCES = 'sources'
    #: When sources sync by themselves.
    SCHEDULES = 'schedules'
    #: Where alerts go (alert destinations) and test alerts.
    ALERTS = 'alerts'
    #: Load the synthetic demo reports into the workspace.
    DEMO = 'demo'


#: The lowest role allowed each permission: the matrix in ADR 0046.
MINIMUM_ROLE: Final[Mapping[Permission, Role]] = MappingProxyType(
    {
        Permission.READ: 'viewer',
        Permission.ADD_REPORTS: 'analyst',
        Permission.REVIEW: 'analyst',
        Permission.NOTES_AND_LINKS: 'analyst',
        Permission.PRODUCTS: 'analyst',
        Permission.REQUIREMENTS: 'analyst',
        Permission.HUNTING: 'analyst',
        Permission.SYNC_SOURCES: 'analyst',
        Permission.LOOKUPS: 'analyst',
        Permission.SOURCES: 'admin',
        Permission.SCHEDULES: 'admin',
        Permission.ALERTS: 'admin',
        Permission.DEMO: 'admin',
    }
)


def is_role(value: object) -> TypeGuard[Role]:
    return isinstance(value, str) and value in ROLES


def parse_role(value: str) -> Role:
    """A role name, case-insensitive; ``ValueError`` names the valid ones."""
    role = value.strip().lower()
    if not is_role(role):
        raise ValueError(f'Unknown role {value!r}; choose one of: {", ".join(ROLES)}')
    return role


def role_allows(role: str | None, permission: Permission) -> bool:
    """Whether ``role`` may use ``permission``. No role (a person waiting for approval) and an unknown
    value may do nothing."""
    if not is_role(role):
        return False
    return ROLES.index(role) >= ROLES.index(MINIMUM_ROLE[permission])


def key_role(access: str) -> Role:
    """The role an API key acts as. Anything but ``read-write`` reads as a viewer; no key is an admin."""
    return 'analyst' if access == 'read-write' else 'viewer'

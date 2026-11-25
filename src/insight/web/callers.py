"""Who makes a request (ADR 0046): the signed-in operator, a signed-in person, an API key, or a visitor
reading the public view. Pure: no database, no framework."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal, TypeAlias

from .. import apikeys
from ..permissions import OPERATOR_ROLE, Permission, Role, key_role, role_allows


@dataclass(frozen=True, slots=True)
class Caller:
    """Who made a request: the signed-in operator, a signed-in person, the API key (named by its public key
    ID), or a visitor reading the public view."""

    kind: Literal['session', 'api_key', 'public']
    key_id: str | None = None
    access: apikeys.Access = 'read-write'
    #: Most restrictive TLP label this caller may read or write (``None``: no per-caller limit).
    max_tlp: str | None = None
    #: The signed-in person (``users.id``); ``None`` for the operator and for API keys.
    user_id: str | None = None
    #: What the caller may do (ADR 0046). Only a person's role is taken as given (``None``: nothing); a key's
    #: follows from its access level and the operator's is admin, whatever is passed.
    role: Role | None = None

    def __post_init__(self) -> None:
        if self.kind == 'api_key':
            object.__setattr__(self, 'role', key_role(self.access))  # never an admin
        elif self.kind == 'public':
            # A visitor reads published intelligence only: a viewer, TLP:CLEAR, whatever is passed.
            object.__setattr__(self, 'role', 'viewer')
            object.__setattr__(self, 'max_tlp', 'CLEAR')
            object.__setattr__(self, 'user_id', None)
        elif self.user_id is None:
            object.__setattr__(self, 'role', OPERATOR_ROLE)

    @property
    def limit_key(self) -> str:
        """Rate-limit bucket: each person, the operator's browser and the API key have their own budget."""
        if self.key_id is not None:
            return f'key:{self.key_id}'
        if self.kind == 'public':
            return 'public'
        return 'session' if self.user_id is None else f'user:{self.user_id}'

    @property
    def actor(self) -> str:
        """How audit events name this caller."""
        if self.key_id is not None:
            return f'api-key:{self.key_id}'
        if self.kind == 'public':
            return 'public'
        return 'operator' if self.user_id is None else f'user:{self.user_id}'

    def may(self, permission: Permission) -> bool:
        """Whether this caller's role allows ``permission``."""
        return role_allows(self.role, permission)


SESSION_CALLER: Final = Caller('session')

#: A visitor reading the public view (``INSIGHT_PUBLIC_VIEW``): a viewer, TLP:CLEAR only, no API.
PUBLIC_CALLER: Final = Caller('public')

#: ``lookup(session) -> caller``: who a signed session cookie belongs to, or ``None`` (not signed in).
SessionLookup: TypeAlias = Callable[[Mapping[str, Any]], Caller | None]

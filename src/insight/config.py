"""Environment-driven application settings."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Self, cast

from .appearance import DEFAULT_THEME, Theme, parse_theme
from .schemas import TLP, TLP_LEVELS

MIN_PASSWORD_LENGTH = 12
MIN_SECRET_LENGTH = 32
DEFAULT_ALLOWED_HOSTS = ('localhost', '127.0.0.1')
#: Most restrictive label this instance stores by default. TLP:RED is for named recipients only and should not
#: sit on an internet-facing server unless the operator decides otherwise (``INSIGHT_MAX_TLP=RED``).
DEFAULT_MAX_TLP: TLP = 'AMBER+STRICT'


def parse_max_tlp(value: str) -> TLP:
    """``INSIGHT_MAX_TLP``: a TLP label (case-insensitive); empty means the default."""
    label = value.strip().upper() or DEFAULT_MAX_TLP
    if label not in TLP_LEVELS:
        raise RuntimeError(f'INSIGHT_MAX_TLP must be one of {", ".join(TLP_LEVELS)}; got {value!r}')
    return cast(TLP, label)


def parse_mfa(value: str) -> bool:
    """``INSIGHT_MFA``: ``on`` requires an authenticator-app code at sign-in. Default (empty): ``off``.

    Strict, because a typo such as ``INSIGHT_MFA=onn`` must not silently leave sign-in password-only.
    """
    word = value.strip().lower()
    if word in {'', 'off', '0', 'false', 'no'}:
        return False
    if word in {'on', '1', 'true', 'yes'}:
        return True
    raise RuntimeError(f'INSIGHT_MFA must be "on" or "off"; got {value!r}')


def parse_run_jobs(value: str) -> bool:
    """``INSIGHT_RUN_JOBS``: ``on`` (default) runs scheduled syncs in this process; ``off`` does not.

    Use ``off`` for every process but one if you ever run several. Strict, like ``INSIGHT_MFA``.
    """
    choice = value.strip().lower()
    if choice in {'', 'on'}:
        return True
    if choice == 'off':
        return False
    raise RuntimeError(f'INSIGHT_RUN_JOBS must be "on" or "off"; got {value!r}')


def parse_trusted_proxies(value: str) -> tuple[str, ...]:
    """``INSIGHT_TRUSTED_PROXIES``: comma-separated IP addresses or CIDR networks of the reverse proxy.

    Validated strictly because uvicorn silently ignores entries it cannot parse (``10.0.0.1/8`` would trust
    nothing, without an error). ``*`` is refused: it would let any client forge its address and scheme.
    """
    entries = tuple(item for item in (x.strip() for x in value.split(',')) if item)
    for entry in entries:
        if entry == '*':
            raise RuntimeError(
                'INSIGHT_TRUSTED_PROXIES=* would let any client forge its address; list the proxy addresses'
            )
        try:
            if '/' in entry:
                ipaddress.ip_network(entry)  # strict: host bits must be zero, e.g. 172.18.0.0/16
            else:
                ipaddress.ip_address(entry)
        except ValueError as exc:
            raise RuntimeError(
                f'INSIGHT_TRUSTED_PROXIES: {entry!r} is not an IP address or network (e.g. 172.18.0.0/16)'
            ) from exc
    return entries


def database_url_from_env(environ: Mapping[str, str] | None = None) -> str:
    """``INSIGHT_DATABASE_URL`` or the default SQLite file under ``INSIGHT_DATA_DIR`` (created if needed)."""
    env = os.environ if environ is None else environ
    if url := env.get('INSIGHT_DATABASE_URL', ''):
        return url
    # Only touch the filesystem when the default SQLite location is actually used.
    data = Path(env.get('INSIGHT_DATA_DIR', 'data'))
    data.mkdir(parents=True, exist_ok=True)
    return f'sqlite:///{data / "insight.db"}'


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable runtime configuration. Construct directly in tests, or via :meth:`from_env`."""

    database_url: str
    password: str
    session_secret: str
    secure_cookies: bool = False
    allowed_hosts: tuple[str, ...] = (*DEFAULT_ALLOWED_HOSTS, 'testserver')
    #: Seconds each failed sign-in waits before answering (sign-ins are checked one at a time).
    failed_login_delay: float = 1.0
    #: Reverse proxies whose ``X-Forwarded-For``/``X-Forwarded-Proto`` headers are believed. Empty: none.
    trusted_proxies: tuple[str, ...] = ()
    #: Reports whose (possibly raised) label is more restrictive are refused on upload (API and workspace).
    max_tlp: TLP = DEFAULT_MAX_TLP
    #: Require an authenticator-app code at sign-in (``INSIGHT_MFA=on``). Off by default. When on, an app
    #: must be paired (``insight mfa setup``); until then sign-in is refused, never silently password-only.
    mfa: bool = False
    #: Colour theme for browsers that have not picked one in the workspace (``INSIGHT_THEME``): ``system``
    #: follows the device's light/dark preference. A choice made in the workspace overrides it per device.
    theme: Theme = DEFAULT_THEME
    #: Run the background job runner (scheduled syncs) in this process (``INSIGHT_RUN_JOBS``, default ``on``).
    #: Off when constructed directly, so tests and tools never start it by accident.
    run_jobs: bool = False

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Self:
        """Build settings from ``INSIGHT_*`` environment variables.

        Raises ``RuntimeError`` when the operator password or session secret is missing or too short, or a
        setting is invalid.
        """
        env = os.environ if environ is None else environ
        password = env.get('INSIGHT_PASSWORD', '')
        secret = env.get('INSIGHT_SESSION_SECRET', '')
        if len(password) < MIN_PASSWORD_LENGTH or len(secret) < MIN_SECRET_LENGTH:
            raise RuntimeError(
                f'Set INSIGHT_PASSWORD ({MIN_PASSWORD_LENGTH}+ characters) and '
                f'INSIGHT_SESSION_SECRET ({MIN_SECRET_LENGTH}+ characters). See README.'
            )
        database_url = database_url_from_env(env)
        hosts = tuple(
            host for host in (x.strip() for x in env.get('INSIGHT_ALLOWED_HOSTS', '').split(',')) if host
        )
        return cls(
            database_url=database_url,
            password=password,
            session_secret=secret,
            secure_cookies=env.get('INSIGHT_SECURE_COOKIES', '0').strip().lower() in {'1', 'true', 'yes'},
            allowed_hosts=hosts or DEFAULT_ALLOWED_HOSTS,
            trusted_proxies=parse_trusted_proxies(env.get('INSIGHT_TRUSTED_PROXIES', '')),
            max_tlp=parse_max_tlp(env.get('INSIGHT_MAX_TLP', '')),
            mfa=parse_mfa(env.get('INSIGHT_MFA', '')),
            theme=parse_theme(env.get('INSIGHT_THEME', '')),
            run_jobs=parse_run_jobs(env.get('INSIGHT_RUN_JOBS', '')),
        )

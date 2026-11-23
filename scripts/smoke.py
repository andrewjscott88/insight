"""End-to-end smoke test of a running Insight instance over HTTP (container, wheel or dev server).

    python scripts/smoke.py http://127.0.0.1:8080 --password "$INSIGHT_PASSWORD"
    python scripts/smoke.py URL --password P --print-cookie   # emit the session cookie (for ZAP scans)

Exit status is non-zero on the first failed check. Used by CI (container job), the milestone gate
(backup drill, DAST) and the post-release verification.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from collections.abc import Sequence
from typing import Any

import httpx

CSRF = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
REQUIRED_HEADERS = ('x-content-type-options', 'x-frame-options', 'referrer-policy', 'cache-control')


#: ``httpx.Client`` in production; Starlette's ``TestClient`` (httpx2-based) in unit tests. The two libraries'
#: client classes are structurally identical but unrelated types, so this stays deliberately loose.
HttpClient = Any


class SmokeFailure(AssertionError):
    pass


def check(condition: object, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def wait_until_healthy(client: HttpClient, timeout: float = 60.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        try:
            response = client.get('/health')
            if response.status_code == 200:
                body: dict[str, Any] = response.json()
                return body
        except (OSError, httpx.TransportError):
            pass  # not listening yet
        if time.monotonic() > deadline:
            raise SmokeFailure(f'/health did not become ready within {timeout:.0f}s')
        time.sleep(1)


def sign_in(client: HttpClient, password: str) -> str:
    """Real form sign-in; returns the API CSRF token."""
    page = client.get('/login')
    check(page.status_code == 200, f'GET /login returned {page.status_code}')
    match = CSRF.search(page.text)
    if match is None:
        raise SmokeFailure('login form has no CSRF token')
    response = client.post('/login', data={'csrf_token': match.group(1), 'password': password})
    check(response.status_code == 303, f'sign-in failed with HTTP {response.status_code}')
    response = client.get('/api/session')
    check(response.status_code == 200, f'GET /api/session returned {response.status_code} after sign-in')
    session = response.json()
    version = session.get('version')
    check(isinstance(version, str) and version.strip(), 'signed-in session is missing the version')
    token: str = session['csrf_token']
    return token


def run(client: HttpClient, password: str, *, load_demo: bool = True, ui: bool = True) -> dict[str, Any]:
    """Run every smoke check; returns the final ``/api/stats``. ``ui=False`` skips the NiceGUI page checks."""
    health = wait_until_healthy(client)
    check(health == {'status': 'ok'}, 'public /health must return only the liveness status')
    response = client.get('/health')
    missing = [h for h in REQUIRED_HEADERS if h not in response.headers]
    check(not missing, f'security headers missing: {missing}')
    if ui:
        anonymous = client.get('/', follow_redirects=False)
        check(anonymous.status_code == 303, f'anonymous workspace access returned {anonymous.status_code}')
    check(client.get('/api/stats').status_code == 401, 'API is reachable without signing in')
    check(client.get('/api/session').status_code == 401, 'session information is public')
    check(
        client.post('/login', data={'csrf_token': 'missing', 'password': password}).status_code == 403,
        'forged CSRF sign-in was not rejected',
    )
    token = sign_in(client, password)
    headers = {'X-CSRF-Token': token}
    if load_demo:
        demo = client.post('/api/demo', headers=headers)
        check(demo.status_code == 200, f'POST /api/demo returned {demo.status_code}')
    if ui:
        workspace = client.get('/')
        check(workspace.status_code == 200, f'workspace returned {workspace.status_code}')
        check('Intel brief' in workspace.text, 'workspace page did not render')
    stats: dict[str, Any] = client.get('/api/stats').json()
    if load_demo:
        check(stats['documents'] >= 3, f'demo data missing: {stats}')
        if ui:
            check('Training scenario' in client.get('/').text, 'demo documents not rendered')
    return stats


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('base_url')
    parser.add_argument('--password', default=os.environ.get('INSIGHT_PASSWORD', ''))
    parser.add_argument('--no-demo', action='store_true', help='do not load the synthetic demo')
    parser.add_argument('--print-cookie', action='store_true', help='print "insight_session=<value>"')
    args = parser.parse_args(argv)
    if not args.password:
        parser.error('--password or INSIGHT_PASSWORD is required')
    with httpx.Client(base_url=args.base_url, timeout=30, trust_env=False) as client:
        try:
            stats = run(client, args.password, load_demo=not args.no_demo)
        except SmokeFailure as exc:
            print(f'SMOKE FAILED: {exc}', file=sys.stderr)
            return 1
        if args.print_cookie:
            print(f'insight_session={client.cookies.get("insight_session")}')
        else:
            print(f'Smoke test passed: {stats}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

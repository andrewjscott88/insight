"""Real phone geometry against an isolated synthetic metadata server; never a provider lookup."""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

if not os.environ.get('INSIGHT_E2E_URL') or not os.environ.get('INSIGHT_E2E_PASSWORD'):
    pytest.skip('set INSIGHT_E2E_URL and INSIGHT_E2E_PASSWORD to run browser tests', allow_module_level=True)

from .test_browser import browser, expect, show, sign_in

__all__ = ['browser']
pytestmark = pytest.mark.e2e


@pytest.fixture(params=[('crtsh', 'crt.sh'), ('circl', 'CIRCL passive DNS')])
def metadata_server(tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[tuple[str, str, str]]:
    provider, name = request.param
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    url = f'http://127.0.0.1:{port}'
    environment = os.environ.copy()
    environment['PYTHONPATH'] = str(Path(__file__).parents[2] / 'src')
    with (tmp_path / 'fixture-server.log').open('w', encoding='utf-8') as log:
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).with_name('pivot_metadata_server.py')),
                str(port),
                str(tmp_path),
                provider,
            ],
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 40
            with httpx.Client(trust_env=False, timeout=1) as client:
                while time.monotonic() < deadline:
                    assert process.poll() is None, 'Synthetic metadata server exited; inspect its fixture log'
                    try:
                        if client.get(url + '/health').status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(0.1)
                else:
                    pytest.fail('Synthetic metadata server did not start')
            yield url, provider, name
        finally:
            process.terminate()
            process.wait(timeout=20)


@pytest.mark.parametrize(('width', 'theme', 'large'), [(320, 'light', False), (390, 'dark', True)])
def test_maximum_provider_metadata_fits_phone(
    browser: Any, metadata_server: tuple[str, str, str], width: int, theme: str, large: bool
) -> None:
    """Regression: long expansion names and metadata stretched the pivot card beyond the phone width."""
    url, provider, name = metadata_server
    context = browser.new_context(
        base_url=url,
        viewport={'width': width, 'height': 844},
        is_mobile=True,
        has_touch=True,
        color_scheme=theme,
    )
    context.set_default_timeout(20_000)
    try:
        page = context.new_page()
        sign_in(page, 'synthetic-password-only')
        expect(page.locator('.side-tabs')).to_be_visible()
        if large:
            page.get_by_role('button', name='Larger text', exact=True).click()
        show(page, 'Investigate', 'Indicators')
        page.get_by_role('button', name=re.compile(r'DOMAIN.*example\.com')).click()
        page.get_by_role('button', name='Pivot', exact=True).click()
        dialog = page.get_by_role('dialog', name='Infrastructure pivots', exact=True)
        expect(dialog).to_be_visible()
        consent = dialog.get_by_role('checkbox', name=f'I approve sending example.com to {name}.', exact=True)
        consent.click()
        # NiceGUI commits the checkbox value after a server round trip.
        expect(consent).to_be_checked()
        button = dialog.get_by_role('button', name=f'Look up at {name}', exact=True)
        expect(button).to_be_enabled()
        button.click()
        expect(button).to_be_disabled()
        expect(dialog.get_by_text('No fresh cached results.', exact=True)).to_have_count(0)
        record = dialog.locator('.q-expansion-item')
        expect(record).to_have_count(1)
        record.get_by_role('button').click()
        prefix, length = ('Issuer: ', 1024) if provider == 'crtsh' else ('Answer: ', 2048)
        value = dialog.get_by_text(prefix + 'x' * length, exact=True)
        expect(value).to_be_visible()
        page.wait_for_function(
            """root => {
                const content = root.querySelector('.q-expansion-item__content');
                return content && content.getBoundingClientRect().height > 0 &&
                    content.clientHeight >= content.scrollHeight - 1 && content.style.height === '' &&
                    !content.getAnimations().some(animation => animation.playState === 'running');
            }""",
            arg=record.element_handle(),
        )
        for element in (dialog.locator('.q-card'), record, record.locator('.q-item__label').first, value):
            assert element.evaluate('e => e.scrollWidth <= e.clientWidth + 1')
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
    finally:
        context.close()

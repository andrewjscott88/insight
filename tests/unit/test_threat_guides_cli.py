"""``insight industries``, ``threat-profile``, ``threat-guide`` and ``rule-add`` (TIP 2.10, ADR 0024)."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from insight import cli

SIGMA = (
    'title: Encoded PowerShell\nlogsource:\n  product: windows\n'
    'detection:\n  sel:\n    x: 1\n  condition: sel\n'
)


@pytest.fixture
def data(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / 'data'
    monkeypatch.setattr(os, 'environ', {'INSIGHT_DATA_DIR': str(folder)})
    assert cli.main(['migrate']) == 0
    return folder


def _seed(data: Path, body: str, tlp: str = 'GREEN') -> str:
    from insight import services
    from insight.models import database
    from insight.schemas import DocumentInput

    engine, sessions = database(f'sqlite:///{data / "insight.db"}', migrate=False)
    try:
        with sessions.begin() as db:
            doc, _ = services.ingest(db, DocumentInput(title='Report', body=body, source_name='S', tlp=tlp))
            return doc.id
    finally:
        engine.dispose()


def test_industries_and_the_top_ten(data: Path, capsys: pytest.CaptureFixture[str]) -> None:
    capsys.readouterr()
    assert cli.main(['industries']) == 0
    out = capsys.readouterr().out
    assert 'Threat library: bundled edition, ATT&CK 20.1.' in out
    assert 'healthcare' in out
    _seed(data, 'Cozy Bear phished a ministry.')
    assert cli.main(['threat-profile', 'government']) == 0
    out = capsys.readouterr().out
    assert out.startswith('TLP:GREEN - groups that cited sources name for Government and diplomacy')
    assert ' 1. G0016 APT29' in out
    assert 'Named in 1 of your reports' in out
    assert cli.main(['threat-profile', 'government', '--max-tlp', 'clear']) == 0
    assert 'TLP:CLEAR' in capsys.readouterr().out
    assert cli.main(['threat-profile', 'nope']) == 1
    assert 'see `insight industries`' in capsys.readouterr().err


@pytest.mark.parametrize('fmt', ['md', 'json', 'navigator', 'sweep-csv', 'sweep-json'])
def test_threat_guides_are_written_privately_and_never_overwritten(
    data: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], fmt: str
) -> None:
    target = tmp_path / f'guide.{fmt}'
    assert cli.main(['threat-guide', 'G0016', str(target), '--format', fmt]) == 0
    assert 'APT29' in capsys.readouterr().out
    text = target.read_text()
    if fmt in ('json', 'navigator', 'sweep-json'):
        json.loads(text)
    if sys.platform != 'win32':
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert cli.main(['threat-guide', 'G0016', str(target), '--format', fmt]) == 1
    assert 'already exists' in capsys.readouterr().err
    assert target.read_text() == text


def test_the_cli_sweep_list_takes_named_reports_only_with_include_named(
    data: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review M2 and L4: linked reports only by default; ``--include-named`` opts in; the audit says which."""
    from sqlalchemy import select

    from insight import services
    from insight.models import AuditEvent, Document, database

    doc_id = _seed(data, 'Cozy Bear used login-microsoftonline.click.')
    engine, sessions = database(f'sqlite:///{data / "insight.db"}', migrate=False)
    try:
        with sessions.begin() as db:
            doc = db.get(Document, doc_id)
            assert doc is not None
            for obs in services.detail(db, doc)['observations']:
                services.set_observation_status(db, obs['id'], 'accepted')
    finally:
        engine.dispose()
    default = tmp_path / 'default.json'
    assert cli.main(['threat-guide', 'G0016', str(default), '--format', 'sweep-json']) == 0
    body = json.loads(default.read_text())
    assert (body['linked_only'], body['indicators']) == (True, [])
    wider = tmp_path / 'wider.json'
    assert cli.main(['threat-guide', 'G0016', str(wider), '--format', 'sweep-json', '--include-named']) == 0
    body = json.loads(wider.read_text())
    assert body['linked_only'] is False
    assert [(i['value'], i['via']) for i in body['indicators']] == [('login-microsoftonline.click', 'named')]
    engine, sessions = database(f'sqlite:///{data / "insight.db"}', migrate=False)
    try:
        with sessions() as db:
            stmt = select(AuditEvent.detail).where(AuditEvent.action == 'actor.guide')
            details = [json.loads(d) for d in db.scalars(stmt.order_by(AuditEvent.created_at))]
    finally:
        engine.dispose()
    assert [d['linked_only'] for d in details] == [True, False]
    capsys.readouterr()


def test_threat_guide_errors(data: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(['threat-guide', 'G0016']) == 2
    assert 'usage: insight threat-guide REF DEST' in capsys.readouterr().err
    assert cli.main(['threat-guide', 'G9999', str(tmp_path / 'x.md')]) == 1
    assert cli.main(['threat-guide', 'G0016', str(tmp_path / 'x.md'), '--format', 'pdf']) == 1
    assert '--format must be one of' in capsys.readouterr().err


def test_rule_add_stores_and_links_a_rule(
    data: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule = tmp_path / 'encoded.yml'
    rule.write_text(SIGMA)
    argv = [
        'rule-add',
        str(rule),
        '--kind',
        'sigma',
        '--link',
        'G0016',
        '--link',
        'T1059.001',
        '--tlp',
        'green',
    ]
    assert cli.main(argv) == 0
    assert 'linked to 2 target(s)' in capsys.readouterr().out
    assert cli.main(argv) == 1
    assert 'already stored' in capsys.readouterr().err
    other = tmp_path / 'bad.yar'
    other.write_text('not a rule')
    assert cli.main(['rule-add', str(other), '--kind', 'yara']) == 1
    assert 'does not look like a YARA rule' in capsys.readouterr().err
    assert cli.main(['rule-add', str(other), '--kind', 'yara', '--tlp', 'RED']) == 1
    guide = tmp_path / 'g.json'
    assert cli.main(['threat-guide', 'G0016', str(guide), '--format', 'json']) == 0
    assert [r['name'] for r in json.loads(guide.read_text())['hunt']['rules']] == ['encoded']

"""Documentation gate: relative links resolve, and the docs describe the shipped version."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import insight

ROOT = Path(__file__).resolve().parent.parent.parent
MARKDOWN = sorted(
    p for p in ROOT.rglob('*.md') if not {'.venv', 'node_modules', 'mutants', 'build'} & set(p.parts)
)
LINK = re.compile(r'\[[^\]]*\]\(([^)\s]+)\)')


@pytest.mark.parametrize('document', MARKDOWN, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_resolve(document: Path) -> None:
    text = re.sub(r'```.*?```', '', document.read_text(encoding='utf-8'), flags=re.DOTALL)
    for target in LINK.findall(text):
        if target.startswith(('http://', 'https://', 'mailto:', '#')):
            continue
        path = (document.parent / target.split('#', 1)[0]).resolve()
        assert path.exists(), f'{document.relative_to(ROOT)} links to missing {target}'


def test_required_documents_exist() -> None:
    required = [
        'README.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'NOTICE',
        'docs/README.md', 'docs/RUNBOOK.md', 'docs/ARCHITECTURE.md', 'docs/API.md', 'docs/EXTRACTION.md',
        'docs/SECURITY.md', 'docs/TESTING.md', 'docs/CI_CD.md', 'docs/RELEASING.md', 'docs/VALIDATION.md',
        'docs/adr/README.md', '.github/pull_request_template.md',
    ]  # fmt: skip
    assert [name for name in required if not (ROOT / name).is_file()] == []


def test_every_adr_is_indexed() -> None:
    index = (ROOT / 'docs' / 'adr' / 'README.md').read_text(encoding='utf-8')
    for adr in sorted((ROOT / 'docs' / 'adr').glob('[0-9][0-9][0-9][0-9]-*.md')):
        assert adr.name in index, f'{adr.name} missing from docs/adr/README.md'


def test_api_reference_covers_every_route() -> None:
    routes = re.findall(r"@app\.(?:get|post)\('([^']+)'", (ROOT / 'src' / 'insight' / 'main.py').read_text())
    reference = (ROOT / 'docs' / 'API.md').read_text(encoding='utf-8')
    normalise = re.compile(r'\{(?:doc_id|obs_id|entity_id)\}')
    undocumented = [route for route in routes if normalise.sub('{id}', route) not in reference]
    assert undocumented == []


def test_readme_states_the_current_version() -> None:
    assert f'Version {insight.__version__}' in (ROOT / 'README.md').read_text(encoding='utf-8')

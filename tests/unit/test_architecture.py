"""Architecture fitness functions: layering rules that code review alone tends to miss.

Decision 4/5: the UI and the JSON API share one query layer (``insight.services``). Neither front end may
build SQL, so search semantics, revision handling and auditing cannot drift apart again.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import insight

PACKAGE = Path(insight.__file__).parent
UI_MODULES = sorted((PACKAGE / 'ui').glob('*.py'))
FRONT_ENDS = [*UI_MODULES, PACKAGE / 'main.py']
SQL_BUILDERS = {'select', 'insert', 'update', 'delete', 'func', 'or_', 'and_', 'text'}
ORM_CLASSES = {'Document', 'Entity', 'Observation', 'Note', 'AuditEvent', 'KEVRecord', 'WatchTerm'}
ORM_CLASSES |= {'SourceRun', 'Enrichment'}


def imports(path: Path) -> list[tuple[str, str]]:
    """``(module, name)`` for every ``from module import name`` (relative modules keep their dots)."""
    found: list[tuple[str, str]] = []
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom):
            module = '.' * node.level + (node.module or '')
            found.extend((module, alias.name) for alias in node.names)
        elif isinstance(node, ast.Import):
            found.extend((alias.name, '') for alias in node.names)
    return found


def test_ui_package_was_split() -> None:
    assert len(UI_MODULES) >= 8
    assert all(len(p.read_text().splitlines()) < 300 for p in UI_MODULES), 'keep UI modules small'


@pytest.mark.parametrize('path', FRONT_ENDS, ids=lambda p: p.name)
def test_front_ends_do_not_build_sql(path: Path) -> None:
    for module, name in imports(path):
        if module == 'sqlalchemy' or module.startswith('sqlalchemy.sql'):
            assert name not in SQL_BUILDERS, (
                f'{path.name} builds SQL ({name}); add a service function instead'
            )
        assert not (module == 'sqlalchemy' and name == ''), f'{path.name} imports sqlalchemy wholesale'


@pytest.mark.parametrize('path', UI_MODULES, ids=lambda p: p.name)
def test_ui_does_not_touch_orm_classes(path: Path) -> None:
    for module, name in imports(path):
        if module.endswith('models'):
            assert name not in ORM_CLASSES, f'{path.name} imports ORM class {name}; use insight.services'


@pytest.mark.parametrize('path', UI_MODULES, ids=lambda p: p.name)
def test_ui_does_not_depend_on_the_api_module(path: Path) -> None:
    assert all(not module.endswith('main') for module, _ in imports(path))

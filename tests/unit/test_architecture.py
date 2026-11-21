"""Architecture fitness functions: layering rules that code review alone tends to miss.

Decision 4/5: the UI and the JSON API share one query layer (``insight.services``). Neither front end may
build SQL, so search semantics, revision handling and auditing cannot drift apart again.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

import insight

PACKAGE = Path(insight.__file__).parent
UI_MODULES = sorted((PACKAGE / 'ui').glob('*.py'))
WEB_MODULES = sorted((PACKAGE / 'web').rglob('*.py'))
FRONT_ENDS = [*UI_MODULES, *WEB_MODULES, PACKAGE / 'main.py']
SERVICE_MODULES = sorted((PACKAGE / 'services').glob('*.py'))
SQL_BUILDERS = {'select', 'insert', 'update', 'delete', 'func', 'or_', 'and_', 'text'}
ORM_CLASSES = {'Document', 'Entity', 'Observation', 'Note', 'AuditEvent', 'KEVRecord', 'WatchTerm'}
ORM_CLASSES |= {'SourceRun', 'Enrichment', 'ApiKey', 'Job', 'Schedule', 'FetchState', 'EntityAssessment'}
ORM_CLASSES |= {'DocumentTechnique'}


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


def test_services_is_a_package_of_small_domain_modules() -> None:
    """B3: one module per domain, so new features land in their own module instead of a 1,300-line file."""
    assert not (PACKAGE / 'services.py').exists()
    names = {p.stem for p in SERVICE_MODULES}
    assert {'tlp', 'audit', 'documents', 'search', 'entities', 'exports', 'triage', 'jobs', 'access'} <= names
    assert all(len(p.read_text().splitlines()) < 400 for p in SERVICE_MODULES), 'keep service modules small'


def test_the_tlp_core_imports_nothing_from_its_siblings() -> None:
    """``services.tlp`` decides what a reader may see; keep it small and free of other domains' logic."""
    sibling = {p.stem for p in SERVICE_MODULES} - {'__init__'}
    for module, name in imports(PACKAGE / 'services' / 'tlp.py'):
        assert module.lstrip('.') not in sibling, module
        assert not (module == '.' and name in sibling), name


def test_every_public_service_name_is_re_exported() -> None:
    """Callers write ``services.ingest(...)``; a name missing from ``__init__`` would break them silently."""
    from insight import services

    for path in SERVICE_MODULES:
        if path.stem == '__init__':
            continue
        tree = ast.parse(path.read_text())
        public = {
            node.name
            for node in tree.body
            if isinstance(node, ast.FunctionDef | ast.ClassDef) and not node.name.startswith('_')
        }
        missing = sorted(name for name in public if name not in services.__all__)
        assert missing == [], f'services/{path.name}: add {missing} to services/__init__.py'


def test_the_web_front_end_is_split_by_area() -> None:
    """B3: ``main.py`` only re-exports; routes live in one module per area under ``insight/web/routes/``."""
    assert not re.search(r'@app\.(get|post|put|delete)\(', (PACKAGE / 'main.py').read_text())
    routes = {p.stem for p in (PACKAGE / 'web' / 'routes').glob('*.py')} - {'__init__'}
    assert {'documents', 'triage', 'exports', 'entities', 'sources', 'workspace'} <= routes
    assert all(len(p.read_text().splitlines()) < 400 for p in WEB_MODULES), 'keep web modules small'


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
    assert all('web' not in module.split('.') for module, _ in imports(path))


#: Service functions that read or change reports. Every call from the API must pass the caller's TLP limit
#: (``max_tlp=``), or a TLP-limited API key could see reports above its limit (ADR 0014).
TLP_AWARE_SERVICES = {
    'DocumentQuery', 'detail', 'list_entities', 'entity_documents', 'count_entity_documents', 'stats',
    'set_document_status', 'set_observation_status', 'add_note', 'ingest', 'brief_data',
    'assess_entity', 'entity_assessment', 'entity_seen', 'blocklist',
    'document_techniques', 'tag_technique', 'untag_technique', 'technique_summary', 'technique_documents',
}  # fmt: skip


def test_api_routes_pass_the_callers_tlp_limit_to_services() -> None:
    tree = ast.Module(
        body=[node for p in WEB_MODULES for node in ast.parse(p.read_text()).body], type_ignores=[]
    )
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == 'services'
        and node.func.attr in TLP_AWARE_SERVICES
    ]
    assert {call.func.attr for call in calls if isinstance(call.func, ast.Attribute)} == TLP_AWARE_SERVICES
    missing = [
        f'services.{call.func.attr} (line {call.lineno})'
        for call in calls
        if isinstance(call.func, ast.Attribute) and not any(kw.arg == 'max_tlp' for kw in call.keywords)
    ]
    assert missing == [], f'pass max_tlp=reader_limit(request): {missing}'
    lookups = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == 'get_document_or_404'
    ]
    assert lookups
    assert all(len(call.args) + len(call.keywords) == 3 for call in lookups), 'pass the TLP limit'


#: Tailwind classes with a fixed colour shade (``text-amber-300``) look right in one theme only.
FIXED_SHADE = re.compile(
    r'\b(?:text|bg|border|ring|outline|decoration|divide|fill|stroke)-'
    r'(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|'
    r'violet|purple|fuchsia|pink|rose)-\d{2,3}\b'
)
HEX_COLOUR = re.compile(r'#[0-9a-fA-F]{3,8}\b')


@pytest.mark.parametrize('path', [p for p in UI_MODULES if p.name != 'theme.py'], ids=lambda p: p.name)
def test_panels_use_theme_colours_only(path: Path) -> None:
    """Colours live in ``ui/theme.py`` as light and dark tokens; a hard-coded one breaks one of the themes."""
    source = path.read_text()
    assert not FIXED_SHADE.findall(source), f'{path.name}: use a theme class (e.g. text-warn) instead'
    assert not HEX_COLOUR.findall(source), f'{path.name}: colours belong in ui/theme.py PALETTES'


@pytest.mark.parametrize('path', UI_MODULES, ids=lambda p: p.name)
def test_responsive_visibility_does_not_use_quasars_hidden_class(path: Path) -> None:
    """Regression: ``hidden sm:block`` never shows, because Quasar's ``.hidden`` is ``!important``.

    The desktop tab labels and the header tagline were invisible at every width; use ``max-sm:hidden``.
    """
    assert not re.findall(
        r"'(?:[^']* )?hidden [^']*\b(?:sm|md|lg|xl):(?:block|flex|inline|grid)", path.read_text()
    )


@pytest.mark.parametrize('path', [p for p in UI_MODULES if p.name != 'messages.py'], ids=lambda p: p.name)
def test_messages_go_through_tell(path: Path) -> None:
    """Regression: messages vanished after ~5 s. ``messages.tell`` keeps them until dismissed (WCAG 2.2.1)."""
    assert 'ui.notify(' not in path.read_text(), f'{path.name}: use messages.tell(...) instead of ui.notify'

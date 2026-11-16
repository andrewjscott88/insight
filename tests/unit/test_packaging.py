"""The installed distribution must ship its templates, static assets and typing marker."""

from __future__ import annotations

from importlib import metadata, resources

import insight


def test_package_data_is_installed() -> None:
    root = resources.files('insight')
    for name in ('templates/login.html', 'templates/logout.html', 'static/app.css', 'py.typed'):
        assert root.joinpath(name).is_file(), name


def test_version_is_single_sourced() -> None:
    assert metadata.version('insight') == insight.__version__


def test_console_script_is_registered() -> None:
    (entry,) = [e for e in metadata.entry_points(group='console_scripts') if e.name == 'insight']
    assert entry.value == 'insight.cli:main'

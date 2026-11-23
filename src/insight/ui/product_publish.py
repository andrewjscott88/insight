"""Publishing a product and downloading it (TIP 4.4, ADR 0036): the next version, the versions so far, and the
Markdown and STIX downloads of the draft and of each version."""

from __future__ import annotations

from nicegui import ui

from .. import services
from .product_sections import Write
from .typography import heading, new_tab_link


def _downloads(case_id: str, version: int | None) -> None:
    suffix = f'&version={version}' if version else ''
    with ui.row().classes('gap-x-6 gap-y-0'):
        new_tab_link('Markdown', f'/api/cases/{case_id}/export?format=md{suffix}')
        new_tab_link('STIX', f'/api/cases/{case_id}/export?format=stix{suffix}')


def render_publish(
    view: services.CaseView, parts: services.ProductParts, write: Write, limit: str | None, editable: bool
) -> None:
    heading('Publish', 3)
    if view.version and view.published_at:
        changed = view.updated_at > view.published_at
        ui.label(
            f'Version {view.version} was published on {view.published_at[:10]}.'
            + (' There are changes since then.' if changed else '')
        ).classes('prose').mark('product-version')
    else:
        ui.label('Not published yet. Publishing keeps this exact text as version 1.').classes('muted prose')
    if editable:
        ui.button(
            f'Publish version {view.version + 1}',
            on_click=lambda: write(
                lambda db: services.publish_product(db, view.id, max_tlp=limit),
                'Published. That version is kept as it is now.',
            ),
        ).classes('self-start').mark('product-publish')
    ui.label('Download the draft:').classes('text-sm')
    _downloads(view.id, None)
    for version in parts.versions:
        ui.label(f'Version {version.version}, {version.published_at[:10]}, TLP:{version.tlp}:').classes(
            'text-sm'
        )
        _downloads(view.id, version.version)

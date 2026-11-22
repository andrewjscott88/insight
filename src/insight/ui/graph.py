"""The link map (TIP 3.2, ADR 0027): what a report, indicator, technique, group, actor or campaign links to.

A text-first view of the graph, so it works with a keyboard, a screen reader and larger text (ADR 0017): the
item in the centre, its direct links and, on request, the items two steps away, grouped by type. Every entry
is a button that puts it in the centre; reports can also be opened in the reader.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from nicegui import ui

from .. import services
from ..services.graph import MAX_NODES, PER_NODE
from .typography import heading
from .workspace import Workspace

TYPE_NAMES: Final = {
    'report': 'Reports',
    'indicator': 'Indicators',
    'technique': 'ATT&CK techniques',
    'group': 'ATT&CK groups',
    'actor': 'Your actors',
    'campaign': 'Campaigns',
}
SINGULAR: Final = {
    'report': 'Report',
    'indicator': 'Indicator',
    'technique': 'ATT&CK technique',
    'group': 'ATT&CK group',
    'actor': 'Actor',
    'campaign': 'Campaign',
}
EDGE_WORDS: Final = {'mentions': 'mentioned', 'tagged': 'tagged', 'linked': 'linked by an analyst'}


def _via(graph: services.Graph) -> dict[str, list[str]]:
    """For each node two steps away, the labels of the direct links it is reached through."""
    labels = {n.id: n.label for n in graph.nodes}
    depth = {n.id: n.depth for n in graph.nodes}
    via: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        for near, far in ((edge.source, edge.target), (edge.target, edge.source)):
            if depth.get(near) == 1 and depth.get(far) == 2:
                via[far].append(labels[near])
    return via


def _edge_kind(graph: services.Graph, node_id: str) -> str:
    for edge in graph.edges:
        if graph.seed in (edge.source, edge.target) and node_id in (edge.source, edge.target):
            return EDGE_WORDS.get(edge.kind, edge.kind)
    return ''


@dataclass
class _View:
    node: str
    depth: int = 1


def open_graph(ws: Workspace, node: str) -> None:
    """Show the link map around ``node`` (``report:<id>``, ``indicator:<entity id>``, ...) in a dialog."""
    state = _View(node)

    with ui.dialog() as dialog, ui.card().classes('w-full max-w-4xl gap-3'):

        def centre(target: str) -> None:
            state.node = target
            body.refresh()

        def open_report(target: str) -> None:
            dialog.close()
            ws.show_inbox()
            ws.open_document(target.removeprefix('report:'))

        def set_depth(value: int) -> None:
            state.depth = value
            body.refresh()

        @ui.refreshable
        def body() -> None:
            if not ws.authorized():
                return
            with ws.read() as db:
                try:
                    graph = services.build_graph(db, state.node, depth=state.depth)
                except LookupError:
                    ui.label('This item is no longer available.').classes('muted')
                    return
            seed = graph.nodes[0]
            heading(f'Links around {seed.label}', 2)
            ui.label(SINGULAR[seed.type] + (f' · {seed.detail}' if seed.detail else '')).classes('muted')
            ui.toggle(
                {1: 'Direct links', 2: 'Two steps'},
                value=state.depth,
                on_change=lambda e: set_depth(e.value),
            ).mark('graph-depth')
            if seed.type == 'report':
                ui.button('Open this report', on_click=lambda: open_report(seed.id)).props('flat no-caps')
            via = _via(graph)
            for depth, title in ((1, 'Direct links'), (2, 'Two steps away')):
                found = [n for n in graph.nodes if n.depth == depth]
                if depth > state.depth:
                    continue
                heading(f'{title} ({len(found)})', 3)
                if not found:
                    ui.label('None.').classes('muted')
                    continue
                by_type: dict[str, list[services.GraphNode]] = defaultdict(list)
                for item in found:
                    by_type[item.type].append(item)
                for kind in TYPE_NAMES:
                    if kind not in by_type:
                        continue
                    heading(TYPE_NAMES[kind], 4)
                    with ui.column().classes('gap-1 w-full'):
                        for item in by_type[kind]:
                            _row(graph, item, via, centre, open_report)
            if seed.truncated or any(n.truncated for n in graph.nodes):
                ui.label(
                    f'Some items have more links than the {PER_NODE} shown for each. Put one in '
                    'the centre to see its own links.'
                ).classes('muted prose')
            if graph.capped:
                ui.label(
                    f'The map stops at {MAX_NODES} items. Show direct links only, or centre '
                    'on a narrower item.'
                ).classes('muted prose')

        body()
        ui.button('Close', on_click=dialog.close).props('flat')
    dialog.open()


def _row(
    graph: services.Graph,
    item: services.GraphNode,
    via: dict[str, list[str]],
    centre: Callable[[str], None],
    open_report: Callable[[str], None],
) -> None:
    with ui.row().classes('w-full items-center gap-2 wrap'):
        detail = f' · {item.detail}' if item.detail else ''
        ui.button(f'{item.label}{detail}', on_click=lambda target=item.id: centre(target)).props(
            'flat no-caps align=left'
        ).classes('text-left break-value').tooltip('Put this in the centre')
        if item.type == 'report':
            ui.button('Open', on_click=lambda target=item.id: open_report(target)).props('flat dense no-caps')
        if item.depth == 1 and (kind := _edge_kind(graph, item.id)):
            ui.label(kind).classes('muted text-sm')
        if item.depth == 2 and via.get(item.id):
            ui.label('via ' + ', '.join(sorted(set(via[item.id]))[:3])).classes('muted text-sm')

"""A capped, TLP-aware graph of what Insight already links (TIP 3.2, ADR 0027).

Nodes are reports, indicators (and CVEs), ATT&CK techniques, ATT&CK groups, and the analyst's actors and
campaigns. Edges are only links Insight records: a report mentions an indicator (not rejected), a report is
tagged with a technique, and the analyst linked an actor, group or campaign to a report, indicator or
technique. Nothing is inferred. Every report-based edge needs a report the caller may read, and every link
and actor or campaign carries its own TLP label, checked the same way.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from typing import Final, Literal, cast

from sqlalchemy import ColumnElement, select
from sqlalchemy.orm import InstrumentedAttribute, Session

from ..attack import catalog
from ..models import (
    ActorDocument,
    Campaign,
    Document,
    DocumentTechnique,
    Entity,
    Observation,
    ThreatActor,
    ThreatLink,
)
from ..threat_library import library
from .techniques import TAGGED
from .tlp import _visible, visible_levels

NodeType = Literal['report', 'indicator', 'technique', 'group', 'actor', 'campaign']
NODE_TYPES: Final[tuple[NodeType, ...]] = ('report', 'indicator', 'technique', 'group', 'actor', 'campaign')
MAX_NODES: Final = 150
#: Neighbours listed per node; a busier node is marked ``truncated``.
PER_NODE: Final = 25
MAX_DEPTH: Final = 2


@dataclass(frozen=True)
class GraphNode:
    id: str
    type: NodeType
    label: str
    detail: str = ''
    depth: int = 0
    truncated: bool = False


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    kind: str


@dataclass
class Graph:
    seed: str
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    #: More nodes were reachable than ``MAX_NODES`` allows.
    capped: bool = False


Neighbour = tuple[str, str, str, str]  # node id, label, detail, edge kind


def _levels(column: InstrumentedAttribute[str], max_tlp: str | None) -> list[ColumnElement[bool]]:
    return [] if max_tlp is None else [column.in_(visible_levels(max_tlp))]


def _report_ok(max_tlp: str | None) -> list[ColumnElement[bool]]:
    return [*_visible(max_tlp), Document.is_current.is_(True)]


def _technique_label(technique_id: str) -> str:
    found = catalog().techniques.get(technique_id)
    return f'{technique_id} {found.full_name}' if found else technique_id


def _group_label(group_id: str) -> str:
    found = library().group(group_id)
    return f'{found.name} ({group_id})' if found else group_id


def _first(rows: Iterable[Neighbour]) -> tuple[list[Neighbour], bool]:
    found = list(rows)
    return found[:PER_NODE], len(found) > PER_NODE


class _Walker:
    def __init__(self, db: Session, max_tlp: str | None) -> None:
        self.db = db
        self.max_tlp = max_tlp

    # --------------------------------------------------------------------------- seeds

    def describe(self, node: str) -> GraphNode | None:
        """The node itself, if it exists and the caller may see it."""
        kind, _, key = node.partition(':')
        db, limit = self.db, self.max_tlp
        if kind == 'report':
            doc = db.scalar(select(Document).where(Document.id == key, *_visible(limit)))
            return GraphNode(node, 'report', doc.title, doc.source_name) if doc else None
        if kind == 'indicator':
            entity = db.get(Entity, key)
            visible = entity is not None and db.scalar(
                select(Observation.id)
                .join(Document, Document.id == Observation.document_id)
                .where(
                    Observation.entity_id == key, Observation.review_status != 'rejected', *_visible(limit)
                )
                .limit(1)
            )
            return GraphNode(node, 'indicator', entity.value, entity.kind) if entity and visible else None
        if kind == 'technique':
            return (
                GraphNode(node, 'technique', _technique_label(key)) if key in catalog().techniques else None
            )
        if kind == 'group':
            return GraphNode(node, 'group', _group_label(key)) if library().group(key) else None
        if kind == 'actor':
            actor = db.scalar(
                select(ThreatActor).where(ThreatActor.id == key, *_levels(ThreatActor.tlp, limit))
            )
            return GraphNode(node, 'actor', actor.name, f'TLP:{actor.tlp}') if actor else None
        if kind == 'campaign':
            found = db.scalar(select(Campaign).where(Campaign.id == key, *_levels(Campaign.tlp, limit)))
            return GraphNode(node, 'campaign', found.name, f'TLP:{found.tlp}') if found else None
        return None

    # --------------------------------------------------------------------------- neighbours

    def neighbours(self, node: str) -> tuple[list[Neighbour], bool]:
        kind, _, key = node.partition(':')
        found: list[Neighbour] = []
        truncated = False
        for part in getattr(self, f'_from_{kind}')(key):
            rows, more = _first(part)
            found += rows
            truncated = truncated or more
        return found, truncated

    def _threat_links(self, *conditions: ColumnElement[bool]) -> list[ThreatLink]:
        limit = self.max_tlp
        stmt = (
            select(ThreatLink)
            .outerjoin(ThreatActor, ThreatActor.id == ThreatLink.actor_id)
            .outerjoin(Campaign, Campaign.id == ThreatLink.campaign_id)
            .outerjoin(Document, Document.id == ThreatLink.document_id)
            .where(*conditions, *_levels(ThreatLink.tlp, limit))
            .order_by(ThreatLink.created_at, ThreatLink.id)
            .limit(PER_NODE + 1)
        )
        if limit is not None:
            levels = visible_levels(limit)
            stmt = stmt.where(
                (ThreatLink.actor_id.is_(None)) | ThreatActor.tlp.in_(levels),
                (ThreatLink.campaign_id.is_(None)) | Campaign.tlp.in_(levels),
                (ThreatLink.document_id.is_(None)) | Document.tlp.in_(levels),
            )
        return list(self.db.scalars(stmt))

    def _subjects(self, links: list[ThreatLink]) -> list[Neighbour]:
        """The actors and campaigns at the other end of threat links."""
        out: list[Neighbour] = []
        for link in links:
            if link.actor_id:
                actor = self.db.get(ThreatActor, link.actor_id)
                out.append((f'actor:{link.actor_id}', actor.name if actor else link.actor_id, '', 'linked'))
            elif link.campaign_id:
                found = self.db.get(Campaign, link.campaign_id)
                out.append((f'campaign:{link.campaign_id}', found.name if found else '', '', 'linked'))
        return out

    def _targets(self, links: list[ThreatLink]) -> list[Neighbour]:
        """The reports, indicators and techniques an actor or campaign is linked to."""
        out: list[Neighbour] = []
        for link in links:
            if link.document_id:
                doc = self.db.get(Document, link.document_id)
                out.append((f'report:{link.document_id}', doc.title if doc else '', '', 'linked'))
            elif link.entity_id:
                entity = self.db.get(Entity, link.entity_id)
                if entity is not None:
                    out.append((f'indicator:{entity.id}', entity.value, entity.kind, 'linked'))
            elif link.technique_id:
                out.append(
                    (f'technique:{link.technique_id}', _technique_label(link.technique_id), '', 'linked')
                )
        return out

    def _from_report(self, key: str) -> list[list[Neighbour]]:
        db, limit = self.db, self.max_tlp
        if db.scalar(select(Document.id).where(Document.id == key, *_visible(limit))) is None:
            return []
        entities = db.execute(
            select(Entity.id, Entity.value, Entity.kind)
            .join(Observation, Observation.entity_id == Entity.id)
            .where(Observation.document_id == key, Observation.review_status != 'rejected')
            .group_by(Entity.id, Entity.value, Entity.kind)
            .order_by(Entity.kind, Entity.value)
            .limit(PER_NODE + 1)
        )
        techniques = db.scalars(
            select(DocumentTechnique.technique_id)
            .where(DocumentTechnique.document_id == key, DocumentTechnique.status == TAGGED)
            .order_by(DocumentTechnique.technique_id)
            .limit(PER_NODE + 1)
        )
        groups = db.scalars(
            select(ActorDocument.group_ref)
            .where(ActorDocument.document_id == key, *_levels(ActorDocument.tlp, limit))
            .order_by(ActorDocument.group_ref)
            .limit(PER_NODE + 1)
        )
        return [
            [(f'indicator:{e}', value, kind, 'mentions') for e, value, kind in entities],
            [(f'technique:{t}', _technique_label(t), '', 'tagged') for t in techniques],
            [self._group_ref(ref) for ref in groups if self._group_visible(ref)],
            self._subjects(self._threat_links(ThreatLink.document_id == key)),
        ]

    def _group_ref(self, ref: str) -> Neighbour:
        if library().group(ref):
            return (f'group:{ref.upper()}', _group_label(ref), '', 'linked')
        actor = self.db.get(ThreatActor, ref)
        return (f'actor:{ref}', actor.name if actor else ref, '', 'linked')

    def _group_visible(self, ref: str) -> bool:
        if library().group(ref) or self.max_tlp is None:
            return True
        actor = self.db.get(ThreatActor, ref)
        return actor is not None and actor.tlp in visible_levels(self.max_tlp)

    def _reports(self, *conditions: ColumnElement[bool]) -> list[Neighbour]:
        rows = self.db.execute(
            select(Document.id, Document.title, Document.source_name)
            .where(*conditions, *_report_ok(self.max_tlp))
            .distinct()
            .order_by(Document.created_at.desc(), Document.id)
            .limit(PER_NODE + 1)
        )
        return [(f'report:{doc_id}', title, source, '') for doc_id, title, source in rows]

    def _from_indicator(self, key: str) -> list[list[Neighbour]]:
        mentioned = self._reports(
            Document.id.in_(
                select(Observation.document_id).where(
                    Observation.entity_id == key, Observation.review_status != 'rejected'
                )
            )
        )
        return [
            [(n, label, detail, 'mentions') for n, label, detail, _ in mentioned],
            self._subjects(self._threat_links(ThreatLink.entity_id == key)),
        ]

    def _from_technique(self, key: str) -> list[list[Neighbour]]:
        tagged = self._reports(
            Document.id.in_(
                select(DocumentTechnique.document_id).where(
                    DocumentTechnique.technique_id == key, DocumentTechnique.status == TAGGED
                )
            )
        )
        return [
            [(n, label, detail, 'tagged') for n, label, detail, _ in tagged],
            self._subjects(self._threat_links(ThreatLink.technique_id == key)),
        ]

    def _from_group(self, key: str) -> list[list[Neighbour]]:
        linked = self._reports(
            Document.id.in_(
                select(ActorDocument.document_id).where(
                    ActorDocument.group_ref == key, *_levels(ActorDocument.tlp, self.max_tlp)
                )
            )
        )
        return [[(n, label, detail, 'linked') for n, label, detail, _ in linked]]

    def _from_actor(self, key: str) -> list[list[Neighbour]]:
        if self.describe(f'actor:{key}') is None:
            return []
        return [*self._from_group(key), self._targets(self._threat_links(ThreatLink.actor_id == key))]

    def _from_campaign(self, key: str) -> list[list[Neighbour]]:
        if self.describe(f'campaign:{key}') is None:
            return []
        return [self._targets(self._threat_links(ThreatLink.campaign_id == key))]


def build_graph(db: Session, node: str, *, depth: int = 1, max_tlp: str | None = None) -> Graph:
    """Nodes within ``depth`` links of ``node`` (at most ``MAX_NODES``), in a deterministic order.

    Raises ``LookupError`` when the node does not exist or is above the caller's TLP limit, so a hidden
    report and a missing one look the same.
    """
    if not 1 <= depth <= MAX_DEPTH:
        raise ValueError(f'depth must be 1 to {MAX_DEPTH}')
    walker = _Walker(db, max_tlp)
    seed = walker.describe(node)
    if seed is None:
        raise LookupError('Node not found')
    graph = Graph(seed=node)
    nodes: dict[str, GraphNode] = {node: seed}
    edges: dict[tuple[str, str], GraphEdge] = {}
    frontier = [node]
    for level in range(1, depth + 1):
        following: list[str] = []
        for current in frontier:
            found, truncated = walker.neighbours(current)
            if truncated:
                nodes[current] = replace(nodes[current], truncated=True)
            for other, label, detail, kind in sorted(found):
                if other not in nodes:
                    if len(nodes) >= MAX_NODES:
                        graph.capped = True
                        continue
                    other_type = cast(NodeType, other.partition(':')[0])
                    nodes[other] = GraphNode(other, other_type, label, detail, level)
                    following.append(other)
                pair = (current, other) if current < other else (other, current)
                edges.setdefault(pair, GraphEdge(pair[0], pair[1], kind))
        frontier = following
    graph.nodes = sorted(nodes.values(), key=lambda n: (n.depth, NODE_TYPES.index(n.type), n.label, n.id))
    graph.edges = sorted(edges.values(), key=lambda e: (e.source, e.target))
    return graph

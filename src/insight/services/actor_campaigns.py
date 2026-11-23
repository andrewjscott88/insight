"""Explicit actor/campaign associations for timelines; shared evidence never creates an association."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ActorCampaign, Campaign, now
from ..schemas import ActorCampaignInput, most_restrictive, tlp_markings
from .actors import _check_label, _insert_link, _who, resolve_group
from .audit import audit
from .campaigns import get_campaign
from .tlp import visible_levels


@dataclass(frozen=True, slots=True)
class ActorCampaignView:
    id: str
    campaign_id: str
    name: str
    note: str
    tlp: str
    linked_at: str
    created_at: str


def actor_campaigns(
    db: Session, ref: str, *, max_tlp: str | None = None, limit: int = 200
) -> list[ActorCampaignView]:
    subject = resolve_group(db, ref, max_tlp=max_tlp)
    levels = visible_levels(max_tlp)
    rows = db.execute(
        select(ActorCampaign, Campaign)
        .join(Campaign, Campaign.id == ActorCampaign.campaign_id)
        .where(
            ActorCampaign.group_ref == subject.ref, ActorCampaign.tlp.in_(levels), Campaign.tlp.in_(levels)
        )
        .order_by(ActorCampaign.created_at.desc(), ActorCampaign.id)
        .limit(min(max(1, limit), 201))
    )
    return [
        ActorCampaignView(
            link.id,
            campaign.id,
            campaign.name,
            link.note,
            most_restrictive(subject.tlp, campaign.tlp, link.tlp),
            link.created_at,
            campaign.created_at,
        )
        for link, campaign in rows
    ]


def link_actor_campaign(
    db: Session, ref: str, payload: ActorCampaignInput, *, max_tlp: str | None = None
) -> ActorCampaign:
    subject = resolve_group(db, ref, max_tlp=max_tlp)
    campaign = db.scalar(
        select(Campaign)
        .where(Campaign.id == payload.campaign_id, Campaign.tlp.in_(visible_levels(max_tlp)))
        .with_for_update()
    )
    if campaign is None:
        raise LookupError('Campaign association not found')
    label = most_restrictive(subject.tlp, campaign.tlp, payload.tlp, *tlp_markings(payload.note))
    _check_label(label, max_tlp, 'campaign associations')
    created = _insert_link(
        db,
        ActorCampaign,
        {
            'group_ref': subject.ref,
            'campaign_id': campaign.id,
            'tlp': label,
            'note': payload.note.strip(),
            'actor': _who(db),
        },
    )
    row = db.scalars(
        select(ActorCampaign)
        .where(ActorCampaign.group_ref == subject.ref, ActorCampaign.campaign_id == campaign.id)
        .with_for_update()
    ).one()
    if row.tlp not in visible_levels(max_tlp):
        raise LookupError('Campaign association not found')
    label = most_restrictive(label, row.tlp)
    changed = created or row.tlp != label or row.note != payload.note.strip()
    row.tlp, row.note = label, payload.note.strip()
    # The campaign may contain text written with this association in view. Removing it never lowers this.
    if campaign.tlp != most_restrictive(campaign.tlp, label):
        campaign.tlp, campaign.updated_at = most_restrictive(campaign.tlp, label), now()
    if changed:
        audit(db, 'actor.campaign.link', subject.ref, campaign.id)
    db.flush()
    return row


def unlink_actor_campaign(db: Session, ref: str, campaign_id: str, *, max_tlp: str | None = None) -> None:
    subject = resolve_group(db, ref, max_tlp=max_tlp)
    get_campaign(db, campaign_id, max_tlp=max_tlp)
    row = db.scalar(
        select(ActorCampaign).where(
            ActorCampaign.group_ref == subject.ref,
            ActorCampaign.campaign_id == campaign_id,
            ActorCampaign.tlp.in_(visible_levels(max_tlp)),
        )
    )
    if row is None:
        raise LookupError('Campaign association not found')
    db.delete(row)
    audit(db, 'actor.campaign.unlink', subject.ref, campaign_id)

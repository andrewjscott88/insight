"""Create the upgrade fixture for the current version: ``tests/fixtures/releases/insight-<version>.sqlite3``.

Run once per final release (see docs/RELEASING.md). Future versions' test suites upgrade every committed
fixture, so a migration that breaks real user data fails CI long before it reaches anyone.

The database is written through the normal services (not raw SQL) and exercises every table: demo reports,
a KEV entry with a publisher edit (revisions), an RSS item, a reviewed manual report with an accepted
observation, a note and a verdict, a watch term, a source run, a cached enrichment, a schedule, a queued job,
a remembered feed download, an API key and a signed-in session (their secrets are thrown away), and
threat-guide records (an actor, a report link, an industry decision, a rule and its link, a hunt and a check).
All data is synthetic. Only the MFA pairing is left out: it would put an authenticator secret in the
repository.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from insight import __version__, services
from insight.connectors import SOURCES, import_kev, parse_feed
from insight.demo import seed
from insight.models import Enrichment, Entity, Observation, SourceRun, database
from insight.schemas import (
    ActorCampaignInput,
    ActorInput,
    ActorLinkInput,
    AssessmentInput,
    CampaignInput,
    CaseInput,
    CaseItemInput,
    CaseNoteInput,
    CredibilityInput,
    CriterionInput,
    DocumentInput,
    EvidenceInput,
    HuntCheckInput,
    HuntInput,
    HuntPackageInput,
    HuntPackageItemInput,
    IndustryClaimInput,
    RequirementInput,
    RfiInput,
    RuleInput,
    RuleLinkInput,
    SightingInput,
    SourceRatingInput,
    ThreatLinkInput,
)

ROOT = Path(__file__).resolve().parent.parent


def kev(description: str) -> bytes:
    row = {
        'cveID': 'CVE-2024-3400',
        'vendorProject': 'Palo Alto Networks',
        'product': 'PAN-OS',
        'dateAdded': '2024-04-12',
        'dueDate': '2024-04-19',
        'requiredAction': 'Apply mitigations per vendor instructions.',
        'shortDescription': description,
    }
    return json.dumps({'vulnerabilities': [row]}).encode()


def build(path: Path) -> None:
    engine, sessions = database(f'sqlite:///{path}')
    try:
        with sessions.begin() as db:
            seed(db)
            services.import_pdf(
                db,
                (ROOT / 'tests' / 'fixtures' / 'advisory.pdf').read_bytes(),
                title='Fixture PDF advisory',
                source_name='Training publisher',
                tlp='GREEN',
                max_tlp='GREEN',
            )
            import_kev(db, kev('Command injection in GlobalProtect.'))
        with sessions.begin() as db:
            import_kev(db, kev('OS command injection in the GlobalProtect feature of PAN-OS.'))
            feed = (
                b'<rss><channel><item><title>ISC Diary: Scanning for 192.0.2.10</title>'
                b'<link>https://isc.sans.edu/diary/1</link><description>Scans.</description></item></channel></rss>'
            )
            for item in parse_feed(feed, SOURCES['sans-isc']):
                services.ingest(
                    db,
                    item.document,
                    ref=services.SourceRef('sans-isc', item.external_id or ''),
                    truncated=item.truncated,
                )
            manual, _ = services.ingest(
                db,
                DocumentInput(
                    title='Analyst paste',
                    body='Seen CVE-2024-3400 exploited with a public PoC; beacon to 198.51.100.7',
                    source_name='IR team',
                    tlp='AMBER',
                ),
            )
            services.set_document_status(db, manual.id, 'reviewed')
            services.add_note(db, manual.id, 'Escalated to SOC lead.')
            observation = db.scalars(select(Observation).where(Observation.document_id == manual.id)).first()
            if observation is None:
                raise RuntimeError('fixture report produced no observations')
            services.set_observation_status(db, observation.id, 'accepted')
            services.add_watch_term(db, 'GlobalProtect')
            db.add(SourceRun(source_key='cisa-kev', status='success', message='fixture'))
            db.add(Enrichment(cve='CVE-2024-3400', provider='epss', payload='{"data": []}'))
            # Tables added since 0.5.0, so later migrations are tested against data in them.
            beacon = db.scalar(select(Entity).where(Entity.value == '198.51.100.7'))
            if beacon is None:
                raise RuntimeError('fixture report produced no beacon address')
            verdict = AssessmentInput(verdict='malicious', reason='Beacon in the IR paste.', tlp='AMBER')
            services.assess_entity(db, beacon.id, verdict)
            when = datetime(2026, 11, 20, tzinfo=UTC)
            services.set_schedule(db, 'cisa-kev', 1440, at=when)
            services.enqueue_job(db, services.SOURCE_SYNC, 'sans-isc', at=when, actor='fixture')
            kev_url = SOURCES['cisa-kev'].url
            services.save_fetch_state(
                db, kev_url, etag='"fixture"', last_modified='', payload_sha256='0' * 64, version='1'
            )
            services.create_api_key(db, name='fixture', access='read', max_tlp='GREEN')
            services.start_operator_session(db, binding='fixture', at=when)  # its ID is thrown away
            services.tag_technique(db, manual.id, 'T1071.001')  # 0.7.0: an analyst's ATT&CK tag
            services.set_source_switch(db, 'talos', True, at=when)  # 0.7.0: an optional source on
            alert_to = services.add_target(
                db, name='Team chat', style='chat', address='https://hooks.example.org/x'
            )
            services.queue_test_alert(db, alert_to.id)  # 0.7.0: an alert destination and a queued alert
            # 0.7.0: a CVE NVD could not answer for, waiting to be tried again (review M2)
            services.record_lookup_failure(db, 'nvd', 'CVE-2024-3400', 'NVD answered HTTP 404', at=when)
            # 0.7.0: threat guides (TIP 2.10): an actor, a report link, an industry decision, a rule, a hunt
            campaign = services.create_campaign(db, CampaignInput(name='Fixture campaign', tlp='GREEN'))
            services.link_actor_campaign(db, 'G0016', ActorCampaignInput(campaign_id=campaign.id))
            services.link_threat(
                db,
                'campaign',
                campaign.id,
                ThreatLinkInput(target_kind='document', target_id=manual.id, tlp='GREEN'),
            )
            actor = services.create_actor(db, ActorInput(name='Fixture Fox', aliases=('FF-1',), tlp='AMBER'))
            services.link_report(db, actor.id, ActorLinkInput(document_id=manual.id, note='Same beacon'))
            services.record_industry_claim(
                db, actor.id, IndustryClaimInput(industry='energy', document_id=manual.id, tlp='AMBER')
            )
            rule = services.add_rule(
                db,
                RuleInput(kind='yara', name='Fixture', body='rule fixture { condition: true }', tlp='GREEN'),
            )
            services.link_rule(db, rule.id, RuleLinkInput(target_kind='group', target_id=actor.id))
            hunt = services.start_hunt(db, actor.id, HuntInput(title='Fixture hunt', tlp='AMBER'))
            services.record_check(
                db, hunt.id, 'T1071.001', HuntCheckInput(result='nothing-found', data_checked='Proxy logs')
            )
            # 0.9.0: a case (TIP 3.8) holding the IR paste and the beacon, with a note
            case = services.create_case(db, CaseInput(title='Fixture case', tlp='AMBER'))
            services.add_case_item(db, case.id, CaseItemInput(kind='document', target_id=manual.id))
            services.add_case_item(db, case.id, CaseItemInput(kind='indicator', target_id=beacon.id))
            services.add_case_note(db, case.id, CaseNoteInput(text='Waiting for proxy logs.'))
            # 1.0: a PIR (TIP 4.1) with a criterion and a cited report, and an RFI from a hunt tool
            pir = services.create_requirement(
                db,
                RequirementInput(
                    kind='pir',
                    question='Are edge appliances being exploited?',
                    tlp='GREEN',
                    criteria=[CriterionInput(kind='cve', value='CVE-2024-3400')],
                ),
            )
            services.add_evidence(db, pir.id, EvidenceInput(document_id=manual.id))
            services.file_rfi(db, RfiInput(question='Is the beacon known C2?', external_ref='hunt-1'))
            # 1.0: a source grade and a report credibility (TIP 4.2)
            services.rate_source(db, SourceRatingInput(source_name='Fixture vendor', reliability='B'))
            services.set_credibility(db, manual.id, CredibilityInput(credibility=2))
            # 1.0: a Suricata rule and a published hunt package (TIP 4.3)
            network = services.add_rule(
                db,
                RuleInput(
                    kind='suricata',
                    name='Fixture DNS beacon',
                    body='alert dns any any -> any any (msg:"Fixture"; content:"example.test"; sid:1;)',
                    tlp='GREEN',
                ),
            )
            hunt_package = services.create_hunt_package(
                db,
                HuntPackageInput(
                    title='Fixture hunt',
                    hypothesis='The beacon calls home over DNS.',
                    tlp='AMBER',
                    items=[
                        HuntPackageItemInput(kind='technique', target_id='T1071.004'),
                        HuntPackageItemInput(kind='indicator', target_id=beacon.id),
                        HuntPackageItemInput(kind='rule', target_id=network.id),
                        HuntPackageItemInput(kind='document', target_id=manual.id),
                    ],
                ),
            )
            services.publish_hunt_package(db, hunt_package.id)
            # 1.0: a hunt tool saw the beacon while running that package (TIP 4.2)
            services.record_sighting(
                db,
                SightingInput(
                    value='198.51.100.7',
                    first_seen=datetime(2026, 11, 1, 9, 30, tzinfo=UTC),
                    last_seen=datetime(2026, 11, 2, 17, 0, tzinfo=UTC),
                    count=12,
                    where='Fixture lab',
                    observer='Fixture hunt tool',
                    hunt_package_id=hunt_package.id,
                    tlp='AMBER',
                ),
            )
    finally:
        engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    target = ROOT / 'tests' / 'fixtures' / 'releases' / f'insight-{__version__}.sqlite3'
    if target.exists() and '--force' not in (argv or sys.argv[1:]):
        print(f'{target.relative_to(ROOT)} already exists (use --force to rebuild).', file=sys.stderr)
        return 1
    target.unlink(missing_ok=True)
    build(target)
    print(f'Wrote {target.relative_to(ROOT)}. Commit it with the release.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

"""Hunt plans preserve sharing rules, explicit links and publisher text boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from io import BytesIO

import pytest
from pypdf import PdfReader
from sqlalchemy.orm import Session

from insight import services
from insight.hunt_guide import GuideSection, HuntGuide, bounded, to_markdown, to_pdf
from insight.hunt_guide_plan import planning_sections
from insight.schemas import ActorInput, ActorLinkInput, AssessmentInput, SoftwareLinkInput
from insight.threat_library import library

from .test_threat_guides import accept_all, report

NOW = datetime.now(UTC)


def text(guide: HuntGuide) -> str:
    return '\n'.join([guide.title, guide.summary, *(line for s in guide.sections for line in s.lines)])


def test_choices_search_catalog_aliases_and_all_visible_actors(db: Session) -> None:
    hidden = services.create_actor(db, ActorInput(name='Secret group', aliases=['Hidden alias'], tlp='AMBER'))
    visible = services.create_actor(db, ActorInput(name='Copper Fox', aliases=['Copper alias'], tlp='GREEN'))
    found = services.hunt_guide_choices(db, kind='actor', q='cozy', max_tlp='GREEN')
    assert [ref for ref, _ in found['actor']] == ['G0016']
    assert 'Cozy Bear' in found['actor'][0][1]
    assert (
        services.hunt_guide_choices(db, kind='actor', q='Copper alias', max_tlp='GREEN')['actor'][0][0]
        == visible.id
    )
    assert services.hunt_guide_choices(db, kind='actor', q='Hidden alias', max_tlp='GREEN')['actor'] == []
    assert services.hunt_guide_choices(db, kind='actor', q=hidden.id, max_tlp='GREEN')['actor'] == []
    for n in range(51):
        services.create_actor(db, ActorInput(name=f'Search actor {n:02}', tlp='CLEAR'))
    first = services.hunt_guide_choices(db, kind='actor', q='Search actor', max_tlp='CLEAR')['actor']
    assert len(first) == 50
    last = services.hunt_guide_choices(db, kind='actor', q='Search actor 50', max_tlp='CLEAR')['actor']
    assert len(last) == 1
    assert 'Search actor 50' in last[0][1]


def test_actor_guide_uses_current_explicit_links_and_metadata_only(db: Session) -> None:
    """Regression: a group name in a report never turns it into attributed hunt evidence."""
    linked = report(
        db, 'Linked evidence', 'DO-NOT-REPRINT publisher text. C2 at bad-hunt-domain.net.', tlp='GREEN'
    )
    accept_all(db, linked)
    linked.source_url = 'https://source.example.org/reports/hunt'
    named = report(db, 'Cozy Bear candidate', 'Cozy Bear used candidate-domain.net.', tlp='GREEN')
    accept_all(db, named)
    secret = report(db, 'SECRET report', 'secret-hunt-domain.net', tlp='AMBER')
    accept_all(db, secret)
    old = report(db, 'Superseded linked item', 'old-hunt-domain.net', tlp='GREEN', key='revision')
    report(db, 'Replacement unlinked item', 'replacement-hunt-domain.net', tlp='GREEN', key='revision')
    for document in (linked, secret, old):
        services.link_report(
            db, 'G0016', ActorLinkInput(document_id=document.id, note='PRIVATE analyst note')
        )
    guide = services.hunt_guide(db, 'actor', 'G0016', max_tlp='GREEN', now=NOW)
    rendered = text(guide)
    assert guide.tlp == 'GREEN'
    assert rendered.count('bad-hunt-domain.net') >= 1
    assert linked.id in rendered
    assert 'https://source.example.org/reports/hunt' in rendered
    assert 'attack.mitre.org/techniques/' in rendered
    for forbidden in (
        'DO-NOT-REPRINT',
        'PRIVATE',
        'SECRET',
        secret.id,
        named.id,
        old.id,
        'candidate-domain.net',
    ):
        assert forbidden not in rendered
    assert 'not proof' in rendered
    assert 'No search or rule has run' in rendered


def test_actor_and_software_link_labels_are_preserved(db: Session) -> None:
    doc = report(db, 'Restricted link', 'software-hunt-domain.net', tlp='CLEAR')
    accept_all(db, doc)
    services.link_report(db, 'G0016', ActorLinkInput(document_id=doc.id, tlp='AMBER'))
    services.link_software_report(db, 'S0154', SoftwareLinkInput(document_id=doc.id, tlp='AMBER'))
    for kind, ref in [('actor', 'G0016'), ('software', 'S0154')]:
        assert doc.id not in text(services.hunt_guide(db, kind, ref, max_tlp='GREEN'))
        full = services.hunt_guide(db, kind, ref, max_tlp='AMBER')
        assert full.tlp == 'AMBER'
        assert doc.id in text(full)


def test_theme_matches_words_and_techniques_but_filters_review_and_verdicts(db: Session) -> None:
    visible = report(db, 'Ransomware news', 'active-hunt-domain.net; safe-hunt-domain.net; expired-hunt.net.')
    accept_all(db, visible)
    unreviewed = report(db, 'Ransomware pending', 'pending-hunt-domain.net')
    secret = report(db, 'SECRET ransomware', 'secret-hunt.net', tlp='AMBER')
    accept_all(db, secret)
    tagged = report(db, 'A technique report', 'T1486 without a theme word.')
    for obs in services.detail(db, visible)['observations']:
        if obs['value'] == 'safe-hunt-domain.net':
            services.assess_entity(
                db, obs['entity_id'], AssessmentInput(verdict='benign', reason='Known safe', tlp='GREEN')
            )
        if obs['value'] == 'expired-hunt.net':
            services.assess_entity(
                db,
                obs['entity_id'],
                AssessmentInput(
                    verdict='malicious',
                    reason='Old',
                    valid_until=(NOW + timedelta(days=1)).date(),
                    tlp='GREEN',
                ),
            )
    guide = services.hunt_guide(db, 'theme', 'ransomware', max_tlp='GREEN', now=NOW + timedelta(days=2))
    rendered = text(guide)
    assert guide.tlp == 'GREEN'
    assert visible.id in rendered
    assert tagged.id in rendered
    assert unreviewed.id in rendered
    assert rendered.count('active-hunt-domain.net') >= 1
    assert 'SECRET' not in rendered
    assert secret.id not in rendered
    assert 'pending-hunt-domain.net' not in rendered
    assert 'safe-hunt-domain.net' not in rendered
    assert 'expired-hunt.net' not in rendered
    assert 'T1486' in rendered
    assert 'Criminals lock up files' in rendered


@pytest.mark.parametrize('expired', [False, True])
@pytest.mark.parametrize('kind', ['theme', 'document'])
def test_excluded_restricted_verdicts_still_label_the_guide(db: Session, expired: bool, kind: str) -> None:
    """Regression: a private benign/expired decision removed a check from a guide labelled public."""
    doc = report(db, 'Ransomware report', 'reviewed-hunt-domain.net', tlp='CLEAR')
    accept_all(db, doc)
    ref = 'ransomware' if kind == 'theme' else doc.id
    when = NOW + timedelta(days=2)
    public = services.hunt_guide(db, kind, ref, max_tlp='GREEN', now=when)
    entity_id = services.detail(db, doc)['observations'][0]['entity_id']
    services.assess_entity(
        db,
        entity_id,
        AssessmentInput(
            verdict='malicious' if expired else 'benign',
            reason='Private decision text',
            valid_until=(NOW + timedelta(days=1)).date() if expired else None,
            tlp='AMBER',
        ),
    )
    restricted = services.hunt_guide(db, kind, ref, max_tlp='AMBER', now=when)
    assert restricted.tlp == 'AMBER'
    assert text(restricted).count('reviewed-hunt-domain.net') == 0
    assert 'No eligible reviewed indicators' in text(restricted)
    assert 'Private decision text' not in text(restricted)
    assert public.tlp == 'CLEAR'
    assert text(public).count('reviewed-hunt-domain.net') >= 1
    assert 'verdict: unknown' in text(public)
    assert services.hunt_guide(db, kind, ref, max_tlp='GREEN', now=when) == public


def test_restricted_exclusion_labels_a_changed_indicator_cap_notice(db: Session) -> None:
    """Regression: removing a private benign value outside the shown 100 changed public cap metadata."""
    values = [f'hunt-cap-{n:03d}.net' for n in range(101)]
    doc = report(db, 'Ransomware report', '; '.join(values), tlp='CLEAR')
    accept_all(db, doc)
    before = services.hunt_guide(db, 'theme', 'ransomware', max_tlp='GREEN', now=NOW)
    assert 'Shows the first 100 eligible indicators' in text(before)
    entity_id = next(
        obs['entity_id'] for obs in services.detail(db, doc)['observations'] if obs['value'] == values[0]
    )
    services.assess_entity(db, entity_id, AssessmentInput(verdict='benign', reason='Private', tlp='AMBER'))
    after = services.hunt_guide(db, 'theme', 'ransomware', max_tlp='AMBER', now=NOW)
    assert after.tlp == 'AMBER'
    assert 'Shows the first 100 eligible indicators' not in text(after)
    assert services.hunt_guide(db, 'theme', 'ransomware', max_tlp='GREEN', now=NOW) == before


def test_empty_theme_plan_is_honest_and_unknown_or_hidden_choices_are_missing(db: Session) -> None:
    guide = services.hunt_guide(db, 'theme', 'zero-day', now=NOW)
    assert guide.tlp == 'CLEAR'
    assert 'No fixed technique mapping' in text(guide)
    assert 'No eligible reviewed indicators' in text(guide)
    hidden = services.create_actor(db, ActorInput(name='Hidden', tlp='AMBER'))
    for kind, ref in [
        ('actor', hidden.id),
        ('actor', 'missing'),
        ('theme', 'missing'),
        ('software', 'S9999'),
        ('x', 'x'),
    ]:
        with pytest.raises(LookupError):
            services.hunt_guide(db, kind, ref, max_tlp='GREEN')


def test_report_and_technique_caps_are_disclosed(db: Session) -> None:
    for n in range(21):
        report(db, f'Phishing report {n}', 'No publisher body in a hunt guide.', tlp='CLEAR')
    guide = services.hunt_guide(db, 'theme', 'phishing')
    sources = next(s for s in guide.sections if s.title == 'Reports used')
    assert len(sources.lines) == 21
    assert 'latest 20' in sources.lines[-1]
    sections = planning_sections(tuple(library().techniques)[:20])
    assert 'first 12' in sections[-1].lines[-1]


def test_markdown_and_pdf_keep_labels_escape_text_and_defang_indicators() -> None:
    guide = HuntGuide(
        'theme',
        'phishing',
        '<script> Hunt [link](https://bad-hunt-domain.net)',
        'Check the logs.',
        'AMBER',
        NOW.isoformat(),
        (
            GuideSection(
                'Look here', ('bad-hunt-domain.net', 'https://bad-hunt-domain.net/path', 'Keep 日本語')
            ),
            GuideSection(
                'Many leads', tuple(f'Lead {i}: review the source and check the time.' for i in range(160))
            ),
        ),
    )
    markdown = to_markdown(guide)
    assert '<script>' not in markdown
    assert '&lt;script&gt;' in markdown
    assert '[link](https://' not in markdown
    assert '日本語' in markdown
    pdf = PdfReader(BytesIO(to_pdf(guide)))
    assert len(pdf.pages) > 1
    for page in pdf.pages:
        assert 'TLP:AMBER' in page.extract_text()
    content = '\n'.join(page.extract_text() for page in pdf.pages)
    assert 'bad-hunt-domain[.]net' in content
    assert 'hxxps://' in content
    assert 'The Markdown keeps them' in content
    assert pdf.metadata is not None
    assert pdf.metadata.subject == 'Threat hunt guide, TLP:AMBER'


def test_size_cap_discloses_shortened_text_and_never_lowers_the_label() -> None:
    guide = HuntGuide(
        'actor',
        'test',
        'Long title ' * 200,
        'Long summary ' * 300,
        'RED',
        NOW.isoformat(),
        tuple(GuideSection('Evidence', ('x' * 2_000,) * 160) for _ in range(25)),
    )
    result = bounded(guide)
    assert result.tlp == 'RED'
    assert len(result.title) <= 300
    assert len(result.summary) <= 1_200
    assert sum(len(line) for section in result.sections for line in section.lines) < 41_000
    assert all(len(line) <= 1_200 for section in result.sections for line in section.lines)
    assert result.sections[-1].title == 'Guide size limit'

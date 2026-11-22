"""TIP 1.3: the brief uses CISA's ransomware flag, NIST NVD's CVSS beside CISA advisories', and EPSS.

Acceptance (docs/ROADMAP-TIP.md 1.3): the KEV ransomware line is present or absent as the data says; an NVD
score of 9.8 beats or joins a CSAF score; missing caches never crash; the wording states only stored facts.
"""

from __future__ import annotations

import importlib.util
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from insight.brief import compose, window_start
from insight.cve_scores import CveScores, EpssScore, NvdScore
from insight.services import BriefData, BriefDocument, BriefKev

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
SINCE = window_start(NOW)
CSAF_KEY = 'cisa-csaf'

_spec = importlib.util.spec_from_file_location('plain', Path(__file__).with_name('test_plain_language.py'))
assert _spec
assert _spec.loader
plain = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plain)


def doc(
    n: int, *, title: str = '', body: str = '', key: str | None = None, source: str = 'SANS'
) -> BriefDocument:
    return BriefDocument(f'd{n}', title or f'Report {n}', source, key, '2026-11-18T09:00:00+00:00', '', body)


def kev(
    cve: str,
    *,
    ransomware: bool = False,
    document: str = '',
    added: str = '2026-11-18',
    exploit: bool = False,
) -> BriefKev:
    return BriefKev(
        cve,
        'Acme',
        'Gateway',
        added,
        '2026-12-09',
        document,
        ransomware=ransomware,
        name='Acme Bug',
        public_exploit=exploit,
    )


def nvd(score: float | None, status: str = 'Analyzed', description: str = '') -> NvdScore:
    return NvdScore(
        score, 'Critical' if score and score >= 9 else 'High', '3.1', '', status, '', description, ()
    )


def scored(cve: str, *, cvss: float | None = None, epss: float | None = None, **nvd_fields: str) -> CveScores:
    return CveScores(
        cve,
        nvd(cvss, **nvd_fields) if cvss is not None or nvd_fields else None,
        EpssScore(epss, 0.99, '2026-11-18') if epss is not None else None,
        '2026-11-18T00:00:00+00:00',
        '2026-11-18T00:00:00+00:00',
    )


def data(**fields: object) -> BriefData:
    defaults: dict[str, object] = {'since': SINCE, 'documents': [], 'mentions': [], 'kev': {}, 'watch': {}}
    return BriefData(**(defaults | fields))  # type: ignore[arg-type]


def titles(result: object) -> list[str]:
    return [h.title for h in result.highlights]  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- ransomware (KEV, TIP 1.1)


def test_ransomware_use_is_said_marked_and_comes_first() -> None:
    entries = {
        'CVE-2026-0001': kev('CVE-2026-0001', document='k1'),
        'CVE-2026-0002': kev('CVE-2026-0002', ransomware=True, document='k2'),
    }
    result = compose(data(kev=entries), as_of=NOW)
    assert 'CISA knows of ransomware campaigns that use 1 of them.' in result.summary
    exploited = [item.text for item in result.sections[0].items]
    assert exploited[0] == 'CVE-2026-0002 · Acme Gateway · added 2026-11-18 · used in ransomware'
    assert not exploited[1].endswith('used in ransomware')
    assert titles(result)[:2] == ['Used in ransomware attacks', 'Known exploitation deserves attention']
    ransomware = result.highlights[0]
    assert '1 flaw in this brief is known to CISA to be used in ransomware campaigns' in ransomware.text
    assert 'does not prove that your business is a target' in ransomware.text
    assert [item.document_id for item in ransomware.evidence] == ['k2']


def test_without_ransomware_use_nothing_mentions_ransomware() -> None:
    result = compose(data(kev={'CVE-2026-0001': kev('CVE-2026-0001')}), as_of=NOW)
    text = ' '.join([*result.summary, *(h.text for h in result.highlights)])
    assert 'ransomware' not in text.lower()
    assert 'Used in ransomware attacks' not in titles(result)


def test_public_exploit_code_is_said_and_marked_before_ransomware_use() -> None:
    """TIP 3.3: a new KEV entry with public exploit code is marked; ransomware entries still sort first."""
    entries = {
        'CVE-2026-0001': kev('CVE-2026-0001', exploit=True),
        'CVE-2026-0002': kev('CVE-2026-0002', ransomware=True, exploit=True),
        'CVE-2026-0003': kev('CVE-2026-0003'),
    }
    result = compose(data(kev=entries), as_of=NOW)
    assert 'Exploit code is public for 2 of them.' in result.summary
    exploited = [item.text for item in result.sections[0].items]
    assert exploited[0] == (
        'CVE-2026-0002 · Acme Gateway · added 2026-11-18 · exploit code public · used in ransomware'
    )
    assert 'CVE-2026-0001 · Acme Gateway · added 2026-11-18 · exploit code public' in exploited
    assert 'CVE-2026-0003 · Acme Gateway · added 2026-11-18' in exploited
    single = compose(data(kev={'CVE-2026-0001': kev('CVE-2026-0001', exploit=True)}), as_of=NOW)
    assert 'Exploit code is public for it.' in single.summary
    plain = compose(data(kev={'CVE-2026-0003': kev('CVE-2026-0003')}), as_of=NOW)
    assert not any('Exploit code' in line for line in plain.summary)


def test_a_single_new_kev_entry_used_in_ransomware_reads_naturally() -> None:
    result = compose(data(kev={'CVE-2026-0002': kev('CVE-2026-0002', ransomware=True)}), as_of=NOW)
    assert 'CISA knows of ransomware campaigns that use it.' in result.summary


# --------------------------------------------------------------------------- NVD CVSS beside CSAF


ADVISORY = doc(
    1,
    title='ICSA-26-322-01 · Acme Gateway',
    key=CSAF_KEY,
    body='- CVE-2026-1000, CVSS 3.1 base score 9.1: Remote code execution in the web UI.',
)


@pytest.mark.parametrize(('nvd_score', 'shown'), [(9.8, 9.8), (9.1, 9.1), (8.0, 9.1)])
def test_nvd_beats_or_joins_a_csaf_score(nvd_score: float, shown: float) -> None:
    mentions = [('d1', 'cve', 'CVE-2026-1000')]
    scores = {'CVE-2026-1000': scored('CVE-2026-1000', cvss=nvd_score)}
    result = compose(data(documents=[ADVISORY], mentions=mentions, scores=scores), as_of=NOW)
    (item,) = result.sections[1].items
    if nvd_score > 9.1:  # NVD's higher score wins and says where it comes from
        assert item.text == 'CVE-2026-1000 · CVSS 9.8 (NIST NVD) · ICSA-26-322-01 · Acme Gateway'
        assert 'The highest base score is 9.8 out of 10, for CVE-2026-1000 (NIST NVD).' in result.summary
    elif nvd_score == 9.1:  # the same score: the advisory's line, nothing added
        assert item.text == 'CVE-2026-1000 · CVSS 9.1 · ICSA-26-322-01 · Acme Gateway'
    else:  # the advisory's higher score, with NVD's beside it
        assert item.text == 'CVE-2026-1000 · CVSS 9.1 · NIST NVD 8 · ICSA-26-322-01 · Acme Gateway'
    assert f'{shown:g} out of 10' in ' '.join(result.summary)


def test_nvd_alone_makes_a_cve_in_any_report_most_severe_and_explains_its_description() -> None:
    report = doc(2, title='Partner note on gateways')
    scores = {
        'CVE-2026-2000': scored(
            'CVE-2026-2000', cvss=9.8, description='Authentication bypass in the admin API.'
        )
    }
    result = compose(
        data(documents=[report], mentions=[('d2', 'cve', 'CVE-2026-2000')], scores=scores), as_of=NOW
    )
    (item,) = result.sections[1].items
    assert item.text == 'CVE-2026-2000 · CVSS 9.8 (NIST NVD) · Partner note on gateways'
    severity = next(h for h in result.highlights if h.title == 'Highest reported severity')
    assert 'NIST NVD rates it, and a new report mentions it: Partner note on gateways.' in severity.text
    assert 'skip sign-in checks' in severity.text


@pytest.mark.parametrize(
    'found',
    [
        None,
        CveScores('CVE-2026-3000'),
        scored('CVE-2026-3000', cvss=9.9, status='Rejected'),
        scored('CVE-2026-3000', status='Awaiting Analysis'),
        scored('CVE-2026-3000', cvss=6.5),
    ],
)
def test_missing_rejected_or_low_scores_add_nothing_and_never_crash(found: CveScores | None) -> None:
    scores = {'CVE-2026-3000': found} if found is not None else {}
    result = compose(
        data(documents=[doc(3)], mentions=[('d3', 'cve', 'CVE-2026-3000')], scores=scores), as_of=NOW
    )
    assert result.sections[1].items == ()
    assert result.sections[1].empty == (
        'No weakness in the new reports scores 9 or more (CVSS, from CISA advisories or NIST NVD).'
    )
    assert 'Likely to be attacked soon' not in titles(result)


# --------------------------------------------------------------------------- EPSS


def test_likely_attacks_are_named_with_their_chance_and_the_caveat() -> None:
    documents = [doc(4, title='Exploit chatter'), doc(5, title='Vendor notice')]
    mentions = [
        ('d4', 'cve', 'CVE-2026-4000'),
        ('d5', 'cve', 'CVE-2026-5000'),
        ('d5', 'cve', 'CVE-2026-6000'),
    ]
    scores = {
        'CVE-2026-4000': scored('CVE-2026-4000', epss=0.42),
        'CVE-2026-5000': scored('CVE-2026-5000', epss=0.12),
        'CVE-2026-6000': scored('CVE-2026-6000', epss=0.02),  # below 10%: not named
    }
    result = compose(data(documents=documents, mentions=mentions, scores=scores), as_of=NOW)
    likely = next(h for h in result.highlights if h.title == 'Likely to be attacked soon')
    assert likely.text.startswith(
        '2 flaws in this brief have an EPSS score of 10% or more: '
        'CVE-2026-4000 (42%) and CVE-2026-5000 (12%). '
    )
    assert 'It says nothing about whether you use the product.' in likely.text
    assert [item.document_id for item in likely.evidence] == ['d4', 'd5']
    assert 'CVE-2026-6000' not in likely.text


def test_every_new_sentence_is_plain() -> None:
    documents = [ADVISORY, doc(2, title='Partner note')]
    entries = {'CVE-2026-0002': kev('CVE-2026-0002', ransomware=True, document='k2')}
    mentions = [('d1', 'cve', 'CVE-2026-1000'), ('d2', 'cve', 'CVE-2026-4000')]
    scores = {
        'CVE-2026-1000': scored('CVE-2026-1000', cvss=9.8),
        'CVE-2026-4000': scored('CVE-2026-4000', epss=0.42),
    }
    result = compose(data(documents=documents, mentions=mentions, kev=entries, scores=scores), as_of=NOW)
    sentences = [
        *result.summary,
        *(h.text for h in result.highlights),
        *(h.action for h in result.highlights),
    ]
    for text in sentences:
        # Names and identifiers come from the data, not from Insight's wording: grade them as plain words.
        text = re.sub(r'CVE-\d{4}-\d+|Acme Gateway|Partner note|ICSA-\S+', 'it', text)
        for sentence in re.split(r'(?<=[.!?])\s+', text):
            assert plain.grade(sentence) <= plain.MAX_GRADE, sentence

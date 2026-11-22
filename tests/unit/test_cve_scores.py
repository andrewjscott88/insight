"""Scores per CVE from cached NVD, EPSS and VulnCheck KEV answers (review C2, TIP 3.3): parsing, wording."""

from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from insight.cve_scores import (
    MAX_VULNCHECK_EXPLOITS,
    CveScores,
    EpssScore,
    NvdScore,
    VulnCheckEntry,
    describe_epss,
    describe_nvd,
    describe_vulncheck,
    parse_epss,
    parse_nvd,
    parse_vulncheck,
    percent,
    scores,
    summarise_vulncheck,
    summary,
)

CVE = 'CVE-2024-3400'


def metric(score: float, severity: str, version: str, kind: str = 'Primary') -> dict[str, Any]:
    return {
        'type': kind,
        'cvssData': {
            'version': version,
            'baseScore': score,
            'baseSeverity': severity,
            'vectorString': f'CVSS:{version}/AV:N',
        },
    }


def nvd_answer(**cve: Any) -> dict[str, Any]:
    body = {'id': CVE, 'vulnStatus': 'Analyzed', 'published': '2024-04-12T08:15:06.230', **cve}
    return {'totalResults': 1, 'vulnerabilities': [{'cve': body}]}


def test_nvd_prefers_the_newest_cvss_version_and_the_primary_score() -> None:
    answer = nvd_answer(
        metrics={
            'cvssMetricV2': [metric(7.5, 'HIGH', '2.0')],
            'cvssMetricV31': [metric(9.0, 'CRITICAL', '3.1', 'Secondary'), metric(10.0, 'CRITICAL', '3.1')],
        },
        descriptions=[{'lang': 'es', 'value': 'Una'}, {'lang': 'en', 'value': 'A command\n  injection'}],
        weaknesses=[{'description': [{'value': 'CWE-77'}, {'value': 'NVD-CWE-noinfo'}, {'value': 'CWE-20'}]}],
    )
    found = parse_nvd(answer)
    assert found == NvdScore(
        score=10.0,
        severity='Critical',
        version='3.1',
        vector='CVSS:3.1/AV:N',
        status='Analyzed',
        published='2024-04-12',
        description='A command injection',
        cwes=('CWE-20', 'CWE-77'),
    )
    assert describe_nvd(found) == 'CVSS 10.0 (Critical), NIST NVD'


def test_nvd_version_4_wins_and_a_single_secondary_score_is_used() -> None:
    answer = nvd_answer(
        metrics={
            'cvssMetricV40': [metric(9.3, 'CRITICAL', '4.0', 'Secondary')],
            'cvssMetricV31': [metric(9.8, 'CRITICAL', '3.1')],
        }
    )
    found = parse_nvd(answer)
    assert found is not None
    assert (found.score, found.version) == (9.3, '4.0')


def test_nvd_cvss_2_severity_sits_outside_cvss_data() -> None:
    answer = nvd_answer(metrics={'cvssMetricV2': [{'type': 'Primary', 'baseSeverity': 'HIGH', 'cvssData': {
        'version': '2.0', 'baseScore': 7.5}}]})  # fmt: skip
    found = parse_nvd(answer)
    assert found is not None
    assert describe_nvd(found) == 'CVSS 7.5 (High), NIST NVD'


@pytest.mark.parametrize(
    ('status', 'wording'),
    [
        ('Rejected', 'NIST NVD: rejected (withdrawn or a duplicate)'),
        ('Awaiting Analysis', 'NIST NVD: not scored yet (awaiting analysis)'),
        ('', 'NIST NVD: not scored yet (no score)'),
    ],
)
def test_nvd_without_a_score_says_why(status: str, wording: str) -> None:
    found = parse_nvd(nvd_answer(vulnStatus=status, metrics={}))
    assert found is not None
    assert found.score is None
    assert describe_nvd(found) == wording


@pytest.mark.parametrize(
    'answer',
    [
        {'totalResults': 0, 'vulnerabilities': []},
        {},
        [],
        None,
        {'vulnerabilities': [{'cve': 'odd'}]},
        {'vulnerabilities': 'odd'},
    ],
)
def test_nvd_answers_without_a_record_give_none(answer: Any) -> None:
    assert parse_nvd(answer) is None


@given(
    st.recursive(
        st.none() | st.booleans() | st.floats() | st.text(),
        lambda c: st.lists(c) | st.dictionaries(st.text(), c),
    )
)
def test_parsing_never_raises_on_odd_answers(answer: Any) -> None:  # fmt: skip
    parse_nvd(answer)
    parse_nvd(
        {'vulnerabilities': [{'cve': {'metrics': answer, 'descriptions': answer, 'weaknesses': answer}}]}
    )
    parse_epss(answer, CVE)
    parse_epss({'data': [answer]}, CVE)


def test_nvd_score_that_is_not_a_number_is_missing() -> None:
    found = parse_nvd(nvd_answer(metrics={'cvssMetricV31': [metric(float('nan'), 'HIGH', '3.1')]}))
    assert found is not None
    assert found.score is None


def test_epss_reads_the_row_for_the_cve() -> None:
    answer = {
        'data': [
            {'cve': 'CVE-2024-1111', 'epss': '0.5', 'percentile': '0.9'},
            {'cve': CVE, 'epss': '0.04231', 'percentile': '0.91234', 'date': '2026-11-20'},
        ]
    }
    found = parse_epss(answer, CVE)
    assert found == EpssScore(probability=0.04231, percentile=0.91234, date='2026-11-20')
    assert describe_epss(found) == (
        'EPSS 4.2% chance of exploitation attempts within 30 days, higher than 91% of CVEs (FIRST)'
    )


@pytest.mark.parametrize(
    'answer',
    [
        {'data': []},
        {'data': [{'cve': 'CVE-2024-1111', 'epss': '0.5'}, {'cve': 'CVE-2024-2222', 'epss': '0.5'}]},
        {'data': [{'cve': CVE, 'epss': '1.5'}]},
        {'data': [{'cve': CVE, 'epss': 'high'}]},
        {'data': 'odd'},
        [],
    ],
)
def test_epss_without_a_usable_score_gives_none(answer: Any) -> None:
    assert parse_epss(answer, CVE) is None


def test_epss_single_row_answer_from_a_manual_lookup_counts_and_odd_percentile_is_dropped() -> None:
    found = parse_epss({'data': [{'epss': '0.97', 'percentile': '7'}]}, CVE)
    assert found == EpssScore(probability=0.97, percentile=None, date='')
    assert describe_epss(found) == 'EPSS 97% chance of exploitation attempts within 30 days (FIRST)'


@pytest.mark.parametrize(
    ('probability', 'text'),
    [
        (0.0, 'under 0.1%'),
        (0.0009, 'under 0.1%'),
        (0.001, '0.1%'),
        (0.0423, '4.2%'),
        (0.5, '50%'),
        (1.0, '100%'),
    ],
)
def test_percent_never_rounds_a_small_chance_to_zero(probability: float, text: str) -> None:
    assert percent(probability) == text


@pytest.mark.parametrize(
    ('percentile', 'rank'),
    [(0.999, ', higher than 99% of CVEs'), (0.5, ', higher than 50% of CVEs'), (0.004, '')],
)
def test_epss_rank_is_rounded_down_and_never_reads_100_or_0(percentile: float, rank: str) -> None:
    text = describe_epss(EpssScore(0.5, percentile, ''))
    assert text == f'EPSS 50% chance of exploitation attempts within 30 days{rank} (FIRST)'


def test_scores_reads_cached_rows_and_summary_says_what_is_missing() -> None:
    nvd = json.dumps(nvd_answer(metrics={'cvssMetricV31': [metric(9.8, 'CRITICAL', '3.1')]}))
    epss = json.dumps({'data': [{'cve': CVE, 'epss': '0.97', 'percentile': '0.999'}]})
    found = scores(
        CVE, [('nvd', nvd, '2026-11-01T00:00:00+00:00'), ('epss', epss, '2026-11-20T00:00:00+00:00')]
    )
    assert found.checked
    assert summary(found) == (
        'CVSS 9.8 (Critical), NIST NVD · '
        'EPSS 97% chance of exploitation attempts within 30 days, higher than 99% of CVEs (FIRST)'
    )
    empty = scores(
        CVE,
        [('nvd', '{"vulnerabilities": []}', 'x'), ('epss', '{"data": []}', 'y'), ('epss', 'not json', 'z')],
    )
    assert summary(empty) == 'NIST NVD has no record of it yet · No EPSS score yet'
    assert summary(CveScores(CVE)) == ''
    assert not CveScores(CVE).checked


# --------------------------------------------------------------------------- VulnCheck KEV (TIP 3.3)


def vulncheck_answer(**extra: Any) -> dict[str, Any]:
    exploit = {
        'xdb_id': 'a1b2c3d4e5f6',
        'xdb_url': 'https://vulncheck.com/xdb/a1b2c3d4e5f6',
        'date_added': '2024-04-16T00:00:00Z',
        'exploit_type': 'initial-access',
        'clone_ssh_url': 'git@github.com:someone/cve-2024-3400.git',
    }
    row = {
        'cve': [CVE],
        'vendorProject': 'Palo Alto Networks',
        'shortDescription': 'A command injection ... (long text that is not kept)',
        'date_added': '2024-04-12T00:00:00Z',
        'knownRansomwareCampaignUse': 'Known',
        'reported_exploited_by_vulncheck_canaries': True,
        'vulncheck_xdb': [exploit],
        'vulncheck_reported_exploitation': [
            {'url': 'https://example.org/a'},
            {'url': 'https://example.org/b'},
        ],
        **extra,
    }
    return {'_meta': {'total_documents': 1}, 'data': [row]}


def test_vulncheck_summary_keeps_metadata_only() -> None:
    kept = summarise_vulncheck(vulncheck_answer(), CVE)
    assert kept == {
        'cve': CVE,
        'listed': True,
        'date_added': '2024-04-12',
        'exploits': [
            {
                'xdb_id': 'a1b2c3d4e5f6',
                'url': 'https://vulncheck.com/xdb/a1b2c3d4e5f6',
                'exploit_type': 'initial-access',
                'date_added': '2024-04-16',
            }
        ],
        'exploit_count': 1,
        'reported_count': 2,
        'canaries': True,
        'ransomware': True,
    }
    stored = json.dumps(kept)
    for dropped in ('git@', 'github.com', 'shortDescription', 'command injection', 'example.org'):
        assert dropped not in stored


@pytest.mark.parametrize(
    'url',
    [
        'https://github.com/someone/poc',
        'http://vulncheck.com/xdb/x',
        'https://vulncheck.com.evil.example/xdb/x',
        'javascript:alert(1)',
        'https://vulncheck.com/xdb/x"><script>',
        None,
    ],
)
def test_vulncheck_links_other_than_its_own_pages_are_dropped(url: Any) -> None:
    exploit = {'xdb_id': 'x', 'xdb_url': url, 'date_added': 'yesterday'}
    kept = summarise_vulncheck(vulncheck_answer(vulncheck_xdb=[exploit]), CVE)
    assert kept['exploits'] == [{'xdb_id': 'x', 'url': '', 'exploit_type': '', 'date_added': ''}]
    # A tampered cache is checked again when read.
    tampered = {**kept, 'exploits': [{'xdb_id': 'x', 'url': url}]}
    entry = parse_vulncheck(tampered)
    assert entry is not None
    assert entry.exploits[0].url == ''


def test_vulncheck_keeps_at_most_ten_exploit_links_but_counts_them_all() -> None:
    many = [{'xdb_id': str(i), 'xdb_url': f'https://vulncheck.com/xdb/{i}'} for i in range(25)]
    entry = parse_vulncheck(summarise_vulncheck(vulncheck_answer(vulncheck_xdb=many), CVE))
    assert entry is not None
    assert len(entry.exploits) == MAX_VULNCHECK_EXPLOITS
    assert entry.exploit_count == 25


@pytest.mark.parametrize('payload', [{'data': []}, {'data': [{'cve': ['CVE-2020-0001']}]}, {}, [], 'x', None])
def test_vulncheck_without_an_entry_for_the_cve_reads_as_not_listed(payload: Any) -> None:
    kept = summarise_vulncheck(payload, CVE)
    assert kept == {'cve': CVE, 'listed': False}
    entry = parse_vulncheck(kept)
    assert entry == VulnCheckEntry(listed=False)
    assert describe_vulncheck(entry) == 'Not in VulnCheck KEV'


def test_vulncheck_entry_matches_a_cve_given_as_a_string() -> None:
    assert summarise_vulncheck(vulncheck_answer(cve=CVE.lower()), CVE)['listed'] is True


@given(
    st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(max_size=20),
        lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=12), c, max_size=4),
        max_leaves=20,
    )
)
def test_vulncheck_parsing_never_raises(junk: Any) -> None:
    summarise_vulncheck(junk, CVE)
    parse_vulncheck(junk)
    if isinstance(junk, dict):
        parse_vulncheck({**junk, 'listed': True})


def test_vulncheck_wording_and_summary() -> None:
    found = scores(
        CVE, [('vulncheck', json.dumps(summarise_vulncheck(vulncheck_answer(), CVE)), '2026-11-20')]
    )
    assert found.checked
    assert found.vulncheck_checked_at == '2026-11-20'
    assert summary(found) == (
        "VulnCheck KEV: exploited, listed 2024-04-12, 1 public exploit, seen by VulnCheck's sensors"
    )
    bare = VulnCheckEntry(listed=True, exploit_count=3)
    assert describe_vulncheck(bare) == 'VulnCheck KEV: exploited, 3 public exploits'

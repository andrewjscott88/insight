"""Scores per CVE from cached NVD and EPSS answers (review C2): safe parsing, and the wording."""

from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from insight.cve_scores import (
    CveScores,
    EpssScore,
    NvdScore,
    describe_epss,
    describe_nvd,
    parse_epss,
    parse_nvd,
    percent,
    scores,
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

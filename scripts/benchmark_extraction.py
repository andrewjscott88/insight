"""Extraction-quality benchmark (Milestone 1 gate): precision/recall per entity kind on a labelled corpus.

    python scripts/benchmark_extraction.py                    # compare with the committed baseline
    python scripts/benchmark_extraction.py --report out.md    # also write a Markdown report (CI summary)
    python scripts/benchmark_extraction.py --update-baseline  # after an intentional improvement

Fails if any kind's precision or recall drops by more than ``TOLERANCE`` versus the baseline. The baseline
records a fingerprint of the corpus it was measured on: if the corpus has changed (new or edited documents),
the gate fails with "corpus changed" instead of reporting misleading regressions, and a human re-baselines.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from insight.extraction import extract

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / 'tests' / 'corpus' / 'extraction.json'
BASELINE = ROOT / 'benchmarks' / 'extraction-baseline.json'
TOLERANCE = 0.01  # one percentage point

Pair = tuple[str, str]


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0


@dataclass
class Result:
    per_kind: dict[str, Counts] = field(default_factory=lambda: defaultdict(Counts))
    misses: list[str] = field(default_factory=list)
    false_alarms: list[str] = field(default_factory=list)

    @property
    def overall(self) -> Counts:
        return Counts(
            sum(c.tp for c in self.per_kind.values()),
            sum(c.fp for c in self.per_kind.values()),
            sum(c.fn for c in self.per_kind.values()),
        )

    def scores(self) -> dict[str, dict[str, float]]:
        rows = dict(sorted(self.per_kind.items()))
        rows['overall'] = self.overall
        return {
            k: {'precision': round(c.precision, 4), 'recall': round(c.recall, 4)} for k, c in rows.items()
        }


def load_corpus(path: Path) -> list[dict[str, object]]:
    """Corpus entries are inline (``text``/``expected``) or point at files (``path``/``expected_path``) for
    full-length reports, relative to the corpus file."""
    documents: list[dict[str, object]] = json.loads(path.read_text(encoding='utf-8'))['documents']
    for document in documents:
        if 'path' in document:
            document['text'] = (path.parent / str(document['path'])).read_text(encoding='utf-8')
            labels = json.loads((path.parent / str(document['expected_path'])).read_text(encoding='utf-8'))
            document['expected'] = labels['expected']
    return documents


def corpus_fingerprint(documents: list[dict[str, object]]) -> str:
    canonical = json.dumps(
        [[d['id'], d['text'], sorted(map(list, d['expected']))] for d in documents],  # type: ignore[call-overload]
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def evaluate(documents: list[dict[str, object]]) -> Result:
    result = Result()
    for document in documents:
        text = str(document['text'])
        expected: set[Pair] = {(str(k), str(v)) for k, v in document['expected']}  # type: ignore[attr-defined]
        found: set[Pair] = {(m.kind, m.value) for m in extract(text)}
        for kind, _value in found & expected:
            result.per_kind[kind].tp += 1
        for kind, value in found - expected:
            result.per_kind[kind].fp += 1
            result.false_alarms.append(f'{document["id"]}: {kind} {value}')
        for kind, value in expected - found:
            result.per_kind[kind].fn += 1
            result.misses.append(f'{document["id"]}: {kind} {value}')
    return result


def regressions(scores: dict[str, dict[str, float]], baseline: dict[str, dict[str, float]]) -> list[str]:
    found: list[str] = []
    for kind, reference in baseline.items():
        current = scores.get(kind, {'precision': 1.0, 'recall': 1.0})
        found.extend(
            f'{kind} {metric} fell from {reference[metric]:.2%} to {current[metric]:.2%}'
            for metric in ('precision', 'recall')
            if current[metric] < reference[metric] - TOLERANCE
        )
    return found


def markdown(result: Result, problems: list[str]) -> str:
    lines = ['## Extraction quality', '', '| kind | precision | recall |', '| --- | --- | --- |']
    lines += [f'| {k} | {v["precision"]:.1%} | {v["recall"]:.1%} |' for k, v in result.scores().items()]
    lines += ['', f'**Regressions:** {"; ".join(problems) if problems else "none"}', '']
    lines += ['<details><summary>Missed indicators</summary>', '', *[f'- {m}' for m in result.misses], '']
    lines += ['</details>', '<details><summary>False positives</summary>', '']
    lines += [*[f'- {f}' for f in result.false_alarms], '', '</details>']
    return '\n'.join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--corpus', type=Path, default=CORPUS)
    parser.add_argument('--baseline', type=Path, default=BASELINE)
    parser.add_argument('--update-baseline', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(argv)
    documents = load_corpus(args.corpus)
    result = evaluate(documents)
    scores = result.scores()
    fingerprint = corpus_fingerprint(documents)
    if args.update_baseline:
        baseline_data = {'corpus_sha256': fingerprint, 'scores': scores}
        args.baseline.write_text(json.dumps(baseline_data, indent=2) + '\n')
        print(f'Baseline updated: {args.baseline}')
        return 0
    baseline = json.loads(args.baseline.read_text())
    if baseline.get('corpus_sha256') != fingerprint:
        problems = [
            'corpus changed since the baseline was recorded: these are not code regressions. Review the '
            'report below, then run `python scripts/benchmark_extraction.py --update-baseline` and commit it'
        ]
    else:
        problems = regressions(scores, baseline['scores'])
    report = markdown(result, problems)
    if args.report:
        args.report.write_text(report)
    print(report)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())

"""Performance budget (milestone gate): ingest throughput, search/detail latency and query counts.

    python scripts/benchmark_performance.py                      # SQLite in a temp directory
    python scripts/benchmark_performance.py --database-url URL   # e.g. the CI PostgreSQL service
    python scripts/benchmark_performance.py --report perf.md

Budgets live in ``benchmarks/performance-budget.json``; exceeding any of them fails the gate.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from sqlalchemy import event

from insight import services
from insight.models import database
from insight.schemas import DocumentInput

ROOT = Path(__file__).resolve().parent.parent
BUDGET = ROOT / 'benchmarks' / 'performance-budget.json'


def synthetic_report(i: int) -> DocumentInput:
    body = (
        f'Report {i}: actor used CVE-2024-{10000 + i % 500} against 192.0.2.{i % 250} and '
        f'198.51.100.{(i * 7) % 250}; payload at https://cdn{i % 40}.example.net/p/{i}.bin with MD5 '
        f'{i:032x}. ' + 'Narrative text about the intrusion and recommended mitigations. ' * 20
    )
    return DocumentInput(
        title=f'Synthetic report {i}', body=body, source_name=f'Publisher {i % 7}', tlp='GREEN'
    )


def p95(samples: list[float]) -> float:
    return statistics.quantiles(samples, n=20)[-1] if len(samples) > 1 else samples[0]


def measure(database_url: str, documents: int) -> dict[str, Any]:
    engine, sessions = database(database_url)
    try:
        started = time.perf_counter()
        with sessions.begin() as db:
            for i in range(documents):
                services.ingest(db, synthetic_report(i))
        ingest_seconds = time.perf_counter() - started

        searches = ['CVE-2024-10042', 'cdn7.example.net', 'publisher 3', 'mitigations', 'no-such-term']
        search_ms: list[float] = []
        with sessions() as db:
            for _ in range(5):
                for q in searches:
                    t = time.perf_counter()
                    docs = services.search_documents(db, services.DocumentQuery(q=q, limit=200))
                    services.summaries(db, docs)
                    search_ms.append((time.perf_counter() - t) * 1000)

            statements: list[str] = []
            listener = lambda *args: statements.append(args[2])  # noqa: E731
            event.listen(engine, 'before_cursor_execute', listener)
            docs = services.search_documents(db, services.DocumentQuery(limit=200))
            services.summaries(db, docs)
            event.remove(engine, 'before_cursor_execute', listener)

            detail_ms: list[float] = []
            for doc in docs[:50]:
                t = time.perf_counter()
                services.detail(db, doc)
                detail_ms.append((time.perf_counter() - t) * 1000)
    finally:
        engine.dispose()
    return {
        'documents': documents,
        'ingest_seconds': round(ingest_seconds, 2),
        'ingest_docs_per_second': round(documents / ingest_seconds, 1),
        'search_p95_ms': round(p95(search_ms), 1),
        'list_page_queries': len(statements),
        'detail_p95_ms': round(p95(detail_ms), 1),
    }


def violations(result: dict[str, Any], budget: dict[str, Any]) -> list[str]:
    checks = [
        ('ingest_seconds', 'ingest_seconds_max'),
        ('search_p95_ms', 'search_p95_ms_max'),
        ('list_page_queries', 'list_page_queries_max'),
        ('detail_p95_ms', 'detail_p95_ms_max'),
    ]
    return [f'{m} = {result[m]} exceeds budget {budget[b]}' for m, b in checks if result[m] > budget[b]]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--database-url')
    parser.add_argument('--documents', type=int)
    parser.add_argument('--budget', type=Path, default=BUDGET)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(argv)
    budget = json.loads(args.budget.read_text())
    documents = args.documents or budget['documents']
    with tempfile.TemporaryDirectory() as tmp:
        url = args.database_url or f'sqlite:///{Path(tmp) / "perf.db"}'
        result = measure(url, documents)
    problems = violations(result, budget)
    lines = ['## Performance budget', '', '| metric | value |', '| --- | --- |']
    lines += [f'| {k} | {v} |' for k, v in result.items()]
    lines += ['', f'**Budget violations:** {"; ".join(problems) if problems else "none"}']
    report = '\n'.join(lines)
    if args.report:
        args.report.write_text(report)
    print(report)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())

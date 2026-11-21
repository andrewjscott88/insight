"""Offline advisory text extraction, refusal limits and the isolated worker boundary."""

from __future__ import annotations

import hashlib
import io
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from pypdf import PdfWriter
from pypdf.generic import ContentStream

from insight import _pdf_worker as worker
from insight import pdf_import
from insight.pdf_import import PdfUnavailable, parse_pdf

FIXTURE = Path(__file__).resolve().parents[1] / 'fixtures' / 'advisory.pdf'
LINUX = pytest.mark.skipif(sys.platform != 'linux', reason='PDF workers require the Linux kernel sandbox')


def pdf_bytes(writer: PdfWriter) -> bytes:
    with io.BytesIO() as output:
        writer.write(output)
        return output.getvalue()


@LINUX
def test_advisory_text_and_original_file_provenance() -> None:
    raw = FIXTURE.read_bytes()
    report = parse_pdf(raw)
    assert report.text == 'Synthetic advisory: example.org observed at 192.0.2.17.'
    assert report.sha256 == 'f411ad4eab7d5fb61fb019829d2e9f721b4bdf084b526ed274bbf3abb119a509'
    assert report.size_bytes == len(raw)
    assert report.page_count == 1


@LINUX
def test_compressed_pages_keep_order_and_original_file_hash() -> None:
    writer = PdfWriter()
    writer.append(FIXTURE)
    writer.append(FIXTURE)
    for page in writer.pages:
        page.compress_content_streams()
    raw = pdf_bytes(writer)
    report = parse_pdf(raw)
    text = 'Synthetic advisory: example.org observed at 192.0.2.17.'
    assert report.text == text + '\n\n' + text
    assert report.sha256 == hashlib.sha256(raw).hexdigest()
    assert report.page_count == 2


@pytest.mark.parametrize('data', [b'', b'plain text', b'<html>advisory</html>'])
def test_non_pdf_is_refused(data: bytes) -> None:
    with pytest.raises(ValueError, match='Choose a PDF'):
        parse_pdf(data)


def test_file_limit_is_applied_before_launch(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_worker(_data: bytes) -> tuple[int, str]:
        pytest.fail('Oversize input reached the worker')

    monkeypatch.setattr(pdf_import, '_read_in_worker', no_worker)
    with pytest.raises(ValueError, match='file limit'):
        parse_pdf(b'%PDF-' + b' ' * (pdf_import.MAX_PDF_BYTES - 4))


@LINUX
def test_truncated_pdf_and_empty_page_are_refused() -> None:
    with pytest.raises(ValueError, match='could not be read'):
        parse_pdf(FIXTURE.read_bytes().split(b'xref')[0])
    writer = PdfWriter()
    writer.add_blank_page(width=500, height=600)
    with pytest.raises(ValueError, match='no extractable text'):
        parse_pdf(pdf_bytes(writer))


@LINUX
def test_encrypted_advisory_is_refused() -> None:
    writer = PdfWriter()
    writer.append(FIXTURE)
    writer.encrypt('fixture password', algorithm='RC4-40')
    with pytest.raises(ValueError, match='Encrypted'):
        parse_pdf(pdf_bytes(writer))


@LINUX
def test_page_count_refuses_the_whole_document() -> None:
    writer = PdfWriter()
    writer.append(FIXTURE)
    for _ in range(worker.MAX_PDF_PAGES):
        writer.add_blank_page(width=500, height=600)
    with pytest.raises(ValueError, match='page, text or resource'):
        parse_pdf(pdf_bytes(writer))


@LINUX
def test_text_limit_refuses_the_whole_document() -> None:
    writer = PdfWriter()
    writer.append(FIXTURE)
    stream = ContentStream(None, writer)
    stream.set_data(b'BT /F1 12 Tf (' + b'X' * (worker.MAX_PDF_CHARS + 1) + b') Tj ET')
    writer.pages[0].replace_contents(stream)
    with pytest.raises(ValueError, match='page, text or resource'):
        parse_pdf(pdf_bytes(writer))


@LINUX
def test_worker_deadline_releases_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = FIXTURE.read_bytes()
    with monkeypatch.context() as mp:
        mp.setattr(pdf_import, 'MAX_WALL_SECONDS', 0)
        with pytest.raises(ValueError, match='time limit'):
            parse_pdf(raw)
    assert parse_pdf(raw).page_count == 1


def test_platform_and_worker_capacity_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = FIXTURE.read_bytes()
    with monkeypatch.context() as mp:
        mp.setattr(sys, 'platform', 'unavailable')
        with pytest.raises(PdfUnavailable, match='requires the Linux'):
            parse_pdf(raw)
    with monkeypatch.context() as mp:
        mp.setattr(sys, 'platform', 'linux')
        mp.setattr(pdf_import, '_SLOTS', threading.BoundedSemaphore(0))
        with pytest.raises(PdfUnavailable, match='busy'):
            parse_pdf(raw)


@LINUX
def test_kernel_enforces_worker_limits_and_denies_new_resources() -> None:
    # Test in a child: a seccomp filter and lowered hard rlimits cannot be removed from pytest.
    check = """
import errno, os, resource, runpy, socket, sys
worker = runpy.run_path(sys.argv[1])
worker['_resource_limits']()
for kind, budget in ((resource.RLIMIT_CPU, 'MAX_CPU_SECONDS'),
                     (resource.RLIMIT_AS, 'MAX_MEMORY_BYTES'),
                     (resource.RLIMIT_FSIZE, 'MAX_OUTPUT_BYTES')):
    soft, hard = resource.getrlimit(kind)
    assert 0 < soft <= hard <= worker[budget]
assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
worker['_restrict_syscalls']()
for operation in (lambda: os.open('/dev/null', os.O_RDONLY),
                  lambda: os.open('/dev/null', os.O_WRONLY),
                  lambda: socket.socket(socket.AF_UNIX),
                  lambda: os.execv('/no-such-pdf-fixture-program', ['fixture'])):
    try:
        operation()
    except OSError as exc:
        assert exc.errno == errno.EPERM
    else:
        raise AssertionError('forbidden resource was available')
"""
    subprocess.run([sys.executable, '-I', '-c', check, worker.__file__], timeout=10, check=True)

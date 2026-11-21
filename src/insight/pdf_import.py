"""Extract advisory text from a local PDF in a bounded, default-deny Linux worker."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from . import _pdf_worker as worker

MAX_PDF_BYTES: Final = worker.MAX_PDF_BYTES
MAX_WALL_SECONDS: Final = 10
_SLOTS = threading.BoundedSemaphore(2)
_WORKER = Path(__file__).with_name('_pdf_worker.py').resolve()
_REFUSALS: Final = {
    worker.INVALID: 'This PDF could not be read.',
    worker.ENCRYPTED: 'Encrypted PDFs cannot be imported.',
    worker.TOO_LARGE: 'The PDF exceeds the page, text or resource limit.',
    worker.NO_TEXT: 'The PDF contains no extractable text.',
}


class PdfUnavailable(RuntimeError):
    """A bounded worker could not start, or all worker slots are occupied."""


@dataclass(frozen=True)
class ParsedPdf:
    text: str
    sha256: str
    size_bytes: int
    page_count: int


def _read_in_worker(data: bytes) -> tuple[int, str]:
    try:
        # The kernel caps writes to this temporary file even if the parser misbehaves. A pipe captured
        # into memory by communicate() would have no comparable bound. Nothing is retained on disk.
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(  # noqa: S603 -- fixed interpreter and worker, no user arguments.
                [sys.executable, '-I', '-B', str(_WORKER)],
                input=data,
                stdout=output,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                cwd='/',
                env={'LC_ALL': 'C.UTF-8'},
                timeout=MAX_WALL_SECONDS,
                check=False,
            )
            if result.returncode == worker.UNAVAILABLE:
                raise PdfUnavailable('The PDF parser sandbox is unavailable.')
            if result.returncode:
                raise ValueError(
                    _REFUSALS.get(result.returncode, 'The PDF could not be parsed within its limits.')
                )
            output.seek(0)
            packet = output.read(worker.MAX_OUTPUT_BYTES + 1)
    except subprocess.TimeoutExpired as exc:
        raise ValueError('The PDF exceeded the parsing time limit.') from exc
    except OSError as exc:
        raise PdfUnavailable('The PDF parser sandbox is unavailable.') from exc

    pages = int.from_bytes(packet[:4], 'big')
    if not 1 <= pages <= worker.MAX_PDF_PAGES or not 4 < len(packet) <= worker.MAX_OUTPUT_BYTES:
        raise ValueError('Invalid PDF parser output.')
    try:
        text = packet[4:].decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValueError('Invalid PDF parser output.') from exc
    if not text.strip() or len(text) > worker.MAX_PDF_CHARS or '\x00' in text:
        raise ValueError('Invalid PDF parser output.')
    return pages, text


def parse_pdf(data: bytes) -> ParsedPdf:
    """Hash the original bytes and extract complete text. No preview, rendering or partial imports."""
    if len(data) > MAX_PDF_BYTES:
        raise ValueError('The PDF exceeds the 2 megabyte file limit.')
    if not data.startswith(b'%PDF-'):
        raise ValueError('Choose a PDF file.')
    if sys.platform != 'linux':
        raise PdfUnavailable('PDF import requires the Linux parser sandbox.')
    if not _SLOTS.acquire(blocking=False):
        raise PdfUnavailable('PDF import is busy. Try again shortly.')
    try:
        pages, text = _read_in_worker(data)
    finally:
        _SLOTS.release()
    return ParsedPdf(
        text=text, sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data), page_count=pages
    )

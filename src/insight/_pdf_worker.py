"""Private worker for the Linux PDF sandbox. Run as an isolated Python process, with no user paths."""

from __future__ import annotations

import codecs
import ctypes
import errno
import io
import sys
from importlib import import_module
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from pypdf import PdfReader

MAX_PDF_BYTES: Final = 2_000_000
MAX_PDF_PAGES: Final = 100
MAX_PDF_CHARS: Final = 200_000
# A four-byte page count followed by at most four UTF-8 bytes per Unicode character.
MAX_OUTPUT_BYTES: Final = 4 + 4 * MAX_PDF_CHARS
MAX_CPU_SECONDS: Final = 5
MAX_MEMORY_BYTES: Final = 256 * 1024 * 1024

INVALID: Final = 2
ENCRYPTED: Final = 3
TOO_LARGE: Final = 4
NO_TEXT: Final = 5
UNAVAILABLE: Final = 6

# libseccomp resolves syscall numbers for the native architecture and rejects other syscall ABIs.
# Only stdin, an anonymous size-limited output file and /dev/null are inherited. The allowlist has
# no path access, networking, process creation, tracing, descriptor transfer or resource-limit changes.
_SYSCALLS: Final = (
    'read',
    'write',
    'close',
    'brk',
    'mmap',
    'mmap2',
    'munmap',
    'mremap',
    'mprotect',
    'madvise',
    'futex',
    'futex_time64',
    'clock_gettime',
    'clock_gettime64',
    'gettimeofday',
    'getrandom',
    'rt_sigaction',
    'rt_sigprocmask',
    'rt_sigreturn',
    'sigaltstack',
    'getpid',
    'gettid',
    'sched_yield',
    'exit',
    'exit_group',
)


def _resource_limits() -> None:
    import resource  # Unix only; the parent can still start on other platforms.

    for kind, cap in (
        (resource.RLIMIT_AS, MAX_MEMORY_BYTES),
        (resource.RLIMIT_CPU, MAX_CPU_SECONDS),
        (resource.RLIMIT_FSIZE, MAX_OUTPUT_BYTES),
        (resource.RLIMIT_CORE, 0),
    ):
        soft, hard = resource.getrlimit(kind)
        limit = min(x for x in (cap, soft, hard) if x != resource.RLIM_INFINITY)
        resource.setrlimit(kind, (limit, limit))


def _restrict_syscalls() -> None:
    """Install a default-deny kernel filter before reading a byte supplied by the caller."""
    lib = ctypes.CDLL('libseccomp.so.2')
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.restype = None
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_rule_add.restype = ctypes.c_int
    lib.seccomp_attr_set.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint32]
    lib.seccomp_attr_set.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_load.restype = ctypes.c_int

    ctx = lib.seccomp_init(0x00050000 | errno.EPERM)  # SCMP_ACT_ERRNO(EPERM)
    if not ctx:
        raise OSError('Cannot allocate PDF sandbox')
    try:
        # SCMP_FLTATR_CTL_TSYNC: protect every thread, including any created by optional runtime libraries.
        if lib.seccomp_attr_set(ctx, 4, 1) != 0:
            raise OSError('Cannot configure PDF sandbox threads')
        for name in _SYSCALLS:
            number = lib.seccomp_syscall_resolve_name(name.encode('ascii'))
            if number >= 0 and lib.seccomp_rule_add(ctx, 0x7FFF0000, number, 0) != 0:  # SCMP_ACT_ALLOW
                raise OSError('Cannot configure PDF sandbox')
        if lib.seccomp_load(ctx) != 0:
            raise OSError('Cannot start PDF sandbox')
    finally:
        lib.seccomp_release(ctx)


def _extract(reader: PdfReader) -> int:
    if reader.is_encrypted:
        return ENCRYPTED
    pages = len(reader.pages)
    if pages > MAX_PDF_PAGES:
        return TOO_LARGE
    chunks: list[str] = []
    length = 0
    for page in reader.pages:
        text = page.extract_text().replace('\r\n', '\n').replace('\r', '\n').strip()
        if not text:
            continue
        if '\x00' in text:
            return INVALID
        length += len(text) + (2 if chunks else 0)
        if length > MAX_PDF_CHARS:
            return TOO_LARGE
        chunks.append(text)
    if not chunks:
        return NO_TEXT
    sys.stdout.buffer.write(pages.to_bytes(4, 'big') + '\n\n'.join(chunks).encode('utf-8'))
    sys.stdout.buffer.flush()
    return 0


def main() -> int:
    try:
        _resource_limits()
        from pypdf import PdfReader, overwrite_configuration

        # A compressed page loads this module lazily. Text extraction never needs an external image decoder.
        import_module('pypdf.filters')
        overwrite_configuration(disable_legacy_handling=True, jbig2dec_binary=None)

        # Python loads codecs lazily. Load text encodings the parser uses before sealing filesystem access.
        for name in (
            'utf-16-be',
            'utf-16-le',
            'utf-16',
            'utf-8',
            'latin-1',
            'charmap',
            'mac_roman',
            'cp1252',
            'cp932',
            'cp950',
            'gb2312',
            'gbk',
            'gb18030',
            'big5',
            'euc-jp',
            'euc-kr',
        ):
            codecs.lookup(name)
        _restrict_syscalls()
    except Exception:  # The worker must fail closed if dependencies or any OS protection are unavailable.
        return UNAVAILABLE

    try:
        raw = sys.stdin.buffer.read(MAX_PDF_BYTES + 1)
        if len(raw) > MAX_PDF_BYTES:
            return TOO_LARGE
        return _extract(PdfReader(io.BytesIO(raw), strict=True))
    except MemoryError:
        return TOO_LARGE
    except Exception:  # Parser errors may contain publisher text. Only a fixed status crosses the boundary.
        return INVALID


if __name__ == '__main__':
    sys.exit(main())

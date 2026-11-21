"""``insight threat-library-sync``: fetch the pinned ATT&CK and MISP galaxy files, build the full library.

The two files are fetched with :func:`insight.connectors.download` (HTTPS, curated hosts, no redirects), from
URLs that name an exact commit, and each must match its pinned SHA-256 before anything is parsed. Then
:func:`insight.threat_library_build.build` writes the full edition atomically to
``<INSIGHT_DATA_DIR>/threat-library.json``. Nothing else is contacted, and the sync runs only when someone
asks for it (ADR 0018, ADR 0025).
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import httpx

from .threat_library_build import build, check_sentences, sha256


@dataclass(frozen=True, slots=True)
class Pinned:
    key: str
    name: str
    version: str
    url: str
    sha256: str
    max_bytes: int

    def describe(self, digest: str) -> dict[str, str]:
        """What the library records about the release it was built from."""
        return {'version': self.version, 'url': self.url, 'sha256': digest}


#: The releases this version of Insight was built and tested against. Change them only together with the
#: bundled edition (``scripts/update_actors.py --pinned``) and review the resulting diff.
PINNED: Final[dict[str, Pinned]] = {
    'attack': Pinned(
        key='attack',
        name='MITRE ATT&CK Enterprise',
        version='20.1',
        url=(
            'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/'
            'a8db2f52eb933c9c99060c123e088b3326d3a607/enterprise-attack/enterprise-attack-20.1.json'
        ),
        sha256='539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5',
        max_bytes=80_000_000,
    ),
    'misp-galaxy': Pinned(
        key='misp-galaxy',
        name='MISP galaxy threat-actor cluster',
        version='359',
        url=(
            'https://raw.githubusercontent.com/MISP/misp-galaxy/'
            '6d78ff22dd1986ffd1a74bd720e635991a52e91a/clusters/threat-actor.json'
        ),
        sha256='90e8c27a4a51a2185261e61f42328e3f7df7c1c69e53bea9b0ba78f07f47bc69',
        max_bytes=8_000_000,
    ),
}


def render(library: dict[str, Any]) -> str:
    """Stable JSON with one group, technique or software entry per line, so updates review as small diffs."""
    lines = ['{']
    keys = list(library)
    for position, key in enumerate(keys):
        value = library[key]
        comma = ',' if position < len(keys) - 1 else ''
        if key in ('groups', 'reviewed_exclusions') and isinstance(value, list):
            items = [f'    {json.dumps(item, ensure_ascii=False, sort_keys=True)}' for item in value]
            lines += [f'  "{key}": [', ',\n'.join(items), f'  ]{comma}']
        elif key in ('techniques', 'software', 'mitigations', 'data_components') and isinstance(value, dict):
            items = [
                f'    {json.dumps(k)}: {json.dumps(v, ensure_ascii=False, sort_keys=True)}'
                for k, v in value.items()
            ]
            lines += [f'  "{key}": {{', ',\n'.join(items), f'  }}{comma}']
        else:
            lines.append(
                f'  {json.dumps(key)}: {json.dumps(value, ensure_ascii=False, sort_keys=True)}{comma}'
            )
    lines.append('}')
    return '\n'.join(lines) + '\n'


async def fetch_pinned(pinned: Pinned, *, transport: httpx.AsyncBaseTransport | None = None) -> bytes:
    """One pinned file, refused unless its SHA-256 matches. ``transport`` exists for offline tests."""
    from .connectors import download  # Deferred: connectors imports the services layer.

    payload = await download(pinned.url, transport=transport, max_bytes=pinned.max_bytes)
    digest = sha256(payload)
    if digest != pinned.sha256:
        raise ValueError(
            f'{pinned.name} {pinned.version}: SHA-256 {digest[:16]}… does not match the pinned release; '
            'nothing was changed'
        )
    return payload


def write_atomically(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.threat-library-', dir=path.parent)
    try:
        with os.fdopen(handle, 'w', encoding='utf-8') as out:
            out.write(text)
        Path(temporary).replace(path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


async def sync_library(target: Path, *, transport: httpx.AsyncBaseTransport | None = None) -> dict[str, Any]:
    """Fetch both pinned releases, build the full edition and write it to ``target``. Returns the library."""
    payloads = {key: await fetch_pinned(pinned, transport=transport) for key, pinned in PINNED.items()}
    bundle = json.loads(payloads['attack'])
    library = build(
        bundle,
        json.loads(payloads['misp-galaxy']),
        full=True,
        attack_source=PINNED['attack'].describe(sha256(payloads['attack'])),
        misp_source=PINNED['misp-galaxy'].describe(sha256(payloads['misp-galaxy'])),
    )
    if problems := check_sentences(library, bundle):
        raise ValueError('ATT&CK evidence check failed: ' + '; '.join(problems[:3]))
    write_atomically(target, render(library))
    return library

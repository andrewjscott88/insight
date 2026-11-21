"""Render reviewed IPs or domains as passive Suricata or Snort 3 alert rules."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Literal

from .extraction import canonical

# Disjoint, signed-32-bit-compatible local SID ranges allow both files to be loaded together.
_SID_BASE = {'ip': 1_000_000_000, 'domain': 1_500_000_000}
_SID_RANGE = 500_000_000


def _sid(value: str, base: int, assigned: set[int]) -> int:
    slot = int.from_bytes(hashlib.sha256(value.encode('ascii')).digest()[:8], 'big') % _SID_RANGE
    while base + slot in assigned:
        slot = (slot + 1) % _SID_RANGE
    assigned.add(base + slot)
    return base + slot


def sensor_rules(engine: Literal['suricata', 'snort'], kind: str, values: Iterable[str]) -> str:
    """Emit exact indicators. Refuse empty results so a refresh cannot silently clear a sensor."""
    if kind not in _SID_BASE:
        raise ValueError('Sensor rules support only kind=ip or kind=domain.')
    lines = [
        f'# Insight {engine} alert rules for reviewed {kind} indicators.',
        '# Contains live indicators. Review before loading and observe the original sharing limits.',
    ]
    assigned: set[int] = set()
    for value in sorted(set(values)):
        # Treat legacy stored values as data even when writing a rule language.
        try:
            valid = '%' not in value and len(value) <= 253 and canonical(kind, value) == value
        except ValueError:
            valid = False
        if not valid:
            raise ValueError('A stored indicator cannot be represented safely in a sensor rule.')
        if kind == 'ip':
            header = f'alert ip any any <> {value} any'
            condition = ''
        elif engine == 'suricata':
            header = 'alert dns any any -> any any'
            condition = f'flow:to_server; dns.query; content:"{value}"; nocase; bsize:{len(value)}; '
        else:
            # Snort 3: exactly the first uncompressed question of a standard UDP DNS query.
            labels = value.encode('ascii').split(b'.')
            qname = b''.join(bytes([len(label)]) + label for label in labels) + b'\x00'
            header = 'alert udp any any -> any 53'
            condition = (
                'byte_test:1,<,8,2; byte_test:2,>,0,4; '
                f'content:"|{qname.hex(" ")}|",nocase,offset 12,depth {len(qname)}; '
            )
        sid = _sid(value, _SID_BASE[kind], assigned)
        lines.append(f'{header} (msg:"Insight reviewed {kind} {value}"; {condition}sid:{sid}; rev:1;)')
    if not assigned:
        raise ValueError('No eligible indicators for these sensor rules.')
    return '\n'.join(lines) + '\n'

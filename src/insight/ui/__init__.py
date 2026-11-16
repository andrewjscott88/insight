"""Python-only analyst workspace (NiceGUI). Untrusted reporting is always rendered as text.

Layering rule (enforced by ``tests/unit/test_architecture.py``): UI modules never build SQL or import the ORM
models; every read and write goes through :mod:`insight.services`, exactly like the JSON API.
"""

from .page import register_ui

__all__ = ['register_ui']

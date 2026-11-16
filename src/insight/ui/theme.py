"""Visual constants and small shared widgets."""

from __future__ import annotations

from typing import Final

from nicegui import ui

TLP_COLORS: Final = {
    'CLEAR': '#cedbe6',
    'GREEN': '#83dbb0',
    'AMBER': '#efc276',
    'AMBER+STRICT': '#efc276',
    'RED': '#f2a4b4',
}

STYLE: Final = """
body { background:#0b121c;color:#e2ebf4;font-family:system-ui,sans-serif; }
.nicegui-content { padding:0;gap:0;width:100%; }
.workspace { width:100%;max-width:1680px;margin:auto;padding:28px 36px; }
.eyebrow { color:#76dfc7;font-size:10px;letter-spacing:2px;font-weight:600; }
.muted { color:#94a5ba; }
.panel { background:#111c29;border:1px solid #283648;border-radius:10px; }
.source-card { border:1px solid #29394a;background:#121e2c;border-radius:7px;padding:16px;width:100%;
  cursor:pointer; }
.source-card:hover { background:#1a2c3b; }
.source-selected { border-color:#76dfc7;background:#18312f; }
.evidence { border-left:2px solid #42665f;padding:8px 12px;background:#0e1723;white-space:pre-wrap;
  overflow-wrap:anywhere; }
.source-body { white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.85;font-size:13px;max-height:350px;
  overflow:auto; }
.q-field__control { background:#0c1622; }
.q-btn { text-transform:none;font-weight:600; }
.break-value { overflow-wrap:anywhere;word-break:break-word; }
@media(max-width:700px) { .workspace { padding:20px 14px; } }
"""


def apply_theme() -> None:
    ui.dark_mode().enable()
    ui.colors(primary='#76dfc7', secondary='#263a4d', accent='#e5bd78', positive='#76dfc7')
    ui.add_css(STYLE)


def tlp_badge(value: str) -> None:
    color = TLP_COLORS.get(value, TLP_COLORS['CLEAR'])
    ui.label(f'TLP:{value}').classes('text-xs rounded px-2 py-1').style(
        f'background:{color}18;color:{color};font-weight:600'
    )

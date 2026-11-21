"""The workspace style sheet, written for readability (ADR 0017).

Targets, from WCAG 2.2 AAA (1.4.8, 2.4.13, 2.5.5), the British Dyslexia Association style guide and W3C COGA:
body text 16 px (never smaller), line height 1.5 or more, lines of about 70 characters at most, sentence
case (no all-caps), left-aligned text, a 3 px focus outline, 44 px targets, and no motion for people who ask
for less. Sizes are in ``rem``, so the per-device "Larger text" setting (``html[data-text="large"]``) scales
them all.

Cascade layers (NiceGUI declares ``theme, base, quasar, nicegui, components, utilities, overrides, ...``):

* unlayered rules beat every layer: design tokens and Insight's own classes;
* ``@layer components``: Quasar component defaults, which Tailwind utilities (``text-xs``) can still override;
* ``@layer theme`` (:data:`QUASAR_OVERRIDES`): the only place that can override Quasar's ``!important`` rules.
"""

from __future__ import annotations

from typing import Final

STYLE: Final = """
:root { --text-xs:1rem;--text-xs--line-height:1.5;--text-sm:1rem;--text-sm--line-height:1.5;
  --text-base:1rem;--text-base--line-height:1.5;--text-lg--line-height:1.5;--text-xl--line-height:1.4;
  --text-2xl--line-height:1.35;--text-3xl--line-height:1.3; }
body.body--dark, body.body--light { background:var(--ins-bg);color:var(--ins-text);font-size:1rem;
  line-height:1.5;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
.nicegui-content { padding:0;gap:0;width:100%; }
.workspace { width:100%;max-width:1680px;margin:auto;padding:28px 36px; }
.workspace h1, .workspace h2, .workspace h3, .q-dialog h2, .q-dialog h3 { margin:0;letter-spacing:normal; }
.page-title { font-size:1.875rem;font-weight:600;line-height:1.3; }
.section-title { font-size:1.25rem;font-weight:600;line-height:1.4; }
.report-title { font-size:1.5rem;font-weight:600;line-height:1.35; }
.subsection-title { font-size:1.125rem;font-weight:600;line-height:1.4; }
.card-title { font-size:1rem;font-weight:600;line-height:1.5; }
.eyebrow { color:var(--ins-accent);font-size:1rem;font-weight:600;letter-spacing:0.01em; }
.muted { color:var(--ins-muted); }
.text-warn { color:var(--ins-warn); }
.text-error { color:var(--ins-error);font-weight:600; }
.divider { border-color:var(--ins-line); }
.panel { background:var(--ins-panel);border:1px solid var(--ins-line);border-radius:10px;
  color:var(--ins-text); }
.source-card { border:1px solid var(--ins-line);background:var(--ins-card);border-radius:7px;padding:16px;
  width:100%;cursor:pointer; }
.source-card:hover { background:var(--ins-hover); }
.source-selected { border-color:var(--ins-accent);border-width:2px;background:var(--ins-selected); }
/* The intel brief's executive summary: set apart like a selected card, with an accent rule on the left. */
.summary-box { border:1px solid var(--ins-line);border-left:4px solid var(--ins-accent);border-radius:8px;
  background:var(--ins-selected); }
.source-card .q-focus-helper { display:none; }
.source-card .q-btn:hover .block { text-decoration:underline; }
/* Reading width: about 70 characters per line (WCAG 1.4.8: at most 80; BDA: 60-70). 1ch is the width of "0",
   wider than an average letter, so 56ch holds about 70-75 characters. */
.prose, .source-body, .evidence { max-width:56ch; }
.source-body { white-space:pre-wrap;overflow-wrap:break-word;font-size:1rem;line-height:1.7; }
.evidence { border-left:3px solid var(--ins-evidence-line);padding:8px 12px;background:var(--ins-evidence-bg);
  white-space:pre-wrap;overflow-wrap:break-word;line-height:1.6; }
.nicegui-link { color:var(--ins-link);text-underline-offset:0.2em; }
.nicegui-link.muted { color:var(--ins-muted); }
.target-link { display:inline-flex;align-items:center;min-height:2.75rem; }
/* Break a word only if it is longer than the whole line (a hash, a URL); `anywhere` broke ordinary words
   ("docume-nts") whenever a box was narrow, which is especially hard to read with dyslexia. */
.break-value { overflow-wrap:break-word; }
.stat-tiles { display:grid;grid-template-columns:repeat(auto-fit, minmax(min(100%, 8.5rem), 1fr)); }
.tlp-badge { font-weight:600; }
/* A warning flag (review Design 1): the text colour already passes contrast; the border marks it as a tag. */
.flag-badge { font-weight:600;border:1px solid currentColor; }
.tlp-clear { color:var(--ins-tlp-clear);background:var(--ins-tlp-clear-bg); }
.tlp-green { color:var(--ins-tlp-green);background:var(--ins-tlp-green-bg); }
.tlp-amber { color:var(--ins-tlp-amber);background:var(--ins-tlp-amber-bg); }
.tlp-red { color:var(--ins-tlp-red);background:var(--ins-tlp-red-bg); }
.theme-switch .q-btn, .text-size-switch .q-btn { color:var(--ins-muted); }
.theme-switch .q-btn.theme-active, .text-size-switch .q-btn.theme-active { color:var(--ins-accent);
  background:var(--ins-selected); }
.glossary dt { font-weight:600; }
.glossary dd { margin:0 0 12px;max-width:56ch; }
.document-reader, .document-list-pane { scroll-margin-top:12px; }
.q-notification__badge { display:none; }
/* Messages stay until dismissed, so they must never hide what has keyboard focus (WCAG 2.4.11): the
   browser keeps focused elements above them (scroll-padding, W3C technique C43); they sit below dialogs. */
html { scroll-padding-bottom:8rem; }
@media(max-width:700px) { .workspace { padding:20px 14px; } }
/* Tabs that do not fit wrap onto a second line instead of a sideways-scrolling strip, which keyboard users
   cannot reach in Safari (axe scrollable-region-focusable) and which hides tabs from view. */
.q-tabs__content.no-wrap { flex-wrap:wrap !important;overflow:visible !important; }
@media(max-width:599.98px) {
  .workspace { padding:14px max(12px, env(safe-area-inset-right)) 28px max(12px, env(safe-area-inset-left)); }
  .page-title { font-size:1.5rem; }
  .report-title { font-size:1.25rem; }
  .q-dialog__inner--minimized { padding:8px; }
  .dialog-card { padding:16px !important; }
}
@layer components {
  .q-btn { text-transform:none;font-weight:600;font-size:1rem;line-height:1.5;min-height:2.75rem; }
  .q-btn.q-btn--dense { min-height:2.75rem;padding-left:0.75rem;padding-right:0.75rem; }
  .q-tab { min-height:3rem;text-transform:none;padding:0 12px; }
  .q-tab--inactive { opacity:1; }
  .q-tab__label { font-size:1rem; }
  .q-field__native, .q-field__input, .q-field__label, .q-field__prefix, .q-field__suffix,
  .q-select__dropdown-icon { font-size:1rem; }
  .q-field__label { color:var(--ins-muted); }
  .q-field__native::placeholder, .q-field__input::placeholder { color:var(--ins-muted);opacity:1; }
  .q-field__control { background:var(--ins-field); }
  .q-field--outlined .q-field__control:before { border-color:var(--ins-field-border); }
  .q-field--outlined .q-field__control:hover:before { border-color:var(--ins-text); }
  .q-field__bottom { font-size:1rem;line-height:1.5; }
  .q-field__focusable-action { width:2.75rem;height:2.75rem;display:inline-flex;align-items:center;
    justify-content:center; }
  .q-item { font-size:1rem; }
  .q-expansion-item .q-item { min-height:3rem; }
  .q-badge { font-size:1rem;line-height:1.5;padding:2px 8px; }
  .q-tooltip { font-size:1rem;line-height:1.5; }
  .q-chip { font-size:1rem;background:var(--ins-selected);color:var(--ins-text); }
  .q-checkbox, .q-toggle { min-height:2.75rem; }
  .q-notification__message { font-size:1rem;line-height:1.5; }
  .q-notifications__list { z-index:5500; }
  .q-expansion-item .q-item__label { max-width:56ch; }
}
"""

#: "Larger text", per device: 19 px base, and more space between letters, words and lines (BDA guidance).
TEXT_SIZE_STYLE: Final = """
html[data-text="large"] { font-size:118.75%;--text-xs--line-height:1.7;--text-sm--line-height:1.7;
  --text-base--line-height:1.7; }
html[data-text="large"] body.body--dark, html[data-text="large"] body.body--light { line-height:1.7;
  letter-spacing:0.03em;word-spacing:0.1em; }
html[data-text="large"] .source-body { line-height:1.9; }
"""

#: Overrides of Quasar ``!important`` rules. Important declarations in earlier cascade layers win, so these
#: live in NiceGUI's first layer.
QUASAR_OVERRIDES: Final = """@layer theme {
  /* Filled primary buttons: Quasar paints their label .text-white (1.6:1 on the dark theme's mint). */
  .q-btn.bg-primary.text-white { color:var(--ins-on-accent) !important; }
  /* Keyboard focus: a 3 px outline in a 7:1 colour, instead of Quasar's faint tint (WCAG 2.4.13). */
  .q-btn:focus-visible, .q-tab:focus-visible, .q-item:focus-visible, .q-checkbox:focus-visible,
  .q-toggle:focus-visible, a:focus-visible,
  [tabindex]:not([tabindex="-1"]):not(.q-field__native):focus-visible {
    outline:3px solid var(--ins-focus) !important;outline-offset:2px !important; }
  .q-field--focused .q-field__control { outline:3px solid var(--ins-focus) !important;
    outline-offset:2px !important; }
  /* Left-aligned text: Quasar centres button labels (.text-center), which made report titles centred. */
  .source-card .q-btn__content, .q-btn__content.justify-start { justify-content:flex-start !important;
    text-align:left !important; }
  .q-item__label { line-height:1.5 !important; }
  /* Messages: Insight's colours (7:1), whatever Quasar type they carry. */
  .q-notification.insight-notice { background:var(--ins-notice-bg) !important;
    color:var(--ins-notice-text) !important; }
  .q-notification.insight-notice--warning { background:var(--ins-notice-warn-bg) !important;
    color:var(--ins-notice-warn-text) !important; }
  .q-notification.insight-notice--error { background:var(--ins-notice-error-bg) !important;
    color:var(--ins-notice-error-text) !important; }
  .q-notification.insight-notice .q-btn { color:var(--ins-notice-text) !important;text-decoration:underline; }
  .q-notification.insight-notice--warning .q-btn { color:var(--ins-notice-warn-text) !important; }
  .q-notification.insight-notice--error .q-btn { color:var(--ins-notice-error-text) !important; }
  @media(max-width:599.98px) {
    .theme-switch .q-btn__content > .block, .text-size-switch .q-btn__content > .block {
      display:none !important; }
    .theme-switch .q-icon.on-left, .text-size-switch .q-icon.on-left { margin-right:0 !important; }
  }
  /* People who ask their device for less motion get none (WCAG 2.3.3). */
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation-duration:0.01ms !important;animation-iteration-count:1 !important;
      transition-duration:0.01ms !important;scroll-behavior:auto !important; }
  }
}"""

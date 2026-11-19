# ADR 0016: Light and dark themes from one set of colour tokens; the choice is per device

Status: accepted (unreleased); refines ADR 0003; colour targets raised by ADR 0017 (7:1, APCA)

## Context
The workspace was dark only, with colours hard-coded in several places: the NiceGUI style sheet, `ui.colors()`,
Tailwind shades in the panels, inline TLP badge styles, the sign-in style sheet and inline styles on the
sign-out page. The operator also reads it on phones, where a dark-only page is hard to read in daylight and where
the layout was built for desktop widths. Filled buttons had white labels on the mint primary colour (1.6:1).

## Decision
- **Three themes:** `system` (follow the device's light/dark setting, live), `light` and `dark`. `system` is the
  default. The operator sets the instance default with `INSIGHT_THEME` (`make theme THEME=...`). An invalid
  value stops start-up, like every other setting.
- **A per-device choice:** three header buttons (Light / Dark / System) switch at once and store the choice in a
  cookie `insight_theme` (one year, `SameSite=Lax`, `Secure` behind HTTPS). The server reads the cookie. That
  way the sign-in and sign-out pages and the workspace render in the right theme from the first paint, with no
  new API route and no database migration. A phone and a desktop can differ. The cookie is a display preference,
  not a credential: only the three known values are accepted, anything else means "the default" and is never
  written into a page.
- **One palette per theme** (`ui/theme.py` `PALETTES`), exposed as `--ins-*` CSS custom properties on Quasar's
  `body--dark` / `body--light` classes. Quasar's own `--q-*` variables are mapped onto them. Panels use theme
  classes (`muted`, `text-warn`, `tlp-badge`...), never hex values or fixed Tailwind shades (architecture test).
  `static/app.css` mirrors the tokens the sign-in pages need (test).
- **Readability is tested:** every text token against every background, in both themes, at WCAG AA (4.5:1),
  from the token values (unit test) and as rendered by Chromium (browser test).
- **Phones:** larger text, 16 px inputs (iOS zooms into anything smaller), 44 px touch targets, short tab
  labels, stat tiles in one row, no nested scrolling for the report text. Opening a report scrolls the reader into
  view where the list is stacked above it, and a "Back to list" button returns.

## Consequences
A new colour needs a light and a dark value, and both must pass the contrast test. Quasar `!important` rules
(button label colour, `.hidden`, `.block`) can only be overridden from NiceGUI's first cascade layer
(`QUASAR_OVERRIDES`). Responsive visibility uses `max-sm:hidden`, because `hidden sm:block` never shows (tested).
Changing the theme in one tab does not repaint other open tabs until they reload.

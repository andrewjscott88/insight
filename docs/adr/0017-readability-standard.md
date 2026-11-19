# ADR 0017: A readability standard for the GUI: WCAG 2.2 AA, its reading-related AAA criteria, and dyslexia guidance

Status: accepted (unreleased); refines ADR 0016

## Context
An audit of the GUI against current guidance for people with reading difficulties (WCAG 2.2, W3C COGA, the
British Dyslexia Association style guide, APCA and plain-language guidance) found six WCAG A/AA failures (no page
language, no headings, a keyboard-inaccessible scroll box, 1.78:1 field borders, a 4.0:1 hover state, validation
errors in library jargon that vanished after about five seconds). It also found small text (98% of desktop text under
16 px, down to 10 px), tight line spacing, lines of up to 130 characters, all-caps labels, a faint focus
indicator, unexplained abbreviations and dark-mode secondary text that APCA rates Lc 51.

## Decision
The GUI meets **WCAG 2.2 A and AA**, and these **AAA** criteria, which exist for reading: 1.4.6 (7:1 text
contrast), 1.4.8 (visual presentation), 2.2.3 (no timing), 2.3.3 (animation from interactions), 2.4.13 (focus
appearance), 2.5.5 (44 px targets), 3.1.3 and 3.1.4 (unusual words, abbreviations) and 3.1.5 (reading level).
In practice:

- **Type:** 16 px minimum everywhere, line height at least 1.5, lines of about 70 characters (`max-width: 56ch`),
  sentence case (no all-caps), left-aligned text, sizes in `rem`.
- **Colour:** every text token at least 7:1 on every background in both themes, and APCA |Lc| at least 90 for body text
  and 75 for the rest (APCA is informative: WCAG 3 is a draft). Field borders and the focus outline at least 3:1.
- **Structure:** real headings (`h1` page, `h2` panels, reports and dialogs, `h3` sections), named dialogs, the
  page language (`lang="en-US"`), links that say they open a new tab.
- **Interaction:** a 3 px focus outline; messages that stay until dismissed and replace each other (one Quasar
  `group`), sit below dialogs and never hide focused content (`scroll-padding`, WCAG 2.4.11). Problems inside an
  open dialog are written in the dialog (`role="alert"`), and invalid fields carry `aria-invalid`. "Reduce motion"
  is honoured.
- **Words:** interface text at Flesch-Kincaid grade 9 or below per sentence, and about age 12 overall. Every
  abbreviation and specialist term is explained in a glossary ("What the words mean"). Validation errors name the
  field as the reader sees it and say what to do.
- **"Larger text"**, per device like the theme (cookie `insight_text`): a 19 px base with more letter, word and
  line spacing.

Tests keep it there: palette contrast (WCAG and APCA, unit); interface text reading level, capitals and glossary
coverage (unit); headings, dialog names, messages and text size (NiceGUI simulation); and in a real browser **axe-core
(no violations of WCAG 2.0-2.2 A/AA/AAA or best practices on every screen, both themes, desktop and phone)**, rendered
typography, focus outlines, persistent messages, "Larger text", reduced motion and the page language.

## Consequences
The desktop layout is roomier: bigger text, more space and less on screen at once. Every new colour needs light and
dark values that pass AAA. New interface text must pass the reading-level test (official names excepted), and new
abbreviations need a glossary entry. axe's own contrast rules misjudge text inside Quasar dialogs (they measure
against the page behind the backdrop), so in dialogs the browser test checks contrast on the painted colours
instead. APCA's stricter font-size lookup is met on the main surfaces; in the dark theme secondary text is about
0.5 px short of it, which we accept to keep a visible difference between primary and secondary text. Automated
checks find only part of what matters: testing with people who have reading difficulties, and with screen readers and
read-aloud tools, is still needed.

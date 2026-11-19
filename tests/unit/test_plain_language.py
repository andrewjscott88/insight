"""Plain language in the interface (WCAG 3.1.3, 3.1.4, 3.1.5, 3.3.3; W3C COGA; ADR 0017).

Every user-facing string in the workspace code and the sign-in templates is collected from the source and
checked: reading level (Flesch-Kincaid grade 9 or lower per sentence-length string: WCAG 3.1.5's "lower
secondary education"), sentence case (no all-caps labels), and every abbreviation explained in the glossary.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from nicegui import ui

import insight
from insight.schemas import TLP_LEVELS, DocumentInput
from insight.ui import messages
from insight.ui.glossary import GLOSSARY
from insight.ui.ingest import FIELD_HELP

PACKAGE = Path(insight.__file__).parent
UI_MODULES = sorted((PACKAGE / 'ui').glob('*.py'))
TEMPLATES = sorted((PACKAGE / 'templates').glob('*.html'))
#: NiceGUI calls whose first argument (or label/placeholder) is text that people read.
TEXT_CALLS = {'label', 'notify', 'tell', 'button', 'checkbox', 'switch', 'input', 'textarea', 'select',
              'link', 'expansion', 'tooltip', 'tab', 'heading', 'new_tab_link', '_tab'}  # fmt: skip
MAX_GRADE = 9.0  # WCAG 3.1.5: lower secondary education level
#: Official names are not ours to rewrite; readers take them in as names, so they count as one short word.
OFFICIAL_NAMES = (
    'Cybersecurity and Infrastructure Security Agency', 'Known Exploited Vulnerabilities',
    'National Vulnerability Database', 'Traffic Light Protocol',
)  # fmt: skip
MAX_OVERALL_GRADE = 7.0


def text_of(node: ast.expr) -> str | None:
    """A string literal, or an f-string with its placeholders as ``X``."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return ''.join(v.value if isinstance(v, ast.Constant) else 'X' for v in node.values)  # type: ignore[misc]
    return None


def interface_strings() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for path in UI_MODULES:
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, 'id', '')
            if name not in TEXT_CALLS:
                continue
            arguments = node.args[:1] + [k.value for k in node.keywords if k.arg in ('label', 'placeholder')]
            found += [(path.name, text) for arg in arguments if (text := text_of(arg)) and text.strip()]
    for template in TEMPLATES:
        body = re.sub(r'<[^>]+>|\{[%{#].*?[%}#]\}', '\n', template.read_text())
        found += [(template.name, line.strip()) for line in body.splitlines() if len(line.split()) >= 2]
    found += [('glossary.py', f'{term}. {text}') for term, text in GLOSSARY]
    return found


def syllables(word: str) -> int:
    """Vowel groups, less a silent final -e and -ed (close to dictionary counts for plain English)."""
    w = word.lower().strip("'’")
    count = len(re.findall(r'[aeiouy]+', w))
    if w.endswith('e') and not w.endswith(('le', 'ee', 'ye')) and count > 1:
        count -= 1
    if w.endswith('ed') and not w.endswith(('ted', 'ded')) and count > 1:
        count -= 1
    return max(count, 1)


def grade(text: str) -> float:
    """Flesch-Kincaid grade level."""
    for name in OFFICIAL_NAMES:
        text = text.replace(name, 'Name')
    words = re.findall(r"[A-Za-z][A-Za-z'’-]*", text)
    sentences = max(1, len(re.findall(r'[.!?](?:\s|$)', text)))
    return 0.39 * len(words) / sentences + 11.8 * sum(map(syllables, words)) / len(words) - 15.59


STRINGS = interface_strings()
SENTENCES = [(where, text) for where, text in STRINGS if len(text.split()) >= 8]


def test_the_collector_finds_the_interface_text() -> None:
    assert len(STRINGS) > 120
    assert ('page.py', 'Intelligence workspace') in STRINGS
    sign_in = [text for where, text in STRINGS if where == 'login.html']
    assert 'Sign in to your private intelligence workspace.' in sign_in


def test_syllable_counter_matches_dictionary_counts() -> None:
    expected = {'the': 1, 'report': 2, 'evidence': 3, 'indicator': 4, 'changed': 1, 'sentence': 2, 'table': 2}
    assert {word: syllables(word) for word in expected} == expected


@pytest.mark.parametrize(('where', 'text'), SENTENCES, ids=[f'{w}:{t[:30]}' for w, t in SENTENCES])
def test_sentences_are_plain(where: str, text: str) -> None:
    assert grade(text) <= MAX_GRADE, f'{where}: grade {grade(text):.1f}, rewrite in shorter, plainer words'


def test_the_interface_as_a_whole_reads_at_about_age_12() -> None:
    corpus = ' '.join(
        text if text.rstrip().endswith(('.', '?', '!')) else text + '.' for _, text in SENTENCES
    )
    assert grade(corpus) <= MAX_OVERALL_GRADE


@pytest.mark.parametrize(('where', 'text'), STRINGS, ids=[f'{w}:{t[:30]}' for w, t in STRINGS])
def test_no_all_caps_labels(where: str, text: str) -> None:
    """Capitals slow reading down, especially for people with dyslexia (BDA style guide). Codes are fine."""
    words = [w for w in re.findall(r'[A-Za-z]{3,}', text) if w not in TLP_LEVELS]
    shouting = [w for w in words if w.isupper()]
    assert len(shouting) < 2 or len(shouting) < len(words) / 2, f'{where}: {text!r} is in capitals'


def abbreviations(text: str) -> set[str]:
    found = set(re.findall(r'\b(?:SHA-\d+|MD5|[A-Z]{2,})(?=s?\b)', text))
    return found - set(TLP_LEVELS) - {'STRICT', 'X', 'XX', 'XXX'}


def test_every_abbreviation_in_the_interface_is_explained_in_the_glossary() -> None:
    terms = ' '.join(term for term, _ in GLOSSARY)
    used = set().union(*(abbreviations(text) for where, text in STRINGS if where != 'glossary.py'))
    assert {'TLP', 'IOC', 'CVE', 'KEV', 'JSON'} <= used, 'the collector should see the common ones'
    assert sorted(used - abbreviations(terms)) == []


def test_every_glossary_explanation_is_plain() -> None:
    assert len(GLOSSARY) >= 25
    for term, text in GLOSSARY:
        if len(text.split()) >= 8:  # the formula is noise on a few words
            assert grade(text) <= MAX_GRADE, f'{term}: grade {grade(text):.1f}'


def test_every_ingest_field_has_a_plain_error_message() -> None:
    """Regression: errors read ``title: String should have at least 1 character``."""
    assert set(FIELD_HELP) == set(DocumentInput.model_fields)
    for message in FIELD_HELP.values():
        assert '_' not in message, 'never an internal field name'
        assert 'String should' not in message, "never the validation library's wording"
        assert message.endswith('.')
        assert grade(message) <= MAX_GRADE


def test_messages_stay_until_dismissed_and_replace_each_other(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: messages, errors included, disappeared after about five seconds (WCAG 2.2.1, 2.2.3)."""
    shown: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(ui, 'notify', lambda message, **options: shown.append((message, options)))
    messages.tell('Saved.', 'success')
    messages.tell('Check the title.', 'warning')
    messages.tell('Sync failed.', 'error')
    for _, options in shown:
        assert options['timeout'] == 0, 'no time limit'
        assert options['close_button'] == 'Dismiss'
        assert options['group'] == messages.GROUP, 'a new message replaces the last, so they never pile up'
        assert options['multi_line'] is True
    assert [options.get('type') for _, options in shown] == [None, 'warning', 'negative']
    assert shown[2][1]['classes'] == 'insight-notice insight-notice--error'

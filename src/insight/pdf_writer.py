"""A small PDF 1.7 writer for Insight's own documents, with no dependencies (ADR 0036).

- US Letter pages; the TLP label in the header and the footer of every page, in 12-point bold type, aligned
  right, in the label's colour on black, as TLP 2.0 asks of documents; page numbers in the footer.
- The standard Helvetica fonts, which every PDF reader has, so nothing is embedded. Text is in Windows-1252
  and measured with the widths in Adobe's Core 14 font metrics (``Helvetica.afm`` and ``Helvetica-Bold.afm``,
  1997). A character outside Windows-1252 prints as ``?``: check with :func:`printable`.
- A tagged structure (headings, paragraphs and lists), the document's language and a bookmark per section,
  for screen readers and navigation. The header and footer are marked as page furniture.
- Compressed page contents, and the same bytes every time for the same blocks, title and date.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

PAGE_WIDTH: Final = 612
PAGE_HEIGHT: Final = 792
MARGIN: Final = 54
WIDTH: Final = PAGE_WIDTH - 2 * MARGIN
TOP: Final = 716  # the first baseline on a page
BOTTOM: Final = 66  # the lowest baseline on a page
HEADER_BOX: Final = 744
FOOTER_BOX: Final = 30
LABEL_SIZE: Final = 12  # TLP 2.0: 12-point type or greater
REGULAR: Final = 'F1'
BOLD: Final = 'F2'

#: TLP 2.0 label colours (RGB), shown on black.
TLP_COLOURS: Final = {
    'RED': (255, 43, 43),
    'AMBER+STRICT': (255, 192, 0),
    'AMBER': (255, 192, 0),
    'GREEN': (51, 255, 0),
    'CLEAR': (255, 255, 255),
}

# Advance widths in thousandths of an em of Windows-1252 characters 32 to 255, two base-32 digits
# each, from Adobe's Core 14 metrics.
_HELVETICA: Final = (
    '8m8mb3hchcrpkr5vadadc5i88mad8m8mhchchchchchchchchchc8m8mi8i8i8hcvnkrkrmimikrj3oami8mfkkrhcq1mioa'
    'kroamikrj3mikrtgkrkrj38m8m8melhcadhchcfkhchc8mhchc6u6ufk6uq1hchchchcadfk8mhcfkmifkfkfkae84aei800'
    'hc8m6uhcadv8hchcadv8kradv88mj38m8m6u6uadadauhcv8adv8fkadtg8mfkkr8madhchchchc84hcadn1bihci8adn1ad'
    'cgi8adadadhcgp8madadbdhcq2q2q2j3krkrkrkrkrkrv8mikrkrkrkr8m8m8m8mmimioaoaoaoaoai8oamimimimikrkrj3'
    'hchchchchchcrpfkhchchchc8m8m8m8mhchchchchchchci8j3hchchchcfkhcfk'
)
_HELVETICA_BOLD: Final = (
    '8madeqhchcrpmi7eadadc5i88mad8m8mhchchchchchchchchchcadadi8i8i8j3ufmimimimikrj3oami8mhcmij3q1mioa'
    'kroamikrj3mikrtgkrkrj3ad8madi8hcadhcj3hcj3hcadj3j38m8mhc8mrpj3j3j3j3c5hcadj3hcoahchcfkc58oc5i800'
    'hc8m8mhcfkv8hchcadv8kradv88mj38m8m8m8mfkfkauhcv8adv8hcadtg8mfkkr8madhchchchc8ohcadn1bihci8adn1ad'
    'cgi8adadadj3hc8madadbdhcq2q2q2j3mimimimimimiv8mikrkrkrkr8m8m8m8mmimioaoaoaoaoai8oamimimimikrkrj3'
    'hchchchchchcrphchchchchc8m8m8m8mj3j3j3j3j3j3j3i8j3j3j3j3j3hcj3hc'
)


def _decode(table: str) -> list[int]:
    return [int(table[i : i + 2], 32) for i in range(0, len(table), 2)]


WIDTHS: Final = {REGULAR: _decode(_HELVETICA), BOLD: _decode(_HELVETICA_BOLD)}

Run = tuple[str, str]  # a font and some text


def _clean(text: str) -> str:
    """Composed characters, no control or invisible format characters, and single spaces."""
    text = unicodedata.normalize('NFC', text)
    text = ''.join(c for c in text if c.isspace() or unicodedata.category(c) not in ('Cc', 'Cf'))
    return re.sub(r'\s+', ' ', text)


def _encode(text: str) -> bytes:
    return text.encode('cp1252', errors='replace')


def printable(text: str) -> bool:
    """Whether every character of ``text`` prints, rather than as ``?``."""
    try:
        _clean(text).encode('cp1252')
    except UnicodeEncodeError:
        return False
    return True


def width_of(text: str, font: str, size: float) -> float:
    table = WIDTHS[font]
    return sum(table[code - 32] for code in _encode(_clean(text)) if code >= 32) * size / 1000


def _append(line: list[Run], font: str, text: str) -> None:
    if line and line[-1][0] == font:
        line[-1] = (font, line[-1][1] + text)
    else:
        line.append((font, text))


def _words(runs: list[Run]) -> list[list[Run]]:
    """The words of ``runs``; a word can change font where no space separates two runs."""
    words: list[list[Run]] = []
    joined = False
    for font, text in runs:
        for part in re.split('( )', _clean(text)):
            if part == ' ':
                joined = False
            elif part:
                if joined and words:
                    _append(words[-1], font, part)
                else:
                    words.append([(font, part)])
                joined = True
    return words


def wrap(runs: list[Run], size: float, width: float) -> list[list[Run]]:
    """Lines of runs no wider than ``width``. A word wider than a line is cut between characters."""
    space = width_of(' ', REGULAR, size)
    lines: list[list[Run]] = []
    line: list[Run] = []
    used = 0.0
    for word in _words(runs):
        wide = sum(width_of(text, font, size) for font, text in word)
        if line and used + space + wide <= width:
            _append(line, word[0][0], ' ')
            used += space
        elif line:
            lines.append(line)
            line, used = [], 0.0
        if wide <= width:
            for font, text in word:
                _append(line, font, text)
            used += wide
            continue
        for font, text in word:
            for char in text:
                step = width_of(char, font, size)
                if line and used + step > width:
                    lines.append(line)
                    line, used = [], 0.0
                _append(line, font, char)
                used += step
    if line or not lines:
        lines.append(line)
    return lines


@dataclass(slots=True)
class Block:
    """A heading (``H1``, ``H2``), a paragraph (``P``) or a list item (``LI``)."""

    tag: str
    runs: list[Run]
    size: float = 10.5
    leading: float = 14.5
    before: float = 6.0
    label: str = ''  # a list item's number or bullet, in its hanging indent
    indent: float = 0.0
    grey: bool = False
    group: int = 0  # the items of one list share it


def paragraph(text: str, **style: Any) -> Block:
    return Block('P', [(REGULAR, text)], **style)


def heading(text: str) -> Block:
    """A section heading, which also gets a bookmark."""
    return Block('H2', [(BOLD, text)], size=13, leading=18, before=14)


def items(entries: list[tuple[str, list[Run]]], group: int) -> list[Block]:
    """One list: each entry is a label and its text. ``group`` tells it apart from the list before it."""
    indent = max([18.0] + [width_of(label, REGULAR, 10.5) + 8 for label, _ in entries])
    return [Block('LI', runs, before=4, label=label, indent=indent, group=group) for label, runs in entries]


def _num(value: float) -> bytes:
    return (f'{value:.3f}'.rstrip('0').rstrip('.') or '0').encode()


def _string(text: str) -> bytes:
    raw = _encode(_clean(text))
    return b'(' + raw.replace(b'\\', b'\\\\').replace(b'(', b'\\(').replace(b')', b'\\)') + b')'


def _unicode(text: str) -> bytes:
    return b'<FEFF' + _clean(text).encode('utf-16-be').hex().upper().encode() + b'>'


def _date(value: Any) -> bytes:
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        return b'D:19700101000000Z'
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime('D:%Y%m%d%H%M%SZ').encode()


@dataclass(slots=True)
class _Element:
    tag: str
    parent: int  # -1 is the structure tree root
    kids: list[int | tuple[int, int]] = field(default_factory=list)  # elements, or (page, marked content)


@dataclass(slots=True)
class _Page:
    ops: list[bytes] = field(default_factory=list)
    owners: list[int] = field(default_factory=list)  # the element each marked-content ID belongs to


class _Layout:
    def __init__(self) -> None:
        self.pages = [_Page()]
        self.elements = [_Element('Document', -1)]
        self.bookmarks: list[tuple[str, int, float]] = []
        self.y = float(TOP)
        self.list: tuple[int, int] | None = None  # (group, element) of the list being placed

    def _element(self, tag: str, parent: int) -> int:
        self.elements.append(_Element(tag, parent))
        self.elements[parent].kids.append(len(self.elements) - 1)
        return len(self.elements) - 1

    def _owner(self, block: Block) -> int:
        if block.tag != 'LI':
            self.list = None
            return self._element(block.tag, 0)
        if self.list is None or self.list[0] != block.group:
            self.list = (block.group, self._element('L', 0))
        return self._element('LBody', self._element('LI', self.list[1]))

    def _mark(self, owner: int) -> None:
        page = self.pages[-1]
        self.elements[owner].kids.append((len(self.pages) - 1, len(page.owners)))
        page.ops.append(b'/%s <</MCID %d>> BDC' % (self.elements[owner].tag.encode(), len(page.owners)))
        page.owners.append(owner)

    def place(self, block: Block) -> None:
        owner = self._owner(block)
        lines = wrap(block.runs, block.size, WIDTH - block.indent)
        if self.y < TOP:
            self.y -= block.before
        if block.tag == 'H2' and self.y - block.leading - 2 * 14.5 < BOTTOM:  # keep it with what follows
            self.pages.append(_Page())
            self.y = float(TOP)
        if block.tag == 'H2':
            self.bookmarks.append((block.runs[0][1], len(self.pages) - 1, self.y + block.size))
        self._mark(owner)
        for number, line in enumerate(lines):
            if self.y < BOTTOM:
                self.pages[-1].ops.append(b'EMC')
                self.pages.append(_Page())
                self.y = float(TOP)
                self._mark(owner)
            ops = [b'0.33 g' if block.grey else b'0 g', b'BT', b'%s %s Td' % (_num(MARGIN), _num(self.y))]
            if number == 0 and block.label:
                ops.append(b'/F1 %s Tf %s Tj' % (_num(block.size), _string(block.label)))
            if block.indent:
                ops.append(b'%s 0 Td' % _num(block.indent))
            ops += [
                b'/%s %s Tf %s Tj' % (font.encode(), _num(block.size), _string(text)) for font, text in line
            ]
            self.pages[-1].ops.append(b' '.join([*ops, b'ET']))
            self.y -= block.leading
        self.pages[-1].ops.append(b'EMC')


def _fit(text: str, font: str, size: float, width: float) -> str:
    if width_of(text, font, size) <= width:
        return text
    while text and width_of(text + '…', font, size) > width:
        text = text[:-1]
    return text.rstrip() + '…'


def _furniture(number: int, total: int, tlp: str, title: str) -> bytes:
    """The header and footer of one page, marked as page furniture rather than content."""
    label = f'TLP:{tlp}'
    box = width_of(label, BOLD, LABEL_SIZE) + 12
    x = PAGE_WIDTH - MARGIN - box
    colour = b' '.join(_num(c / 255) for c in TLP_COLOURS.get(tlp, TLP_COLOURS['CLEAR']))
    ops = []
    for kind, y, text in (('Header', HEADER_BOX, title), ('Footer', FOOTER_BOX, f'Page {number} of {total}')):
        ops += [
            b'/Artifact <</Type /Pagination /Subtype /%s>> BDC' % kind.encode(),
            b'0 g %s %s %s 18 re f' % (_num(x), _num(y), _num(box)),
            b'%s rg BT /F2 %d Tf %s %s Td %s Tj ET'
            % (colour, LABEL_SIZE, _num(x + 6), _num(y + 5), _string(label)),
            b'0.33 g BT /F1 9 Tf %s %s Td %s Tj ET' % (_num(MARGIN), _num(y + 5), _string(text)),
            b'EMC',
        ]
    return b'\n'.join(ops)


def _font(name: bytes, font: str) -> bytes:
    widths = b' '.join(b'%d' % w for w in WIDTHS[font])
    return (
        b'<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding /FirstChar 32 '
        b'/LastChar 255 /Widths [%s] >>' % (name, widths)
    )


def _assemble(objects: list[bytes]) -> bytes:
    """``objects[i]`` is object ``i + 1``: 1 is the catalog and 5 the document information."""
    out = bytearray(b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n')
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b'%d 0 obj\n%s\nendobj\n' % (number, body)
    start = len(out)
    out += b'xref\n0 %d\n0000000000 65535 f \n' % (len(objects) + 1)
    out += b''.join(b'%010d 00000 n \n' % offset for offset in offsets)
    digest = hashlib.sha256(bytes(out)).hexdigest()[:32].upper().encode()
    trailer = b'trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R /ID [<%s> <%s>] >>\nstartxref\n%d\n%%%%EOF\n'
    return bytes(out + trailer % (len(objects) + 1, digest, digest, start))


def render(blocks: list[Block], *, title: str, subject: str, tlp: str, when: Any) -> bytes:
    """The PDF of ``blocks``. ``when`` (an ISO 8601 time) is its creation date; ``tlp`` labels every page."""
    layout = _Layout()
    for block in blocks:
        layout.place(block)
    total = len(layout.pages)
    first_element = 8
    first_bookmark = first_element + len(layout.elements)
    first_page = first_bookmark + len(layout.bookmarks)

    def page(index: int) -> int:
        return first_page + 2 * index

    def ref(element: int) -> bytes:
        return b'%d 0 R' % (first_element + element)

    date = _date(when)
    parents = b' '.join(b'%d [%s]' % (i, b' '.join(map(ref, p.owners))) for i, p in enumerate(layout.pages))
    objects = [
        b'<< /Type /Catalog /Pages 2 0 R /Lang (en-US) /MarkInfo << /Marked true >> /StructTreeRoot 6 0 R '
        b'/Outlines 7 0 R /ViewerPreferences << /DisplayDocTitle true >> >>',
        b'<< /Type /Pages /Kids [%s] /Count %d >>'
        % (b' '.join(b'%d 0 R' % page(i) for i in range(total)), total),
        _font(b'Helvetica', REGULAR),
        _font(b'Helvetica-Bold', BOLD),
        b'<< /Title %s /Subject %s /Creator (Insight) /CreationDate (%s) /ModDate (%s) >>'
        % (_unicode(title), _unicode(subject), date, date),
        b'<< /Type /StructTreeRoot /K %s /ParentTree << /Nums [%s] >> /ParentTreeNextKey %d >>'
        % (ref(0), parents, total),
        b'<< /Type /Outlines /First %d 0 R /Last %d 0 R /Count %d >>'
        % (first_bookmark, first_page - 1, len(layout.bookmarks))
        if layout.bookmarks
        else b'<< /Type /Outlines /Count 0 >>',
    ]
    for element in layout.elements:
        kids = [
            ref(kid)
            if isinstance(kid, int)
            else b'<< /Type /MCR /Pg %d 0 R /MCID %d >>' % (page(kid[0]), kid[1])
            for kid in element.kids
        ]
        parent = b'6 0 R' if element.parent < 0 else ref(element.parent)
        objects.append(
            b'<< /Type /StructElem /S /%s /P %s /K [%s] >>' % (element.tag.encode(), parent, b' '.join(kids))
        )
    count = len(layout.bookmarks)
    for i, (name, index, y) in enumerate(layout.bookmarks):
        siblings = (b' /Prev %d 0 R' % (first_bookmark + i - 1) if i else b'') + (
            b' /Next %d 0 R' % (first_bookmark + i + 1) if i < count - 1 else b''
        )
        objects.append(
            b'<< /Title %s /Parent 7 0 R%s /Dest [%d 0 R /XYZ null %s null] >>'
            % (_unicode(name), siblings, page(index), _num(y))
        )
    header = _fit(title, REGULAR, 9, WIDTH - width_of(f'TLP:{tlp}', BOLD, LABEL_SIZE) - 24)
    for i, contents in enumerate(layout.pages):
        stream = zlib.compress(_furniture(i + 1, total, tlp, header) + b'\n' + b'\n'.join(contents.ops), 9)
        objects.append(
            b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 3 0 R /F2 4 0 R '
            b'>> >> /Contents %d 0 R /StructParents %d /Tabs /S >>'
            % (PAGE_WIDTH, PAGE_HEIGHT, page(i) + 1, i)
        )
        objects.append(
            b'<< /Length %d /Filter /FlateDecode >>\nstream\n%s\nendstream' % (len(stream), stream)
        )
    return _assemble(objects)

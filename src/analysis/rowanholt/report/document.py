"""A report as a list of blocks, written out as Markdown or as DOCX.

The DOCX is WordprocessingML written with the stdlib (zipfile and escaped XML): headings, paragraphs
with bold, italic and code runs, bullet lists, quotes and tables, on A4 with table widths in DXA.
"""

import io
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Sequence, Tuple, Union
from xml.sax.saxutils import escape

Run = Tuple[str, str]  # (text, style): "", "b", "i", "code", or "raw" (Markdown as written, plain in DOCX)
Text = Union[str, Sequence[Run]]


@dataclass
class Heading:
    level: int
    text: str


@dataclass
class Para:
    runs: Text


@dataclass
class Bullets:
    items: List[Text]


@dataclass
class Quote:
    text: str


@dataclass
class Table:
    headers: List[str]
    rows: List[List[Text]]
    weights: List[int] = field(default_factory=list)  # relative column widths


Block = Union[Heading, Para, Bullets, Quote, Table]


def runs(text: Text) -> List[Run]:
    return [(text, "")] if isinstance(text, str) else list(text)


def plain(text: Text) -> str:
    return "".join(t for t, _ in runs(text))


def shifted(blocks: List[Block], by: int) -> List[Block]:
    """The blocks with every heading ``by`` levels down (a report inside another, as an appendix)."""
    return [Heading(min(b.level + by, 6), b.text) if isinstance(b, Heading) else b for b in blocks]


# ---- Markdown ----

def _md_inline(text: Text, in_table: bool = False) -> str:
    out = []
    for value, style in runs(text):
        if style == "raw" and not in_table:  # an analyst's own Markdown (a note)
            out.append(value)
            continue
        if in_table:
            value = " ".join(value.splitlines())
        if style == "code":
            fence = "``" if "`" in value else "`"
            pad = " " if value.startswith("`") or value.endswith("`") else ""
            value = f"{fence}{pad}{value}{pad}{fence}" if value else ""
        else:
            value = re.sub(r"([\\`*_\[\]<>])", r"\\\1", value)  # evidence is text, never markup
            value = f"**{value}**" if style == "b" and value else f"*{value}*" if style == "i" and value else value
        # A table cell ends at a pipe, inside a code span too (GitHub's tables)
        out.append(value.replace("|", "\\|") if in_table else value)
    return "".join(out)


def markdown(blocks: List[Block]) -> str:
    lines: List[str] = []
    for block in blocks:
        if isinstance(block, Heading):
            lines += ["#" * block.level + " " + _md_inline(block.text), ""]
        elif isinstance(block, Para):
            lines += [_md_inline(block.runs), ""]
        elif isinstance(block, Bullets):
            lines += [f"- {_md_inline(item)}" for item in block.items] + [""]
        elif isinstance(block, Quote):
            lines += ["> " + line if line else ">" for line in block.text.splitlines() or [""]]
            lines.append("")
        elif isinstance(block, Table):
            lines.append("| " + " | ".join(_md_inline(h, True) for h in block.headers) + " |")
            lines.append("|" + "|".join("---" for _ in block.headers) + "|")
            for row in block.rows:
                lines.append("| " + " | ".join(_md_inline(c, True) for c in row) + " |")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---- DOCX ----

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
TEXT_WIDTH = 9026  # A4 (11906 twips) less 2.5 cm margins, in DXA
_INVALID_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")


def _xml_text(value: str) -> str:
    return escape(_INVALID_XML.sub("�", value))


def _w_runs(text: Text, table: bool = False) -> str:
    out = []
    for value, style in runs(text):
        props = {"b": "<w:b/>", "i": "<w:i/>", "code": '<w:rStyle w:val="CodeChar"/>'}.get(style, "")
        if table:
            props += '<w:sz w:val="16"/>'
        rpr = f"<w:rPr>{props}</w:rPr>" if props else ""
        pieces = value.split("\n")
        body = "<w:br/>".join(f'<w:t xml:space="preserve">{_xml_text(p)}</w:t>' for p in pieces)
        out.append(f"<w:r>{rpr}{body}</w:r>")
    return "".join(out)


def _w_para(text: Text, style: str = "", extra: str = "", table: bool = False) -> str:
    ppr = (f'<w:pStyle w:val="{style}"/>' if style else "") + extra
    return f"<w:p>{f'<w:pPr>{ppr}</w:pPr>' if ppr else ''}{_w_runs(text, table)}</w:p>"


def _widths(table: Table) -> List[int]:
    weights = table.weights if len(table.weights) == len(table.headers) else [1] * len(table.headers)
    total = sum(weights)
    widths = [TEXT_WIDTH * w // total for w in weights]
    widths[-1] += TEXT_WIDTH - sum(widths)
    return widths


def _w_table(table: Table) -> str:
    widths = _widths(table)
    border = "".join(f'<w:{side} w:val="single" w:sz="4" w:space="0" w:color="A6A6A6"/>'
                     for side in ("top", "left", "bottom", "right", "insideH", "insideV"))
    # CT_TblPr's order: width, borders, layout, cell margins
    out = [f'<w:tbl><w:tblPr><w:tblW w:w="{TEXT_WIDTH}" w:type="dxa"/><w:tblBorders>{border}</w:tblBorders>'
           '<w:tblLayout w:type="fixed"/>'
           '<w:tblCellMar><w:left w:w="80" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr>',
           "<w:tblGrid>" + "".join(f'<w:gridCol w:w="{w}"/>' for w in widths) + "</w:tblGrid>"]

    def row(cells: Sequence[Text], header: bool) -> str:
        trpr = "<w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>" if header else "<w:trPr><w:cantSplit/></w:trPr>"
        shade = '<w:shd w:val="clear" w:color="auto" w:fill="D5E3E8"/>' if header else ""
        tcs = []
        for width, cell in zip(widths, list(cells) + [""] * (len(widths) - len(cells))):
            content = [(t, "b") for t, _ in runs(cell)] if header else cell
            tcs.append(f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/>{shade}</w:tcPr>'
                       f'{_w_para(content, "TableText", table=True)}</w:tc>')
        return f"<w:tr>{trpr}{''.join(tcs)}</w:tr>"

    out.append(row(table.headers, True))
    out += [row(cells, False) for cells in table.rows]
    out.append("</w:tbl>")
    return "".join(out)


def _w_body(blocks: List[Block]) -> str:
    out = []
    for block in blocks:
        if isinstance(block, Heading):
            out.append(_w_para(block.text, "Title" if block.level == 1 else f"Heading{min(block.level - 1, 3)}"))
        elif isinstance(block, Para):
            out.append(_w_para(block.runs))
        elif isinstance(block, Bullets):
            numbering = '<w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr>'
            out += [_w_para(item, "ListBullet", numbering) for item in block.items]
        elif isinstance(block, Quote):
            out.append(_w_para(block.text, "Quote"))
        elif isinstance(block, Table):
            out.append(_w_table(block))
            out.append(_w_para("", extra='<w:spacing w:after="0"/>'))
    return "".join(out)


_STYLES = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="{W}">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri"/>
<w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-GB"/></w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>
<w:pPr><w:spacing w:after="240"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="17365D"/><w:sz w:val="40"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>
<w:pPr><w:keepNext/><w:spacing w:before="360" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="17365D"/><w:sz w:val="30"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>
<w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:color w:val="1F6F78"/><w:sz w:val="25"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>
<w:pPr><w:keepNext/><w:spacing w:before="200" w:after="60"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:sz w:val="22"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="ListBullet"><w:name w:val="List Bullet"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:after="40"/><w:ind w:left="360" w:hanging="360"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Quote"><w:name w:val="Quote"/><w:basedOn w:val="Normal"/>
<w:pPr><w:pBdr><w:left w:val="single" w:sz="12" w:space="8" w:color="1F6F78"/></w:pBdr><w:ind w:left="567"/></w:pPr><w:rPr><w:i/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn w:val="Normal"/>
<w:pPr><w:spacing w:before="20" w:after="20" w:line="240" w:lineRule="auto"/></w:pPr><w:rPr><w:sz w:val="16"/></w:rPr></w:style>
<w:style w:type="character" w:styleId="CodeChar"><w:name w:val="Code"/>
<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="18"/></w:rPr></w:style>
</w:styles>"""

_NUMBERING = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:numbering xmlns:w="{W}">
<w:abstractNum w:abstractNumId="0"><w:multiLevelType w:val="singleLevel"/>
<w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="•"/><w:lvlJc w:val="left"/>
<w:pPr><w:ind w:left="360" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum>
<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>
</w:numbering>"""

_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"""

_DOCUMENT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>
</Relationships>"""

_APP = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Rowanholt</Application></Properties>"""


def docx(blocks: List[Block], title: str) -> bytes:
    """The blocks as a .docx file's bytes."""
    document = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:document xmlns:w="{W}" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>'
                f"{_w_body(blocks)}"
                '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1418" w:right="1440" w:bottom="1418" '
                'w:left="1440" w:header="709" w:footer="709" w:gutter="0"/></w:sectPr></w:body></w:document>')
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<cp:coreProperties '
            'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f"<dc:title>{_xml_text(title)}</dc:title><dc:creator>Rowanholt (Elrond)</dc:creator>"
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified></cp:coreProperties>')
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _CONTENT_TYPES)
        archive.writestr("_rels/.rels", _RELS)
        archive.writestr("word/_rels/document.xml.rels", _DOCUMENT_RELS)
        archive.writestr("word/document.xml", document)
        archive.writestr("word/styles.xml", _STYLES)
        archive.writestr("word/numbering.xml", _NUMBERING)
        archive.writestr("docProps/core.xml", core)
        archive.writestr("docProps/app.xml", _APP)
    return buffer.getvalue()

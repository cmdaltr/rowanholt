"""
What Aulë's model is given about a case, with every row numbered so its answer can cite them.

The context is the analysts' confirmed findings, the hosts, the tagged ATT&CK techniques, the rows
Aulë's offline answers rest on (flagged persistence, suspicious commands, staging, detections,
Elrond's analysis, threat intelligence, what's rare), and the rows of the hosts' cooked and analysis
tables that contain the question's words. Each row is tagged [R1], [R2]...; the model is asked to
cite the tags, and only a tag that was in the context maps back to a row (cited()), so a model
can't put a row in an answer that it wasn't given.
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

try:
    from . import case_files, aule_offline
except ImportError:  # main.py imports the routes as top-level modules too
    import case_files
    import aule_offline

logger = logging.getLogger(__name__)

MAX_CHARS = 15000
MAX_ROW_CHARS = 400
LEADS = ("persistence", "commands", "staging", "detections", "analysis", "threat_intel", "rare", "logins")
# Words too common in a question to say which rows it's about
STOPWORDS = {"what", "which", "when", "where", "were", "was", "who", "whom", "that", "this", "there", "their", "with",
             "from", "have", "has", "had", "does", "did", "the", "and", "any", "anything", "case", "host", "hosts",
             "show", "find", "about", "look", "like", "into", "been", "they", "them", "than", "then", "also", "some",
             "tell", "list", "give", "happened", "happen", "evidence", "suspicious"}
MAX_TERMS = 5
MAX_FILE_BYTES = 32 << 20  # tables searched for the question's words; bigger ones are left to the case browser
MAX_MATCHES = 25
MAX_MATCHES_PER_FILE = 3
SAID = {"host", "artefact", "source_path"}  # envelope fields the line already gives
EMPTY = {"[]", "null", "{}"}
# A cited tag, [R3], or several in one bracket, as models write them: [R2, R3], [R2–R5], [R2-R5, R8]
TAG_ITEM = r"R\d+(?:\s*[-–—]\s*R?\d+)?"
TAG = re.compile(rf"\[\s*({TAG_ITEM}(?:\s*[,;]\s*{TAG_ITEM})*)\s*\]")
TAG_RANGE = re.compile(r"R(\d+)(?:\s*[-–—]\s*R?(\d+))?")
MAX_RANGE = 25  # a wider range is a gesture at the whole context, not a citation

CITE_INSTRUCTIONS = (
    "Rows in the case data are tagged [R1], [R2] and so on. When a statement rests on a row, cite its tag "
    "in square brackets right after the statement, for example [R3], or [R3][R4] for two; never a range. "
    "Cite only tags that appear in the "
    "case data; never invent one. If the case data doesn't answer the question, say so.")


def terms(question: str) -> List[str]:
    """The question's words worth searching the tables for: the longest first."""
    words = {w.lower() for w in re.findall(r"[\w.\-:/\\]{4,}", question)}
    return sorted((w for w in words if w not in STOPWORDS), key=lambda w: (-len(w), w))[:MAX_TERMS]


class Context:
    """The numbered rows given to the model, and the text it reads."""

    def __init__(self) -> None:
        self.rows: Dict[str, Dict[str, str]] = {}
        self._seen: Dict[Tuple[str, str, str], str] = {}
        self.parts: List[str] = []
        self.shown = ""

    def tag(self, row: Dict[str, str]) -> str:
        """The tag for a cited row (host, file, row_ref, hash, line), the same tag for the same row."""
        key = (row["host"], row["file"], row["row_ref"])
        if key not in self._seen:
            tag = f"R{len(self.rows) + 1}"
            self._seen[key] = tag
            self.rows[tag] = row
        return self._seen[key]

    def text(self) -> str:
        """What the model reads: cut at MAX_CHARS, and only the tags left in it can be cited."""
        self.shown = "\n\n".join(self.parts)[:MAX_CHARS]
        return self.shown


def _searched(root: Path, words: List[str], context: Context) -> List[str]:
    """Lines for the rows of the hosts' tables that contain one of the words."""
    lines: List[str] = []
    for host in case_files.hosts(root):
        for folder in (host / "artefacts" / "cooked", host / "analysis"):
            for path in sorted(p for p in folder.rglob("*") if p.suffix.lower() in case_files.ROW_FILES and p.is_file()) \
                    if folder.is_dir() else []:
                if len(lines) >= MAX_MATCHES:
                    return lines
                try:
                    if path.stat().st_size > MAX_FILE_BYTES:
                        continue
                    hits = 0
                    for ref, row in case_files.records(path):
                        cells = " ".join(v or "" for v in row.values()).lower()
                        if not any(w in cells for w in words):
                            continue
                        compact = json.dumps({k: v for k, v in row.items() if v and v not in EMPTY and k not in SAID},
                                             ensure_ascii=False)[:MAX_ROW_CHARS]
                        file = str(path.relative_to(host))
                        tag = context.tag({"host": host.name, "file": file, "row_ref": ref,
                                           "hash": case_files.row_hash(row), "line": f"{path.stem}: {compact}"})
                        lines.append(f"[{tag}] {host.name} {file} row {ref}: {compact}")
                        hits += 1
                        if hits >= MAX_MATCHES_PER_FILE or len(lines) >= MAX_MATCHES:
                            break
                except (OSError, ValueError, case_files.CaseFileError) as e:
                    logger.debug(f"Couldn't search {path}: {e}")
    return lines


def build(case_path: str, question: str = "", findings: Optional[List[Dict]] = None) -> Context:
    """The context for one question about the case at case_path."""
    context = Context()
    confirmed = [f for f in findings or [] if f.get("status") == "confirmed"]
    if confirmed:
        context.parts.append("## Confirmed findings (analysts)\n" + "\n".join(
            f"- {f['title']} ({f.get('technique') or 'no technique'}): {f['host']} {f['artefact']} row {f['row_ref']}: "
            f"{(f.get('excerpt') or '')[:300]}" for f in confirmed[:30]))
    context.parts.append(aule_offline.hosts(case_path))
    context.parts.append(aule_offline.techniques(case_path))

    # The question's own rows first: they're what it's about
    words = terms(question)
    if words:
        lines = _searched(Path(case_path), words, context)
        if lines:
            context.parts.append(f"## Rows containing {', '.join(words)}\n" + "\n".join(lines))

    for question_id in LEADS:
        answer = aule_offline.answer_with_rows(question_id, case_path)
        lines = [f"[{context.tag(row)}] {row['host']} {row['file']} row {row['row_ref']}: {row['line']}"
                 for row in answer["rows"]]
        if lines:
            title = aule_offline.CASE_QUESTIONS[question_id]["question"]
            context.parts.append(f"## {title}\n" + "\n".join(lines))
    return context


def _tag_numbers(answer: str) -> Iterator[str]:
    """Each tag number the answer cites, ranges spelt out (R2–R5 is R2, R3, R4, R5)."""
    for group in TAG.findall(answer):
        for first, last in TAG_RANGE.findall(group):
            start, end = int(first), int(last or first)
            if start <= end <= start + MAX_RANGE:
                yield from (str(n) for n in range(start, end + 1))


def cited(answer: str, context: Context) -> List[Dict[str, str]]:
    """The rows the answer cites by tag, in the order it first cites them; tags it wasn't shown are dropped."""
    out: List[Dict[str, str]] = []
    for number in dict.fromkeys(_tag_numbers(answer)):
        row = context.rows.get(f"R{number}")
        if row and f"[R{number}]" in context.shown:
            out.append({**row, "tag": f"R{number}"})
    return out

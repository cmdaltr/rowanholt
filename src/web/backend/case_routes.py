"""The case browser and collaboration: a case's tables, findings flagged on their rows, notes,
host assignments, an activity feed, and a report and Navigator layer from confirmed findings.

Every route is under /api/jobs/{job_id}/, so auth/access.py's job check covers it in server
mode: whoever can see the job can browse, flag and note. The one websocket, /live, isn't seen by
that middleware, so it checks with access.websocket_user itself. Nothing writes to the case directory;
findings, notes and activity live in Postgres and reference rows by file, row and hash.
"""

import asyncio
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

try:
    from . import case_files
    from .auth import access
    from .auth.users import find_user, load_users
    from .storage import CaseActivityModel, CaseFindingModel, CaseHostModel, CaseNoteModel
except ImportError:
    import case_files
    from auth import access
    from auth.users import find_user, load_users
    from storage import CaseActivityModel, CaseFindingModel, CaseHostModel, CaseNoteModel

router = APIRouter(prefix="/api/jobs/{job_id}/case", tags=["Case browser"])
logger = logging.getLogger(__name__)

STATUSES = ("lead", "confirmed", "benign")
HOST_STATUSES = ("to do", "in progress", "done")
TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
EXCERPT = 600
LIVE_EVERY = 2.0  # seconds between the live socket's checks
# Eru's MCP server (src/eru_mcp) sends this on every call, so what it writes reads as Eru's, on the
# analyst's behalf, and never passes for the analyst's own work
AGENT_HEADER = "X-Rowanholt-Agent"
# What an MCP server from before the rename sends: still Eru, never the analyst
OLD_AGENT_HEADER = "X-Rivendell-Agent"
ERU_MCP = "eru-mcp"


class Conflict(Exception):
    """A finding changed since the caller loaded it; carries its current state."""

    def __init__(self, current: Dict):
        super().__init__(f"finding #{current['id']} changed")
        self.current = current


class AlreadyFlagged(Exception):
    """Someone flagged the row first: carries their finding (two flags at the same moment)."""

    def __init__(self, finding: Dict):
        super().__init__("already flagged")
        self.finding = finding


class CaseStore:
    """Findings, notes, assignments and activity. Takes a SQLAlchemy session factory (JobStorage.Session)."""

    def __init__(self, session_factory):
        self.Session = session_factory

    def _log(self, session, job_id: str, actor: str, action: str, detail: str) -> None:
        session.add(CaseActivityModel(job_id=job_id, actor=actor, action=action, detail=detail[:1000],
                                      created_at=datetime.now()))

    @staticmethod
    def _finding(row: CaseFindingModel) -> Dict:
        return {"id": row.id, "host": row.host, "artefact": row.artefact, "row_ref": row.row_ref,
                "row_hash": row.row_hash, "excerpt": row.excerpt or "", "title": row.title,
                "technique": row.technique or "", "status": row.status, "author": row.author,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None}

    def findings(self, job_id: str, status: str = "") -> List[Dict]:
        with self.Session() as session:
            rows = session.query(CaseFindingModel).filter(CaseFindingModel.job_id == job_id)
            if status:
                rows = rows.filter(CaseFindingModel.status == status)
            return [self._finding(r) for r in rows.order_by(CaseFindingModel.id)]

    def count_findings(self, job_id: str) -> int:
        """How many findings the job has: a restart rewrites the rows they point at."""
        with self.Session() as session:
            return session.query(CaseFindingModel).filter(CaseFindingModel.job_id == job_id).count()

    def existing(self, job_id: str, host: str, artefact: str, row_ref: str) -> Optional[Dict]:
        """The finding already on this row, if anyone flagged it."""
        with self.Session() as session:
            row = session.query(CaseFindingModel).filter(
                CaseFindingModel.job_id == job_id, CaseFindingModel.host == host,
                CaseFindingModel.artefact == artefact, CaseFindingModel.row_ref == row_ref).first()
            return self._finding(row) if row else None

    def add_finding(self, job_id: str, actor: str, **fields) -> Dict:
        now = datetime.now()
        with self.Session() as session:
            row = CaseFindingModel(job_id=job_id, author=actor, created_at=now, updated_at=now, **fields)
            session.add(row)
            try:
                session.flush()
            except IntegrityError:
                # Flagged by someone else since existing() looked (uq_case_findings_row)
                session.rollback()
                raise AlreadyFlagged(self.existing(job_id, fields["host"], fields["artefact"], fields["row_ref"]))
            self._log(session, job_id, actor, "flagged",
                      f"#{row.id} {row.title} ({row.host}: {row.artefact} row {row.row_ref})")
            session.commit()
            return self._finding(row)

    def update_finding(self, job_id: str, finding_id: int, actor: str, expected: Optional[str] = None,
                       **changes) -> Optional[Dict]:
        """None when there's no such finding; raises Conflict when `expected` (the updated_at the
        caller loaded) is no longer current, so two analysts can't silently overwrite each other."""
        with self.Session() as session:
            row = session.get(CaseFindingModel, finding_id)
            if not row or row.job_id != job_id:
                return None
            if expected and row.updated_at and row.updated_at.isoformat() != expected:
                raise Conflict(self._finding(row))
            for key, value in changes.items():
                if value is not None and getattr(row, key) != value:
                    setattr(row, key, value)
                    if key == "status":
                        self._log(session, job_id, actor, "marked", f"#{row.id} {row.title}: {value}")
                    else:
                        self._log(session, job_id, actor, "edited", f"#{row.id} {row.title}: {key}")
            row.updated_at = datetime.now()
            session.commit()
            return self._finding(row)

    def delete_finding(self, job_id: str, finding_id: int, actor: str) -> bool:
        with self.Session() as session:
            row = session.get(CaseFindingModel, finding_id)
            if not row or row.job_id != job_id:
                return False
            session.query(CaseNoteModel).filter(CaseNoteModel.finding_id == finding_id).delete()
            self._log(session, job_id, actor, "removed", f"#{row.id} {row.title}")
            session.delete(row)
            session.commit()
            return True

    def notes(self, job_id: str) -> List[Dict]:
        with self.Session() as session:
            return [{"id": n.id, "finding_id": n.finding_id, "author": n.author, "body": n.body,
                     "created_at": n.created_at.isoformat() if n.created_at else None}
                    for n in session.query(CaseNoteModel).filter(CaseNoteModel.job_id == job_id)
                    .order_by(CaseNoteModel.id)]

    def add_note(self, job_id: str, actor: str, body: str, finding_id: Optional[int]) -> Optional[Dict]:
        with self.Session() as session:
            if finding_id is not None:
                finding = session.get(CaseFindingModel, finding_id)
                if not finding or finding.job_id != job_id:
                    return None
            note = CaseNoteModel(job_id=job_id, finding_id=finding_id, author=actor, body=body,
                                 created_at=datetime.now())
            session.add(note)
            session.flush()
            self._log(session, job_id, actor, "noted", f"on #{finding_id}" if finding_id else "on the case")
            session.commit()
            return {"id": note.id, "finding_id": finding_id, "author": actor, "body": body,
                    "created_at": note.created_at.isoformat()}

    def assignments(self, job_id: str) -> Dict[str, Dict]:
        with self.Session() as session:
            return {h.host: {"assignee": h.assignee or "", "status": h.status, "updated_by": h.updated_by or "",
                             "updated_at": h.updated_at.isoformat() if h.updated_at else None}
                    for h in session.query(CaseHostModel).filter(CaseHostModel.job_id == job_id)}

    def assign(self, job_id: str, host: str, actor: str, assignee: Optional[str], status: Optional[str]) -> Dict:
        with self.Session() as session:
            row = session.get(CaseHostModel, (job_id, host))
            if not row:
                row = CaseHostModel(job_id=job_id, host=host, status="to do")
                session.add(row)
            if assignee is not None and assignee != (row.assignee or ""):
                row.assignee = assignee or None
                self._log(session, job_id, actor, "assigned", f"{host} to {assignee}" if assignee else f"{host}: unassigned")
            if status is not None and status != row.status:
                row.status = status
                self._log(session, job_id, actor, "marked", f"{host}: {status}")
            row.updated_by, row.updated_at = actor, datetime.now()
            session.commit()
            return {"assignee": row.assignee or "", "status": row.status, "updated_by": actor,
                    "updated_at": row.updated_at.isoformat()}

    def activity(self, job_id: str, since_id: int = 0, limit: int = 200) -> List[Dict]:
        with self.Session() as session:
            rows = session.query(CaseActivityModel).filter(CaseActivityModel.job_id == job_id,
                                                            CaseActivityModel.id > since_id) \
                .order_by(CaseActivityModel.id.desc()).limit(limit).all()
            return [{"id": a.id, "actor": a.actor, "action": a.action, "detail": a.detail or "",
                     "created_at": a.created_at.isoformat() if a.created_at else None} for a in rows]

    def latest(self, job_id: str) -> int:
        """The newest activity id on this job (0 for none): every write the case browser shows logs one."""
        with self.Session() as session:
            return session.query(func.max(CaseActivityModel.id)).filter(CaseActivityModel.job_id == job_id).scalar() or 0

    def record(self, job_id: str, actor: str, action: str, detail: str) -> None:
        with self.Session() as session:
            self._log(session, job_id, actor, action, detail)
            session.commit()


_store: Optional[CaseStore] = None
_jobs = None


def configure(storage) -> None:
    """Give the routes the backend's JobStorage (main.py does, beside access.configure)."""
    global _store, _jobs
    _store = CaseStore(storage.Session)
    _jobs = storage


def store() -> CaseStore:
    if _store is None:
        raise RuntimeError("case_routes.configure() hasn't been called")
    return _store


def restart_refusal(job_id: str, confirm: bool) -> Optional[Dict]:
    """Why a restart needs confirming (the job has findings and the caller didn't say confirm), or None."""
    if confirm:
        return None
    count = store().count_findings(job_id)
    if not count:
        return None
    return {"findings": count,
            "message": f"This case has {count} finding{'' if count == 1 else 's'}. Restarting rewrites the case's "
                       "output, so any row that changes will show \"row changed\" in the case browser. "
                       "Restart with confirm=true to go ahead."}


def _by_eru(request: Request) -> bool:
    """Eru's MCP server says so in a header; an eru-mcp token is Eru whatever it says."""
    return (any(request.headers.get(h, "").strip().lower() == ERU_MCP for h in (AGENT_HEADER, OLD_AGENT_HEADER))
            or access.token_scope(request) == ERU_MCP)


def _actor(request: Request) -> str:
    user = access.current_user(request).get("username") or "local"
    return f"Eru (for {user})" if _by_eru(request) else user


def _root(job_id: str) -> Path:
    job = _jobs.get_job(job_id) if _jobs else None
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    root = case_files.case_root(job.destination_path or "", job.case_number)
    if not root:
        raise HTTPException(status_code=404, detail="This job has no case output yet")
    return root


def _file(job_id: str, host: str, path: str) -> Path:
    try:
        return case_files.resolve(_root(job_id), host, path)
    except case_files.CaseFileError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


def findings_for_case(case_path: str) -> List[Dict]:
    """For Eru: the findings on every job whose output is this case directory."""
    if not _jobs or not _store:
        return []
    target = Path(case_path).resolve()
    found = []
    for job in _jobs.list_jobs(limit=100000):
        if not job.destination_path:
            continue
        root = case_files.case_root(job.destination_path, job.case_number)
        if Path(job.destination_path).resolve() == target or (root and root.resolve() == target):
            found.extend(_store.findings(job.id))
    return found


# ---- browsing ----

@router.get("")
async def case_overview(job_id: str):
    """Hosts and their tables, with each host's assignment."""
    root = _root(job_id)
    listing = case_files.listing(root)
    assigned = store().assignments(job_id)
    for host in listing["hosts"]:
        host.update(assigned.get(host["host"], {"assignee": "", "status": "to do"}))
    counts: Dict[str, int] = {}
    for finding in store().findings(job_id):
        counts[finding["status"]] = counts.get(finding["status"], 0) + 1
    return {**listing, "findings": counts}


@router.get("/rows")
async def rows(job_id: str, host: str, path: str, q: str = "", offset: int = Query(0, ge=0),
               limit: int = Query(100, ge=1, le=500)):
    try:
        return case_files.page(_file(job_id, host, path), q, offset, limit)
    except case_files.CaseFileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/rows.csv")
async def rows_csv(job_id: str, host: str, path: str, q: str = ""):
    """A table (its filtered rows, with q) as CSV, for a spreadsheet: the case keeps JSON Lines."""
    table = _file(job_id, host, path)
    try:  # a broken table is refused before the response starts
        next(case_files.records(table), None)
    except case_files.CaseFileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    name = re.sub(r"[^\w.+-]", "_", f"{'' if host == case_files.CASE_HOST else host + '_'}{Path(path).stem}") + ".csv"
    return StreamingResponse(case_files.csv_export(table, q), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ---- findings ----

class FindingIn(BaseModel):
    host: str
    artefact: str
    row_ref: str
    title: str = Field(..., min_length=1, max_length=500)
    technique: str = ""
    status: str = "lead"


class FindingUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    technique: Optional[str] = None
    status: Optional[str] = None
    updated_at: Optional[str] = None  # what the caller loaded: a newer one means someone else changed it


def _check(status: Optional[str], technique: Optional[str]) -> Optional[str]:
    if status is not None and status not in STATUSES:
        raise HTTPException(status_code=400, detail=f"status is one of {', '.join(STATUSES)}")
    if technique:
        technique = technique.strip().upper()
        if not TECHNIQUE.match(technique):
            raise HTTPException(status_code=400, detail="technique is an ATT&CK ID such as T1059.001")
    return technique


@router.get("/findings")
async def list_findings(job_id: str, status: str = "", verify: bool = False):
    """Findings; with verify, whether each row still reads the same (a re-run may have changed it)."""
    found = store().findings(job_id, status)
    if verify and found:
        root = _root(job_id)
        for finding in found:
            try:
                row = case_files.find_row(case_files.resolve(root, finding["host"], finding["artefact"]),
                                          finding["row_ref"])
            except case_files.CaseFileError:
                row = None
            finding["intact"] = bool(row) and case_files.row_hash(row) == finding["row_hash"]
    return found


@router.post("/findings")
async def flag(job_id: str, finding: FindingIn, request: Request):
    """Flag a row. The row is read here, so its hash and excerpt are what the case holds."""
    technique = _check(finding.status, finding.technique)
    if _by_eru(request) and finding.status != "lead":
        raise HTTPException(status_code=403, detail="Eru flags leads only: confirming or dismissing is an analyst's")
    try:
        row = case_files.find_row(_file(job_id, finding.host, finding.artefact), finding.row_ref)
    except case_files.CaseFileError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if row is None:
        raise HTTPException(status_code=404, detail=f"No row {finding.row_ref} in {finding.artefact}")
    already = store().existing(job_id, finding.host, finding.artefact, finding.row_ref)
    if already:
        raise _flagged_already(already)
    excerpt = "; ".join(f"{k}: {v}" for k, v in row.items() if v)[:EXCERPT]
    try:
        return store().add_finding(job_id, _actor(request), host=finding.host, artefact=finding.artefact,
                                   row_ref=finding.row_ref, row_hash=case_files.row_hash(row), excerpt=excerpt,
                                   title=finding.title.strip(), technique=technique or None, status=finding.status)
    except AlreadyFlagged as exc:
        raise _flagged_already(exc.finding)


def _flagged_already(already: Dict) -> HTTPException:
    return HTTPException(status_code=409, detail=f"{already['author']} already flagged this row as "
                         f"#{already['id']} ({already['title']}, {already['status']}): add a note to it instead")


@router.patch("/findings/{finding_id}")
async def update_finding(job_id: str, finding_id: int, update: FindingUpdate, request: Request):
    if _by_eru(request):
        raise HTTPException(status_code=403, detail="Eru doesn't change findings: an analyst does")
    technique = _check(update.status, update.technique)
    try:
        changed = store().update_finding(job_id, finding_id, _actor(request), expected=update.updated_at,
                                         title=update.title,
                                         technique=technique if update.technique is not None else None,
                                         status=update.status)
    except Conflict as exc:
        raise HTTPException(status_code=409, detail=f"Finding #{finding_id} was changed since you loaded it "
                            f"(now {exc.current['status']}); reload and try again")
    if not changed:
        raise HTTPException(status_code=404, detail="Finding not found")
    return changed


@router.delete("/findings/{finding_id}")
async def delete_finding(job_id: str, finding_id: int, request: Request):
    if _by_eru(request):
        raise HTTPException(status_code=403, detail="Eru doesn't remove findings: an analyst does")
    if not store().delete_finding(job_id, finding_id, _actor(request)):
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"deleted": finding_id}


# ---- notes, hosts, activity ----

class NoteIn(BaseModel):
    body: str = Field(..., min_length=1, max_length=20000)
    finding_id: Optional[int] = None


class HostUpdate(BaseModel):
    assignee: Optional[str] = None
    status: Optional[str] = None


@router.get("/notes")
async def list_notes(job_id: str):
    return store().notes(job_id)


@router.post("/notes")
async def add_note(job_id: str, note: NoteIn, request: Request):
    added = store().add_note(job_id, _actor(request), note.body, note.finding_id)
    if not added:
        raise HTTPException(status_code=404, detail="Finding not found")
    return added


@router.put("/hosts/{host}")
async def assign_host(job_id: str, host: str, update: HostUpdate, request: Request):
    if _by_eru(request):
        raise HTTPException(status_code=403, detail="Eru doesn't assign hosts: an analyst does")
    if update.status is not None and update.status not in HOST_STATUSES:
        raise HTTPException(status_code=400, detail=f"status is one of {', '.join(HOST_STATUSES)}")
    if host not in {h.name for h in case_files.hosts(_root(job_id))}:
        raise HTTPException(status_code=404, detail=f"No host {host!r} in this case")
    assignee = update.assignee.strip() if update.assignee is not None else None
    if assignee and access.server_mode():
        # On a team server an assignee is someone who can sign in; on one machine it stays free text
        user = find_user(load_users(), assignee)
        if not user or not user.get("is_active", True):
            raise HTTPException(status_code=400, detail=f"No active user {assignee!r}")
        assignee = user["username"]
    return store().assign(job_id, host, _actor(request), assignee, update.status)


@router.get("/activity")
async def activity(job_id: str, since: int = Query(0, ge=0)):
    """Newest first; poll with `since` (the highest id seen) for what's new."""
    return store().activity(job_id, since)


def live_state(job_id: str) -> Dict:
    """What the live socket watches: the activity feed, and the job's own progress (the case's
    tables appear as it runs)."""
    job = _jobs.get_job(job_id) if _jobs else None
    status = getattr(job, "status", "") or ""
    return {"activity": store().latest(job_id), "status": getattr(status, "value", status),
            "progress": getattr(job, "progress", 0) or 0}


@router.websocket("/live")
async def live(websocket: WebSocket, job_id: str):
    """Says when the case changes, so the case browser reloads at once rather than on its next poll.
    Sends only {activity, status, progress}: the data itself still comes through the routes above.
    The caller is checked as for those (access.websocket_user, from the session cookie or a bearer
    header, never a token in the URL), and again before each check, so signing out, an expired
    sign-in or the job no longer being shared closes it."""
    if not access.websocket_user(websocket):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    sent = None
    try:
        while True:
            if not access.websocket_user(websocket):
                await websocket.close(code=1008)
                return
            state = await asyncio.to_thread(live_state, job_id)
            if state != sent:
                await websocket.send_json(state)
                sent = state
            # Waits by listening, so a closed tab ends this at once; what the page sends is ignored
            try:
                message = await asyncio.wait_for(websocket.receive(), LIVE_EVERY)
            except asyncio.TimeoutError:
                continue
            if message["type"] == "websocket.disconnect":
                return
    except WebSocketDisconnect:
        pass


# ---- output from confirmed findings ----

def report_markdown(case_number: str, findings: List[Dict], notes: List[Dict]) -> str:
    confirmed = [f for f in findings if f["status"] == "confirmed"]
    by_finding: Dict[int, List[Dict]] = {}
    for note in notes:
        by_finding.setdefault(note["finding_id"], []).append(note)
    lines = [f"# {case_number}: confirmed findings", "",
             f"{len(confirmed)} confirmed of {len(findings)} flagged "
             f"({sum(f['status'] == 'lead' for f in findings)} still leads, "
             f"{sum(f['status'] == 'benign' for f in findings)} benign).", ""]
    if by_finding.get(None):
        lines += ["## Case notes", ""]
        for note in by_finding[None]:
            lines += [f"*{note['author']}, {(note['created_at'] or '')[:16].replace('T', ' ')}*", "", note["body"], ""]
    for host in sorted({f["host"] for f in confirmed}):
        lines += [f"## {host}", ""]
        for f in (f for f in confirmed if f["host"] == host):
            technique = f" (**{f['technique']}**)" if f["technique"] else ""
            lines += [f"### {f['id']}. {f['title']}{technique}", "",
                      f"`{f['artefact']}`, row {f['row_ref']}; flagged by {f['author']}.", "",
                      f"> {f['excerpt']}", ""]
            for note in by_finding.get(f["id"], []):
                lines += [f"- {note['author']}: {note['body']}"]
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def navigator_layer(case_number: str, findings: List[Dict]) -> Dict:
    """An ATT&CK Navigator layer of the confirmed findings' techniques, in post/mitre/nav_config.py's format."""
    techniques: Dict[str, List[str]] = {}
    for f in findings:
        if f["status"] == "confirmed" and f["technique"]:
            techniques.setdefault(f["technique"], []).append(f"#{f['id']} {f['title']}")
    return {
        "name": f"{case_number} (confirmed)",
        "versions": {"attack": "13", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques behind the analysts' confirmed findings only",
        "filters": {"platforms": ["Linux", "macOS", "Windows", "Containers"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True,
                   "showAggregateScores": False, "countUnscored": False},
        "hideDisabled": False,
        "techniques": [{"techniqueID": t, "color": "#ed5565", "comment": "; ".join(titles)[:1000], "enabled": True,
                        "showSubtechniques": "." in t} for t, titles in sorted(techniques.items())],
        "legendItems": [{"label": "Confirmed finding", "color": "#ed5565"}],
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


@router.get("/report", response_class=PlainTextResponse)
async def report(job_id: str, request: Request):
    job = _jobs.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    store().record(job_id, _actor(request), "exported", "the report")
    return report_markdown(job.case_number, store().findings(job_id), store().notes(job_id))


@router.get("/layer")
async def layer(job_id: str):
    job = _jobs.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return navigator_layer(job.case_number, store().findings(job_id))

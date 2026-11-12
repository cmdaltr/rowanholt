"""
AI Assistant API Routes

FastAPI routes for Smith AI assistant functionality.
"""

import os
import json
import logging
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

try:
    from . import case_files, smith_context, smith_offline
    from .auth import access
    from .storage import JobStorage
except ImportError:  # main.py imports the routes as top-level modules too
    import case_files
    import smith_context
    import smith_offline
    from auth import access
    from storage import JobStorage

# Initialize router
router = APIRouter(prefix="/api/ai", tags=["AI"])

logger = logging.getLogger(__name__)

# Configuration
ROWANHOLT_DATA_DIR = os.getenv("ROWANHOLT_DATA_DIR", "/opt/rowanholt/data")
# For Docker on macOS, use host.docker.internal to reach host machine's Ollama
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://host.docker.internal:11434")
DEFAULT_MODEL = os.getenv("ROWANHOLT_MODEL_NAME", "llama3.2:3b")
# Ollama's own default window (2048 tokens) is shorter than the case context Smith sends
NUM_CTX = int(os.getenv("ROWANHOLT_NUM_CTX", "8192"))


# Request/Response Models
class ChatRequest(BaseModel):
    message: str
    context: Optional[str] = "forensic_assistant"


class QueryRequest(BaseModel):
    question: str


class OfflineRequest(BaseModel):
    question_id: str
    case_id: Optional[str] = None
    # The job whose output to read; without it, the first visible job with case_id
    job_id: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    model: Optional[str] = None
    processing_time: Optional[float] = None


def old_model_names(model: str) -> List[str]:
    """What a smith model (src/models/Modelfile.smith*) was called before the analyst was renamed,
    newest first: smith-qwen was aule-qwen (Aulë, until 12 November 2026) and before that eru-qwen
    (Eru, until 9 November 2026); smith:latest was aule:latest and eru:latest. Empty for any other model."""
    if model == "smith" or model.startswith(("smith-", "smith:")):
        return [old + model[len("smith"):] for old in ("aule", "eru")]
    return []


def _installed(model: str, models: List[str]) -> bool:
    return model in models or any(model in m for m in models)


# LLM Interface
class OllamaClient:
    """Simple Ollama HTTP client."""

    def __init__(self, host: str = OLLAMA_HOST, model: str = DEFAULT_MODEL):
        self.host = host
        # The model asked for; self.model is the one used, an old name when only that is pulled
        self.configured = model
        self.model = model
        self._resolved = False

    async def generate(self, prompt: str, system: str = None) -> str:
        """Generate a response from Ollama."""
        import httpx

        if not self._resolved:
            await self.check_available()
        url = f"{self.host}/api/generate"

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_ctx": NUM_CTX},
        }

        if system:
            payload["system"] = system

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                return data.get("response", "")
        except httpx.HTTPError as e:
            logger.error(f"Ollama HTTP error: {e}")
            reason = smith_offline.unavailable_reason(await self.check_available(), self.host, self.model)
            raise HTTPException(status_code=503, detail=reason or f"LLM service unavailable: {e}")
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            raise HTTPException(status_code=500, detail=f"LLM error: {e}")

    async def check_available(self) -> Dict[str, Any]:
        """Check if Ollama is available and get model info."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                # Check if Ollama is running
                response = await client.get(f"{self.host}/api/tags")
                response.raise_for_status()
                data = response.json()

                models = [m.get("name") for m in data.get("models", [])]
                self.model = self.choose_model(models)
                self._resolved = True

                return {
                    "available": True,
                    "models": models,
                    "default_model": self.model,
                    "model_loaded": _installed(self.model, models)
                }
        except Exception as e:
            logger.debug(f"Ollama not available: {e}")
            return {"available": False, "error": str(e)}

    def choose_model(self, models: List[str]) -> str:
        """The configured model, or an old name of it when only that is pulled (old_model_names)."""
        if _installed(self.configured, models):
            return self.configured
        for old in old_model_names(self.configured):
            if _installed(old, models):
                if self.model != old:
                    logger.info(f"{self.configured} isn't pulled but {old}, its name before Smith, is: using {old}")
                return old
        return self.configured


# Initialize Ollama client
ollama = OllamaClient()

# Forensic assistant system prompt
FORENSIC_SYSTEM_PROMPT = """You are Smith, an AI forensic analysis assistant for Rowanholt, a digital forensics acceleration suite.

Your expertise includes:
- Windows, macOS, and Linux forensics
- Memory analysis and artifact interpretation
- Timeline analysis and correlation
- MITRE ATT&CK technique identification
- Incident response and investigation methodology
- Malware analysis basics
- Log analysis (Windows Event Logs, Syslog, etc.)
- Registry analysis
- Browser forensics
- Network forensics

Guidelines:
- Provide accurate, technical forensic guidance
- Reference MITRE ATT&CK techniques when relevant (e.g., T1059.001 for PowerShell)
- Suggest specific artifacts to examine
- Recommend investigation paths
- Be concise but thorough
- Always note when something requires further verification
- Never make up evidence or findings

When analyzing case data, base your answers ONLY on the provided context. If insufficient information, say so."""


@router.get("/status")
async def get_ai_status():
    """
    Get AI service status.

    Returns:
        LLM availability and configuration
    """
    status = await ollama.check_available()
    usable = bool(status.get("available") and status.get("model_loaded"))

    return {
        "llm_available": usable,
        "ollama_running": bool(status.get("available")),
        "model_name": ollama.model if usable else None,
        "models": status.get("models", []),
        "ollama_host": OLLAMA_HOST,
        "data_dir": ROWANHOLT_DATA_DIR,
        # Why free text won't work, for Ask Smith to show; empty when it will
        "reason": "" if usable else smith_offline.unavailable_reason(status, OLLAMA_HOST, DEFAULT_MODEL),
    }


@router.get("/offline/questions")
async def list_offline_questions():
    """Questions Smith answers from the case files alone, with no LLM."""
    return {"questions": smith_offline.catalogue()}


@router.post("/offline/answer")
async def answer_offline_question(request: OfflineRequest, http_request: Request):
    """Answer one offline question, from the selected case's files where it needs a case."""
    if request.case_id and not access.case_allowed(access.current_user(http_request), request.case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    user = access.current_user(http_request)
    case_path, job_id = await _find_case(request.case_id, user, request.job_id) if request.case_id else (None, None)
    if request.case_id and not case_path:
        raise HTTPException(status_code=404, detail="Case not found")
    try:
        result = smith_offline.answer_with_rows(request.question_id, case_path)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"No offline question '{request.question_id}'")
    # The rows it cited are flagged on job_id's case; a case directory with no job behind it can't be flagged
    return {**result, "rows": result["rows"] if job_id else [], "job_id": job_id, "offline": True}


@router.get("/cases")
async def list_indexed_cases(request: Request):
    """
    List cases with indexed vector databases.

    Returns:
        List of available cases
    """
    cases = []

    try:
        if os.path.exists(ROWANHOLT_DATA_DIR):
            for case_dir in os.listdir(ROWANHOLT_DATA_DIR):
                case_path = os.path.join(ROWANHOLT_DATA_DIR, case_dir)
                vector_db_path = os.path.join(case_path, "vector_db")

                if os.path.isdir(case_path):
                    indexed = os.path.exists(vector_db_path)
                    cases.append({
                        "case_id": case_dir,
                        "path": case_path,
                        "indexed": indexed,
                    })

        # Also check completed jobs for case data
        job_storage = JobStorage()

        for job in job_storage.list_jobs(limit=100000):
            if job.status.value == "completed" and job.destination_path:
                dest_path = Path(job.destination_path)
                if dest_path.exists():
                    # One entry per job: two jobs can share a case number, and Smith reads the one chosen
                    vector_db = dest_path / "vector_db"
                    cooked = dest_path / "cooked"
                    cases.append({
                        "case_id": job.case_number,
                        "path": str(dest_path),
                        "indexed": vector_db.exists(),
                        "has_artifacts": cooked.exists(),
                        "job_id": job.id,
                    })

    except Exception as e:
        logger.error(f"Error listing cases: {e}")

    user = access.current_user(request)
    return {"cases": [c for c in cases if c.get("job_id") and access.can_access_job(user, c["job_id"])
                      or not c.get("job_id") and _folder_cases_visible(user)]}


@router.post("/chat")
async def general_chat(request: ChatRequest):
    """
    General AI chat without case context.

    Args:
        request: Chat request with message

    Returns:
        AI response
    """
    import time
    start_time = time.time()

    try:
        # Generate response
        response = await ollama.generate(
            prompt=request.message,
            system=FORENSIC_SYSTEM_PROMPT
        )

        processing_time = time.time() - start_time

        return ChatResponse(
            response=response,
            model=ollama.model,
            processing_time=processing_time
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cases/{case_id}/info")
async def get_case_info(case_id: str, http_request: Request, job_id: Optional[str] = None):
    """
    Get information about a case.

    Args:
        case_id: Case identifier

    Returns:
        Case information
    """
    case_path, found = await _find_case(case_id, access.current_user(http_request), job_id)
    if not case_path or not os.path.exists(case_path):
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    vector_db_path = os.path.join(case_path, "vector_db")
    job_info = JobStorage().get_job(found) if found else None

    # Gather case info
    info = {
        "case_id": case_id,
        "path": case_path,
        "indexed": os.path.exists(vector_db_path),
    }

    if job_info:
        info["job_id"] = job_info.id
        info["status"] = job_info.status.value
        info["created_at"] = job_info.created_at.isoformat() if job_info.created_at else None

    # Processed artefacts: the tables in each host's artefacts/cooked
    if os.path.isdir(case_path):
        cooked = [h / "artefacts" / "cooked" for h in case_files.hosts(Path(case_path))]
        artifact_count = sum(1 for folder in cooked if folder.is_dir()
                             for p in folder.rglob("*") if p.suffix.lower() in case_files.ROW_FILES)
        if artifact_count:
            info["has_artifacts"] = True
            info["artifact_count"] = artifact_count

    return info


@router.post("/cases/{case_id}/query")
async def query_case(case_id: str, request: QueryRequest, http_request: Request, job_id: Optional[str] = None):
    """
    Query a case using natural language.

    Args:
        case_id: Case identifier
        request: Query request with question

    Returns:
        AI response with sources, and the rows it cited (as the offline answers give them) with the job
        they're on
    """
    import time
    start_time = time.time()

    case_path, job_id = await _find_case(case_id, access.current_user(http_request), job_id)
    if not case_path:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    # Check for vector database
    vector_db_path = os.path.join(case_path, "vector_db")

    # If vector DB exists, use RAG query
    if os.path.exists(vector_db_path):
        try:
            # Try to use the forensic query engine
            from rowanholt.ai.query_engine import ForensicQueryEngine

            engine = ForensicQueryEngine.load(case_id, case_path)
            result = engine.query(request.question)

            return {
                "question": result.question,
                "answer": result.answer,
                "sources": [
                    {
                        "content": src.content[:200] + "..." if len(src.content) > 200 else src.content,
                        "metadata": src.metadata,
                        "relevance_score": src.relevance_score
                    }
                    for src in result.sources
                ],
                "confidence": result.confidence,
                "processing_time": result.processing_time,
                "rows": [],
                "job_id": job_id,
            }
        except ImportError:
            logger.warning("ForensicQueryEngine not available, using direct LLM query")
        except Exception as e:
            logger.warning(f"RAG query failed: {e}, falling back to direct query")

    # Fall back to direct LLM query with artifact context
    context = _case_context(case_path, request.question)

    prompt = f"""Based on the following forensic case data:

{context.text()}

Question: {request.question}

Provide a detailed forensic analysis answer based on the case data provided."""

    response = await ollama.generate(prompt=prompt, system=f"{FORENSIC_SYSTEM_PROMPT}\n\n{smith_context.CITE_INSTRUCTIONS}")

    processing_time = time.time() - start_time

    return {
        "question": request.question,
        "answer": response,
        "sources": [],
        "confidence": 0.7,
        "processing_time": processing_time,
        "rows": _rows_for(smith_context.cited(response, context), job_id),
        "job_id": job_id,
    }


@router.post("/cases/{case_id}/suggestions")
async def get_investigation_suggestions(case_id: str, http_request: Request, job_id: Optional[str] = None):
    """
    Get AI-generated investigation path suggestions.

    Args:
        case_id: Case identifier

    Returns:
        List of investigation suggestions, each with the rows it cites, and all of them with the job
    """
    # Find case path
    case_path, job_id = await _find_case(case_id, access.current_user(http_request), job_id)

    if not case_path:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    # Gather context
    context = _case_context(case_path, "suspicious activities")

    prompt = f"""Based on the following forensic case data:

{context.text()}

Analyze the evidence and suggest 5 specific investigation paths. For each:
1. Provide a clear title
2. Explain what to investigate and why
3. List specific artifacts or data sources to examine
4. Note any MITRE ATT&CK techniques to look for

Format as a numbered list."""

    response = await ollama.generate(prompt=prompt, system=f"{FORENSIC_SYSTEM_PROMPT}\n\n{smith_context.CITE_INSTRUCTIONS}")

    # Parse response into suggestions
    suggestions = _parse_suggestions(response)
    for suggestion in suggestions:
        suggestion["rows"] = _rows_for(smith_context.cited(f"{suggestion['title']} {suggestion['description']}", context), job_id)

    return {
        "case_id": case_id,
        "suggestions": suggestions,
        "rows": _rows_for(smith_context.cited(response, context), job_id),
        "job_id": job_id,
    }


@router.post("/cases/{case_id}/summary")
async def generate_case_summary(case_id: str, http_request: Request, job_id: Optional[str] = None):
    """
    Generate an executive summary for a case.

    Args:
        case_id: Case identifier

    Returns:
        Case summary
    """
    # Find case path
    case_path, job_id = await _find_case(case_id, access.current_user(http_request), job_id)

    if not case_path:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    # Gather comprehensive context
    context = _case_context(case_path, "")

    prompt = f"""Based on the following forensic case data:

{context.text()}

Generate a comprehensive executive summary including:
1. Executive Summary (2-3 paragraphs)
2. Key Findings (bullet points)
3. Timeline Summary (chronological key events)
4. MITRE ATT&CK Techniques Detected
5. Recommendations for remediation

Be thorough but concise."""

    response = await ollama.generate(prompt=prompt, system=f"{FORENSIC_SYSTEM_PROMPT}\n\n{smith_context.CITE_INSTRUCTIONS}")

    return {
        "case_id": case_id,
        "executive_summary": response,
        "generated_at": datetime.now().isoformat(),
        "rows": _rows_for(smith_context.cited(response, context), job_id),
        "job_id": job_id,
    }


# Helper functions
async def _find_case_path(case_id: str) -> Optional[str]:
    """Find the path for a case ID."""
    return (await _find_case(case_id))[0]


def _folder_cases_visible(user: Optional[dict]) -> bool:
    """A case folder in the data directory has no job, so no owner: on a team server, admins only."""
    return user is None or not access.server_mode() or access.is_admin(user)


def _job_case_root(job) -> Optional[str]:
    """The folder with the host folders, as the case browser finds it: the destination or <destination>/<case>."""
    if not job.destination_path:
        return None
    root = case_files.case_root(job.destination_path, job.case_number)
    if root:
        return str(root)
    return job.destination_path if os.path.exists(job.destination_path) else None


async def _find_case(case_id: str, user: Optional[dict] = None,
                     job_id: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """(case path, the job it's the output of): a case in the data directory has no job; with `user`,
    only jobs they can see. With `job_id`, that job's output and no other (two jobs can share a
    case number), or nothing if it isn't the caller's or isn't this case."""
    if job_id:
        job = JobStorage().get_job(job_id)
        if not job or job.case_number != case_id or (user is not None and not access.can_access_job(user, job.id)):
            return None, None
        return _job_case_root(job), job.id

    data_path = os.path.join(ROWANHOLT_DATA_DIR, case_id)
    if os.path.exists(data_path) and _folder_cases_visible(user):
        return data_path, None

    try:
        job_storage = JobStorage()

        for job in job_storage.list_jobs(limit=100000):
            if job.case_number != case_id or not job.destination_path:
                continue
            if user is not None and not access.can_access_job(user, job.id):
                continue
            root = _job_case_root(job)
            if root:
                return root, job.id
    except Exception as e:
        logger.error(f"Error checking job storage: {e}")

    return None, None


def _case_context(case_path: str, question: str) -> smith_context.Context:
    """The numbered case context for the model, the analysts' findings first."""
    findings = smith_offline.FINDINGS(case_path) if smith_offline.FINDINGS else []
    return smith_context.build(case_path, question, findings)


def _rows_for(rows: List[Dict[str, str]], job_id: Optional[str]) -> List[Dict[str, str]]:
    """Cited rows can be flagged only on a job's case; a case directory with no job behind it has none."""
    return rows if job_id else []


def _parse_suggestions(response: str) -> List[Dict[str, Any]]:
    """Parse LLM response into suggestion objects."""
    suggestions = []
    lines = response.strip('\n').split('\n')

    def numbered(text: str) -> bool:
        return bool(text) and text[0].isdigit() and '.' in text[:4]

    # A suggestion starts at a numbered line of the outermost list; the numbered points the prompt
    # asks for under each one are indented further, and belong to its description
    depths = [len(l) - len(l.lstrip()) for l in lines if numbered(l.strip())]
    top = min(depths) if depths else 0

    current_suggestion = None
    current_description = []

    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        # Check if it's a numbered item of the outermost list
        if numbered(line) and len(raw) - len(raw.lstrip()) == top:
            # Save previous suggestion
            if current_suggestion:
                current_suggestion["description"] = ' '.join(current_description)
                suggestions.append(current_suggestion)

            # Start new suggestion
            title = line.split('.', 1)[1].strip() if '.' in line else line
            # Clean up title (remove ** markdown if present)
            title = title.replace('**', '').strip()

            current_suggestion = {
                "title": title,
                "description": "",
                "priority": "medium"
            }
            current_description = []
        elif current_suggestion:
            current_description.append(line)

    # Don't forget the last one
    if current_suggestion:
        current_suggestion["description"] = ' '.join(current_description)
        suggestions.append(current_suggestion)

    return suggestions

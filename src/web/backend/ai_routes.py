"""
AI Assistant API Routes

FastAPI routes for Eru AI assistant functionality.
"""

import os
import json
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

try:
    from . import case_files, eru_offline
    from .auth import access
    from .storage import JobStorage
except ImportError:  # main.py imports the routes as top-level modules too
    import case_files
    import eru_offline
    from auth import access
    from storage import JobStorage

# Initialize router
router = APIRouter(prefix="/api/ai", tags=["AI"])

logger = logging.getLogger(__name__)

# Configuration
RIVENDELL_DATA_DIR = os.getenv("RIVENDELL_DATA_DIR", "/opt/rivendell/data")
# For Docker on macOS, use host.docker.internal to reach host machine's Ollama
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://host.docker.internal:11434")
DEFAULT_MODEL = os.getenv("RIVENDELL_MODEL_NAME", "llama3.2:3b")


# Request/Response Models
class ChatRequest(BaseModel):
    message: str
    context: Optional[str] = "forensic_assistant"


class QueryRequest(BaseModel):
    question: str


class OfflineRequest(BaseModel):
    question_id: str
    case_id: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    model: Optional[str] = None
    processing_time: Optional[float] = None


# LLM Interface
class OllamaClient:
    """Simple Ollama HTTP client."""

    def __init__(self, host: str = OLLAMA_HOST, model: str = DEFAULT_MODEL):
        self.host = host
        self.model = model

    async def generate(self, prompt: str, system: str = None) -> str:
        """Generate a response from Ollama."""
        import httpx

        url = f"{self.host}/api/generate"

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
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
            reason = eru_offline.unavailable_reason(await self.check_available(), self.host, self.model)
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

                return {
                    "available": True,
                    "models": models,
                    "default_model": self.model,
                    "model_loaded": self.model in models or any(self.model in m for m in models)
                }
        except Exception as e:
            logger.debug(f"Ollama not available: {e}")
            return {"available": False, "error": str(e)}


# Initialize Ollama client
ollama = OllamaClient()

# Forensic assistant system prompt
FORENSIC_SYSTEM_PROMPT = """You are Eru, an AI forensic analysis assistant for Rivendell, a digital forensics acceleration suite.

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
        "model_name": DEFAULT_MODEL if usable else None,
        "models": status.get("models", []),
        "ollama_host": OLLAMA_HOST,
        "data_dir": RIVENDELL_DATA_DIR,
        # Why free text won't work, for Ask Eru to show; empty when it will
        "reason": "" if usable else eru_offline.unavailable_reason(status, OLLAMA_HOST, DEFAULT_MODEL),
    }


@router.get("/offline/questions")
async def list_offline_questions():
    """Questions Eru answers from the case files alone, with no LLM."""
    return {"questions": eru_offline.catalogue()}


@router.post("/offline/answer")
async def answer_offline_question(request: OfflineRequest, http_request: Request):
    """Answer one offline question, from the selected case's files where it needs a case."""
    if request.case_id and not access.case_allowed(access.current_user(http_request), request.case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    case_path = await _find_case_path(request.case_id) if request.case_id else None
    try:
        answer = eru_offline.answer(request.question_id, case_path)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"No offline question '{request.question_id}'")
    return {"answer": answer, "offline": True}


@router.get("/cases")
async def list_indexed_cases(request: Request):
    """
    List cases with indexed vector databases.

    Returns:
        List of available cases
    """
    cases = []

    try:
        if os.path.exists(RIVENDELL_DATA_DIR):
            for case_dir in os.listdir(RIVENDELL_DATA_DIR):
                case_path = os.path.join(RIVENDELL_DATA_DIR, case_dir)
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

        for job in job_storage.list_jobs():
            if job.status.value == "completed" and job.destination_path:
                dest_path = Path(job.destination_path)
                if dest_path.exists():
                    # Check if already in list
                    case_id = job.case_number
                    if not any(c["case_id"] == case_id for c in cases):
                        # Check for vector DB or cooked directory
                        vector_db = dest_path / "vector_db"
                        cooked = dest_path / "cooked"

                        cases.append({
                            "case_id": case_id,
                            "path": str(dest_path),
                            "indexed": vector_db.exists(),
                            "has_artifacts": cooked.exists(),
                            "job_id": job.id,
                        })

    except Exception as e:
        logger.error(f"Error listing cases: {e}")

    visible = access.visible_cases(access.current_user(request))
    if visible is not None:
        cases = [c for c in cases if c["case_id"] in visible]
    return {"cases": cases}


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
            model=DEFAULT_MODEL,
            processing_time=processing_time
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cases/{case_id}/info")
async def get_case_info(case_id: str):
    """
    Get information about a case.

    Args:
        case_id: Case identifier

    Returns:
        Case information
    """
    # Try to find case in data directory
    case_path = os.path.join(RIVENDELL_DATA_DIR, case_id)
    vector_db_path = os.path.join(case_path, "vector_db")

    # Also check job storage
    job_storage = JobStorage()

    job_info = None
    for job in job_storage.list_jobs():
        if job.case_number == case_id:
            job_info = job
            if job.destination_path:
                case_path = job.destination_path
                vector_db_path = os.path.join(case_path, "vector_db")
            break

    if not os.path.exists(case_path):
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

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

    # Check for artifacts
    cooked_path = os.path.join(case_path, "cooked")
    if os.path.exists(cooked_path):
        info["has_artifacts"] = True
        # Count artifact files
        artifact_count = sum(1 for _ in Path(cooked_path).rglob("*.json"))
        info["artifact_count"] = artifact_count

    return info


@router.post("/cases/{case_id}/query")
async def query_case(case_id: str, request: QueryRequest):
    """
    Query a case using natural language.

    Args:
        case_id: Case identifier
        request: Query request with question

    Returns:
        AI response with sources
    """
    import time
    start_time = time.time()

    # Find case path
    case_path = None

    # Check data directory
    data_path = os.path.join(RIVENDELL_DATA_DIR, case_id)
    if os.path.exists(data_path):
        case_path = data_path

    # Check job storage
    if not case_path:
        job_storage = JobStorage()

        for job in job_storage.list_jobs():
            if job.case_number == case_id and job.destination_path:
                if os.path.exists(job.destination_path):
                    case_path = job.destination_path
                    break

    if not case_path:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    # Check for vector database
    vector_db_path = os.path.join(case_path, "vector_db")

    # If vector DB exists, use RAG query
    if os.path.exists(vector_db_path):
        try:
            # Try to use the forensic query engine
            from rivendell.ai.query_engine import ForensicQueryEngine

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
            }
        except ImportError:
            logger.warning("ForensicQueryEngine not available, using direct LLM query")
        except Exception as e:
            logger.warning(f"RAG query failed: {e}, falling back to direct query")

    # Fall back to direct LLM query with artifact context
    context = await _gather_case_context(case_path, request.question)

    prompt = f"""Based on the following forensic case data:

{context}

Question: {request.question}

Provide a detailed forensic analysis answer based on the case data provided."""

    response = await ollama.generate(prompt=prompt, system=FORENSIC_SYSTEM_PROMPT)

    processing_time = time.time() - start_time

    return {
        "question": request.question,
        "answer": response,
        "sources": [],
        "confidence": 0.7,
        "processing_time": processing_time,
    }


@router.post("/cases/{case_id}/suggestions")
async def get_investigation_suggestions(case_id: str):
    """
    Get AI-generated investigation path suggestions.

    Args:
        case_id: Case identifier

    Returns:
        List of investigation suggestions
    """
    # Find case path
    case_path = await _find_case_path(case_id)

    if not case_path:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    # Gather context
    context = await _gather_case_context(case_path, "suspicious activities")

    prompt = f"""Based on the following forensic case data:

{context}

Analyze the evidence and suggest 5 specific investigation paths. For each:
1. Provide a clear title
2. Explain what to investigate and why
3. List specific artifacts or data sources to examine
4. Note any MITRE ATT&CK techniques to look for

Format as a numbered list."""

    response = await ollama.generate(prompt=prompt, system=FORENSIC_SYSTEM_PROMPT)

    # Parse response into suggestions
    suggestions = _parse_suggestions(response)

    return {
        "case_id": case_id,
        "suggestions": suggestions
    }


@router.post("/cases/{case_id}/summary")
async def generate_case_summary(case_id: str):
    """
    Generate an executive summary for a case.

    Args:
        case_id: Case identifier

    Returns:
        Case summary
    """
    # Find case path
    case_path = await _find_case_path(case_id)

    if not case_path:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    # Gather comprehensive context
    context = await _gather_case_context(case_path, "key findings timeline IOCs")

    prompt = f"""Based on the following forensic case data:

{context}

Generate a comprehensive executive summary including:
1. Executive Summary (2-3 paragraphs)
2. Key Findings (bullet points)
3. Timeline Summary (chronological key events)
4. MITRE ATT&CK Techniques Detected
5. Recommendations for remediation

Be thorough but concise."""

    response = await ollama.generate(prompt=prompt, system=FORENSIC_SYSTEM_PROMPT)

    return {
        "case_id": case_id,
        "executive_summary": response,
        "generated_at": datetime.now().isoformat()
    }


# Helper functions
async def _find_case_path(case_id: str) -> Optional[str]:
    """Find the path for a case ID."""
    # Check data directory
    data_path = os.path.join(RIVENDELL_DATA_DIR, case_id)
    if os.path.exists(data_path):
        return data_path

    # Check job storage
    try:
        job_storage = JobStorage()

        for job in job_storage.list_jobs():
            if job.case_number == case_id and job.destination_path:
                # The folder with the host folders, as the case browser finds it: the destination or <destination>/<case>
                root = case_files.case_root(job.destination_path, job.case_number)
                if root:
                    return str(root)
                if os.path.exists(job.destination_path):
                    return job.destination_path
    except Exception as e:
        logger.error(f"Error checking job storage: {e}")

    return None


async def _gather_case_context(case_path: str, query_hint: str) -> str:
    """Gather relevant context from case artifacts."""
    context_parts = []

    # The analysts' confirmed findings go first: they're what the case is known to hold
    confirmed = [f for f in (eru_offline.FINDINGS(case_path) if eru_offline.FINDINGS else [])
                 if f["status"] == "confirmed"]
    if confirmed:
        context_parts.append("## Confirmed findings (analysts)\n" + "\n".join(
            f"- {f['title']} ({f['technique'] or 'no technique'}): {f['host']} {f['artefact']} row {f['row_ref']}: "
            f"{f['excerpt'][:300]}" for f in confirmed[:30]))

    # Look for cooked artifacts
    cooked_path = os.path.join(case_path, "cooked")
    if os.path.exists(cooked_path):
        # Get relevant JSON files (limit to prevent token overflow)
        json_files = list(Path(cooked_path).rglob("*.json"))[:20]

        for json_file in json_files:
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)

                # Format based on content
                if isinstance(data, list):
                    # Take first few records
                    sample = data[:10]
                    context_parts.append(f"## {json_file.stem}\n{json.dumps(sample, indent=2, default=str)[:2000]}")
                elif isinstance(data, dict):
                    context_parts.append(f"## {json_file.stem}\n{json.dumps(data, indent=2, default=str)[:2000]}")
            except Exception as e:
                logger.debug(f"Error reading {json_file}: {e}")
                continue

    # Look for timeline
    timeline_path = os.path.join(case_path, "timeline")
    if os.path.exists(timeline_path):
        csv_files = list(Path(timeline_path).glob("*.csv"))
        for csv_file in csv_files[:2]:
            try:
                with open(csv_file, 'r') as f:
                    lines = f.readlines()[:50]  # First 50 lines
                context_parts.append(f"## Timeline - {csv_file.stem}\n{''.join(lines)}")
            except Exception:
                pass

    # Look for IOC files
    analysis_path = os.path.join(case_path, "analysis")
    if os.path.exists(analysis_path):
        for pattern in ["*ioc*", "*indicator*", "*suspicious*"]:
            for match_file in Path(analysis_path).glob(pattern):
                try:
                    with open(match_file, 'r') as f:
                        content = f.read()[:3000]
                    context_parts.append(f"## {match_file.stem}\n{content}")
                except Exception:
                    pass

    if not context_parts:
        return "No artifact data available for this case."

    return "\n\n".join(context_parts)[:15000]  # Limit total context


def _parse_suggestions(response: str) -> List[Dict[str, Any]]:
    """Parse LLM response into suggestion objects."""
    suggestions = []
    lines = response.strip().split('\n')

    current_suggestion = None
    current_description = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Check if it's a numbered item
        if line[0].isdigit() and '.' in line[:4]:
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

#!/usr/bin/env python3
"""
AI Chat Web Interface

FastAPI-based web interface for AI-powered forensic queries.

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.middleware.cors import CORSMiddleware
    import asyncio

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from .query_engine import ForensicQueryEngine
from .models import QueryResult


# Global app instance
app = FastAPI(title="Dernvale AI Assistant", version="2.1.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store active query engines
query_engines: Dict[str, ForensicQueryEngine] = {}

# Configuration
config = {
    "base_dir": os.getenv("DERNVALE_DATA_DIR", "/opt/dernvale/data"),
    "llm_type": os.getenv("DERNVALE_LLM_TYPE", "ollama"),
    "model_name": os.getenv("DERNVALE_MODEL_NAME", "llama3"),
}

logger = logging.getLogger(__name__)


def get_query_engine(case_id: str) -> ForensicQueryEngine:
    """
    Get or create query engine for a case.

    Args:
        case_id: Case identifier

    Returns:
        ForensicQueryEngine instance
    """
    if case_id not in query_engines:
        try:
            engine = ForensicQueryEngine.load(
                case_id=case_id,
                base_dir=config["base_dir"],
                config={"llm_type": config["llm_type"], "model_name": config["model_name"]},
            )
            query_engines[case_id] = engine
            logger.info(f"Loaded query engine for case {case_id}")
        except Exception as e:
            logger.error(f"Failed to load query engine for case {case_id}: {e}")
            raise HTTPException(status_code=404, detail=f"Case {case_id} not found or not indexed")

    return query_engines[case_id]


@app.get("/")
async def root():
    """Root endpoint."""
    return {"name": "Dernvale AI Assistant", "version": "2.1.0", "status": "running"}


@app.get("/ai/cases")
async def list_cases():
    """List available cases."""
    try:
        base_dir = config["base_dir"]
        cases = []

        if os.path.exists(base_dir):
            for case_dir in os.listdir(base_dir):
                case_path = os.path.join(base_dir, case_dir)
                vector_db_path = os.path.join(case_path, "vector_db")

                if os.path.isdir(case_path) and os.path.exists(vector_db_path):
                    cases.append({"case_id": case_dir, "path": case_path, "indexed": True})

        return {"cases": cases}

    except Exception as e:
        logger.error(f"Error listing cases: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ai/cases/{case_id}/info")
async def get_case_info(case_id: str):
    """Get case information."""
    try:
        engine = get_query_engine(case_id)
        stats = engine.get_statistics()
        return stats

    except Exception as e:
        logger.error(f"Error getting case info: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/ai/cases/{case_id}/query")
async def query_case(case_id: str, request: Request):
    """
    Query a case using natural language.

    Body:
        {
            "question": "What PowerShell commands were executed?"
        }
    """
    try:
        body = await request.json()
        question = body.get("question")

        if not question:
            raise HTTPException(status_code=400, detail="Question is required")

        engine = get_query_engine(case_id)
        result = engine.query(question)

        return result.to_dict()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error querying case: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/ai/cases/{case_id}/suggestions")
async def get_suggestions(case_id: str):
    """Get investigation path suggestions."""
    try:
        engine = get_query_engine(case_id)
        suggestions = engine.suggest_investigation_paths()

        return {"case_id": case_id, "suggestions": [s.to_dict() for s in suggestions]}

    except Exception as e:
        logger.error(f"Error getting suggestions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/ai/cases/{case_id}/summary")
async def get_summary(case_id: str):
    """Generate case summary."""
    try:
        engine = get_query_engine(case_id)
        summary = engine.generate_summary()

        return summary.to_dict()

    except Exception as e:
        logger.error(f"Error generating summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ai/chat/{case_id}", response_class=HTMLResponse)
async def ai_chat_interface(case_id: str):
    """Render AI chat interface."""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dernvale AI Assistant - Case {case_id}</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}

            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: #f5f5f5;
                color: #333;
            }}

            #app-container {{
                display: flex;
                flex-direction: column;
                height: 100vh;
            }}

            #header {{
                background: #2c3e50;
                color: white;
                padding: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}

            #header h1 {{
                font-size: 24px;
                margin-bottom: 5px;
            }}

            #header p {{
                opacity: 0.8;
                font-size: 14px;
            }}

            #chat-container {{
                flex: 1;
                display: flex;
                flex-direction: column;
                max-width: 1200px;
                width: 100%;
                margin: 0 auto;
                padding: 20px;
                overflow: hidden;
            }}

            #messages {{
                flex: 1;
                overflow-y: auto;
                padding: 20px;
                background: white;
                border-radius: 8px;
                margin-bottom: 20px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            }}

            .message {{
                margin-bottom: 20px;
                animation: fadeIn 0.3s;
            }}

            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(10px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}

            .user-message {{
                display: flex;
                justify-content: flex-end;
            }}

            .user-message .message-content {{
                background: #3498db;
                color: white;
                padding: 12px 16px;
                border-radius: 18px 18px 4px 18px;
                max-width: 70%;
            }}

            .ai-message {{
                display: flex;
                flex-direction: column;
                align-items: flex-start;
            }}

            .ai-message .message-content {{
                background: #ecf0f1;
                color: #2c3e50;
                padding: 12px 16px;
                border-radius: 18px 18px 18px 4px;
                max-width: 80%;
            }}

            .sources {{
                margin-top: 10px;
                padding: 10px;
                background: #f8f9fa;
                border-left: 3px solid #3498db;
                border-radius: 4px;
                font-size: 12px;
                max-width: 80%;
            }}

            .sources strong {{
                display: block;
                margin-bottom: 5px;
                color: #2c3e50;
            }}

            .source-item {{
                padding: 4px 0;
                color: #7f8c8d;
            }}

            .loading {{
                display: inline-block;
                margin-left: 10px;
            }}

            .loading::after {{
                content: '...';
                animation: dots 1.5s steps(4, end) infinite;
            }}

            @keyframes dots {{
                0%, 20% {{ content: '.'; }}
                40% {{ content: '..'; }}
                60%, 100% {{ content: '...'; }}
            }}

            #input-container {{
                display: flex;
                gap: 10px;
                background: white;
                padding: 15px;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            }}

            #question-input {{
                flex: 1;
                padding: 12px 16px;
                border: 2px solid #ecf0f1;
                border-radius: 24px;
                font-size: 14px;
                outline: none;
                transition: border-color 0.3s;
            }}

            #question-input:focus {{
                border-color: #3498db;
            }}

            #send-btn {{
                padding: 12px 24px;
                background: #3498db;
                color: white;
                border: none;
                border-radius: 24px;
                cursor: pointer;
                font-size: 14px;
                font-weight: 600;
                transition: background 0.3s;
            }}

            #send-btn:hover {{
                background: #2980b9;
            }}

            #send-btn:disabled {{
                background: #95a5a6;
                cursor: not-allowed;
            }}

            .example-queries {{
                margin-top: 10px;
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
            }}

            .example-query {{
                padding: 6px 12px;
                background: #ecf0f1;
                border-radius: 12px;
                font-size: 12px;
                cursor: pointer;
                transition: background 0.3s;
            }}

            .example-query:hover {{
                background: #bdc3c7;
            }}
        </style>
    </head>
    <body>
        <div id="app-container">
            <div id="header">
                <h1>Dernvale AI Assistant</h1>
                <p>Case ID: {case_id}</p>
            </div>

            <div id="chat-container">
                <div id="messages">
                    <div class="ai-message">
                        <div class="message-content">
                            Hello! I'm the Dernvale AI Assistant. I can help you analyze this forensic case using natural language queries.
                            Ask me about timeline events, IOCs, processes, network activity, or any other artifacts in this investigation.
                        </div>
                    </div>
                </div>

                <div id="input-container">
                    <input type="text" id="question-input" placeholder="Ask a question about the investigation..." autocomplete="off">
                    <button id="send-btn" onclick="sendQuestion()">Send</button>
                </div>

                <div class="example-queries">
                    <div class="example-query" onclick="setQuery('What PowerShell commands were executed?')">PowerShell commands</div>
                    <div class="example-query" onclick="setQuery('Show network connections to external IPs')">Network activity</div>
                    <div class="example-query" onclick="setQuery('What MITRE ATT&CK techniques were detected?')">MITRE techniques</div>
                    <div class="example-query" onclick="setQuery('Summarize the attack timeline')">Timeline summary</div>
                </div>
            </div>
        </div>

        <script>
            const caseId = '{case_id}';
            let isProcessing = false;

            function setQuery(query) {{
                document.getElementById('question-input').value = query;
                document.getElementById('question-input').focus();
            }}

            async function sendQuestion() {{
                const input = document.getElementById('question-input');
                const sendBtn = document.getElementById('send-btn');
                const question = input.value.trim();

                if (!question || isProcessing) return;

                isProcessing = true;
                sendBtn.disabled = true;

                displayUserMessage(question);
                input.value = '';

                // Show loading
                displayLoadingMessage();

                try {{
                    const response = await fetch(`/ai/cases/${{caseId}}/query`, {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{ question: question }})
                    }});

                    const data = await response.json();

                    // Remove loading message
                    removeLoadingMessage();

                    if (response.ok) {{
                        displayAIMessage(data.answer, data.sources);
                    }} else {{
                        displayErrorMessage(data.detail || 'An error occurred');
                    }}
                }} catch (error) {{
                    removeLoadingMessage();
                    displayErrorMessage('Network error: ' + error.message);
                }} finally {{
                    isProcessing = false;
                    sendBtn.disabled = false;
                    input.focus();
                }}
            }}

            function displayUserMessage(message) {{
                const messagesDiv = document.getElementById('messages');
                const messageEl = document.createElement('div');
                messageEl.className = 'message user-message';
                messageEl.innerHTML = `<div class="message-content">${{escapeHtml(message)}}</div>`;
                messagesDiv.appendChild(messageEl);
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }}

            function displayAIMessage(answer, sources) {{
                const messagesDiv = document.getElementById('messages');
                const messageEl = document.createElement('div');
                messageEl.className = 'message ai-message';

                let sourcesHtml = '';
                if (sources && sources.length > 0) {{
                    sourcesHtml = '<div class="sources"><strong>Sources:</strong>';
                    sources.slice(0, 3).forEach((src, idx) => {{
                        const sourceType = src.metadata.type || 'unknown';
                        const sourceInfo = src.metadata.source || src.metadata.name || 'N/A';
                        sourcesHtml += `<div class="source-item">${{idx + 1}}. [${{sourceType}}] ${{sourceInfo}}</div>`;
                    }});
                    sourcesHtml += '</div>';
                }}

                messageEl.innerHTML = `
                    <div class="message-content">${{formatAnswer(answer)}}</div>
                    ${{sourcesHtml}}
                `;
                messagesDiv.appendChild(messageEl);
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }}

            function displayLoadingMessage() {{
                const messagesDiv = document.getElementById('messages');
                const messageEl = document.createElement('div');
                messageEl.className = 'message ai-message';
                messageEl.id = 'loading-message';
                messageEl.innerHTML = '<div class="message-content">Analyzing<span class="loading"></span></div>';
                messagesDiv.appendChild(messageEl);
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }}

            function removeLoadingMessage() {{
                const loadingEl = document.getElementById('loading-message');
                if (loadingEl) {{
                    loadingEl.remove();
                }}
            }}

            function displayErrorMessage(error) {{
                const messagesDiv = document.getElementById('messages');
                const messageEl = document.createElement('div');
                messageEl.className = 'message ai-message';
                messageEl.innerHTML = `<div class="message-content" style="background: #e74c3c; color: white;">Error: ${{escapeHtml(error)}}</div>`;
                messagesDiv.appendChild(messageEl);
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }}

            function formatAnswer(text) {{
                // Basic formatting
                text = escapeHtml(text);
                // Convert numbered lists
                text = text.replace(/^(\\d+\\.)\\s/gm, '<br><strong>$1</strong> ');
                // Convert bullet points
                text = text.replace(/^[-*]\\s/gm, '<br>• ');
                return text;
            }}

            function escapeHtml(text) {{
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }}

            // Send on Enter key
            document.getElementById('question-input').addEventListener('keypress', function(e) {{
                if (e.key === 'Enter' && !isProcessing) {{
                    sendQuestion();
                }}
            }});
        </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html)


@app.websocket("/ai/ws/{case_id}")
async def websocket_endpoint(websocket: WebSocket, case_id: str):
    """WebSocket endpoint for real-time AI queries."""
    await websocket.accept()
    logger.info(f"WebSocket connection established for case {case_id}")

    try:
        # Get query engine
        engine = get_query_engine(case_id)

        while True:
            # Receive question
            data = await websocket.receive_json()
            question = data.get("question")

            if not question:
                await websocket.send_json({"error": "Question is required"})
                continue

            # Process query
            try:
                result = engine.query(question)
                await websocket.send_json(result.to_dict())
            except Exception as e:
                logger.error(f"Error processing query: {e}")
                await websocket.send_json({"error": str(e)})

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for case {case_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        try:
            await websocket.close()
        except:
            pass


def start_server(host: str = "0.0.0.0", port: int = 5687):
    """
    Start the web server.

    Args:
        host: Host to bind to
        port: Port to listen on
    """
    if not FASTAPI_AVAILABLE:
        raise ImportError(
            "FastAPI required for web interface. Install with: "
            "pip install fastapi uvicorn websockets"
        )

    try:
        import uvicorn

        logger.info(f"Starting Dernvale AI Assistant web interface on {host}:{port}")
        uvicorn.run(app, host=host, port=port)
    except ImportError:
        raise ImportError("uvicorn required. Install with: pip install uvicorn")


if __name__ == "__main__":
    start_server()

#!/usr/bin/env python3
"""
Forensic Query Engine

AI-powered natural language query engine for forensic data analysis.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import os
import json
import logging
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    from langchain.llms import LlamaCpp, Ollama
    from langchain.chains import RetrievalQA
    from langchain.prompts import PromptTemplate
    from langchain.embeddings import HuggingFaceEmbeddings
    from langchain.vectorstores import Chroma
    from langchain.callbacks.manager import CallbackManager
    from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

from .models import QueryResult, SourceDocument, InvestigationSuggestion, CaseSummary


class ForensicQueryEngine:
    """
    AI-powered query engine for forensic data.

    Capabilities:
    - Natural language querying of forensic artifacts
    - Timeline analysis
    - IOC correlation
    - MITRE ATT&CK technique identification
    - Investigation path suggestions
    - Case summary generation
    """

    # Forensic-specific prompt templates
    QUERY_PROMPT = """You are a digital forensics expert analyzing case {case_id}.

Context from investigation:
{context}

Analyst Question: {question}

Provide a detailed forensic analysis answer. Include:
1. Direct answer to the question
2. Supporting evidence from the context
3. Relevant timestamps or artifact sources
4. Any security concerns or red flags
5. Suggested follow-up investigation steps

Important: Base your answer ONLY on the provided context. If the context doesn't contain enough information, say so.

Answer:"""

    SUMMARY_PROMPT = """You are a digital forensics expert. Generate a comprehensive case summary based on the following investigation data:

{context}

Generate a summary that includes:
1. Executive Summary (2-3 paragraphs)
2. Key Findings (bullet points)
3. Timeline Summary (chronological key events)
4. MITRE ATT&CK Techniques Detected
5. Recommendations for remediation

Summary:"""

    SUGGESTIONS_PROMPT = """You are a digital forensics expert. Based on these suspicious activities and findings:

{findings}

Suggest 5 specific investigation paths to pursue. For each path:
1. Provide a clear title
2. Explain what to investigate and why
3. List specific artifacts or data sources to examine
4. Note any MITRE ATT&CK techniques to look for

Suggestions:"""

    def __init__(self, case_id: str, vector_store_dir: str, config: Optional[Dict] = None):
        """
        Initialize forensic query engine.

        Args:
            case_id: Case identifier
            vector_store_dir: Directory containing vector database
            config: Optional configuration dict
                - llm_type: 'llamacpp' or 'ollama' (default: 'ollama')
                - model_path: Path to model file (for llamacpp)
                - model_name: Model name (for ollama, default: 'llama3')
                - temperature: LLM temperature (default: 0.1)
                - max_tokens: Max tokens to generate (default: 2048)
                - n_ctx: Context window size (default: 4096)
        """
        if not LANGCHAIN_AVAILABLE:
            raise ImportError(
                "LangChain required for AI querying. Install with: "
                "pip install langchain chromadb sentence-transformers llama-cpp-python"
            )

        self.case_id = case_id
        self.vector_store_dir = vector_store_dir
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Initialize embedding model
        embedding_model = self.config.get(
            "embedding_model", "sentence-transformers/all-MiniLM-L6-v2"
        )
        self.embeddings = HuggingFaceEmbeddings(
            model_name=embedding_model, model_kwargs={"device": self.config.get("device", "cpu")}
        )

        # Load vector store
        self.vectorstore = Chroma(
            collection_name=f"case_{case_id}",
            embedding_function=self.embeddings,
            persist_directory=vector_store_dir,
        )

        # Initialize LLM
        self.llm = self._initialize_llm()

        # Create retrieval chain
        self.retriever = self.vectorstore.as_retriever(
            search_type="similarity", search_kwargs={"k": self.config.get("top_k", 10)}
        )

        self.logger.info(f"Initialized query engine for case {case_id}")

    def _initialize_llm(self):
        """Initialize the LLM based on configuration."""
        llm_type = self.config.get("llm_type", "ollama")

        if llm_type == "llamacpp":
            # Use local LlamaCpp model
            model_path = self.config.get("model_path", "/opt/rowanholt/models/llama-3-70b.gguf")

            if not os.path.exists(model_path):
                raise FileNotFoundError(
                    f"LLM model not found at {model_path}. "
                    "Please download a compatible GGUF model."
                )

            callback_manager = CallbackManager([StreamingStdOutCallbackHandler()])

            return LlamaCpp(
                model_path=model_path,
                n_ctx=self.config.get("n_ctx", 4096),
                n_batch=self.config.get("n_batch", 512),
                temperature=self.config.get("temperature", 0.1),
                max_tokens=self.config.get("max_tokens", 2048),
                callback_manager=callback_manager,
                verbose=self.config.get("verbose", False),
            )

        elif llm_type == "ollama":
            # Use Ollama (easier setup, runs locally)
            model_name = self.config.get("model_name", "llama3")

            return Ollama(
                model=model_name,
                temperature=self.config.get("temperature", 0.1),
                num_predict=self.config.get("max_tokens", 2048),
            )

        else:
            raise ValueError(f"Unknown LLM type: {llm_type}. Use 'llamacpp' or 'ollama'")

    def query(self, question: str) -> QueryResult:
        """
        Query forensic data using natural language.

        Args:
            question: Natural language question

        Returns:
            QueryResult with answer and sources
        """
        start_time = time.time()

        try:
            # Create prompt
            prompt = PromptTemplate(
                template=self.QUERY_PROMPT, input_variables=["case_id", "context", "question"]
            )

            # Retrieve relevant documents
            docs = self.retriever.get_relevant_documents(question)

            # Build context from documents
            context = "\n\n".join([doc.page_content for doc in docs[:10]])

            # Generate answer
            formatted_prompt = prompt.format(
                case_id=self.case_id, context=context, question=question
            )

            answer = self.llm(formatted_prompt)

            # Create source documents
            sources = [
                SourceDocument(
                    content=doc.page_content,
                    metadata=doc.metadata,
                    relevance_score=1.0 / (i + 1),  # Simple relevance scoring
                )
                for i, doc in enumerate(docs[:5])
            ]

            processing_time = time.time() - start_time

            result = QueryResult(
                question=question,
                answer=answer.strip(),
                sources=sources,
                confidence=0.8,  # Could be enhanced with actual confidence scoring
                processing_time=processing_time,
                metadata={
                    "case_id": self.case_id,
                    "documents_retrieved": len(docs),
                    "llm_type": self.config.get("llm_type", "ollama"),
                },
            )

            self.logger.info(f"Query processed in {processing_time:.2f}s")
            return result

        except Exception as e:
            self.logger.error(f"Error processing query: {e}")
            return QueryResult(
                question=question,
                answer=f"Error processing query: {e}",
                sources=[],
                confidence=0.0,
                processing_time=time.time() - start_time,
            )

    def suggest_investigation_paths(self) -> List[InvestigationSuggestion]:
        """
        Suggest investigation paths based on findings.

        Returns:
            List of investigation suggestions
        """
        try:
            # Query for suspicious activities
            suspicious_query = "What suspicious activities, anomalies, or security concerns have been detected in this investigation?"
            suspicious_result = self.query(suspicious_query)

            # Generate suggestions
            prompt = self.SUGGESTIONS_PROMPT.format(findings=suspicious_result.answer)
            suggestions_text = self.llm(prompt)

            # Parse suggestions (basic parsing)
            suggestions = []
            lines = suggestions_text.strip().split("\n")

            current_suggestion = None
            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Check if it's a numbered suggestion
                if line[0].isdigit() and "." in line[:3]:
                    if current_suggestion:
                        suggestions.append(current_suggestion)

                    # Extract title
                    title = line.split(".", 1)[1].strip()
                    current_suggestion = InvestigationSuggestion(
                        title=title, description="", priority="medium"
                    )
                elif current_suggestion:
                    # Add to description
                    current_suggestion.description += line + " "

            if current_suggestion:
                suggestions.append(current_suggestion)

            self.logger.info(f"Generated {len(suggestions)} investigation suggestions")
            return suggestions

        except Exception as e:
            self.logger.error(f"Error generating suggestions: {e}")
            return []

    def generate_summary(self) -> CaseSummary:
        """
        Generate comprehensive case summary.

        Returns:
            CaseSummary object
        """
        try:
            # Gather context from multiple queries
            timeline_result = self.query("Summarize the key timeline events")
            iocs_result = self.query("List all IOCs and indicators of compromise detected")
            attck_result = self.query("What MITRE ATT&CK techniques were detected?")

            # Build comprehensive context
            context = f"""
Timeline Events:
{timeline_result.answer}

IOCs Detected:
{iocs_result.answer}

MITRE ATT&CK Techniques:
{attck_result.answer}
"""

            # Generate executive summary
            prompt = self.SUMMARY_PROMPT.format(context=context)
            summary_text = self.llm(prompt)

            # Parse summary (basic parsing)
            summary = CaseSummary(
                case_id=self.case_id,
                executive_summary=summary_text.strip(),
                timeline_summary=timeline_result.answer,
                key_findings=[],
                attck_techniques=[],
                recommendations=[],
            )

            # Extract IOCs
            for source in iocs_result.sources:
                if source.metadata.get("type") == "ioc":
                    summary.iocs_detected.append(
                        {
                            "type": source.metadata.get("ioc_type", "unknown"),
                            "value": source.metadata.get("value", "N/A"),
                            "severity": source.metadata.get("severity", "unknown"),
                        }
                    )

            self.logger.info(f"Generated case summary for {self.case_id}")
            return summary

        except Exception as e:
            self.logger.error(f"Error generating summary: {e}")
            return CaseSummary(
                case_id=self.case_id, executive_summary=f"Error generating summary: {e}"
            )

    def search_similar(self, text: str, top_k: int = 5) -> List[SourceDocument]:
        """
        Search for similar documents using vector similarity.

        Args:
            text: Text to search for
            top_k: Number of results to return

        Returns:
            List of similar source documents
        """
        try:
            docs = self.vectorstore.similarity_search(text, k=top_k)

            return [
                SourceDocument(
                    content=doc.page_content, metadata=doc.metadata, relevance_score=1.0 / (i + 1)
                )
                for i, doc in enumerate(docs)
            ]

        except Exception as e:
            self.logger.error(f"Error searching similar documents: {e}")
            return []

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get query engine statistics.

        Returns:
            Dictionary with statistics
        """
        try:
            collection = self.vectorstore._collection
            count = collection.count()

            return {
                "case_id": self.case_id,
                "document_count": count,
                "llm_type": self.config.get("llm_type", "ollama"),
                "embedding_model": self.config.get(
                    "embedding_model", "sentence-transformers/all-MiniLM-L6-v2"
                ),
                "vector_store_dir": self.vector_store_dir,
            }

        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {}

    @classmethod
    def load(cls, case_id: str, base_dir: str = None, config: Optional[Dict] = None):
        """
        Load existing query engine for a case.

        Args:
            case_id: Case identifier
            base_dir: Base directory containing cases (default: /opt/rowanholt/data)
            config: Optional configuration

        Returns:
            ForensicQueryEngine instance
        """
        if base_dir is None:
            base_dir = os.getenv("ROWANHOLT_DATA_DIR", "/opt/rowanholt/data")

        vector_store_dir = os.path.join(base_dir, case_id, "vector_db")

        if not os.path.exists(vector_store_dir):
            raise FileNotFoundError(
                f"Vector store not found for case {case_id} at {vector_store_dir}. "
                "Please index the case first using ForensicDataIndexer."
            )

        return cls(case_id, vector_store_dir, config)

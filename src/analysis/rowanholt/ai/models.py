#!/usr/bin/env python3
"""
AI Agent Data Models

Data structures for AI query results and metadata.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime


@dataclass
class SourceDocument:
    """
    Source document referenced in AI response.

    Attributes:
        content: Text content of the document
        metadata: Document metadata (type, timestamp, source, etc.)
        relevance_score: Similarity/relevance score (0.0 to 1.0)
    """

    content: str
    metadata: Dict[str, Any]
    relevance_score: float = 0.0

    def __str__(self) -> str:
        """String representation."""
        doc_type = self.metadata.get("type", "unknown")
        source = self.metadata.get("source", "unknown")
        return f"[{doc_type}] {source} (score: {self.relevance_score:.2f})"


@dataclass
class QueryResult:
    """
    Result of an AI query.

    Attributes:
        question: Original question asked
        answer: AI-generated answer
        sources: List of source documents used
        confidence: Confidence score (0.0 to 1.0)
        timestamp: When the query was executed
        processing_time: Time taken to process query (seconds)
        metadata: Additional metadata
    """

    question: str
    answer: str
    sources: List[SourceDocument] = field(default_factory=list)
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    processing_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "question": self.question,
            "answer": self.answer,
            "sources": [
                {
                    "content": src.content,
                    "metadata": src.metadata,
                    "relevance_score": src.relevance_score,
                }
                for src in self.sources
            ],
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "processing_time": self.processing_time,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QueryResult":
        """Create from dictionary."""
        sources = [
            SourceDocument(
                content=src["content"],
                metadata=src["metadata"],
                relevance_score=src.get("relevance_score", 0.0),
            )
            for src in data.get("sources", [])
        ]

        return cls(
            question=data["question"],
            answer=data["answer"],
            sources=sources,
            confidence=data.get("confidence", 0.0),
            timestamp=(
                datetime.fromisoformat(data["timestamp"]) if "timestamp" in data else datetime.now()
            ),
            processing_time=data.get("processing_time", 0.0),
            metadata=data.get("metadata", {}),
        )


@dataclass
class InvestigationSuggestion:
    """
    AI-generated investigation suggestion.

    Attributes:
        title: Suggestion title
        description: Detailed description
        priority: Priority level (high, medium, low)
        attck_techniques: Related MITRE ATT&CK techniques
        artifacts_to_check: List of artifact types to examine
        queries: Suggested queries to run
    """

    title: str
    description: str
    priority: str = "medium"
    attck_techniques: List[str] = field(default_factory=list)
    artifacts_to_check: List[str] = field(default_factory=list)
    queries: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "attck_techniques": self.attck_techniques,
            "artifacts_to_check": self.artifacts_to_check,
            "queries": self.queries,
        }


@dataclass
class CaseSummary:
    """
    AI-generated case summary.

    Attributes:
        case_id: Case identifier
        executive_summary: High-level summary
        key_findings: List of key findings
        timeline_summary: Summary of key timeline events
        iocs_detected: List of IOCs detected
        attck_techniques: MITRE ATT&CK techniques detected
        recommendations: Investigation recommendations
        generated_at: When summary was generated
    """

    case_id: str
    executive_summary: str
    key_findings: List[str] = field(default_factory=list)
    timeline_summary: str = ""
    iocs_detected: List[Dict[str, Any]] = field(default_factory=list)
    attck_techniques: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "case_id": self.case_id,
            "executive_summary": self.executive_summary,
            "key_findings": self.key_findings,
            "timeline_summary": self.timeline_summary,
            "iocs_detected": self.iocs_detected,
            "attck_techniques": self.attck_techniques,
            "recommendations": self.recommendations,
            "generated_at": self.generated_at.isoformat(),
        }

    def to_markdown(self) -> str:
        """Generate markdown report."""
        md = f"# Case Summary: {self.case_id}\n\n"
        md += f"**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        md += "## Executive Summary\n\n"
        md += f"{self.executive_summary}\n\n"

        if self.key_findings:
            md += "## Key Findings\n\n"
            for i, finding in enumerate(self.key_findings, 1):
                md += f"{i}. {finding}\n"
            md += "\n"

        if self.timeline_summary:
            md += "## Timeline Summary\n\n"
            md += f"{self.timeline_summary}\n\n"

        if self.iocs_detected:
            md += "## IOCs Detected\n\n"
            md += "| Type | Value | Severity |\n"
            md += "|------|-------|----------|\n"
            for ioc in self.iocs_detected:
                md += f"| {ioc.get('type', 'N/A')} | {ioc.get('value', 'N/A')} | {ioc.get('severity', 'N/A')} |\n"
            md += "\n"

        if self.attck_techniques:
            md += "## MITRE ATT&CK Techniques\n\n"
            for technique in self.attck_techniques:
                md += f"- {technique}\n"
            md += "\n"

        if self.recommendations:
            md += "## Recommendations\n\n"
            for i, rec in enumerate(self.recommendations, 1):
                md += f"{i}. {rec}\n"
            md += "\n"

        return md

"""
AI-Powered Analysis Agent Module

Provides AI capabilities for querying and analyzing forensic data using natural language.

Author: Dernvale DF Acceleration Suite
Version: 2.1.0
"""

from .indexer import ForensicDataIndexer
from .query_engine import ForensicQueryEngine
from .models import QueryResult, SourceDocument

__all__ = [
    "ForensicDataIndexer",
    "ForensicQueryEngine",
    "QueryResult",
    "SourceDocument",
]

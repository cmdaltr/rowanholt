#!/usr/bin/env python3
"""
Rowanholt AI Assistant CLI

Command-line interface for AI-powered forensic analysis.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import argparse
import sys
import os
import json
from pathlib import Path
from typing import Optional

from .indexer import ForensicDataIndexer
from .query_engine import ForensicQueryEngine
from .models import QueryResult


def index_case(args):
    """Index case data for AI querying."""
    print(f"[*] Indexing case {args.case_id}...")
    print(f"[*] Output directory: {args.output_dir}")

    # Configuration
    config = {"llm_type": args.llm_type, "model_name": args.model_name, "device": args.device}

    try:
        # Initialize indexer
        indexer = ForensicDataIndexer(args.case_id, args.output_dir, config)

        # Index based on provided files
        counts = {}

        if args.timeline:
            print(f"[*] Indexing timeline: {args.timeline}")
            counts["timeline"] = indexer.index_timeline(args.timeline)

        if args.iocs:
            print(f"[*] Indexing IOCs: {args.iocs}")
            counts["iocs"] = indexer.index_iocs(args.iocs)

        if args.processes:
            print(f"[*] Indexing processes: {args.processes}")
            counts["processes"] = indexer.index_processes(args.processes)

        if args.network:
            print(f"[*] Indexing network: {args.network}")
            counts["network"] = indexer.index_network(args.network)

        if args.registry:
            print(f"[*] Indexing registry: {args.registry}")
            counts["registry"] = indexer.index_registry(args.registry)

        if args.files:
            print(f"[*] Indexing files: {args.files}")
            counts["files"] = indexer.index_files(args.files)

        if args.cloud_logs:
            print(f"[*] Indexing cloud logs: {args.cloud_logs}")
            counts["cloud_logs"] = indexer.index_cloud_logs(args.cloud_logs, args.cloud_provider)

        # If no specific files provided, try to index all
        if not any(
            [
                args.timeline,
                args.iocs,
                args.processes,
                args.network,
                args.registry,
                args.files,
                args.cloud_logs,
            ]
        ):
            print(f"[*] Indexing all artifacts from {args.output_dir}")
            counts = indexer.index_all(args.output_dir)

        # Show results
        print("\n[+] Indexing complete!")
        print("\nIndexed documents:")
        for artifact_type, count in counts.items():
            print(f"  - {artifact_type}: {count} documents")

        # Show collection info
        info = indexer.get_collection_info()
        print(f"\nTotal documents in collection: {info.get('document_count', 0)}")
        print(f"Vector database: {info.get('vector_db_dir', 'N/A')}")

        return 0

    except Exception as e:
        print(f"[!] Error: {e}")
        return 1


def query_case(args):
    """Query case using AI."""
    try:
        # Configuration
        config = {
            "llm_type": args.llm_type,
            "model_name": args.model_name,
            "model_path": args.model_path,
            "temperature": args.temperature,
            "max_tokens": args.max_tokens,
        }

        # Load query engine
        print(f"[*] Loading query engine for case {args.case_id}...")
        engine = ForensicQueryEngine.load(args.case_id, args.base_dir, config)

        # Execute query
        print(f"\n[?] {args.question}\n")
        result = engine.query(args.question)

        # Display answer
        print(f"[AI] {result.answer}\n")

        # Display sources
        if result.sources and not args.no_sources:
            print("[Sources]")
            for i, source in enumerate(result.sources[:5], 1):
                source_type = source.metadata.get("type", "unknown")
                source_info = source.metadata.get("source", source.metadata.get("name", "N/A"))
                print(
                    f"{i}. [{source_type}] {source_info} (relevance: {source.relevance_score:.2f})"
                )

        # Show metadata
        if args.verbose:
            print(f"\n[Metadata]")
            print(f"Processing time: {result.processing_time:.2f}s")
            print(f"Documents retrieved: {result.metadata.get('documents_retrieved', 0)}")
            print(f"Confidence: {result.confidence:.2f}")

        # Save to file if requested
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result.to_dict(), f, indent=2)
            print(f"\n[+] Result saved to {args.output}")

        return 0

    except Exception as e:
        print(f"[!] Error: {e}")
        return 1


def summary_case(args):
    """Generate case summary."""
    try:
        # Configuration
        config = {
            "llm_type": args.llm_type,
            "model_name": args.model_name,
            "model_path": args.model_path,
        }

        # Load query engine
        print(f"[*] Loading query engine for case {args.case_id}...")
        engine = ForensicQueryEngine.load(args.case_id, args.base_dir, config)

        # Generate summary
        print(f"[*] Generating case summary...\n")
        summary = engine.generate_summary()

        # Display summary
        if args.format == "json":
            print(json.dumps(summary.to_dict(), indent=2))
        elif args.format == "markdown":
            print(summary.to_markdown())
        else:
            # Plain text
            print(f"Case Summary: {summary.case_id}")
            print("=" * 60)
            print(f"\n{summary.executive_summary}\n")

            if summary.key_findings:
                print("\nKey Findings:")
                for i, finding in enumerate(summary.key_findings, 1):
                    print(f"{i}. {finding}")

            if summary.attck_techniques:
                print(f"\nMITRE ATT&CK Techniques: {', '.join(summary.attck_techniques)}")

        # Save to file if requested
        if args.output:
            if args.format == "markdown":
                with open(args.output, "w") as f:
                    f.write(summary.to_markdown())
            else:
                with open(args.output, "w") as f:
                    json.dump(summary.to_dict(), f, indent=2)
            print(f"\n[+] Summary saved to {args.output}")

        return 0

    except Exception as e:
        print(f"[!] Error: {e}")
        return 1


def suggest_case(args):
    """Suggest investigation paths."""
    try:
        # Configuration
        config = {
            "llm_type": args.llm_type,
            "model_name": args.model_name,
            "model_path": args.model_path,
        }

        # Load query engine
        print(f"[*] Loading query engine for case {args.case_id}...")
        engine = ForensicQueryEngine.load(args.case_id, args.base_dir, config)

        # Generate suggestions
        print(f"[*] Generating investigation suggestions...\n")
        suggestions = engine.suggest_investigation_paths()

        # Display suggestions
        print("[Suggested Investigation Paths]\n")
        for i, suggestion in enumerate(suggestions, 1):
            print(f"{i}. {suggestion.title}")
            print(f"   Priority: {suggestion.priority}")
            if suggestion.description:
                print(f"   {suggestion.description[:200]}...")
            if suggestion.attck_techniques:
                print(f"   MITRE ATT&CK: {', '.join(suggestion.attck_techniques)}")
            print()

        # Save to file if requested
        if args.output:
            with open(args.output, "w") as f:
                json.dump([s.to_dict() for s in suggestions], f, indent=2)
            print(f"[+] Suggestions saved to {args.output}")

        return 0

    except Exception as e:
        print(f"[!] Error: {e}")
        return 1


def search_case(args):
    """Search for similar documents."""
    try:
        # Configuration
        config = {"llm_type": args.llm_type, "model_name": args.model_name}

        # Load query engine
        print(f"[*] Loading query engine for case {args.case_id}...")
        engine = ForensicQueryEngine.load(args.case_id, args.base_dir, config)

        # Search
        print(f"[*] Searching for: {args.query}\n")
        results = engine.search_similar(args.query, top_k=args.top_k)

        # Display results
        print(f"[Found {len(results)} similar documents]\n")
        for i, doc in enumerate(results, 1):
            print(
                f"{i}. [{doc.metadata.get('type', 'unknown')}] (score: {doc.relevance_score:.2f})"
            )
            print(f"   {doc.content[:200]}...")
            print()

        return 0

    except Exception as e:
        print(f"[!] Error: {e}")
        return 1


def info_case(args):
    """Show case information."""
    try:
        config = {}

        # Load query engine
        engine = ForensicQueryEngine.load(args.case_id, args.base_dir, config)

        # Get statistics
        stats = engine.get_statistics()

        # Display info
        print(f"\nCase Information: {stats['case_id']}")
        print("=" * 60)
        print(f"Documents indexed: {stats.get('document_count', 0)}")
        print(f"LLM type: {stats.get('llm_type', 'N/A')}")
        print(f"Embedding model: {stats.get('embedding_model', 'N/A')}")
        print(f"Vector store: {stats.get('vector_store_dir', 'N/A')}")

        return 0

    except Exception as e:
        print(f"[!] Error: {e}")
        return 1


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Rowanholt AI Assistant CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Index a case
  %(prog)s index CASE-001 /output/CASE-001 --timeline timeline.csv --iocs iocs.csv

  # Query a case
  %(prog)s query CASE-001 "What PowerShell commands were executed?"

  # Generate summary
  %(prog)s summary CASE-001 --format markdown --output summary.md

  # Get investigation suggestions
  %(prog)s suggest CASE-001

  # Search for similar documents
  %(prog)s search CASE-001 "suspicious PowerShell activity"
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Index command
    index_parser = subparsers.add_parser("index", help="Index case data for AI querying")
    index_parser.add_argument("case_id", help="Case ID")
    index_parser.add_argument("output_dir", help="Case output directory")
    index_parser.add_argument("--timeline", help="Timeline CSV file")
    index_parser.add_argument("--iocs", help="IOCs CSV file")
    index_parser.add_argument("--processes", help="Processes CSV file")
    index_parser.add_argument("--network", help="Network CSV file")
    index_parser.add_argument("--registry", help="Registry CSV file")
    index_parser.add_argument("--files", help="Files CSV file")
    index_parser.add_argument("--cloud-logs", help="Cloud logs JSON file")
    index_parser.add_argument(
        "--cloud-provider", choices=["aws", "azure", "gcp"], help="Cloud provider"
    )
    index_parser.add_argument(
        "--llm-type", default="ollama", choices=["ollama", "llamacpp"], help="LLM type"
    )
    index_parser.add_argument("--model-name", default="llama3", help="Model name (for ollama)")
    index_parser.add_argument(
        "--device", default="cpu", choices=["cpu", "cuda"], help="Device for embeddings"
    )

    # Query command
    query_parser = subparsers.add_parser("query", help="Query case using natural language")
    query_parser.add_argument("case_id", help="Case ID")
    query_parser.add_argument("question", help="Question to ask")
    query_parser.add_argument("--base-dir", default=None, help="Base directory for cases")
    query_parser.add_argument(
        "--llm-type", default="ollama", choices=["ollama", "llamacpp"], help="LLM type"
    )
    query_parser.add_argument("--model-name", default="llama3", help="Model name")
    query_parser.add_argument("--model-path", help="Model path (for llamacpp)")
    query_parser.add_argument("--temperature", type=float, default=0.1, help="LLM temperature")
    query_parser.add_argument("--max-tokens", type=int, default=2048, help="Max tokens to generate")
    query_parser.add_argument("--no-sources", action="store_true", help="Don't show sources")
    query_parser.add_argument("--output", "-o", help="Save result to file")
    query_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # Summary command
    summary_parser = subparsers.add_parser("summary", help="Generate case summary")
    summary_parser.add_argument("case_id", help="Case ID")
    summary_parser.add_argument("--base-dir", default=None, help="Base directory for cases")
    summary_parser.add_argument(
        "--llm-type", default="ollama", choices=["ollama", "llamacpp"], help="LLM type"
    )
    summary_parser.add_argument("--model-name", default="llama3", help="Model name")
    summary_parser.add_argument("--model-path", help="Model path (for llamacpp)")
    summary_parser.add_argument(
        "--format", default="text", choices=["text", "json", "markdown"], help="Output format"
    )
    summary_parser.add_argument("--output", "-o", help="Save summary to file")

    # Suggest command
    suggest_parser = subparsers.add_parser("suggest", help="Suggest investigation paths")
    suggest_parser.add_argument("case_id", help="Case ID")
    suggest_parser.add_argument("--base-dir", default=None, help="Base directory for cases")
    suggest_parser.add_argument(
        "--llm-type", default="ollama", choices=["ollama", "llamacpp"], help="LLM type"
    )
    suggest_parser.add_argument("--model-name", default="llama3", help="Model name")
    suggest_parser.add_argument("--model-path", help="Model path (for llamacpp)")
    suggest_parser.add_argument("--output", "-o", help="Save suggestions to file")

    # Search command
    search_parser = subparsers.add_parser("search", help="Search for similar documents")
    search_parser.add_argument("case_id", help="Case ID")
    search_parser.add_argument("query", help="Search query")
    search_parser.add_argument("--base-dir", default=None, help="Base directory for cases")
    search_parser.add_argument("--llm-type", default="ollama", help="LLM type")
    search_parser.add_argument("--model-name", default="llama3", help="Model name")
    search_parser.add_argument("--top-k", type=int, default=5, help="Number of results")

    # Info command
    info_parser = subparsers.add_parser("info", help="Show case information")
    info_parser.add_argument("case_id", help="Case ID")
    info_parser.add_argument("--base-dir", default=None, help="Base directory for cases")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Route to command handler
    if args.command == "index":
        return index_case(args)
    elif args.command == "query":
        return query_case(args)
    elif args.command == "summary":
        return summary_case(args)
    elif args.command == "suggest":
        return suggest_case(args)
    elif args.command == "search":
        return search_case(args)
    elif args.command == "info":
        return info_case(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())

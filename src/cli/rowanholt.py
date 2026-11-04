#!/usr/bin/env python3
"""
Rowanholt - Unified Digital Forensics Suite
Combining Gandalf (acquisition) and Elrond (analysis)

Usage:
    rowanholt acquire [options]   - Acquire forensic artifacts (Gandalf)
    rowanholt analyze [options]   - Analyze forensic artifacts (Elrond)
    rowanholt web [options]        - Start web interface
    rowanholt anduril [command]    - Administer Rowanholt's Docker containers (Anduril)
    rowanholt --version            - Show version
    rowanholt --help               - Show help
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Gandalf and Elrond both parse arguments at import time, so they run as
# subprocesses. src/analysis is deliberately kept off sys.path: its platform/
# package would shadow the stdlib module of the same name.
ROWANHOLT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))  # anduril_cli

VERSION = "2.0.0"

def print_banner():
    """Print Rowanholt banner"""
    banner = r"""
    ____                                    _
   |  _ \   ___  _ __  _ __  __   __  __ _ | |  ___
   | | | | / _ \| '__|| '_ \ \ \ / / / _` || | / _ \
   | |_| ||  __/| |   | | | | \ V / | (_| || ||  __/
   |____/  \___||_|   |_| |_|  \_/   \__,_||_| \___|

   Digital Forensics Suite - Acquisition & Analysis
   Version {}

   Gandalf: Remote Forensic Acquisition
   Elrond:  Automated Forensic Analysis
""".format(VERSION)
    print(banner)


def cmd_acquire(args):
    """Run Gandalf acquisition"""
    print("[*] Starting Gandalf acquisition module...")

    # gandalf.py parses its arguments at import time, so run it as its own process.
    gandalf_py = ROWANHOLT_ROOT / "acquisition" / "python" / "gandalf.py"
    if not gandalf_py.exists():
        print(f"[ERROR] Gandalf not found at {gandalf_py}")
        return 1
    cmd = [sys.executable, str(gandalf_py), args.encryption, args.mode]
    if args.output:
        cmd.extend(["-O", args.output])
    if args.memory:
        cmd.append("-M")
    if args.access_times:
        cmd.append("-A")
    if args.collect_files:
        cmd.append("-F")  # gandalf.py's flag for --CollectFiles
    print(f"[*] {' '.join(cmd)}")
    return subprocess.call(cmd, cwd=str(gandalf_py.parent))


def cmd_analyze(args):
    """Run Elrond analysis"""
    print("[*] Starting Elrond analysis module...")

    # Elrond parses its arguments at import time, so run it as its own process
    # (which also keeps the analysis tools behind a subprocess boundary).
    elrond_py = ROWANHOLT_ROOT / "analysis" / "elrond.py"
    if not elrond_py.exists():
        print(f"[ERROR] Elrond not found at {elrond_py}")
        return 1
    cmd = [sys.executable, str(elrond_py), args.case_id, args.evidence_path]
    if args.output:
        cmd.append(args.output)
    for enabled, flag in (
        (args.collect, "--Collect"),
        (args.process, "--Process"),
        (args.analyze, "--Analysis"),
        (args.splunk, "--Splunk"),
        (args.elastic, "--Elastic"),
        (args.brisk, "--Brisk"),
    ):
        if enabled:
            cmd.append(flag)
    print(f"[*] {' '.join(cmd)}")
    return subprocess.call(cmd, cwd=str(ROWANHOLT_ROOT / "analysis"))


def cmd_web(args):
    """Start web interface"""
    print("[*] Starting Rowanholt web interface...")

    try:
        import uvicorn
        from web.backend.main import app

        host = args.host or "0.0.0.0"
        port = args.port or 8000

        print(f"[+] Starting server on {host}:{port}")
        print(f"[+] API documentation: http://{host}:{port}/docs")

        uvicorn.run(
            "web.backend.main:app",
            host=host,
            port=port,
            reload=args.reload,
            log_level="info"
        )

    except ImportError as e:
        print(f"[ERROR] Failed to import web dependencies: {e}")
        print("[*] Install web dependencies: pip install -r requirements/web.txt")
        return 1

    return 0


def main():
    """Main entry point"""

    parser = argparse.ArgumentParser(
        description="Rowanholt - Digital Forensics Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Acquire from local system with encryption
  rowanholt acquire Password Local -m -o /evidence

  # Analyze acquired evidence
  rowanholt analyze CASE-001 /evidence/hostname.tar.gz /output -CPA

  # Start web interface
  rowanholt web --port 8000

  # Rowanholt containers, and enabling Docker administration in the web UI
  rowanholt anduril status
  rowanholt anduril enable

  # Use individual tools directly:
  python3 acquisition/python/gandalf.py Password Local -M
  python3 analysis/elrond.py CASE-001 /evidence /output -CPAS
        """
    )

    parser.add_argument('--version', action='version', version=f'Rowanholt {VERSION}')

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Acquire command (Gandalf)
    acquire_parser = subparsers.add_parser('acquire', help='Acquire forensic artifacts')
    acquire_parser.add_argument('encryption', choices=['Key', 'Password', 'None'],
                               help='Encryption method')
    acquire_parser.add_argument('mode', choices=['Local', 'Remote'],
                               help='Acquisition mode')
    acquire_parser.add_argument('-o', '--output', help='Output directory')
    acquire_parser.add_argument('-m', '--memory', action='store_true',
                               help='Acquire memory dump')
    acquire_parser.add_argument('-a', '--access-times', action='store_true',
                               help='Collect access times')
    acquire_parser.add_argument('-c', '--collect-files', action='store_true',
                               help='Collect specific files')
    acquire_parser.set_defaults(func=cmd_acquire)

    # Analyze command (Elrond)
    analyze_parser = subparsers.add_parser('analyze', help='Analyze forensic artifacts')
    analyze_parser.add_argument('case_id', help='Case identifier')
    analyze_parser.add_argument('evidence_path', help='Path to evidence file/directory')
    analyze_parser.add_argument('output', nargs='?', help='Output directory')
    analyze_parser.add_argument('-C', '--collect', action='store_true',
                               help='Collection phase')
    analyze_parser.add_argument('-P', '--process', action='store_true',
                               help='Processing phase')
    analyze_parser.add_argument('-A', '--analyze', action='store_true',
                               help='Analysis phase')
    analyze_parser.add_argument('-S', '--splunk', action='store_true',
                               help='Export to Splunk')
    analyze_parser.add_argument('-E', '--elastic', action='store_true',
                               help='Export to Elasticsearch')
    analyze_parser.add_argument('-B', '--brisk', action='store_true',
                               help='Brisk mode (quick analysis)')
    analyze_parser.set_defaults(func=cmd_analyze)

    # Web command
    web_parser = subparsers.add_parser('web', help='Start web interface')
    web_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    web_parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    web_parser.add_argument('--reload', action='store_true', help='Auto-reload on changes')
    web_parser.set_defaults(func=cmd_web)

    # Anduril command (Docker administration; `aragorn` is an alias)
    from anduril_cli import add_parser as add_anduril_parser

    add_anduril_parser(subparsers)

    # Parse args
    args = parser.parse_args()

    # Print banner
    print_banner()

    # Execute command
    if hasattr(args, 'func'):
        return args.func(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())

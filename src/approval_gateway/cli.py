"""Offline CLI: no service, listener, credentials, or remote connector required."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .demo import run_demo
from .models import GatewayError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the synthetic tool-approval decision demo entirely offline.")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="Generate an interactive HTML report, JSON evidence, and local simulator database")
    demo.add_argument("--output-dir", type=Path, default=Path("artifacts/demo"), help="New evidence directory (default: artifacts/demo)")
    args = parser.parse_args(argv)
    try:
        result = run_demo(args.output_dir.resolve())
    except (GatewayError, OSError) as error:
        print(f"Demo refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0

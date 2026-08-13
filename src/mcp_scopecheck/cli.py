"""Command-line interface for MCP ScopeCheck."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .auditor import audit
from .models import Severity
from .parser import ParseTargetError
from .render import render_report


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-scopecheck",
        description="Compare MCP tool claims with statically reachable Python behavior.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit_parser = subparsers.add_parser(
        "audit",
        help="audit a local Python file or directory without executing it",
    )
    audit_parser.add_argument("target", help="local Python file or source directory")
    audit_parser.add_argument(
        "--fail-on",
        type=_severity,
        default=Severity.LOW,
        metavar="SEVERITY",
        help="exit 1 at or above: low, medium, high, critical (default: low)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "audit":
        parser.error("a command is required")

    try:
        report = audit(args.target)
    except (OSError, ParseTargetError) as exc:
        print(f"mcp-scopecheck: {exc}", file=sys.stderr)
        return 2

    print(render_report(report))
    if report.diagnostics:
        print("mcp-scopecheck: audit incomplete because diagnostics were reported", file=sys.stderr)
        return 2
    if not report.tools:
        print("mcp-scopecheck: no supported MCP tool decorators were found", file=sys.stderr)
        return 2
    return 1 if report.findings_at_or_above(args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())

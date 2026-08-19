"""Command-line interface for MCP ScopeCheck."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .auditor import audit
from .models import AnalysisStatus, AuditReport, Severity
from .parser import ParseTargetError
from .render import escape_terminal_text, render_report
from .sarif import render_sarif, render_sarif_failure


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
    audit_parser.add_argument(
        "--format",
        choices=("text", "sarif"),
        default="text",
        dest="output_format",
        help="report format: text (default) or sarif",
    )
    return parser


def _exit_code(report: AuditReport, threshold: Severity) -> int:
    if report.completeness.status is not AnalysisStatus.COMPLETE:
        return 2
    return 1 if report.findings_at_or_above(threshold) else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "audit":
        parser.error("a command is required")

    try:
        report = audit(args.target)
    except (OSError, ParseTargetError) as exc:
        if args.output_format == "sarif":
            print(render_sarif_failure(args.target, exc))
            return 2
        print(f"mcp-scopecheck: {escape_terminal_text(exc)}", file=sys.stderr)
        return 2

    exit_code = _exit_code(report, args.fail_on)
    if args.output_format == "sarif":
        print(render_sarif(report, exit_code))
        return exit_code

    print(render_report(report))
    if exit_code == 2:
        if report.diagnostics:
            message = (
                "mcp-scopecheck: audit incomplete because diagnostics were reported "
                f"(status: {report.completeness.status.value})"
            )
        elif not report.tools and not report.completeness.potential_registrations:
            message = "mcp-scopecheck: no supported MCP tool decorators were found"
        else:
            message = (
                f"mcp-scopecheck: audit {report.completeness.status.value}; "
                "review completeness"
            )
        print(message, file=sys.stderr)
        return 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

"""Analysis-completeness and unresolved-edge regressions."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from mcp_scopecheck.auditor import audit
from mcp_scopecheck.cli import main
from mcp_scopecheck.models import AnalysisStatus, UnresolvedReason
from mcp_scopecheck.render import render_report


def _write(root: Path, source: str) -> None:
    (root / "server.py").write_text(source, encoding="utf-8")


def _invoke(root: Path) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(["audit", str(root)])
    return code, stdout.getvalue(), stderr.getvalue()


class CompletenessTests(unittest.TestCase):
    def test_same_file_edges_are_resolved_deduplicated_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(
                root,
                "\n".join(
                    [
                        "def helper():",
                        "    return 'ok'",
                        "@mcp.tool()",
                        "def entry():",
                        "    helper()",
                        "    return helper()",
                    ]
                ),
            )
            report = audit(root)

        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)
        self.assertEqual(len(report.completeness.resolved_edges), 2)
        self.assertEqual(report.completeness.unresolved_edges, [])
        self.assertTrue(
            all(edge.target_symbol == "helper" for edge in report.completeness.resolved_edges)
        )

    def test_supported_unresolved_reason_categories_make_analysis_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(
                root,
                "\n".join(
                    [
                        "import importlib",
                        "from helpers import *",
                        "@audit_wrapper",
                        "@mcp.tool()",
                        "def entry(callback):",
                        "    importlib.import_module('computed_' + 'module')",
                        "    callback()",
                        "    return 1",
                    ]
                ),
            )
            report = audit(root)

        reasons = {edge.reason for edge in report.completeness.unresolved_edges}
        self.assertEqual(report.completeness.status, AnalysisStatus.PARTIAL)
        self.assertEqual(
            reasons,
            {
                UnresolvedReason.DYNAMIC_IMPORT,
                UnresolvedReason.HIGHER_ORDER_CALL,
                UnresolvedReason.WILDCARD_IMPORT,
                UnresolvedReason.WRAPPER_INDIRECTION,
            },
        )

    def test_instance_dispatch_is_explicitly_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(
                root,
                "@mcp.tool()\ndef entry(self):\n    return self.operation()\n",
            )
            report = audit(root)

        self.assertEqual(report.completeness.status, AnalysisStatus.PARTIAL)
        self.assertEqual(
            [edge.reason for edge in report.completeness.unresolved_edges],
            [UnresolvedReason.UNSUPPORTED_INSTANCE_DISPATCH],
        )

    def test_potential_registration_forms_are_counted_but_not_claimed_analyzed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(
                root,
                "\n".join(
                    [
                        "@server.list_tools()",
                        "def list_tools():",
                        "    return [Tool(name='one'), Tool(name='two')]",
                        "mcp.add_tool(operation)",
                        "class Service:",
                        "    def setup(self):",
                        "        @self.mcp.tool()",
                        "        def nested():",
                        "            return 1",
                    ]
                ),
            )
            report = audit(root)
            code, output, _ = _invoke(root)

        self.assertEqual(report.completeness.status, AnalysisStatus.PARTIAL)
        self.assertEqual(report.completeness.supported_registrations, 0)
        self.assertEqual(report.completeness.unresolved_registrations, 4)
        self.assertEqual(code, 2)
        self.assertIn("Potential unsupported MCP registrations (4)", output)

    def test_exit_code_two_precedes_findings_for_partial_and_failed_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(
                root,
                "\n".join(
                    [
                        "import subprocess",
                        "@audit_wrapper",
                        "@mcp.tool()",
                        "def entry():",
                        "    return subprocess.run(['fixed'])",
                    ]
                ),
            )
            partial_code, partial_output, _ = _invoke(root)
            self.assertEqual(partial_code, 2)
            self.assertIn("[CRITICAL] MSC106", partial_output)
            self.assertIn("Completeness (partial)", partial_output)

            (root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
            failed_code, failed_output, _ = _invoke(root)

        self.assertEqual(failed_code, 2)
        self.assertIn("[CRITICAL] MSC106", failed_output)
        self.assertIn("Completeness (failed)", failed_output)

    def test_unresolved_edge_budget_fails_closed_and_never_executes_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / "executed.txt"
            _write(
                root,
                "\n".join(
                    [
                        "import importlib",
                        f"open({str(sentinel)!r}, 'w').write('executed')",
                        "@mcp.tool()",
                        "def entry(callback):",
                        "    callback()",
                        "    callback()",
                        "    return importlib.import_module('dynamic_name')",
                    ]
                ),
            )
            with patch("mcp_scopecheck.analyzer.MAX_UNRESOLVED_LOCAL_EDGES", 1):
                report = audit(root)

        self.assertEqual(report.completeness.status, AnalysisStatus.FAILED)
        self.assertTrue(report.completeness.notifications)
        self.assertFalse(sentinel.exists())

    def test_untrusted_ledger_text_is_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(
                root,
                "@mcp.tool()\ndef entry(callback):\n    return callback()\n",
            )
            report = audit(root)
            edge = report.completeness.unresolved_edges[0]
            report.completeness.unresolved_edges[0] = replace(
                edge,
                candidate="bad\n\x1b[2J\u202e",
            )
            rendered = render_report(report)

        self.assertIn("bad\\u000A\\u001B[2J\\u202E", rendered)
        self.assertNotIn("\x1b", rendered)


if __name__ == "__main__":
    unittest.main()

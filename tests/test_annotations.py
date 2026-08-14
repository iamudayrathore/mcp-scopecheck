"""MCP annotation normalization and contract-semantics tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_scopecheck.auditor import audit
from mcp_scopecheck.models import AuditReport, Severity
from mcp_scopecheck.render import render_report


def _audit_source(root: Path, source: str) -> AuditReport:
    (root / "server.py").write_text(source, encoding="utf-8")
    return audit(root)


class AnnotationSemanticsTests(unittest.TestCase):
    def test_snake_and_camel_case_hints_normalize_identically(self) -> None:
        camel_source = "\n".join(
            [
                "@mcp.tool(annotations=ToolAnnotations(",
                "    readOnlyHint=True,",
                "    destructiveHint=False,",
                "    idempotentHint=True,",
                "    openWorldHint=False,",
                "))",
                "def inspect_value():",
                "    return 'ok'",
            ]
        )
        snake_source = camel_source.replace("OnlyH", "_only_h")
        snake_source = snake_source.replace("destructiveH", "destructive_h")
        snake_source = snake_source.replace("idempotentH", "idempotent_h")
        snake_source = snake_source.replace("openWorldH", "open_world_h")

        with tempfile.TemporaryDirectory() as first_directory:
            with tempfile.TemporaryDirectory() as second_directory:
                camel_report = _audit_source(Path(first_directory), camel_source)
                snake_report = _audit_source(Path(second_directory), snake_source)

        expected = {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
        self.assertEqual(camel_report.diagnostics, [])
        self.assertEqual(snake_report.diagnostics, [])
        self.assertEqual(camel_report.tools[0].annotations, expected)
        self.assertEqual(snake_report.tools[0].annotations, expected)
        self.assertEqual(camel_report.snapshot, snake_report.snapshot)
        claims = (
            "Claims:      readOnlyHint=true, destructiveHint=false, "
            "idempotentHint=true, openWorldHint=false"
        )
        self.assertIn(claims, render_report(camel_report))
        self.assertIn(claims, render_report(snake_report))

    def test_conflicting_aliases_are_invalidated_deterministically(self) -> None:
        first_source = (
            "@mcp.tool(annotations={"
            "'readOnlyHint': True, 'read_only_hint': False, 'custom': 1})\n"
            "def example():\n"
            "    return None\n"
        )
        second_source = (
            "@mcp.tool(annotations={"
            "'read_only_hint': False, 'custom': 1, 'readOnlyHint': True})\n"
            "def example():\n"
            "    return None\n"
        )
        with tempfile.TemporaryDirectory() as first_directory:
            with tempfile.TemporaryDirectory() as second_directory:
                first = _audit_source(Path(first_directory), first_source)
                second = _audit_source(Path(second_directory), second_source)

        expected_message = (
            "invalid tool metadata: conflicting annotation aliases for "
            "'readOnlyHint': readOnlyHint=True, read_only_hint=False"
        )
        self.assertEqual(first.tools[0].annotations, {"custom": 1})
        self.assertEqual(second.tools[0].annotations, {"custom": 1})
        self.assertEqual([item.message for item in first.diagnostics], [expected_message])
        self.assertEqual([item.message for item in second.diagnostics], [expected_message])

    def test_only_known_mutating_http_methods_conflict_with_read_only(self) -> None:
        methods = ("get", "head", "options", "request", "post", "put", "patch", "delete")
        source = ["import httpx"]
        for method in methods:
            source.extend(
                [
                    "@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))",
                    f"def {method}_operation():",
                    f"    return httpx.{method}('https://example.invalid')",
                ]
            )
        with tempfile.TemporaryDirectory() as directory:
            report = _audit_source(Path(directory), "\n".join(source))

        read_only_conflicts = {
            finding.tool_name
            for finding in report.findings
            if finding.rule_id == "MSC101"
        }
        self.assertEqual(
            read_only_conflicts,
            {"post_operation", "put_operation", "patch_operation", "delete_operation"},
        )

    def test_closed_world_egress_is_distinct_from_read_only_conflict(self) -> None:
        source = "\n".join(
            [
                "import httpx",
                "@mcp.tool(annotations=ToolAnnotations(",
                "    read_only_hint=True, open_world_hint=False",
                "))",
                "def fetch():",
                "    return httpx.get('https://example.invalid')",
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            report = _audit_source(Path(directory), source)

        self.assertNotIn("MSC101", {finding.rule_id for finding in report.findings})
        closed_world = [
            finding for finding in report.findings if finding.rule_id == "MSC108"
        ]
        self.assertEqual(len(closed_world), 1)
        self.assertEqual(closed_world[0].severity, Severity.HIGH)
        self.assertEqual(
            closed_world[0].title,
            "Closed-world claim conflicts with network egress",
        )


if __name__ == "__main__":
    unittest.main()

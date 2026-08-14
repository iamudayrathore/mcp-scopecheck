"""Security-boundary tests for human-readable output."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from mcp_scopecheck.cli import main
from mcp_scopecheck.models import (
    AuditReport,
    Capability,
    Diagnostic,
    Evidence,
    Finding,
    ObservedCapability,
    Parameter,
    Severity,
    ToolDefinition,
)
from mcp_scopecheck.render import escape_terminal_text, render_report


class RenderSecurityTests(unittest.TestCase):
    def test_escape_terminal_text_neutralizes_controls_and_preserves_unicode(self) -> None:
        controls = "".join(chr(codepoint) for codepoint in range(0x20))
        controls += "".join(chr(codepoint) for codepoint in range(0x7F, 0xA0))
        controls += "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
        controls += "\u2028\u2029\u2066\u2067\u2068\u2069\ud800"

        escaped = escape_terminal_text(f"café 工具 {controls}")

        self.assertIn("café 工具", escaped)
        self.assertIn("\\u0000", escaped)
        self.assertIn("\\u001B", escaped)
        self.assertIn("\\u007F", escaped)
        self.assertIn("\\u0085", escaped)
        self.assertIn("\\u202E", escaped)
        self.assertIn("\\u2069", escaped)
        self.assertIn("\\uD800", escaped)
        self.assertFalse(any(character in escaped for character in controls))

    def test_report_fields_cannot_inject_or_reorder_output(self) -> None:
        tool = ToolDefinition(
            name="scan\x1b[2J\nFindings (0)\rspoof",
            function_name="scan\u202e",
            description="ordinary café 工具\x00\t\u0085\u202e hidden",
            source_file="evil\rname.py",
            line_number=7,
            end_line=9,
            parameters=(Parameter("path\u2066"),),
            annotations={"readOnlyHint": True},
        )
        evidence = Evidence(
            source_file="evil\rname.py",
            line_number=8,
            symbol="client.post\x1b[31m",
            detail="detail\nforged",
        )
        capability = ObservedCapability(Capability.NETWORK_EGRESS, evidence)
        finding = Finding(
            rule_id="MSC999",
            title="Unsafe\nFindings (0)",
            severity=Severity.HIGH,
            tool_name=tool.name,
            message="why\x00\r\nFindings (0)",
            remediation="fix\tthis\u202e",
            evidence=evidence,
        )
        report = AuditReport(
            target=Path("café/工具\x1b[2J"),
            files_scanned=1,
            tools=[tool],
            capabilities={tool.key: [capability]},
            findings=[finding],
            diagnostics=[Diagnostic("bad\u202efile.py", "parse\nerror\x00")],
            snapshot="0" * 64,
        )

        rendered = render_report(report)

        self.assertIn("café/工具", rendered)
        self.assertIn("\\u001B[2J", rendered)
        self.assertIn("\\u0000", rendered)
        self.assertIn("\\u0009", rendered)
        self.assertIn("\\u000AFindings (0)", rendered)
        self.assertIn("\\u000D", rendered)
        self.assertIn("\\u202E", rendered)
        self.assertIn("\\u2066", rendered)
        for forbidden in ("\x00", "\x1b", "\r", "\t", "\x85", "\u202e", "\u2066"):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(
            [line for line in rendered.splitlines() if line.startswith("Findings (")],
            ["Findings (1)"],
        )

    def test_cli_errors_escape_hostile_target_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = f"{directory}/missing\x1b[2J\nFindings (0)\u202e"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["audit", target])

        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout.getvalue(), "")
        error = stderr.getvalue()
        self.assertIn("\\u001B[2J\\u000AFindings (0)\\u202E", error)
        self.assertNotIn("\x1b", error)
        self.assertNotIn("\u202e", error)
        self.assertEqual(len(error.splitlines()), 1)


if __name__ == "__main__":
    unittest.main()

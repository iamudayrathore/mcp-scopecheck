"""CLI threshold and audit-error contract tests."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mcp_scopecheck.cli import main


def invoke(arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()


class CliTests(unittest.TestCase):
    def test_fail_on_threshold_changes_exit_for_high_only_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "read.py").write_text(
                "\n".join(
                    [
                        "@mcp.tool()",
                        "def read(path: str):",
                        "    return open(path).read()",
                    ]
                ),
                encoding="utf-8",
            )
            high_code, high_output, _ = invoke(
                ["audit", "--fail-on", "high", str(root)]
            )
            critical_code, critical_output, _ = invoke(
                ["audit", "--fail-on", "critical", str(root)]
            )

        self.assertEqual(high_code, 1)
        self.assertEqual(critical_code, 0)
        self.assertIn("[HIGH] MSC103", high_output)
        self.assertEqual(high_output, critical_output)

    def test_missing_target_and_no_supported_tools_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing_code, _, missing_error = invoke(["audit", str(root / "missing")])
            (root / "plain.py").write_text("value = 1\n", encoding="utf-8")
            empty_code, empty_output, empty_error = invoke(["audit", str(root)])

        self.assertEqual(missing_code, 2)
        self.assertIn("target does not exist", missing_error)
        self.assertEqual(empty_code, 2)
        self.assertIn("Surface:      0 MCP tool(s) discovered", empty_output)
        self.assertIn("no supported MCP tool decorators", empty_error)

    def test_visible_diagnostics_make_the_audit_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "valid.py").write_text(
                "@mcp.tool()\ndef valid():\n    return 'ok'\n",
                encoding="utf-8",
            )
            (root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
            code, output, error = invoke(["audit", str(root)])

        self.assertEqual(code, 2)
        self.assertIn("Diagnostics (1)", output)
        self.assertIn("audit incomplete because diagnostics were reported", error)

    def test_internal_failures_are_not_mislabeled_as_target_errors(self) -> None:
        with patch("mcp_scopecheck.cli.audit", side_effect=RuntimeError("internal failure")):
            with self.assertRaisesRegex(RuntimeError, "internal failure"):
                invoke(["audit", "."])


if __name__ == "__main__":
    unittest.main()

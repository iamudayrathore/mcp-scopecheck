"""Total-work budgets and explicit symlink-policy regressions."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mcp_scopecheck.cli import main
from mcp_scopecheck.parser import ParseTargetError, parse_project


class ResourceLimitTests(unittest.TestCase):
    def test_total_source_byte_limit_stops_with_stable_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = "value = 'first'\n"
            (root / "a.py").write_text(first, encoding="utf-8")
            (root / "b.py").write_text("value = 'second'\n", encoding="utf-8")
            with patch(
                "mcp_scopecheck.parser.MAX_TOTAL_SOURCE_BYTES",
                len(first.encode("utf-8")) + 1,
            ):
                project = parse_project(root)

        self.assertEqual(project.files_scanned, 1)
        self.assertEqual(len(project.diagnostics), 1)
        self.assertEqual(
            project.diagnostics[0].message,
            "analysis incomplete: total Python source bytes exceed limit of 17",
        )

    def test_total_ast_node_limit_stops_before_reporting_a_clean_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.py").write_text(
                "@mcp.tool()\ndef example(value: str):\n    return value\n",
                encoding="utf-8",
            )
            with patch("mcp_scopecheck.parser.MAX_TOTAL_AST_NODES", 5):
                project = parse_project(root)

        self.assertEqual(project.tools, [])
        self.assertEqual(len(project.diagnostics), 1)
        self.assertEqual(
            project.diagnostics[0].message,
            "analysis incomplete: total AST node count exceeds limit of 5",
        )

    def test_ast_depth_limit_is_iterative_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expression = "root" + ".child" * 20
            (root / "deep.py").write_text(f"value = {expression}\n", encoding="utf-8")
            with patch("mcp_scopecheck.parser.MAX_AST_DEPTH", 8):
                project = parse_project(root)

        self.assertEqual(len(project.diagnostics), 1)
        self.assertEqual(
            project.diagnostics[0].message,
            "analysis incomplete: AST depth exceeds limit of 8",
        )

    def test_diagnostic_collection_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(4):
                (root / f"broken_{index}.py").write_text("def broken(:\n", encoding="utf-8")
            with patch("mcp_scopecheck.parser.MAX_DIAGNOSTICS", 2):
                project = parse_project(root)

        self.assertEqual(len(project.diagnostics), 2)
        self.assertEqual(project.diagnostics[-1].source_file, "<target>")
        self.assertEqual(
            project.diagnostics[-1].message,
            "analysis incomplete: diagnostic limit of 2 reached",
        )

    def test_budget_diagnostic_makes_cli_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.py").write_text(
                "@mcp.tool()\ndef example():\n    return None\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch("mcp_scopecheck.parser.MAX_TOTAL_AST_NODES", 1):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    exit_code = main(["audit", str(root)])

        self.assertEqual(exit_code, 2)
        self.assertIn(
            "analysis incomplete: total AST node count exceeds limit of 1",
            stdout.getvalue(),
        )
        self.assertIn("audit incomplete because diagnostics were reported", stderr.getvalue())

    def test_in_root_directory_symlink_to_outside_is_never_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "target"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "inside.py").write_text(
                "@mcp.tool()\ndef inside():\n    return 'inside'\n",
                encoding="utf-8",
            )
            (outside / "outside.py").write_text(
                "@mcp.tool()\ndef outside():\n    return 'outside'\n",
                encoding="utf-8",
            )
            link = root / "linked"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")

            project = parse_project(root)

            self.assertEqual(project.files_scanned, 1)
            self.assertEqual([tool.name for tool in project.tools], ["inside"])
            with self.assertRaisesRegex(ParseTargetError, "must not be a symlink"):
                parse_project(link)


if __name__ == "__main__":
    unittest.main()

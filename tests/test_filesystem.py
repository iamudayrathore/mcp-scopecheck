"""Qualified filesystem-call and mode-classification regressions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_scopecheck.auditor import audit
from mcp_scopecheck.models import AuditReport, Capability


def _audit_source(source: str) -> AuditReport:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "server.py").write_text(source, encoding="utf-8")
        return audit(root)


def _filesystem_capabilities(report: AuditReport, tool_name: str) -> set[Capability]:
    tool = next(tool for tool in report.tools if tool.name == tool_name)
    return {
        item.capability
        for item in report.capabilities[tool.key]
        if item.capability in {Capability.FILESYSTEM_READ, Capability.FILESYSTEM_WRITE}
    }


class FilesystemClassificationTests(unittest.TestCase):
    def test_unrelated_method_names_are_not_filesystem_operations(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import webbrowser",
                    "@mcp.tool()",
                    "def unrelated(value: str, obj):",
                    "    value.replace('old', 'new')",
                    "    webbrowser.open('https://example.invalid')",
                    "    obj.open()",
                    "    obj.read()",
                    "    obj.write('value')",
                    "    obj.read_text()",
                    "    return obj.replace('old', 'new')",
                ]
            )
        )

        self.assertEqual(_filesystem_capabilities(report, "unrelated"), set())
        self.assertNotIn("MSC103", {finding.rule_id for finding in report.findings})

    def test_builtin_open_static_modes_and_dynamic_lower_bound(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import builtins",
                    "from io import open as io_open",
                    "@mcp.tool()",
                    "def default_read(path: str):",
                    "    return open(path)",
                    "@mcp.tool()",
                    "def binary_read(path: str):",
                    "    return builtins.open(path, 'rb')",
                    "@mcp.tool()",
                    "def static_writes(path: str):",
                    "    open(path, 'w')",
                    "    open(path, mode='a')",
                    "    open(path, 'x')",
                    "    return io_open(path, 'r+')",
                    "@mcp.tool()",
                    "def dynamic_mode(path: str, mode: str):",
                    "    return open(path, mode)",
                ]
            )
        )

        self.assertEqual(
            _filesystem_capabilities(report, "default_read"),
            {Capability.FILESYSTEM_READ},
        )
        self.assertEqual(
            _filesystem_capabilities(report, "binary_read"),
            {Capability.FILESYSTEM_READ},
        )
        self.assertEqual(
            _filesystem_capabilities(report, "static_writes"),
            {Capability.FILESYSTEM_WRITE},
        )
        self.assertEqual(
            _filesystem_capabilities(report, "dynamic_mode"),
            {Capability.FILESYSTEM_READ},
        )

    def test_pathlib_receivers_and_aliases_are_proven(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import pathlib as paths",
                    "from pathlib import Path as P",
                    "ROOT = P('/srv/docs')",
                    "ROOT = ROOT / 'nested'",
                    "@mcp.tool()",
                    "def path_read(name: str):",
                    "    target = paths.Path(name)",
                    "    alias = target",
                    "    alias.read_text()",
                    "    return P(name).open('rb')",
                    "@mcp.tool()",
                    "def path_write(name: str):",
                    "    target = (ROOT / name).resolve()",
                    "    target.write_text('value')",
                    "    return target.open(mode='a')",
                    "@mcp.tool()",
                    "def path_iteration():",
                    "    for target in ROOT.rglob('*.md'):",
                    "        target.read_bytes()",
                    "    return None",
                ]
            )
        )

        self.assertEqual(
            _filesystem_capabilities(report, "path_read"),
            {Capability.FILESYSTEM_READ},
        )
        self.assertEqual(
            _filesystem_capabilities(report, "path_write"),
            {Capability.FILESYSTEM_WRITE},
        )
        self.assertEqual(
            _filesystem_capabilities(report, "path_iteration"),
            {Capability.FILESYSTEM_READ},
        )

    def test_os_open_flags_and_aliases_are_classified(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import os as operating",
                    "from os import O_WRONLY as WRITE_ONLY",
                    "from os import open as raw_open",
                    "@mcp.tool()",
                    "def read_only(path: str):",
                    "    return operating.open(path, operating.O_RDONLY)",
                    "@mcp.tool()",
                    "def write_only(path: str):",
                    "    return raw_open(path, WRITE_ONLY)",
                    "@mcp.tool()",
                    "def read_write_create(path: str):",
                    "    return operating.open(path, operating.O_RDWR | operating.O_CREAT)",
                    "@mcp.tool()",
                    "def append(path: str):",
                    "    return operating.open(path, operating.O_APPEND)",
                    "@mcp.tool()",
                    "def truncate(path: str):",
                    "    return operating.open(path, operating.O_TRUNC)",
                    "@mcp.tool()",
                    "def dynamic_flags(path: str, flags: int):",
                    "    return operating.open(path, flags)",
                ]
            )
        )

        self.assertEqual(
            _filesystem_capabilities(report, "read_only"),
            {Capability.FILESYSTEM_READ},
        )
        for tool_name in ("write_only", "read_write_create", "append", "truncate"):
            self.assertEqual(
                _filesystem_capabilities(report, tool_name),
                {Capability.FILESYSTEM_WRITE},
            )
        self.assertEqual(
            _filesystem_capabilities(report, "dynamic_flags"),
            {Capability.FILESYSTEM_READ},
        )

    def test_qualified_os_and_shutil_write_aliases_remain_supported(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import os as operating",
                    "import shutil as files",
                    "from shutil import move as relocate",
                    "@mcp.tool()",
                    "def mutate(first: str, second: str):",
                    "    operating.replace(first, second)",
                    "    files.copy(first, second)",
                    "    return relocate(first, second)",
                ]
            )
        )

        self.assertEqual(
            _filesystem_capabilities(report, "mutate"),
            {Capability.FILESYSTEM_WRITE},
        )


if __name__ == "__main__":
    unittest.main()

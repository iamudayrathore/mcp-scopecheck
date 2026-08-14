"""Lexical reachability and function-local import regressions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_scopecheck.analyzer import reachable_functions
from mcp_scopecheck.auditor import audit
from mcp_scopecheck.models import AuditReport, Capability
from mcp_scopecheck.parser import parse_project


def _audit_source(source: str) -> AuditReport:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "server.py").write_text(source, encoding="utf-8")
        return audit(root)


def _capabilities(report: AuditReport, tool_name: str) -> set[Capability]:
    tool = next(tool for tool in report.tools if tool.name == tool_name)
    return {item.capability for item in report.capabilities[tool.key]}


def _network_symbols(report: AuditReport, tool_name: str) -> list[str]:
    tool = next(tool for tool in report.tools if tool.name == tool_name)
    return [
        item.evidence.symbol
        for item in report.capabilities[tool.key]
        if item.capability == Capability.NETWORK_EGRESS
    ]


class ScopeReachabilityTests(unittest.TestCase):
    def test_uncalled_sync_and_async_nested_bodies_are_not_reachable(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import subprocess",
                    "import requests",
                    "@mcp.tool()",
                    "def sync_outer():",
                    "    def dormant():",
                    "        subprocess.run(['false'])",
                    "        return requests.get('https://example.invalid')",
                    "    return 'ok'",
                    "@mcp.tool()",
                    "async def async_outer():",
                    "    async def dormant():",
                    "        subprocess.run(['false'])",
                    "        return requests.get('https://example.invalid')",
                    "    return 'ok'",
                ]
            )
        )

        self.assertEqual(_capabilities(report, "sync_outer"), set())
        self.assertEqual(_capabilities(report, "async_outer"), set())

    def test_directly_called_sync_and_async_nested_helpers_are_reachable(self) -> None:
        source = "\n".join(
            [
                "import subprocess",
                "import requests",
                "@mcp.tool()",
                "def sync_outer():",
                "    def run():",
                "        return subprocess.run(['true'])",
                "    return run()",
                "@mcp.tool()",
                "async def async_outer():",
                "    async def fetch():",
                "        return requests.get('https://example.invalid')",
                "    return await fetch()",
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.py").write_text(source, encoding="utf-8")
            project = parse_project(root)
            sync_records = reachable_functions(project, project.tools[0])
            async_records = reachable_functions(project, project.tools[1])
            report = audit(root)

        self.assertEqual(
            {record.node.name for record in sync_records},
            {"sync_outer", "run"},
        )
        self.assertEqual(
            {record.node.name for record in async_records},
            {"async_outer", "fetch"},
        )
        self.assertIn(Capability.PROCESS_EXECUTION, _capabilities(report, "sync_outer"))
        self.assertIn(Capability.NETWORK_EGRESS, _capabilities(report, "async_outer"))

    def test_function_local_import_aliases_resolve_in_sync_and_async_tools(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "@mcp.tool()",
                    "def local_requests():",
                    "    import requests as web",
                    "    return web.get('https://example.invalid')",
                    "@mcp.tool()",
                    "async def local_httpx():",
                    "    from httpx import post as send",
                    "    return send('https://example.invalid')",
                    "@mcp.tool()",
                    "def captured_import():",
                    "    import requests as web",
                    "    def fetch():",
                    "        return web.get('https://example.invalid')",
                    "    return fetch()",
                ]
            )
        )

        self.assertEqual(_network_symbols(report, "local_requests"), ["requests.get"])
        self.assertEqual(_network_symbols(report, "local_httpx"), ["httpx.post"])
        self.assertEqual(_network_symbols(report, "captured_import"), ["requests.get"])

    def test_shadowing_respects_parameters_module_state_and_statement_order(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import requests as web",
                    "@mcp.tool()",
                    "def ordered():",
                    "    web.get('https://example.invalid/first')",
                    "    web = {}",
                    "    return web.get('field')",
                    "@mcp.tool()",
                    "def parameter_shadow(web):",
                    "    return web.get('field')",
                    "import httpx as replaced",
                    "replaced = {}",
                    "@mcp.tool()",
                    "def module_shadow():",
                    "    return replaced.get('field')",
                ]
            )
        )

        self.assertEqual(_network_symbols(report, "ordered"), ["requests.get"])
        self.assertEqual(_network_symbols(report, "parameter_shadow"), [])
        self.assertEqual(_network_symbols(report, "module_shadow"), [])

    def test_class_and_comprehension_execution_boundaries_are_distinct(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import requests",
                    "import subprocess",
                    "@mcp.tool()",
                    "def dormant_method():",
                    "    class Worker:",
                    "        def run(self):",
                    "            return subprocess.run(['false'])",
                    "    return Worker",
                    "@mcp.tool()",
                    "def active_class_body():",
                    "    class Probe:",
                    "        response = requests.get('https://example.invalid')",
                    "    return Probe",
                    "@mcp.tool()",
                    "def eager_comprehension(urls):",
                    "    return [requests.get(url) for url in urls]",
                    "@mcp.tool()",
                    "def shadowed_comprehension(values):",
                    "    return [requests.get('field') for requests in values]",
                    "@mcp.tool()",
                    "def dormant_lambda():",
                    "    callback = lambda: subprocess.run(['false'])",
                    "    return callback",
                ]
            )
        )

        self.assertEqual(_capabilities(report, "dormant_method"), set())
        self.assertEqual(
            _capabilities(report, "active_class_body"),
            {Capability.NETWORK_EGRESS},
        )
        self.assertEqual(
            _capabilities(report, "eager_comprehension"),
            {Capability.NETWORK_EGRESS},
        )
        self.assertEqual(_capabilities(report, "shadowed_comprehension"), set())
        self.assertEqual(_capabilities(report, "dormant_lambda"), set())


if __name__ == "__main__":
    unittest.main()

"""Lexical reachability and function-local import regressions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_scopecheck.analyzer import reachable_functions
from mcp_scopecheck.auditor import audit
from mcp_scopecheck.models import AnalysisStatus, AuditReport, Capability, UnresolvedReason
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
    def test_registered_tool_keeps_its_exact_function_when_name_is_redefined(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import subprocess",
                    "@mcp.tool(name='dangerous_first')",
                    "def duplicate(command):",
                    "    return subprocess.run(command, shell=True)",
                    "@mcp.tool(name='benign_second')",
                    "def duplicate(command):",
                    "    return command",
                ]
            )
        )

        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)
        self.assertEqual(
            _capabilities(report, "dangerous_first"),
            {Capability.PROCESS_EXECUTION},
        )
        self.assertEqual(_capabilities(report, "benign_second"), set())
        self.assertEqual(
            [(finding.rule_id, finding.tool_name) for finding in report.findings],
            [("MSC106", "dangerous_first")],
        )

    def test_compound_statement_import_bindings_fail_closed(self) -> None:
        static_branch = _audit_source(
            "\n".join(
                [
                    "if True:",
                    "    from subprocess import run",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    return run(command, shell=True)",
                ]
            )
        )
        conditional_branch = _audit_source(
            "\n".join(
                [
                    "enabled = True",
                    "if enabled:",
                    "    from subprocess import run",
                    "else:",
                    "    run = None",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    return run(command, shell=True)",
                ]
            )
        )
        try_fallback = _audit_source(
            "\n".join(
                [
                    "@mcp.tool()",
                    "def execute(command):",
                    "    try:",
                    "        import subprocess as process",
                    "    except ImportError:",
                    "        process = None",
                    "    return process.run(command, shell=True)",
                ]
            )
        )
        static_path = _audit_source(
            "\n".join(
                [
                    "from pathlib import Path",
                    "if True:",
                    "    ROOT = Path('/srv/docs')",
                    "@mcp.tool()",
                    "def read_index():",
                    "    return ROOT.read_text()",
                ]
            )
        )
        conditional_path = _audit_source(
            "\n".join(
                [
                    "from pathlib import Path",
                    "configured = True",
                    "if configured:",
                    "    ROOT = Path('/srv/docs')",
                    "else:",
                    "    ROOT = object()",
                    "@mcp.tool()",
                    "def read_index():",
                    "    return ROOT.read_text()",
                ]
            )
        )
        conditional_helper = _audit_source(
            "\n".join(
                [
                    "if True:",
                    "    def helper(command):",
                    "        return command",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    return helper(command)",
                ]
            )
        )
        conditional_wildcard = _audit_source(
            "\n".join(
                [
                    "if True:",
                    "    from helpers import *",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    return helper(command)",
                ]
            )
        )

        self.assertEqual(static_branch.completeness.status, AnalysisStatus.COMPLETE)
        self.assertEqual(
            _capabilities(static_branch, "execute"),
            {Capability.PROCESS_EXECUTION},
        )
        self.assertEqual(static_path.completeness.status, AnalysisStatus.COMPLETE)
        self.assertEqual(
            _capabilities(static_path, "read_index"),
            {Capability.FILESYSTEM_READ},
        )
        for report in (
            conditional_branch,
            try_fallback,
            conditional_path,
            conditional_helper,
        ):
            with self.subTest(report=report.snapshot):
                self.assertEqual(report.completeness.status, AnalysisStatus.PARTIAL)
                self.assertEqual(
                    {edge.reason for edge in report.completeness.unresolved_edges},
                    {UnresolvedReason.AMBIGUOUS_BINDING},
                )
        self.assertEqual(conditional_wildcard.completeness.status, AnalysisStatus.PARTIAL)
        self.assertIn(
            UnresolvedReason.WILDCARD_IMPORT,
            {edge.reason for edge in conditional_wildcard.completeness.unresolved_edges},
        )

    def test_resolved_local_eval_is_not_dynamic_code_execution(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "def eval(value):",
                    "    return value.upper()",
                    "@mcp.tool()",
                    "def normalize(value):",
                    "    return eval(value)",
                ]
            )
        )

        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)
        self.assertEqual(_capabilities(report, "normalize"), set())
        self.assertEqual(report.findings, [])
        self.assertEqual(
            [edge.target_symbol for edge in report.completeness.resolved_edges],
            ["eval"],
        )

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

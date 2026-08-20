"""Bounded cross-module reachability regressions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_scopecheck.auditor import audit
from mcp_scopecheck.models import AnalysisStatus, AuditReport, Capability, UnresolvedReason


def _sources(root: Path, files: dict[str, str]) -> None:
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


def _capabilities(report: AuditReport, tool_name: str) -> set[Capability]:
    tool = next(item for item in report.tools if item.name == tool_name)
    return {item.capability for item in report.capabilities[tool.key]}


class CrossModuleTests(unittest.TestCase):
    def test_relative_absolute_aliased_and_qualified_local_imports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _sources(
                root,
                {
                    "pkg/__init__.py": "",
                    "pkg/ops.py": (
                        "import requests\n"
                        "def operation():\n"
                        "    return requests.get('https://service.example.invalid')\n"
                    ),
                    "pkg/server.py": "\n".join(
                        [
                            "from .ops import operation as relative_alias",
                            "from pkg.ops import operation as absolute_alias",
                            "from . import ops as module_alias",
                            "import pkg.ops as qualified_module",
                            "@mcp.tool(description='Fetch from a hosted search service.')",
                            "def relative_tool():",
                            "    return relative_alias()",
                            "@mcp.tool(description='Fetch from a hosted search service.')",
                            "def absolute_tool():",
                            "    return absolute_alias()",
                            "@mcp.tool(description='Fetch from a hosted search service.')",
                            "def module_alias_tool():",
                            "    return module_alias.operation()",
                            "@mcp.tool(description='Fetch from a hosted search service.')",
                            "def qualified_tool():",
                            "    return qualified_module.operation()",
                        ]
                    ),
                },
            )
            report = audit(root)

        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)
        for name in (
            "relative_tool",
            "absolute_tool",
            "module_alias_tool",
            "qualified_tool",
        ):
            self.assertEqual(_capabilities(report, name), {Capability.NETWORK_EGRESS})
        self.assertEqual(len(report.completeness.resolved_edges), 4)

    def test_one_hop_init_reexport_and_import_cycle_terminate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _sources(
                root,
                {
                    "pkg/__init__.py": "from .worker import perform\n",
                    "pkg/worker.py": (
                        "from .cycle import back\n"
                        "def perform(path):\n"
                        "    return back(path)\n"
                    ),
                    "pkg/cycle.py": (
                        "from .worker import perform\n"
                        "def back(path):\n"
                        "    value = open(path).read()\n"
                        "    perform(path)\n"
                        "    return value\n"
                    ),
                    "pkg/server.py": (
                        "from pkg import perform\n"
                        "@mcp.tool()\n"
                        "def entry(path: str):\n"
                        "    return perform(path)\n"
                    ),
                },
            )
            report = audit(root)

        self.assertEqual(_capabilities(report, "entry"), {Capability.FILESYSTEM_READ})
        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)
        evidence = report.capabilities[report.tools[0].key][0].evidence
        self.assertEqual(
            [(step.source_file, step.symbol) for step in evidence.path],
            [
                ("pkg/server.py", "entry"),
                ("pkg/worker.py", "perform"),
                ("pkg/cycle.py", "back"),
                ("pkg/cycle.py", "open"),
            ],
        )

    def test_same_named_modules_remain_qualified_to_their_packages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _sources(
                root,
                {
                    "first/helpers.py": "import os\ndef work():\n    return os.getenv('FIRST')\n",
                    "second/helpers.py": "def work():\n    return eval('2')\n",
                    "first/server.py": (
                        "from first.helpers import work\n"
                        "@mcp.tool()\n"
                        "def entry():\n"
                        "    return work()\n"
                    ),
                },
            )
            report = audit(root)

        self.assertEqual(_capabilities(report, "entry"), {Capability.ENVIRONMENT_READ})
        self.assertNotIn("MSC107", {finding.rule_id for finding in report.findings})

    def test_ambiguous_missing_and_class_targets_are_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _sources(
                root,
                {
                    "one/src/shared.py": "def work():\n    return 1\n",
                    "two/src/shared.py": "def work():\n    return 2\n",
                    "pkg/__init__.py": "",
                    "pkg/types.py": "class Worker:\n    pass\n",
                    "pkg/server.py": "\n".join(
                        [
                            "from shared import work",
                            "from .missing import absent",
                            "from .types import Worker",
                            "@mcp.tool()",
                            "def entry():",
                            "    work()",
                            "    absent()",
                            "    return Worker()",
                        ]
                    ),
                },
            )
            report = audit(root)

        self.assertEqual(report.completeness.status, AnalysisStatus.PARTIAL)
        self.assertEqual(
            {edge.reason for edge in report.completeness.unresolved_edges},
            {
                UnresolvedReason.AMBIGUOUS_LOCAL_TARGET,
                UnresolvedReason.MISSING_LOCAL_TARGET,
                UnresolvedReason.UNSUPPORTED_INSTANCE_DISPATCH,
            },
        )

    def test_shadowing_reassignment_and_external_packages_are_not_local_edges(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _sources(
                root,
                {
                    "pkg/__init__.py": "",
                    "pkg/ops.py": "def work():\n    return 1\n",
                    "pkg/server.py": "\n".join(
                        [
                            "import requests",
                            "from .ops import work",
                            "@mcp.tool(description='Fetch from a URL.')",
                            "def entry(callback):",
                            "    work = callback",
                            "    work()",
                            "    return requests.get('https://example.invalid')",
                        ]
                    ),
                },
            )
            report = audit(root)

        self.assertEqual(_capabilities(report, "entry"), {Capability.NETWORK_EGRESS})
        self.assertEqual(
            [edge.reason for edge in report.completeness.unresolved_edges],
            [UnresolvedReason.HIGHER_ORDER_CALL],
        )
        self.assertFalse(
            any("requests" in edge.candidate for edge in report.completeness.unresolved_edges)
        )

    def test_function_local_import_resolves_until_deletion_shadows_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _sources(
                root,
                {
                    "pkg/__init__.py": "",
                    "pkg/ops.py": "import os\ndef work():\n    return os.getenv('SETTING')\n",
                    "pkg/server.py": "\n".join(
                        [
                            "@mcp.tool()",
                            "def resolved():",
                            "    from .ops import work as local_work",
                            "    return local_work()",
                            "@mcp.tool()",
                            "def deleted(callback):",
                            "    from .ops import work",
                            "    del work",
                            "    work = callback",
                            "    return work()",
                        ]
                    ),
                },
            )
            report = audit(root)

        self.assertEqual(_capabilities(report, "resolved"), {Capability.ENVIRONMENT_READ})
        deleted_edges = [
            edge
            for edge in report.completeness.unresolved_edges
            if edge.tool_name == "deleted"
        ]
        self.assertEqual(
            [edge.reason for edge in deleted_edges],
            [UnresolvedReason.HIGHER_ORDER_CALL],
        )

    def test_unresolved_init_reexport_is_not_guessed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _sources(
                root,
                {
                    "pkg/__init__.py": "from .missing import operation\n",
                    "pkg/server.py": (
                        "from pkg import operation\n"
                        "@mcp.tool()\n"
                        "def entry():\n"
                        "    return operation()\n"
                    ),
                },
            )
            report = audit(root)

        self.assertEqual(
            [edge.reason for edge in report.completeness.unresolved_edges],
            [UnresolvedReason.UNRESOLVED_REEXPORT],
        )

    def test_cross_module_analysis_never_executes_top_level_target_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / "executed.txt"
            _sources(
                root,
                {
                    "pkg/__init__.py": "",
                    "pkg/ops.py": "\n".join(
                        [
                            "from pathlib import Path",
                            f"Path({str(sentinel)!r}).write_text('executed')",
                            "def work():",
                            "    return eval('1 + 1')",
                        ]
                    ),
                    "pkg/server.py": (
                        "from .ops import work\n"
                        "@mcp.tool()\n"
                        "def entry():\n"
                        "    return work()\n"
                    ),
                },
            )
            report = audit(root)

        self.assertIn("MSC107", {finding.rule_id for finding in report.findings})
        self.assertFalse(sentinel.exists())

    def test_direct_capabilities_and_shortest_path_cross_modules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _sources(
                root,
                {
                    "pkg/__init__.py": "",
                    "pkg/sinks.py": "\n".join(
                        [
                            "import os, subprocess, requests",
                            "def all_effects(path):",
                            "    os.getenv('SETTING')",
                            "    open(path, 'w').write('x')",
                            "    subprocess.run(['fixed'])",
                            "    return requests.get('https://service.example.invalid')",
                        ]
                    ),
                    "pkg/middle.py": (
                        "from .sinks import all_effects\n"
                        "def delegate(path):\n"
                        "    return all_effects(path)\n"
                    ),
                    "pkg/server.py": "\n".join(
                        [
                            "from .middle import delegate",
                            "@mcp.tool(description='Fetch from a hosted service.')",
                            "def entry(path: str):",
                            "    return delegate(path)",
                        ]
                    ),
                },
            )
            report = audit(root)

        self.assertEqual(
            _capabilities(report, "entry"),
            {
                Capability.ENVIRONMENT_READ,
                Capability.FILESYSTEM_WRITE,
                Capability.NETWORK_EGRESS,
                Capability.PROCESS_EXECUTION,
            },
        )
        for item in report.capabilities[report.tools[0].key]:
            self.assertEqual(item.evidence.path[0].symbol, "entry")
            self.assertEqual(item.evidence.path[1].symbol, "delegate")
            self.assertEqual(item.evidence.path[2].symbol, "all_effects")
            self.assertEqual(item.evidence.path[-1].source_file, "pkg/sinks.py")

    def test_rule_consumers_use_cross_module_capabilities_conservatively(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _sources(
                root,
                {
                    "pkg/__init__.py": "",
                    "pkg/sinks.py": "\n".join(
                        [
                            "import requests, subprocess",
                            "def mutate(path):",
                            "    open(path, 'w').write('x')",
                            "    subprocess.run(['fixed'])",
                            "    return requests.get('http://127.0.0.1:8000/data')",
                            "def dynamic():",
                            "    return eval('1 + 1')",
                        ]
                    ),
                    "pkg/server.py": "\n".join(
                        [
                            "from .sinks import mutate, dynamic",
                            "@mcp.tool(",
                            "    description='Fetch issues from the GitHub API.',",
                            "    annotations={'readOnlyHint': True, 'openWorldHint': False},",
                            ")",
                            "def claimed(path: str):",
                            "    return mutate(path)",
                            "@mcp.tool(annotations={'readOnlyHint': True})",
                            "def code_tool():",
                            "    return dynamic()",
                        ]
                    ),
                },
            )
            report = audit(root)

        rules = {(finding.tool_name, finding.rule_id) for finding in report.findings}
        self.assertTrue(
            {
                ("claimed", "MSC101"),
                ("claimed", "MSC101"),
                ("claimed", "MSC106"),
                ("claimed", "MSC108"),
                ("code_tool", "MSC101"),
                ("code_tool", "MSC107"),
            }
            <= rules
        )
        self.assertNotIn(("claimed", "MSC102"), rules)

    def test_msc105_does_not_cross_function_or_module_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _sources(
                root,
                {
                    "pkg/__init__.py": "",
                    "pkg/send.py": (
                        "import requests\n"
                        "def send(value):\n"
                        "    return requests.post('https://service.example.invalid', data=value)\n"
                    ),
                    "pkg/server.py": "\n".join(
                        [
                            "import os",
                            "from .send import send",
                            "@mcp.tool(description='Send data to a hosted service.')",
                            "def entry():",
                            "    value = os.getenv('SETTING')",
                            "    return send(value)",
                        ]
                    ),
                },
            )
            report = audit(root)

        self.assertNotIn("MSC105", {finding.rule_id for finding in report.findings})
        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)

    def test_graph_and_path_budgets_fail_closed(self) -> None:
        files = {
            "pkg/__init__.py": "",
            "pkg/c.py": "import os\ndef finish():\n    os.getenv('A')\n    return os.getenv('B')\n",
            "pkg/b.py": "from .c import finish\ndef middle():\n    return finish()\n",
            "pkg/server.py": (
                "from .b import middle\n"
                "@mcp.tool()\n"
                "def entry():\n"
                "    return middle()\n"
            ),
        }
        patches = (
            patch("mcp_scopecheck.analyzer.MAX_CROSS_MODULE_HOPS", 1),
            patch("mcp_scopecheck.analyzer.MAX_LOCAL_MODULES", 1),
            patch("mcp_scopecheck.analyzer.MAX_REACHABLE_FUNCTIONS_PER_TOOL", 1),
            patch("mcp_scopecheck.analyzer.MAX_CAPABILITY_PATHS_PER_TOOL", 1),
            patch("mcp_scopecheck.auditor.MAX_RESOLVED_LOCAL_EDGES", 1),
        )
        for budget_patch in patches:
            with self.subTest(budget=budget_patch.attribute):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    _sources(root, files)
                    with budget_patch:
                        report = audit(root)
                self.assertEqual(report.completeness.status, AnalysisStatus.FAILED)
                self.assertTrue(
                    any(
                        item.code == "MSC-ANALYSIS-BUDGET"
                        for item in report.completeness.notifications
                    )
                )


if __name__ == "__main__":
    unittest.main()

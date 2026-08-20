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

    def test_tool_definition_expressions_are_analyzed_at_definition_time(self) -> None:
        direct_sink = _audit_source(
            "\n".join(
                [
                    "import subprocess",
                    "@mcp.tool()",
                    "def entry(value=subprocess.run(['fixed'])):",
                    "    return value",
                ]
            )
        )
        redefined_helper = _audit_source(
            "\n".join(
                [
                    "import subprocess",
                    "def helper():",
                    "    return subprocess.run(['fixed'])",
                    "@mcp.tool()",
                    "def entry(value=helper()):",
                    "    return value",
                    "def helper():",
                    "    return 'benign'",
                ]
            )
        )
        direct_annotation = _audit_source(
            "\n".join(
                [
                    "import subprocess",
                    "@mcp.tool()",
                    "def entry(value: subprocess.run(['fixed'])):",
                    "    return value",
                ]
            )
        )
        deferred_annotation = _audit_source(
            "\n".join(
                [
                    "from __future__ import annotations",
                    "import subprocess",
                    "@mcp.tool()",
                    "def entry(value: subprocess.run(['fixed'])):",
                    "    return value",
                ]
            )
        )
        deferred_helper_annotation = _audit_source(
            "\n".join(
                [
                    "from __future__ import annotations",
                    "from pathlib import Path",
                    "root = object()",
                    "def helper(value: (root := Path('/'))):",
                    "    return value",
                    "@mcp.tool()",
                    "def entry():",
                    "    return root.read_text()",
                ]
            )
        )

        self.assertEqual(direct_sink.completeness.status, AnalysisStatus.COMPLETE)
        self.assertEqual(
            _capabilities(direct_sink, "entry"),
            {Capability.PROCESS_EXECUTION},
        )
        self.assertEqual(
            _capabilities(direct_annotation, "entry"),
            {Capability.PROCESS_EXECUTION},
        )
        self.assertEqual(_capabilities(deferred_annotation, "entry"), set())
        self.assertEqual(deferred_helper_annotation.completeness.status, AnalysisStatus.COMPLETE)
        self.assertEqual(_capabilities(deferred_helper_annotation, "entry"), set())
        self.assertEqual(redefined_helper.completeness.status, AnalysisStatus.PARTIAL)
        self.assertIn(
            UnresolvedReason.AMBIGUOUS_LOCAL_TARGET,
            {edge.reason for edge in redefined_helper.completeness.unresolved_edges},
        )

    def test_abrupt_and_suppressing_control_flow_fails_closed(self) -> None:
        sources = {
            "module_loop_else": "\n".join(
                [
                    "import math as process",
                    "items = []",
                    "for item in items:",
                    "    import subprocess as process",
                    "    break",
                    "else:",
                    "    process = math",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    return process.run(command, shell=True)",
                ]
            ),
            "function_loop_else": "\n".join(
                [
                    "import math",
                    "@mcp.tool()",
                    "def execute(command, items):",
                    "    process = math",
                    "    for item in items:",
                    "        import subprocess as process",
                    "        break",
                    "    else:",
                    "        process = math",
                    "    return process.run(command, shell=True)",
                ]
            ),
            "while_prefix": "\n".join(
                [
                    "import math",
                    "@mcp.tool()",
                    "def execute(command, enabled):",
                    "    process = math",
                    "    while enabled:",
                    "        import subprocess as process",
                    "        break",
                    "        process = math",
                    "    return process.run(command, shell=True)",
                ]
            ),
            "loop_carried_binding": "\n".join(
                [
                    "import math",
                    "@mcp.tool()",
                    "def execute(command, items):",
                    "    process = math",
                    "    for item in items:",
                    "        process.run(command)",
                    "        import subprocess as process",
                    "    return None",
                ]
            ),
            "while_test_loop_carried_binding": "\n".join(
                [
                    "import math",
                    "@mcp.tool()",
                    "def execute(command, enabled):",
                    "    process = math",
                    "    while enabled and process.run(command):",
                    "        import subprocess as process",
                    "    return None",
                ]
            ),
            "try_prefix": "\n".join(
                [
                    "import math",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    process = math",
                    "    try:",
                    "        import subprocess as process",
                    "        math.sqrt(command)",
                    "        process = math",
                    "    except Exception:",
                    "        pass",
                    "    return process.run(command, shell=True)",
                ]
            ),
            "with_suppression": "\n".join(
                [
                    "import contextlib",
                    "import math",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    process = math",
                    "    with contextlib.suppress(Exception):",
                    "        import subprocess as process",
                    "        math.sqrt(command)",
                    "        process = math",
                    "    return process.run(command, shell=True)",
                ]
            ),
            "except_star_sequence": "\n".join(
                [
                    "import math",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    process = math",
                    "    try:",
                    "        operation()",
                    "    except* ValueError:",
                    "        import subprocess as process",
                    "    except* TypeError:",
                    "        return process.run(command)",
                    "    return None",
                ]
            ),
            "match_guard": "\n".join(
                [
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def read(value):",
                    "    root = object()",
                    "    match value:",
                    "        case _ if (root := Path('/')) and False:",
                    "            root = object()",
                    "    return root.read_text()",
                ]
            ),
            "match_guard_fallthrough": "\n".join(
                [
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def read(value):",
                    "    root = object()",
                    "    match value:",
                    "        case 0 if (root := Path('/')) and False:",
                    "            pass",
                    "        case _:",
                    "            return root.read_text()",
                    "    return None",
                ]
            ),
            "comprehension_walrus": "\n".join(
                [
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def read(values):",
                    "    root = object()",
                    "    [(root := Path(value)) for value in values]",
                    "    return root.read_text()",
                ]
            ),
            "conditional_path_value": "\n".join(
                [
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def read(flag):",
                    "    root = Path('/') if flag else object()",
                    "    return root.read_text()",
                ]
            ),
            "conditional_client_value": "\n".join(
                [
                    "import httpx",
                    "@mcp.tool()",
                    "def send(flag):",
                    "    client = httpx.Client() if flag else object()",
                    "    return client.post('https://example.invalid')",
                ]
            ),
            "conditional_import_reference": "\n".join(
                [
                    "import math",
                    "import subprocess",
                    "@mcp.tool()",
                    "def execute(command, flag):",
                    "    process = subprocess if flag else math",
                    "    return process.run(command)",
                ]
            ),
            "module_import_reference_alias": "\n".join(
                [
                    "import subprocess",
                    "process = subprocess",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    return process.run(command)",
                ]
            ),
            "module_class_reference_alias": "\n".join(
                [
                    "class Worker:",
                    "    @staticmethod",
                    "    def run(command):",
                    "        return command",
                    "Alias = Worker",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    return Alias.run(command)",
                ]
            ),
            "function_destructured_import": "\n".join(
                [
                    "import subprocess",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    process, other = subprocess, None",
                    "    return process.run(command)",
                ]
            ),
            "function_destructured_path": "\n".join(
                [
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def read():",
                    "    root, other = Path('/'), None",
                    "    return root.read_text()",
                ]
            ),
            "function_destructured_client": "\n".join(
                [
                    "import httpx",
                    "@mcp.tool()",
                    "def send():",
                    "    client, other = httpx.Client(), None",
                    "    return client.post('https://example.invalid')",
                ]
            ),
            "module_destructured_import": "\n".join(
                [
                    "import subprocess",
                    "process, other = subprocess, None",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    return process.run(command)",
                ]
            ),
            "module_destructured_path": "\n".join(
                [
                    "from pathlib import Path",
                    "root, other = Path('/'), None",
                    "@mcp.tool()",
                    "def read():",
                    "    return root.read_text()",
                ]
            ),
            "function_destructured_self_reference": "\n".join(
                [
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def read():",
                    "    root = Path('/')",
                    "    root, other = root, None",
                    "    return root.read_text()",
                ]
            ),
            "module_destructured_self_reference": "\n".join(
                [
                    "import subprocess",
                    "process = subprocess",
                    "process, other = process, None",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    return process.run(command)",
                ]
            ),
            "destructured_path_before_walrus": "\n".join(
                [
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def read():",
                    "    root = Path('/')",
                    "    root, other = root, (root := object())",
                    "    return root.read_text()",
                ]
            ),
            "destructured_import_before_walrus": "\n".join(
                [
                    "import subprocess as process",
                    "@mcp.tool()",
                    "def execute(command):",
                    "    process, other = process, (process := object())",
                    "    return process.run(command)",
                ]
            ),
            "destructured_client_before_walrus": "\n".join(
                [
                    "import httpx",
                    "@mcp.tool()",
                    "def send():",
                    "    client = httpx.Client()",
                    "    client, other = client, (client := object())",
                    "    return client.post('https://example.invalid')",
                ]
            ),
            "short_circuit_walrus": "\n".join(
                [
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def read(flag):",
                    "    root = Path('/')",
                    "    flag and (root := object())",
                    "    return root.read_text()",
                ]
            ),
            "conditional_expression_walrus": "\n".join(
                [
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def read(flag):",
                    "    root = Path('/')",
                    "    object() if flag else (root := object())",
                    "    return root.read_text()",
                ]
            ),
            "chained_comparison_walrus": "\n".join(
                [
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def read():",
                    "    root = Path('/')",
                    "    2 < 1 < (root := object())",
                    "    return root.read_text()",
                ]
            ),
        }

        for label, source in sources.items():
            with self.subTest(label=label):
                report = _audit_source(source)
                self.assertEqual(report.completeness.status, AnalysisStatus.PARTIAL)
                self.assertIn(
                    UnresolvedReason.AMBIGUOUS_BINDING,
                    {edge.reason for edge in report.completeness.unresolved_edges},
                )

    def test_wrappers_classes_and_nested_callbacks_are_never_silently_followed(self) -> None:
        wrapped = _audit_source(
            "\n".join(
                [
                    "import builtins",
                    "def replace(function):",
                    "    return builtins.eval",
                    "@replace",
                    "def calculate(value):",
                    "    return value",
                    "@mcp.tool()",
                    "def entry(value):",
                    "    return calculate(value)",
                ]
            )
        )
        class_dispatch = _audit_source(
            "\n".join(
                [
                    "import subprocess",
                    "class Worker:",
                    "    @staticmethod",
                    "    def run(command):",
                    "        return subprocess.run(command, shell=True)",
                    "@mcp.tool()",
                    "def entry(command):",
                    "    return Worker.run(command)",
                ]
            )
        )
        nested_class_dispatch = _audit_source(
            "\n".join(
                [
                    "import subprocess",
                    "@mcp.tool()",
                    "def entry(command):",
                    "    class Worker:",
                    "        @staticmethod",
                    "        def run(value):",
                    "            return subprocess.run(value, shell=True)",
                    "    return Worker.run(command)",
                ]
            )
        )
        nested_callback = _audit_source(
            "\n".join(
                [
                    "import subprocess",
                    "@mcp.tool()",
                    "def entry(pool, command):",
                    "    def helper():",
                    "        return subprocess.run(command, shell=True)",
                    "    return pool.submit(helper)",
                ]
            )
        )
        direct_lambda_call = _audit_source(
            "\n".join(
                [
                    "import subprocess",
                    "@mcp.tool()",
                    "def entry(command):",
                    "    return (lambda: subprocess.run(command, shell=True))()",
                ]
            )
        )
        conditional_callable = _audit_source(
            "\n".join(
                [
                    "def bad(command):",
                    "    return command",
                    "def good(command):",
                    "    return command",
                    "@mcp.tool()",
                    "def entry(command, flag):",
                    "    return (bad if flag else good)(command)",
                ]
            )
        )
        nested_nonlocal_write = _audit_source(
            "\n".join(
                [
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def entry():",
                    "    root = object()",
                    "    def set_root():",
                    "        nonlocal root",
                    "        root = Path('/')",
                    "    set_root()",
                    "    return root.read_text()",
                ]
            )
        )
        module_global_write = _audit_source(
            "\n".join(
                [
                    "from pathlib import Path",
                    "ROOT = object()",
                    "def set_root():",
                    "    global ROOT",
                    "    ROOT = Path('/')",
                    "@mcp.tool()",
                    "def entry():",
                    "    set_root()",
                    "    return ROOT.read_text()",
                ]
            )
        )

        for report, reason in (
            (wrapped, UnresolvedReason.WRAPPER_INDIRECTION),
            (class_dispatch, UnresolvedReason.UNSUPPORTED_INSTANCE_DISPATCH),
            (nested_class_dispatch, UnresolvedReason.UNSUPPORTED_INSTANCE_DISPATCH),
            (nested_callback, UnresolvedReason.HIGHER_ORDER_CALL),
            (direct_lambda_call, UnresolvedReason.HIGHER_ORDER_CALL),
            (conditional_callable, UnresolvedReason.HIGHER_ORDER_CALL),
            (nested_nonlocal_write, UnresolvedReason.OUTER_SCOPE_STATE),
            (module_global_write, UnresolvedReason.OUTER_SCOPE_STATE),
        ):
            with self.subTest(reason=reason):
                self.assertEqual(report.completeness.status, AnalysisStatus.PARTIAL)
                self.assertIn(
                    reason,
                    {edge.reason for edge in report.completeness.unresolved_edges},
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

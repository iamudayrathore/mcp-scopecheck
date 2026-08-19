"""Regressions proving filesystem scope is decided by dataflow, not parameter naming.

Before v0.2.1 `MSC103` and `MSC104` only tracked parameters whose *name* matched a
fixed list. A tool that took `filepath`, `target`, or `name` and passed it straight
to a filesystem call produced `Findings (0)` with completeness `complete` and exit
`0` - a clean bill of health for unrestricted read and write. These tests pin the
corrected behavior in both directions: proven path positions are flagged whatever
the parameter is called, and parameters that never reach a filesystem sink are
still not treated as filesystem roots.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_scopecheck.auditor import audit
from mcp_scopecheck.models import AnalysisStatus, AuditReport


def _audit_source(source: str) -> AuditReport:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "server.py").write_text(source, encoding="utf-8")
        return audit(root)


def _tools_for(report: AuditReport, rule_id: str) -> set[str]:
    return {
        finding.tool_name for finding in report.findings if finding.rule_id == rule_id
    }


class UnconventionallyNamedPathParameterTests(unittest.TestCase):
    def test_non_path_names_reaching_filesystem_sinks_are_flagged(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import shutil",
                    "from pathlib import Path",
                    "ROOT = Path('/srv/docs')",
                    "@mcp.tool()",
                    "def read_doc(filepath: str):",
                    "    return Path(filepath).read_text()",
                    "@mcp.tool()",
                    "def open_doc(target: str):",
                    "    return open(target).read()",
                    "@mcp.tool()",
                    "def write_note(name: str, body: str):",
                    "    Path(name).write_text(body)",
                    "@mcp.tool()",
                    "def copy_out(dest: str):",
                    "    shutil.copy(str(ROOT / 'template.txt'), dest)",
                    "@mcp.tool()",
                    "def joined(label: str):",
                    "    import os",
                    "    return open(os.path.join('/srv/docs', label)).read()",
                ]
            )
        )

        self.assertEqual(
            _tools_for(report, "MSC103"),
            {"read_doc", "open_doc", "write_note", "copy_out", "joined"},
        )
        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)

    def test_data_arguments_beside_a_path_are_not_treated_as_paths(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "from pathlib import Path",
                    "ROOT = Path('/srv/docs')",
                    "@mcp.tool()",
                    "def save(body: str, encoding: str = 'utf-8'):",
                    "    (ROOT / 'report.txt').write_text(body, encoding=encoding)",
                    "@mcp.tool()",
                    "def split_text(text: str, sep: str = '/'):",
                    "    return '|'.join(text.split(sep))",
                    "@mcp.tool()",
                    "def label(name: str, prefix: str = '/'):",
                    "    return prefix + name",
                ]
            )
        )

        self.assertEqual(_tools_for(report, "MSC103"), set())
        self.assertEqual(_tools_for(report, "MSC104"), set())
        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)

    def test_guards_still_clear_unconventionally_named_parameters(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "from pathlib import Path",
                    "ROOT = Path('/srv/docs')",
                    "@mcp.tool()",
                    "def read_note(name: str):",
                    "    candidate = (ROOT / name).resolve()",
                    "    candidate.relative_to(ROOT)",
                    "    return candidate.read_text()",
                ]
            )
        )

        self.assertEqual(_tools_for(report, "MSC103"), set())
        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)

    def test_dangerous_default_is_flagged_for_a_proven_filesystem_parameter(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def listing(base: str = '/'):",
                    "    return [p.name for p in Path(base).iterdir()]",
                ]
            )
        )

        self.assertEqual(_tools_for(report, "MSC104"), {"listing"})
        self.assertEqual(_tools_for(report, "MSC103"), {"listing"})

    def test_dangerous_default_evidence_points_at_the_parameter_default(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "from pathlib import Path",  # line 1
                    "@mcp.tool()",  # line 2
                    "def listing(",  # line 3
                    "    unused: str,",  # line 4
                    "    base: str = '/',",  # line 5
                    "):",  # line 6
                    "    return [p.name for p in Path(base).iterdir()]",  # line 7
                ]
            )
        )

        finding = next(
            item for item in report.findings if item.rule_id == "MSC104"
        )
        self.assertEqual(finding.evidence.line_number, 5)
        self.assertEqual(finding.evidence.symbol, "base default")


class SuppressionScopeTests(unittest.TestCase):
    def test_an_unrelated_unresolved_call_no_longer_hides_a_traversal(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import importlib",
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def read_doc(filepath: str, plugin: str):",
                    "    text = Path(filepath).read_text()",
                    "    return importlib.import_module(plugin).process(text)",
                ]
            )
        )

        self.assertEqual(_tools_for(report, "MSC103"), {"read_doc"})
        self.assertEqual(report.completeness.status, AnalysisStatus.PARTIAL)
        self.assertTrue(
            any(
                item.code == "MSC103-GUARD-UNKNOWN"
                for item in report.completeness.notifications
            )
        )

    def test_no_guard_notification_for_tools_without_filesystem_involvement(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import importlib",
                    "@mcp.tool()",
                    "def compute(expression: str, plugin: str):",
                    "    return importlib.import_module(plugin).run(expression)",
                ]
            )
        )

        self.assertEqual(
            [
                item.code
                for item in report.completeness.notifications
                if item.code == "MSC103-GUARD-UNKNOWN"
            ],
            [],
        )
        self.assertEqual(report.completeness.status, AnalysisStatus.PARTIAL)


class LocalClassDispatchTests(unittest.TestCase):
    def test_same_file_class_construction_reports_instance_dispatch(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "class Helper:",
                    "    def go(self, value):",
                    "        return value",
                    "@mcp.tool()",
                    "def lookup(query: str):",
                    "    return Helper().go(query)",
                ]
            )
        )

        reasons = {
            edge.reason.value for edge in report.completeness.unresolved_edges
        }
        self.assertIn("unsupported instance/class dispatch", reasons)
        self.assertNotIn("higher-order call", reasons)


if __name__ == "__main__":
    unittest.main()

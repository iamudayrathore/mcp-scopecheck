"""Correlated path-guard and dangerous-default regressions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_scopecheck.auditor import audit
from mcp_scopecheck.models import AuditReport


def _audit_source(source: str) -> AuditReport:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "server.py").write_text(source, encoding="utf-8")
        return audit(root)


def _findings(report: AuditReport, rule_id: str) -> dict[str, str]:
    return {
        finding.tool_name: finding.message
        for finding in report.findings
        if finding.rule_id == rule_id
    }


class PathScopeTests(unittest.TestCase):
    def test_unrelated_guard_does_not_suppress_another_path_flow(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "from pathlib import Path",
                    "ROOT = Path('/srv/docs')",
                    "@mcp.tool()",
                    "def read_doc(first_path: str, second_path: str):",
                    "    checked = (ROOT / first_path).resolve()",
                    "    checked.relative_to(ROOT)",
                    "    return (ROOT / second_path).resolve().read_text()",
                ]
            )
        )

        finding = _findings(report, "MSC103")["read_doc"]
        self.assertIn("['second_path']", finding)
        self.assertNotIn("first_path", finding)

    def test_guarded_alias_and_direct_helper_guard_suppress_the_same_flow(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "from pathlib import Path",
                    "ROOT = Path('/srv/docs')",
                    "def validate(candidate):",
                    "    candidate.relative_to(ROOT)",
                    "def read_unchecked(value):",
                    "    return open(value).read()",
                    "def read_fixed():",
                    "    return (ROOT / 'fixed.md').read_text()",
                    "@mcp.tool()",
                    "def guarded_alias(path: str):",
                    "    candidate = (ROOT / path).resolve()",
                    "    alias = candidate",
                    "    alias.relative_to(ROOT)",
                    "    return candidate.read_text()",
                    "@mcp.tool()",
                    "def guarded_helper(file_path: str):",
                    "    candidate = (ROOT / file_path).resolve()",
                    "    validate(candidate)",
                    "    return candidate.read_text()",
                    "@mcp.tool()",
                    "def delegated(file_path: str):",
                    "    return read_unchecked(file_path)",
                    "@mcp.tool()",
                    "def unrelated_fixed(path: str):",
                    "    read_fixed()",
                    "    return path",
                ]
            )
        )

        findings = _findings(report, "MSC103")
        self.assertNotIn("guarded_alias", findings)
        self.assertNotIn("guarded_helper", findings)
        self.assertIn("delegated", findings)
        self.assertNotIn("unrelated_fixed", findings)

    def test_checked_boolean_and_commonpath_guards_must_dominate_the_sink(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import os",
                    "from pathlib import Path",
                    "ROOT = Path('/srv/docs')",
                    "@mcp.tool()",
                    "def boolean_guard(path: str):",
                    "    candidate = (ROOT / path).resolve()",
                    "    if not candidate.is_relative_to(ROOT):",
                    "        raise ValueError('outside root')",
                    "    return candidate.read_text()",
                    "@mcp.tool()",
                    "def commonpath_guard(file_path: str):",
                    "    candidate = (ROOT / file_path).resolve()",
                    "    if os.path.commonpath([str(ROOT), str(candidate)]) != str(ROOT):",
                    "        raise ValueError('outside root')",
                    "    return candidate.read_text()",
                    "@mcp.tool()",
                    "def conditional_only(path: str, validate: bool):",
                    "    candidate = (ROOT / path).resolve()",
                    "    if validate:",
                    "        candidate.relative_to(ROOT)",
                    "    return candidate.read_text()",
                    "@mcp.tool()",
                    "def unchecked_boolean(file_path: str):",
                    "    candidate = (ROOT / file_path).resolve()",
                    "    candidate.is_relative_to(ROOT)",
                    "    return candidate.read_text()",
                ]
            )
        )

        findings = _findings(report, "MSC103")
        self.assertNotIn("boolean_guard", findings)
        self.assertNotIn("commonpath_guard", findings)
        self.assertIn("conditional_only", findings)
        self.assertIn("unchecked_boolean", findings)

    def test_only_the_unguarded_parameter_is_reported(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "from pathlib import Path",
                    "ROOT = Path('/srv/docs')",
                    "@mcp.tool()",
                    "def compare(first_path: str, second_path: str):",
                    "    first = (ROOT / first_path).resolve()",
                    "    second = (ROOT / second_path).resolve()",
                    "    first.relative_to(ROOT)",
                    "    first.read_text()",
                    "    return second.read_text()",
                ]
            )
        )

        finding = _findings(report, "MSC103")["compare"]
        self.assertIn("['second_path']", finding)
        self.assertNotIn("first_path", finding)

    def test_root_and_actually_expanded_home_defaults_are_dangerous(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "import os",
                    "from pathlib import Path as P",
                    "@mcp.tool()",
                    "def posix_root(root: str = '/'):",
                    "    return root",
                    "@mcp.tool()",
                    "def path_root(root=P('/')):",
                    "    return root",
                    "@mcp.tool()",
                    "def expanded_tilde(root: str = '~'):",
                    "    return P(root).expanduser()",
                    "@mcp.tool()",
                    "def expanded_tilde_slash(root: str = '~/'):",
                    "    return os.path.expanduser(root)",
                    "@mcp.tool()",
                    "def static_expansion(root=os.path.expanduser('~/')):",
                    "    return root",
                    "@mcp.tool()",
                    "def path_home(root=P.home()):",
                    "    return root",
                ]
            )
        )

        self.assertEqual(
            set(_findings(report, "MSC104")),
            {
                "expanded_tilde",
                "expanded_tilde_slash",
                "path_home",
                "path_root",
                "posix_root",
                "static_expansion",
            },
        )

    def test_unexpanded_or_bounded_home_and_windows_defaults_are_not_equated(self) -> None:
        report = _audit_source(
            "\n".join(
                [
                    "from pathlib import Path",
                    "@mcp.tool()",
                    "def literal_tilde(root: str = '~'):",
                    "    return root",
                    "@mcp.tool()",
                    "def bounded_home(root: str = '~/.scopecheck'):",
                    "    return Path(root).expanduser()",
                    "@mcp.tool()",
                    "def bounded_project(root: str = '~/project'):",
                    "    return Path(root).expanduser()",
                    "@mcp.tool()",
                    "def windows_drive(root: str = 'C:\\\\'):",
                    "    return root",
                    "@mcp.tool()",
                    "def dynamic_default(root=get_root()):",
                    "    return root",
                ]
            )
        )

        self.assertEqual(_findings(report, "MSC104"), {})


if __name__ == "__main__":
    unittest.main()

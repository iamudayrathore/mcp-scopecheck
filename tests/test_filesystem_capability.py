"""Filesystem capability reporting after MSC103/MSC104 were withdrawn in 0.2.5.

The containment rules are gone; the capability is not. ScopeCheck still reports
that a tool reaches a filesystem operation, and the evidence path to it, because
that part is decided by the call graph rather than by the guard model that failed
across four consecutive release candidates.

These tests pin both halves: the capability is observed through the routes that
matter, and no containment verdict is emitted for it.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_scopecheck.auditor import audit
from mcp_scopecheck.models import AuditReport, Capability

PREAMBLE = (
    "from pathlib import Path\n"
    "ROOT = Path('/srv/docs')\n"
    "def _resolve(value):\n"
    "    return ROOT / value\n"
)


def _audit(body: str, *, annotations: str = "") -> AuditReport:
    decorator = f"@mcp.tool(annotations={{{annotations}}})" if annotations else "@mcp.tool()"
    source = (
        f"{PREAMBLE}"
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('t')\n\n"
        f"{decorator}\n"
        "def entry(name: str, body: str = ''):\n"
        '    """Read or write a bundled documentation file."""\n'
        f"{body}\n"
    )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "server.py").write_text(source, encoding="utf-8")
        return audit(root)


def _capabilities(report: AuditReport) -> set[Capability]:
    return {
        item.capability
        for items in report.capabilities.values()
        for item in items
    }


def _rules(report: AuditReport) -> set[str]:
    return {finding.rule_id for finding in report.findings}


class WithdrawnRuleTests(unittest.TestCase):
    """MSC103 and MSC104 must not be emitted, and must not be advertised."""

    def test_no_containment_verdict_is_produced(self) -> None:
        for label, body in (
            ("unguarded read", "    Path(name).read_text()"),
            ("unguarded write", "    Path(name).write_text(body)"),
            ("root default", "    Path(name).iterdir()"),
        ):
            with self.subTest(shape=label):
                self.assertEqual(_rules(_audit(body)) & {"MSC103", "MSC104"}, set())

    def test_withdrawn_rules_are_absent_from_the_sarif_catalogue(self) -> None:
        from mcp_scopecheck.sarif import RULE_METADATA

        self.assertNotIn("MSC103", RULE_METADATA)
        self.assertNotIn("MSC104", RULE_METADATA)


class CapabilityObservationTests(unittest.TestCase):
    """The capability itself is still reported, by every route that reaches it."""

    def test_direct_filesystem_access_is_observed(self) -> None:
        read = _capabilities(_audit("    Path(name).read_text()"))
        self.assertIn(Capability.FILESYSTEM_READ, read)
        self.assertIn(
            Capability.FILESYSTEM_WRITE,
            _capabilities(_audit("    Path(name).write_text(body)")),
        )

    def test_access_through_a_local_helper_is_observed(self) -> None:
        report = _audit("    _resolve(name).write_text(body)")
        self.assertIn(Capability.FILESYSTEM_WRITE, _capabilities(report))

    def test_access_through_a_container_is_observed(self) -> None:
        report = _audit('    d = {"a": Path(name)}\n    d["a"].read_text()')
        self.assertIn(Capability.FILESYSTEM_READ, _capabilities(report))

    def test_evidence_records_the_path_to_the_sink(self) -> None:
        report = _audit("    _resolve(name).write_text(body)")
        evidence = next(
            item.evidence
            for items in report.capabilities.values()
            for item in items
            if item.capability is Capability.FILESYSTEM_WRITE
        )
        self.assertTrue(evidence.path, "capability evidence must carry a trace")
        self.assertEqual(evidence.path[0].symbol, "entry")


class SpeculativeReceiverTests(unittest.TestCase):
    """An inferred path must not invent a capability on unrelated objects.

    `ENTRIES[key].touch()` on an in-memory cache reported a filesystem write, and
    with the contract rules still active it also produced a HIGH readOnlyHint
    conflict. Ambiguous method names on a merely-inferred receiver no longer count.
    """

    def test_ambiguous_methods_on_a_container_element_are_not_filesystem(self) -> None:
        for method in ("touch", "rename", "open", "chmod", "unlink"):
            with self.subTest(method=method):
                report = _audit(f"    ENTRIES = {{}}\n    ENTRIES[name].{method}()")
                self.assertEqual(_capabilities(report), set())
                self.assertEqual(_rules(report), set())

    def test_ambiguous_methods_on_a_proven_path_are_filesystem(self) -> None:
        """A constructed Path is proven, so every sink method on it counts.

        Treating any call receiver as speculative made `Path(name).unlink()` report
        no capability while `p = Path(name); p.unlink()` reported the write - the
        same code, judged differently on line count.
        """

        for body, capability in (
            ("    Path(name).unlink()", Capability.FILESYSTEM_WRITE),
            ("    Path(name).touch()", Capability.FILESYSTEM_WRITE),
            ("    Path(name).rename('x')", Capability.FILESYSTEM_WRITE),
            ("    Path(name).open().read()", Capability.FILESYSTEM_READ),
            ("    _resolve(name).touch()", Capability.FILESYSTEM_WRITE),
            ("    (p := Path(name)).touch()", Capability.FILESYSTEM_WRITE),
        ):
            with self.subTest(body=body.strip()):
                self.assertIn(capability, _capabilities(_audit(body)))

    def test_one_line_and_two_line_spellings_agree(self) -> None:
        single = _capabilities(_audit("    Path(name).unlink()"))
        split = _capabilities(_audit("    p = Path(name)\n    p.unlink()"))
        self.assertEqual(single, split)

    def test_pathlib_exclusive_methods_on_a_container_element_still_count(self) -> None:
        for method in ("read_text", "iterdir", "read_bytes"):
            with self.subTest(method=method):
                report = _audit(f"    ENTRIES = {{}}\n    ENTRIES[name].{method}()")
                self.assertTrue(_capabilities(report) & {
                    Capability.FILESYSTEM_READ,
                    Capability.FILESYSTEM_WRITE,
                })


if __name__ == "__main__":
    unittest.main()

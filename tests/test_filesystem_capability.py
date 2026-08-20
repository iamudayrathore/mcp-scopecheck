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

    def test_access_through_a_container_is_a_known_blind_spot(self) -> None:
        """Documented in docs/limitations.md; pinned so it cannot change silently."""

        report = _audit('    d = {"a": Path(name)}\n    d["a"].read_text()')
        self.assertEqual(_capabilities(report), set())

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


class ContainerElementTests(unittest.TestCase):
    """A container element is deliberately not treated as a path.

    Whether `D[k]` holds a path is not knowable here. Treating it as one invented
    filesystem writes on in-memory caches; gating that on method names made
    `D[k].touch()` and `entry = D[k]; entry.touch()` disagree - the same
    spelling-dependent verdict that led to withdrawing MSC103. A path retrieved
    from a container by subscript is not tracked. That is a bounded false negative,
    stated in docs/limitations.md, and preferred to an unbounded false positive on
    ordinary code.
    """

    def test_no_capability_is_invented_for_container_elements(self) -> None:
        for method in ("touch", "rename", "open", "chmod", "unlink", "read_text"):
            with self.subTest(method=method):
                report = _audit(f"    ENTRIES = {{}}\n    ENTRIES[name].{method}()")
                self.assertEqual(_capabilities(report), set())
                self.assertEqual(_rules(report), set())

    def test_container_verdict_does_not_depend_on_spelling(self) -> None:
        inline = _audit("    ENTRIES = {}\n    ENTRIES[name].touch()")
        bound = _audit("    ENTRIES = {}\n    entry = ENTRIES[name]\n    entry.touch()")
        self.assertEqual(_capabilities(inline), _capabilities(bound))
        self.assertEqual(_rules(inline), _rules(bound))

    def test_a_normalizing_hop_does_not_launder_a_container_element(self) -> None:
        report = _audit("    R = {}\n    R[name].resolve(name).rename(name)")
        self.assertEqual(_capabilities(report), set())

    def test_str_of_a_path_is_a_string_not_a_path(self) -> None:
        """`str.replace` collides with `Path.replace`, which renames a file."""

        report = _audit("    raw = str(ROOT / name)\n    raw.replace('a', 'b')")
        self.assertEqual(_capabilities(report), set())

    def test_str_of_a_path_still_reaches_a_real_sink(self) -> None:
        report = _audit("    open(str(Path(name))).read()")
        self.assertIn(Capability.FILESYSTEM_READ, _capabilities(report))



if __name__ == "__main__":
    unittest.main()

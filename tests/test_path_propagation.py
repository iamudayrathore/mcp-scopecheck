"""Regressions for path-taint propagation and fail-closed lineage.

v0.2.1 fixed which parameters were *seeded* into the filesystem dataflow, but not
how taint *propagated*. `_value()` modeled a short list of expression forms and
returned an empty value for everything else, and `_merge_states` intersected
bindings at control-flow joins. Both dropped taint silently: a caller-controlled
path reaching an unguarded filesystem call produced `Findings (0)`, completeness
`complete`, and exit `0` - the exact failure this scanner exists to prevent.

These tests pin both halves of the fix: ordinary path construction now propagates
and is reported, and anything still outside the model fails closed to `partial`
with a named notification rather than going silent.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_scopecheck.auditor import audit
from mcp_scopecheck.models import AnalysisStatus, AuditReport

PREAMBLE = (
    "import code\n"
    "import multiprocessing\n"
    "import os\n"
    "import os.path\n"
    "import posixpath\n"
    "import pty\n"
    "import runpy\n"
    "import types\n"
    "import urllib.parse\n"
    "from pathlib import Path\n"
    "ROOT = Path('/srv/docs')\n"
    "def _pick(n):\n"
    "    return n\n"
)


def _audit(body: str, *, annotations: str = "", preamble_extra: str = "") -> AuditReport:
    decorator = f"@mcp.tool(annotations={{{annotations}}})" if annotations else "@mcp.tool()"
    source = (
        f"{PREAMBLE}{preamble_extra}\n"
        f"{decorator}\n"
        "def entry(name: str):\n"
        '    """Read a bundled documentation file."""\n'
        f"{body}\n"
    )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "server.py").write_text(source, encoding="utf-8")
        return audit(root)


def _rules(report: AuditReport) -> set[str]:
    return {finding.rule_id for finding in report.findings}


class PathPropagationTests(unittest.TestCase):
    """Ordinary path construction must not launder caller-controlled input."""

    CASES = {
        "percent_format": '    target = "%s/%s" % ("/srv", name)\n    open(target).read()',
        "str_format": '    target = "{}/{}".format("/srv", name)\n    open(target).read()',
        "str_join": '    target = "/".join(["/srv", name])\n    open(target).read()',
        "os_sep_join": '    target = os.sep.join(["/srv", name])\n    open(target).read()',
        "posixpath_join": '    target = posixpath.join("/srv", name)\n    open(target).read()',
        "strip": '    target = name.strip("/")\n    open(target).read()',
        "lstrip": '    target = name.lstrip("./")\n    open(target).read()',
        "replace_dotdot": '    target = name.replace("..", "")\n    open(target).read()',
        "removeprefix": '    target = name.removeprefix("/")\n    open(target).read()',
        "encode_decode": "    target = name.encode().decode()\n    open(target).read()",
        "ternary": '    target = name if name else "d"\n    open(target).read()',
        "walrus": "    target = (t := name)\n    open(target).read()",
        "subscript_dict": '    target = {"k": name}["k"]\n    open(target).read()',
        "subscript_list": "    target = [name][0]\n    open(target).read()",
        "slice": "    target = name[0:]\n    open(target).read()",
        "unquote": "    target = urllib.parse.unquote(name)\n    open(target).read()",
        "tuple_unpack": "    target, _ = name, 1\n    open(target).read()",
        "aug_assign": '    target = "/srv"\n    target += name\n    open(target).read()',
        "for_binding": "    for target in [name]:\n        pass\n    open(target).read()",
        "try_binding": (
            "    try:\n        target = name\n"
            '    except Exception:\n        target = "d"\n'
            "    open(target).read()"
        ),
    }

    def test_every_construction_form_is_reported(self) -> None:
        for label, body in self.CASES.items():
            with self.subTest(form=label):
                report = _audit(body)
                self.assertIn(
                    "MSC103",
                    _rules(report),
                    f"{label} laundered a caller-controlled path",
                )
                self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)


class FailClosedLineageTests(unittest.TestCase):
    """Unmodeled lineage must be reported as incomplete, never as clean.

    These forms are deliberately NOT modeled. The requirement is not that they
    produce a finding - MSC103 asserts a path is *unguarded*, and that claim
    cannot be made about lineage the analyzer did not follow. The requirement is
    that they never produce a clean result.
    """

    UNMODELED = {
        "helper_return": "    target = _pick(name)\n    open(target).read()",
        "listcomp_result": "    target = [n for n in [name]][0]\n    open(target).read()",
        "next_iter": "    target = next(iter([name]))\n    open(target).read()",
        "external_call": (
            "    import somepkg\n"
            "    target = somepkg.sanitize(name)\n"
            "    open(target).read()"
        ),
    }

    def test_unmodeled_forms_never_produce_a_clean_result(self) -> None:
        for label, body in self.UNMODELED.items():
            with self.subTest(form=label):
                report = _audit(body)
                self.assertNotEqual(
                    report.completeness.status,
                    AnalysisStatus.COMPLETE,
                    f"{label} produced a clean audit on unfollowed lineage",
                )

    def test_unmodeled_transform_downgrades_to_partial_with_a_notification(self) -> None:
        report = _audit(
            "    import somepkg\n"
            "    target = somepkg.sanitize(name)\n"
            "    open(target).read()"
        )

        self.assertEqual(report.completeness.status, AnalysisStatus.PARTIAL)
        self.assertNotIn("MSC103", _rules(report))
        self.assertTrue(
            any(
                item.code == "MSC103-LINEAGE-UNPROVEN"
                for item in report.completeness.notifications
            ),
            "unmodeled lineage must be named in the completeness ledger",
        )

    def test_unproven_lineage_is_not_asserted_as_an_unguarded_finding(self) -> None:
        """MSC103 claims a path is unguarded; it must not claim that unproven."""

        report = _audit(
            "    import somepkg\n"
            "    target = somepkg.sanitize(name)\n"
            "    open(target).read()"
        )
        self.assertEqual(_rules(report) & {"MSC103"}, set())


class PropagationFalsePositiveTests(unittest.TestCase):
    """Widened propagation must not turn ordinary code into findings."""

    def test_recognized_guard_still_clears_a_constructed_path(self) -> None:
        report = _audit(
            "    candidate = (ROOT / name).resolve()\n"
            "    candidate.relative_to(ROOT)\n"
            "    candidate.read_text()"
        )
        self.assertNotIn("MSC103", _rules(report))
        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)

    def test_string_methods_on_data_that_never_reaches_a_sink_are_clean(self) -> None:
        report = _audit(
            '    text = (ROOT / "index.txt").read_text()\n'
            "    return [line for line in text.splitlines() if name.lower() in line.lower()]"
        )
        self.assertNotIn("MSC103", _rules(report))
        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)

    def test_derived_data_written_to_a_fixed_path_is_clean(self) -> None:
        report = _audit('    (ROOT / "report.txt").write_text(name.strip())')
        self.assertNotIn("MSC103", _rules(report))
        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)


class ProcessAndCodeSinkTests(unittest.TestCase):
    """Execution primitives must not report `Observed: none`."""

    PROCESS = {
        "execv": '    os.execv("/bin/sh", ["sh", "-c", name])',
        "execl": '    os.execl("/bin/sh", "sh", "-c", name)',
        "execvp": '    os.execvp("sh", ["sh", "-c", name])',
        "spawnv": '    os.spawnv(os.P_WAIT, "/bin/sh", ["sh", "-c", name])',
        "posix_spawn": '    os.posix_spawn("/bin/sh", ["sh", "-c", name], {})',
        "fork": "    os.fork()",
        "pty_spawn": '    pty.spawn(["/bin/sh", "-c", name])',
        "pty_fork": "    pty.fork()",
        "multiprocessing": "    multiprocessing.Process(target=os.system, args=(name,))",
    }
    CODE = {
        "runpy_path": "    runpy.run_path(name)",
        "runpy_module": "    runpy.run_module(name)",
        "code_interact": "    code.InteractiveInterpreter().runsource(name)",
        "function_type": '    types.FunctionType(compile(name, "<s>", "exec"), {})()',
    }

    def test_process_primitives_are_reported(self) -> None:
        for label, body in self.PROCESS.items():
            with self.subTest(primitive=label):
                report = _audit(body, annotations="'readOnlyHint': True")
                rules = _rules(report)
                self.assertIn("MSC106", rules, f"{label} reported no process execution")
                self.assertIn("MSC101", rules, f"{label} did not conflict with readOnlyHint")

    def test_dynamic_code_primitives_are_reported(self) -> None:
        for label, body in self.CODE.items():
            with self.subTest(primitive=label):
                self.assertIn("MSC107", _rules(_audit(body)), f"{label} reported no code execution")


class UntrackableStoreTests(unittest.TestCase):
    """Storing tool input where the analyzer cannot follow it must not read clean.

    0.2.2 claimed "unfollowed lineage fails closed" but `_assigned_names` returned
    nothing for subscript and attribute targets, so `_assign` bound nothing and the
    `proven` flag was never set. Four idioms produced completeness `complete`, no
    findings, and exit 0 for unrestricted caller-controlled file reads.
    """

    def test_subscript_store_degrades_to_partial(self) -> None:
        report = _audit(
            "    request = {}\n"
            '    request["target"] = name\n'
            '    open(request["target"]).read()'
        )
        self.assertNotEqual(report.completeness.status, AnalysisStatus.COMPLETE)
        self.assertTrue(
            any(
                item.code == "MSC103-LINEAGE-UNPROVEN"
                for item in report.completeness.notifications
            )
        )

    def test_attribute_store_degrades_to_partial(self) -> None:
        report = _audit(
            "    class Box:\n        target = None\n"
            "    Box.target = name\n"
            "    open(Box.target).read()"
        )
        self.assertNotEqual(report.completeness.status, AnalysisStatus.COMPLETE)

    def test_global_write_degrades_to_partial(self) -> None:
        report = _audit(
            "    global _PENDING\n    _PENDING = name\n    open(_PENDING).read()",
            preamble_extra="_PENDING = ''",
        )
        self.assertNotEqual(report.completeness.status, AnalysisStatus.COMPLETE)

    def test_match_capture_is_bound_and_reported(self) -> None:
        report = _audit(
            "    match name:\n"
            "        case str() as target:\n"
            "            open(target).read()"
        )
        self.assertIn("MSC103", _rules(report))

    def test_container_mutation_taints_the_container(self) -> None:
        report = _audit(
            "    queue = []\n    queue.append(name)\n    open(queue[0]).read()"
        )
        self.assertIn("MSC103", _rules(report))


class GeneratorExpressionTests(unittest.TestCase):
    """A generator expression must not hide the capabilities inside it.

    Before 0.2.3 both visitors read only the first `iter`, so a sink in the element
    expression was never observed at all - `Side effects: 0`, `Observed: none`,
    `complete`, exit 0, which is an affirmative denial of a capability the tool has.
    """

    def test_process_execution_inside_a_generator_is_observed(self) -> None:
        report = _audit(
            "    import subprocess\n"
            '    return "".join(\n'
            "        subprocess.check_output(name, shell=True).decode() for _ in range(1)\n"
            "    )",
            annotations="'readOnlyHint': True",
        )
        rules = _rules(report)
        self.assertIn("MSC106", rules)
        self.assertIn("MSC101", rules)

    def test_filesystem_access_inside_a_generator_is_observed(self) -> None:
        report = _audit('    return "".join(open(name).read() for _ in range(1))')
        self.assertIn("MSC103", _rules(report))


class GuardSurvivalTests(unittest.TestCase):
    """Guards must survive normalization and branches that carry no taint."""

    def test_guard_on_a_normalized_temporary_covers_the_receiver(self) -> None:
        """`t.resolve().relative_to(ROOT)` proves containment for `t` itself."""

        report = _audit(
            '    target = ROOT / (name + ".md")\n'
            "    target.resolve().relative_to(ROOT.resolve())\n"
            "    target.read_text()"
        )
        self.assertNotIn("MSC103", _rules(report))
        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)

    def test_untainted_fallback_branch_does_not_dissolve_the_guard(self) -> None:
        """The canonical containment idiom: guard in try, fixed path in except."""

        report = _audit(
            "    try:\n"
            '        target = ROOT / "sections" / (name + ".md")\n'
            "        target.resolve().relative_to(ROOT.resolve())\n"
            "    except ValueError:\n"
            '        target = ROOT / "index.md"\n'
            "    target.read_text()"
        )
        self.assertNotIn("MSC103", _rules(report))

    def test_an_unguarded_try_branch_is_still_reported(self) -> None:
        """Guard survival must not silence a genuinely unguarded join."""

        report = _audit(
            "    try:\n        target = name\n"
            '    except Exception:\n        target = "d"\n'
            "    open(target).read()"
        )
        self.assertIn("MSC103", _rules(report))


class DefeatedGuardTests(unittest.TestCase):
    """A containment check that cannot constrain the sink must not clear it.

    Containment is a proven fact about a value, not a mark that spreads. Releases
    before 0.2.4 set a guard whenever a `relative_to` call appeared and carried it
    through any derivation, so a swallowed exception or a path built by escaping out
    of the guarded value produced a clean audit on real traversal.
    """

    def test_swallowed_exception_does_not_establish_a_guard(self) -> None:
        for label, handler in (
            ("pass", "        pass"),
            ("bare_except", "        _ = 1"),
        ):
            with self.subTest(handler=label):
                report = _audit(
                    "    try:\n"
                    "        t = ROOT / name\n"
                    "        t.relative_to(ROOT)\n"
                    "    except ValueError:\n"
                    f"{handler}\n"
                    "    t.read_text()"
                )
                self.assertIn("MSC103", _rules(report))

    def test_contextlib_suppress_does_not_establish_a_guard(self) -> None:
        report = _audit(
            "    import contextlib\n"
            "    t = ROOT / name\n"
            "    with contextlib.suppress(ValueError):\n"
            "        t.relative_to(ROOT)\n"
            "    t.read_text()"
        )
        self.assertIn("MSC103", _rules(report))

    def test_containment_does_not_survive_added_components(self) -> None:
        """Proving `t` is contained proves nothing about `t / x`."""

        for label, sink in (
            ("parent_escape", '    (t / ".." / ".." / "etc" / "passwd").read_text()'),
            ("joinpath", '    t.joinpath("..", "etc").read_text()'),
            ("expanduser", "    t.expanduser().read_text()"),
        ):
            with self.subTest(derivation=label):
                report = _audit(
                    "    t = ROOT / name\n"
                    "    t.resolve().relative_to(ROOT)\n"
                    f"{sink}"
                )
                self.assertIn("MSC103", _rules(report))

    def test_containment_survives_pure_normalization(self) -> None:
        report = _audit(
            "    t = ROOT / name\n"
            "    t.resolve().relative_to(ROOT)\n"
            "    t.resolve().read_text()"
        )
        self.assertNotIn("MSC103", _rules(report))

    def test_untainted_fallback_still_preserves_the_guard(self) -> None:
        """The canonical idiom must not regress while fixing the swallowed case."""

        report = _audit(
            "    try:\n"
            '        t = ROOT / "sections" / (name + ".md")\n'
            "        t.resolve().relative_to(ROOT.resolve())\n"
            "    except ValueError:\n"
            '        t = ROOT / "index.md"\n'
            "    t.read_text()"
        )
        self.assertNotIn("MSC103", _rules(report))


class UntrackedStoreSpellingTests(unittest.TestCase):
    """`d[k] = p` and `d.__setitem__(k, p)` are the same store, reported the same."""

    STORES = {
        "subscript": '    r = {}\n    r["t"] = name\n    open(r["t"]).read()',
        "dunder": '    r = {}\n    r.__setitem__("t", name)\n    open(r["t"]).read()',
        "operator": (
            "    import operator\n    r = {}\n"
            '    operator.setitem(r, "t", name)\n    open(r["t"]).read()'
        ),
        "heappush": (
            "    import heapq\n    q = []\n"
            "    heapq.heappush(q, name)\n    open(q[0]).read()"
        ),
        "appendleft": (
            "    import collections\n    q = collections.deque()\n"
            "    q.appendleft(name)\n    open(q[0]).read()"
        ),
    }

    def test_no_spelling_of_an_untracked_store_reads_clean(self) -> None:
        for label, body in self.STORES.items():
            with self.subTest(store=label):
                report = _audit(body)
                self.assertNotEqual(
                    report.completeness.status,
                    AnalysisStatus.COMPLETE,
                    f"{label} produced a clean audit",
                )

    def test_stores_without_filesystem_involvement_are_not_reported(self) -> None:
        """Putting a parameter in a dict is ordinary code, not a filesystem concern."""

        report = _audit(
            "    envelope = {}\n"
            '    envelope["message"] = name\n'
            '    envelope["length"] = len(name)\n'
            "    return envelope"
        )
        self.assertEqual(report.completeness.status, AnalysisStatus.COMPLETE)
        self.assertEqual(_rules(report), set())


if __name__ == "__main__":
    unittest.main()

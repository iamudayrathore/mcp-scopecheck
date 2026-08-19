"""SARIF 2.1.0 output and CLI regressions."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from mcp_scopecheck.auditor import audit
from mcp_scopecheck.cli import main
from mcp_scopecheck.sarif import render_sarif


def _invoke(arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()


def _document(output: str) -> dict[str, Any]:
    document = json.loads(output)
    assert isinstance(document, dict)
    return document


def _all_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for value_item in value for item in _all_strings(value_item)]
    if isinstance(value, dict):
        return [
            item
            for key, value_item in value.items()
            for item in [*_all_strings(key), *_all_strings(value_item)]
        ]
    return []


class SarifTests(unittest.TestCase):
    def test_msc102_rule_metadata_and_message_use_review_semantics(self) -> None:
        source = "\n".join(
            [
                "import requests",
                "@mcp.tool(description='Fetches issues from the GitHub API.')",
                "def lookup(base: str):",
                "    return requests.get(base + '/issues')",
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.py").write_text(source, encoding="utf-8")
            report = audit(root)
            document = _document(render_sarif(report, 1))
        run = document["runs"][0]
        rule = next(
            item for item in run["tool"]["driver"]["rules"] if item["id"] == "MSC102"
        )
        self.assertEqual(
            rule["shortDescription"]["text"], "External network egress requires review"
        )
        result = next(item for item in run["results"] if item["ruleId"] == "MSC102")
        message = result["message"]["text"]
        self.assertIn("External network egress requires review", message)
        self.assertIn("modeled reachable external network call", message)
        self.assertNotIn("absent from the tool", message)
        self.assertNotIn("not disclosed", message.lower())

    def test_clean_finding_partial_and_failed_reports_are_valid_json(self) -> None:
        cases = {
            "clean": (
                "@mcp.tool()\ndef entry():\n    return 1\n",
                0,
                0,
                "complete",
            ),
            "finding": (
                "import subprocess\n"
                "@mcp.tool()\n"
                "def entry():\n"
                "    return subprocess.run(['fixed'])\n",
                1,
                1,
                "complete",
            ),
            "partial": (
                "import subprocess\n"
                "@wrapper\n"
                "@mcp.tool()\n"
                "def entry():\n"
                "    return subprocess.run(['fixed'])\n",
                2,
                1,
                "partial",
            ),
        }
        for label, (source, expected_code, result_count, status) in cases.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "server.py").write_text(source, encoding="utf-8")
                    code, output, error = _invoke(
                        ["audit", str(root), "--format", "sarif"]
                    )
                document = _document(output)
                run = document["runs"][0]
                invocation = run["invocations"][0]
                self.assertEqual(document["version"], "2.1.0")
                self.assertEqual(code, expected_code)
                self.assertEqual(error, "")
                self.assertEqual(len(run["results"]), result_count)
                self.assertEqual(
                    invocation["properties"]["scopecheck"]["completeness"]["status"],
                    status,
                )
                self.assertEqual(invocation["exitCode"], expected_code)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "valid.py").write_text(
                "@mcp.tool()\ndef entry():\n    return 1\n",
                encoding="utf-8",
            )
            (root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
            code, output, error = _invoke(["audit", str(root), "--format", "sarif"])
        document = _document(output)
        invocation = document["runs"][0]["invocations"][0]
        self.assertEqual((code, error), (2, ""))
        self.assertFalse(invocation["executionSuccessful"])
        self.assertTrue(
            any(
                item["descriptor"]["id"] == "MSC-DIAGNOSTIC"
                for item in invocation["toolExecutionNotifications"]
            )
        )

    def test_missing_target_is_also_a_pure_sarif_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            code, output, error = _invoke(
                ["audit", str(missing), "--format", "sarif"]
            )

        document = _document(output)
        invocation = document["runs"][0]["invocations"][0]
        self.assertEqual((code, error), (2, ""))
        self.assertEqual(invocation["exitCode"], 2)
        self.assertEqual(
            invocation["toolExecutionNotifications"][0]["descriptor"]["id"],
            "MSC-AUDIT-FAILED",
        )

    def test_findings_have_rule_metadata_locations_and_shortest_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "pkg"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "ops.py").write_text(
                "import subprocess\ndef run():\n    return subprocess.run(['fixed'])\n",
                encoding="utf-8",
            )
            (package / "server.py").write_text(
                "from .ops import run\n@mcp.tool()\ndef entry():\n    return run()\n",
                encoding="utf-8",
            )
            report = audit(root)
            first = render_sarif(report, 1)
            second = render_sarif(report, 1)

        self.assertEqual(first, second)
        document = _document(first)
        run = document["runs"][0]
        driver = run["tool"]["driver"]
        result = run["results"][0]
        self.assertEqual(result["ruleId"], "MSC106")
        self.assertEqual(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "pkg/ops.py",
        )
        self.assertEqual(
            [item["message"]["text"] for item in result["relatedLocations"]],
            ["entry", "run", "subprocess.run"],
        )
        self.assertTrue(any(item["id"] == "MSC106" for item in driver["rules"]))
        self.assertEqual(driver["semanticVersion"], driver["version"])

    def test_incompleteness_is_notification_not_security_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.py").write_text(
                "@wrapper\n@mcp.tool()\ndef entry(callback):\n    return callback()\n",
                encoding="utf-8",
            )
            code, output, error = _invoke(["audit", str(root), "--format", "sarif"])

        document = _document(output)
        run = document["runs"][0]
        notification_ids = {
            item["descriptor"]["id"]
            for item in run["invocations"][0]["toolExecutionNotifications"]
        }
        self.assertEqual((code, error), (2, ""))
        self.assertEqual(run["results"], [])
        self.assertIn("MSC-INCOMPLETE-EDGE", notification_ids)

    def test_single_file_and_directory_artifact_uris_are_relative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "server.py"
            target.write_text(
                "import subprocess\n@mcp.tool()\ndef entry():\n    return subprocess.run(['x'])\n",
                encoding="utf-8",
            )
            _, directory_output, _ = _invoke(
                ["audit", str(root), "--format", "sarif"]
            )
            _, file_output, _ = _invoke(
                ["audit", str(target), "--format", "sarif"]
            )

        for output in (directory_output, file_output):
            location = _document(output)["runs"][0]["results"][0]["locations"][0]
            self.assertEqual(
                location["physicalLocation"]["artifactLocation"]["uri"],
                "server.py",
            )

    def test_untrusted_control_newline_and_bidi_text_is_sanitized(self) -> None:
        hostile_name = "bad\nname\x1b[2J\u202e"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.py").write_text(
                "\n".join(
                    [
                        "import subprocess",
                        f"@mcp.tool(name={hostile_name!r})",
                        "def entry():",
                        "    return subprocess.run(['fixed'])",
                    ]
                ),
                encoding="utf-8",
            )
            code, output, error = _invoke(["audit", str(root), "--format", "sarif"])

        document = _document(output)
        strings = _all_strings(document)
        self.assertEqual((code, error), (1, ""))
        self.assertTrue(any("\\u000A" in item for item in strings))
        for forbidden in ("\n", "\r", "\x1b", "\u202e"):
            self.assertFalse(any(forbidden in item for item in strings))


if __name__ == "__main__":
    unittest.main()

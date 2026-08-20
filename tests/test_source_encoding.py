"""Strict PEP 263 source-decoding and fail-incomplete regressions."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mcp_scopecheck.cli import main
from mcp_scopecheck.parser import parse_project


class SourceEncodingTests(unittest.TestCase):
    def test_utf8_default_and_matching_cookie_are_accepted(self) -> None:
        cases = (
            b'@mcp.tool(description="caf\xc3\xa9")\ndef default_utf8():\n    return "ok"\n',
            b'# coding: utf-8\n@mcp.tool(description="caf\xc3\xa9")\n'
            b'def cookie_utf8():\n    return "ok"\n',
            b'\xef\xbb\xbf# coding: utf-8\n@mcp.tool(description="caf\xc3\xa9")\n'
            b'def bom_utf8():\n    return "ok"\n',
        )
        for source in cases:
            with self.subTest(source=source[:20]):
                with tempfile.TemporaryDirectory() as directory:
                    target = Path(directory) / "server.py"
                    target.write_bytes(source)
                    project = parse_project(target)

                self.assertEqual(project.diagnostics, [])
                self.assertEqual(project.tools[0].description, "café")

    def test_latin1_cookie_preserves_description_and_identifier(self) -> None:
        source = (
            '# coding: latin-1\n@mcp.tool(description="café")\n'
            'def café_tool():\n    return "café"\n'
        ).encode("latin-1")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "server.py"
            target.write_bytes(source)
            project = parse_project(target)

        self.assertEqual(project.diagnostics, [])
        self.assertEqual(len(project.tools), 1)
        self.assertEqual(project.tools[0].name, "café_tool")
        self.assertEqual(project.tools[0].function_name, "café_tool")
        self.assertEqual(project.tools[0].description, "café")

    def test_encoding_failures_are_diagnostics_exit_two_and_never_execute(self) -> None:
        cases = {
            "explicit-invalid-utf8": b"# coding: utf-8\n# invalid: \xff\n",
            "default-invalid-utf8": b"# invalid: \xff\n",
            "unknown-cookie": b"# coding: no-such-codec\n",
            "bom-cookie-conflict": b"\xef\xbb\xbf# coding: latin-1\n",
        }
        for label, prefix in cases.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    sentinel = root / "executed.txt"
                    suffix = (
                        "from pathlib import Path\n"
                        f"Path({str(sentinel)!r}).write_text('executed')\n"
                        "@mcp.tool()\n"
                        "def valid_tool():\n"
                        "    return 'ok'\n"
                    ).encode("ascii")
                    target = root / "server.py"
                    target.write_bytes(prefix + suffix)
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        exit_code = main(["audit", str(target)])

                    output = stdout.getvalue()
                    error = stderr.getvalue()
                    self.assertEqual(exit_code, 2)
                    self.assertIn("source encoding", output)
                    self.assertIn("audit incomplete because diagnostics were reported", error)
                    self.assertNotIn("Traceback", output + error)
                    self.assertFalse(sentinel.exists())

    def test_raw_byte_limit_precedes_encoding_detection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "server.py"
            target.write_bytes(b"# coding: no-such-codec\n")
            with patch("mcp_scopecheck.parser.MAX_SOURCE_BYTES", 10):
                project = parse_project(target)

        self.assertEqual(project.files_scanned, 0)
        self.assertEqual(len(project.diagnostics), 1)
        self.assertIn("file exceeds 10 bytes", project.diagnostics[0].message)
        self.assertNotIn("encoding", project.diagnostics[0].message)


class NonTextCodecTests(unittest.TestCase):
    """A declared codec that is not a text encoding must fail closed, not crash.

    CPython raises LookupError from `tokenize.detect_encoding`, not from `.decode`,
    so catching it only around the decode let a crafted coding cookie escape as an
    unhandled exception: exit 1 with no output. Exit 1 means "complete, findings at
    threshold" in the documented contract, so a workflow branching on the exit code
    read a crash as a scan result, and SARIF output was empty despite the promise
    that stdout is JSON on every nonzero exit.
    """

    def test_binary_codecs_fail_closed(self) -> None:
        for codec in ("rot13", "base64", "hex", "bz2", "zlib", "quopri", "uu"):
            with self.subTest(codec=codec):
                with tempfile.TemporaryDirectory() as directory:
                    target = Path(directory) / "server.py"
                    target.write_bytes(f"# -*- coding: {codec} -*-\nx = 1\n".encode())
                    project = parse_project(target)

                self.assertTrue(
                    project.diagnostics,
                    f"{codec} produced no diagnostic instead of failing closed",
                )

    def test_binary_codec_exits_two_with_sarif_on_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "server.py"
            target.write_bytes(b"# -*- coding: rot13 -*-\nx = 1\n")
            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                code = main(["audit", str(target), "--format", "sarif"])

        self.assertEqual(code, 2)
        self.assertTrue(stdout.getvalue().lstrip().startswith("{"))


if __name__ == "__main__":
    unittest.main()

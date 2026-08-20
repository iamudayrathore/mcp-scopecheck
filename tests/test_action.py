"""Static policy regressions for the published composite GitHub Action.

The action installs a pinned scanner version and is the surface most users will
adopt first, so its defaults must not drift from the package and its own action
pins must stay immutable.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "action.yml"


class ActionPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = ACTION.read_text(encoding="utf-8")

    def test_default_scanner_version_matches_the_package_version(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        version = re.search(r'(?m)^version = "([^"]+)"', pyproject)
        assert version is not None
        self.assertIn(f'default: "{version.group(1)}"', self.text)

    def test_nested_actions_are_full_sha_pinned(self) -> None:
        uses = re.findall(r"(?m)^\s+-?\s*uses:\s*([^\s#]+)", self.text)
        self.assertTrue(uses)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

    def test_install_is_dependency_free_and_version_pinned(self) -> None:
        self.assertIn("--no-deps", self.text)
        self.assertIn('"mcp-scopecheck==${SCOPECHECK_VERSION}"', self.text)

    def test_target_controlled_inputs_are_passed_through_the_environment(self) -> None:
        """Target paths and thresholds must never be interpolated into a shell line."""

        for command in re.findall(r"(?ms)^        run: \|\n(.*?)(?=\n    - |\Z)", self.text):
            with self.subTest(command=command[:40]):
                self.assertNotIn("${{", command)

    def test_exit_two_is_not_reported_as_a_clean_result(self) -> None:
        self.assertIn("partial or failed", self.text)
        self.assertIn("exit-code", self.text)


if __name__ == "__main__":
    unittest.main()

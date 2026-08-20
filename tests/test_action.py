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

    def test_audit_step_clears_errexit_before_capturing_the_exit_status(self) -> None:
        """GitHub runs composite bash steps as `bash -e`.

        Without an explicit `set +e` the shell aborts on a nonzero audit before
        `$?` is captured, so the action fails instead of reporting the exit code.
        """

        self.assertIn("set +e", self.text)
        audit = self.text[self.text.index("id: audit") :]
        self.assertLess(audit.index("set +e"), audit.index("scopecheck_exit=$?"))

    def test_every_workflow_and_action_pins_third_party_actions_by_sha(self) -> None:
        """The README claims this rule is enforced repository-wide, so enforce it.

        `test_release_workflow` covers only release.yml and the check above covers
        only action.yml, which left ci.yml unenforced while the README claimed
        otherwise. Local `./` references are self-references, not third-party
        supply chain, so they are exempt.
        """

        sources = sorted((ROOT / ".github" / "workflows").glob("*.yml")) + [ACTION]
        self.assertGreaterEqual(len(sources), 3)
        checked = 0
        for source in sources:
            text = source.read_text(encoding="utf-8")
            for action in re.findall(r"(?m)^\s+-?\s*uses:\s*([^\s#]+)", text):
                if action == "./":
                    continue
                checked += 1
                with self.subTest(source=source.name, action=action):
                    self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")
        self.assertGreater(checked, 0)

    def test_readme_pins_this_action_by_full_commit_sha(self) -> None:
        """The published usage example must not teach a mutable ref.

        Branch refs and git tags are both movable, so a consumer who pins either
        one executes whatever the ref points at on their next run. ScopeCheck
        enforces full-SHA pinning on its own workflows and must not document a
        weaker pattern for its users.
        """

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        references = re.findall(r"uses:\s*iamudayrathore/mcp-scopecheck@(\S+)", readme)
        self.assertTrue(references, "README must document the action")
        for reference in references:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"^[0-9a-f]{40}$")

    def test_exit_two_is_not_reported_as_a_clean_result(self) -> None:
        self.assertIn("partial or failed", self.text)
        self.assertIn("exit-code", self.text)


if __name__ == "__main__":
    unittest.main()

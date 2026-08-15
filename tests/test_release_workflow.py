"""Static policy regression for the manual Trusted Publishing workflow."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def _job(text: str, name: str, next_name: str | None) -> str:
    start = text.index(f"  {name}:\n")
    end = len(text) if next_name is None else text.index(f"  {next_name}:\n", start)
    return text[start:end]


class ReleaseWorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.verify = _job(cls.text, "verify_source", "build")
        cls.build = _job(cls.text, "build", "publish")
        cls.publish = _job(cls.text, "publish", None)

    def test_dispatch_requires_tag_and_full_sha_inputs(self) -> None:
        dispatch = self.text[: self.text.index("permissions:")]
        self.assertRegex(dispatch, r"(?m)^      tag:\n(?:        .+\n)*        required: true$")
        self.assertRegex(
            dispatch,
            r"(?m)^      commit_sha:\n(?:        .+\n)*        required: true$",
        )
        self.assertIn("commit SHA must be 40 lowercase hexadecimal characters", (
            ROOT / "scripts" / "verify_release_source.py"
        ).read_text(encoding="utf-8"))

    def test_source_verification_binds_tag_main_version_and_exact_ci(self) -> None:
        script = (ROOT / "scripts" / "verify_release_source.py").read_text(encoding="utf-8")
        for required in (
            "refs/remotes/origin/main",
            "release tag must be annotated",
            "release tag does not peel to the approved commit SHA",
            "approved commit is not reachable from origin/main",
            "release tag does not match the package version",
            '"head_sha": commit_sha',
            'payload.get("total_count")',
            "total_count != 1",
            "len(runs) != total_count",
            "_response_has_next_page(headers)",
            'run.get("conclusion") == "success"',
            'run.get("path") == CI_WORKFLOW_PATH',
        ):
            self.assertIn(required, script)
        self.assertIn('test "${DISPATCH_REF}" = "refs/heads/main"', self.verify)
        self.assertLess(
            self.verify.index("Verify tag, commit, version, ancestry, and exact-SHA CI"),
            self.verify.index("Expose validated immutable inputs"),
        )

    def test_oidc_is_isolated_to_source_free_publish_job(self) -> None:
        self.assertNotIn("id-token: write", self.verify)
        self.assertNotIn("id-token: write", self.build)
        self.assertEqual(self.publish.count("id-token: write"), 1)
        self.assertNotIn("actions/checkout", self.publish)
        self.assertNotIn("actions/setup-python", self.publish)
        self.assertNotIn("scripts/", self.publish)

    def test_artifact_is_built_once_then_transferred_and_verified(self) -> None:
        self.assertEqual(self.text.count("python -m build"), 1)
        self.assertIn("actions/upload-artifact@", self.build)
        self.assertIn("release-manifest.json", self.build)
        self.assertIn("actions/download-artifact@", self.publish)
        self.assertIn("Verify release manifest and checksums", self.publish)
        self.assertIn("hashlib.sha256", self.publish)

    def test_all_third_party_actions_are_full_sha_pinned(self) -> None:
        uses = re.findall(r"(?m)^\s+-?\s*uses:\s*([^\s#]+)", self.text)
        self.assertGreaterEqual(len(uses), 7)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()

"""Unit regressions for immutable release-source verification."""

from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
import urllib.request
from pathlib import Path

from scripts.verify_release_source import (
    ReleaseVerificationError,
    _successful_ci_run,
    validate_inputs,
    verify_ci,
    verify_repository,
)

APPROVED_SHA = "a" * 40


class _Response(io.BytesIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class ReleaseSourceTests(unittest.TestCase):
    def test_version_matching_annotated_tag_on_side_branch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "work"
            remote = root / "remote.git"
            subprocess.run(
                ["git", "init", "--initial-branch=main", str(repository)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "init", "--bare", str(remote)],
                check=True,
                capture_output=True,
            )
            for key, value in (("user.name", "Test"), ("user.email", "test@example.invalid")):
                subprocess.run(
                    ["git", "-C", str(repository), "config", key, value],
                    check=True,
                )
            (repository / "pyproject.toml").write_text(
                '[project]\nname = "test"\nversion = "0.1.2"\n',
                encoding="utf-8",
            )
            subprocess.run(
                ["git", "-C", str(repository), "add", "pyproject.toml"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-m", "main"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "remote", "add", "origin", str(remote)],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "push", "-u", "origin", "main"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "switch", "-c", "side"],
                check=True,
                capture_output=True,
            )
            (repository / "side.txt").write_text("unreviewed\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(repository), "add", "side.txt"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-m", "side"],
                check=True,
                capture_output=True,
            )
            commit_sha = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(
                ["git", "-C", str(repository), "tag", "-a", "v0.1.2", "-m", "release"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "push", "origin", "refs/tags/v0.1.2"],
                check=True,
                capture_output=True,
            )

            with self.assertRaisesRegex(ReleaseVerificationError, "not reachable"):
                verify_repository(repository, "v0.1.2", commit_sha)

    def test_dispatch_inputs_require_release_tag_and_full_lowercase_sha(self) -> None:
        validate_inputs("v0.1.2", APPROVED_SHA)
        for tag, commit_sha in (
            ("0.1.2", APPROVED_SHA),
            ("v0.1.2/other", APPROVED_SHA),
            ("v0.1.2", "a" * 39),
            ("v0.1.2", "A" * 40),
        ):
            with self.subTest(tag=tag, commit_sha=commit_sha):
                with self.assertRaises(ReleaseVerificationError):
                    validate_inputs(tag, commit_sha)

    def test_ci_evidence_must_match_every_exact_run_property(self) -> None:
        valid = {
            "head_sha": APPROVED_SHA,
            "head_branch": "main",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "path": ".github/workflows/ci.yml",
        }
        self.assertTrue(_successful_ci_run({"workflow_runs": [valid]}, APPROVED_SHA))
        for field, value in (
            ("head_sha", "b" * 40),
            ("head_branch", "side-branch"),
            ("event", "pull_request"),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("path", ".github/workflows/other.yml"),
        ):
            with self.subTest(field=field):
                run = {**valid, field: value}
                self.assertFalse(_successful_ci_run({"workflow_runs": [run]}, APPROVED_SHA))

    def test_ci_query_is_exact_sha_and_fails_closed_without_matching_run(self) -> None:
        payload = json.dumps({"workflow_runs": []}).encode("utf-8")

        def opener(request: urllib.request.Request, *, timeout: int) -> _Response:
            self.assertEqual(timeout, 30)
            url = request.full_url
            self.assertIn(f"head_sha={APPROVED_SHA}", url)
            self.assertIn("branch=main", url)
            self.assertIn("event=push", url)
            self.assertIn("status=success", url)
            return _Response(payload)

        with self.assertRaisesRegex(ReleaseVerificationError, "no successful"):
            verify_ci(
                api_url="https://api.github.invalid",
                github_repository="owner/repository",
                token="test-token",
                commit_sha=APPROVED_SHA,
                opener=opener,
            )

    def test_ci_query_accepts_only_matching_successful_run(self) -> None:
        payload = json.dumps(
            {
                "workflow_runs": [
                    {
                        "head_sha": APPROVED_SHA,
                        "head_branch": "main",
                        "event": "push",
                        "status": "completed",
                        "conclusion": "success",
                        "path": ".github/workflows/ci.yml",
                    }
                ]
            }
        ).encode("utf-8")
        verify_ci(
            api_url="https://api.github.invalid",
            github_repository="owner/repository",
            token="test-token",
            commit_sha=APPROVED_SHA,
            opener=lambda request, timeout: _Response(payload),
        )


if __name__ == "__main__":
    unittest.main()

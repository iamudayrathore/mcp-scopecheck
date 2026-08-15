"""Unit regressions for immutable release-source verification."""

from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from scripts.verify_release_source import (
    ReleaseVerificationError,
    _successful_ci_run,
    validate_inputs,
    verify_ci,
    verify_repository,
)

APPROVED_SHA = "a" * 40
CI_PATH = ".github/workflows/ci.yml"
_DEFAULT_COUNT = object()


class _Response(io.BytesIO):
    def __init__(
        self,
        body: bytes,
        *,
        headers: dict[str, str] | None = None,
        status: int = 200,
    ) -> None:
        super().__init__(body)
        self.headers = headers or {}
        self.status = status

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def _run(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@contextmanager
def _release_repository(version: str = "0.1.2") -> Iterator[tuple[Path, str]]:
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
        _run(repository, "config", "user.name", "Test")
        _run(repository, "config", "user.email", "test@example.invalid")
        (repository / "pyproject.toml").write_text(
            f'[project]\nname = "test"\nversion = "{version}"\n',
            encoding="utf-8",
        )
        _run(repository, "add", "pyproject.toml")
        _run(repository, "commit", "-m", "main")
        _run(repository, "remote", "add", "origin", str(remote))
        _run(repository, "push", "-u", "origin", "main")
        yield repository, _run(repository, "rev-parse", "HEAD")


def _push_tag(repository: Path, *, annotated: bool = True) -> None:
    arguments = ["tag"]
    if annotated:
        arguments.extend(["-a", "v0.1.2", "-m", "release"])
    else:
        arguments.append("v0.1.2")
    _run(repository, *arguments)
    _run(repository, "push", "origin", "refs/tags/v0.1.2")


def _valid_run(**changes: object) -> dict[str, object]:
    run: dict[str, object] = {
        "id": 123,
        "head_sha": APPROVED_SHA,
        "head_branch": "main",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "path": CI_PATH,
    }
    run.update(changes)
    return run


def _payload(
    *runs: dict[str, object],
    total_count: object = _DEFAULT_COUNT,
) -> dict[str, object]:
    return {
        "total_count": len(runs) if total_count is _DEFAULT_COUNT else total_count,
        "workflow_runs": list(runs),
    }


class ReleaseSourceTests(unittest.TestCase):
    def _verify_payload(
        self,
        payload: object,
        *,
        headers: dict[str, str] | None = None,
        status: int = 200,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        verify_ci(
            api_url="https://api.github.invalid",
            github_repository="owner/repository",
            token="test-token",
            commit_sha=APPROVED_SHA,
            opener=lambda request, timeout: _Response(
                body,
                headers=headers,
                status=status,
            ),
        )

    def assert_ci_rejected(
        self,
        payload: object,
        *,
        headers: dict[str, str] | None = None,
        status: int = 200,
    ) -> None:
        with self.assertRaises(ReleaseVerificationError):
            self._verify_payload(payload, headers=headers, status=status)

    def test_exact_annotated_main_commit_and_version_are_accepted(self) -> None:
        with _release_repository() as (repository, commit_sha):
            _push_tag(repository)
            self.assertEqual(
                verify_repository(repository, "v0.1.2", commit_sha),
                "0.1.2",
            )

    def test_version_matching_annotated_tag_on_side_branch_is_rejected(self) -> None:
        with _release_repository() as (repository, _):
            _run(repository, "switch", "-c", "side")
            (repository / "side.txt").write_text("unreviewed\n", encoding="utf-8")
            _run(repository, "add", "side.txt")
            _run(repository, "commit", "-m", "side")
            commit_sha = _run(repository, "rev-parse", "HEAD")
            _push_tag(repository)

            with self.assertRaisesRegex(ReleaseVerificationError, "not reachable"):
                verify_repository(repository, "v0.1.2", commit_sha)

    def test_lightweight_tag_is_rejected(self) -> None:
        with _release_repository() as (repository, commit_sha):
            _push_tag(repository, annotated=False)
            with self.assertRaisesRegex(ReleaseVerificationError, "must be annotated"):
                verify_repository(repository, "v0.1.2", commit_sha)

    def test_tag_must_peel_to_approved_sha(self) -> None:
        with _release_repository() as (repository, _):
            _push_tag(repository)
            with self.assertRaisesRegex(ReleaseVerificationError, "does not peel"):
                verify_repository(repository, "v0.1.2", "b" * 40)

    def test_tag_must_match_version(self) -> None:
        with _release_repository(version="0.1.3") as (repository, commit_sha):
            _push_tag(repository)
            with self.assertRaisesRegex(ReleaseVerificationError, "does not match"):
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

    def test_ci_accepts_one_complete_unambiguous_matching_run(self) -> None:
        payload = _payload(_valid_run())
        self.assertTrue(_successful_ci_run(payload, APPROVED_SHA))

        def opener(request: urllib.request.Request, *, timeout: int) -> _Response:
            self.assertEqual(timeout, 30)
            url = request.full_url
            self.assertIn(f"head_sha={APPROVED_SHA}", url)
            self.assertIn("branch=main", url)
            self.assertIn("event=push", url)
            self.assertIn("status=success", url)
            self.assertIn("per_page=100", url)
            return _Response(json.dumps(payload).encode("utf-8"))

        verify_ci(
            api_url="https://api.github.invalid",
            github_repository="owner/repository",
            token="test-token",
            commit_sha=APPROVED_SHA,
            opener=opener,
        )

    def test_ci_rejects_missing_or_invalid_total_count(self) -> None:
        run = _valid_run()
        missing = {"workflow_runs": [run]}
        cases = {
            "missing": missing,
            "null": _payload(run, total_count=None),
            "boolean": _payload(run, total_count=True),
            "string": _payload(run, total_count="1"),
            "float": _payload(run, total_count=1.0),
            "negative": _payload(total_count=-1),
            "zero": _payload(total_count=0),
            "greater-than-one": _payload(run, _valid_run(id=124), total_count=2),
        }
        for label, payload in cases.items():
            with self.subTest(label=label):
                self.assert_ci_rejected(payload)

    def test_ci_rejects_missing_nonlist_or_count_inconsistent_run_list(self) -> None:
        run = _valid_run()
        cases = {
            "missing-runs": {"total_count": 1},
            "null-runs": {"total_count": 1, "workflow_runs": None},
            "object-runs": {"total_count": 1, "workflow_runs": {}},
            "string-runs": {"total_count": 1, "workflow_runs": "run"},
            "count-one-list-empty": _payload(total_count=1),
            "count-zero-list-one": _payload(run, total_count=0),
            "claimed-101-list-one": _payload(run, total_count=101),
        }
        for label, payload in cases.items():
            with self.subTest(label=label):
                self.assert_ci_rejected(payload)

    def test_ci_rejects_duplicate_multiple_or_mixed_runs(self) -> None:
        matching = _valid_run()
        cases = {
            "duplicate-identical": _payload(matching, dict(matching)),
            "multiple-distinct": _payload(matching, _valid_run(id=124)),
            "matching-plus-unrelated": _payload(
                matching,
                _valid_run(id=125, head_sha="b" * 40),
            ),
        }
        for label, payload in cases.items():
            with self.subTest(label=label):
                self.assert_ci_rejected(payload)

    def test_ci_rejects_any_next_page_link_case_insensitively(self) -> None:
        payload = _payload(_valid_run())
        links = (
            {"Link": '<https://api.github.invalid/page/2>; rel="next"'},
            {"lInK": '<https://api.github.invalid/page/2>; ReL="NeXt"'},
            {"LINK": "<https://api.github.invalid/page/2>; REL=NEXT"},
            {"link": '<https://api.github.invalid/page/2>; rel="prev next"'},
        )
        for headers in links:
            with self.subTest(headers=headers):
                self.assert_ci_rejected(payload, headers=headers)

        self.assert_ci_rejected(
            _payload(_valid_run(), total_count=101),
            headers={"Link": '<https://api.github.invalid/page/2>; rel="next"'},
        )

    def test_ci_rejects_malformed_top_level_and_run_fields(self) -> None:
        for payload in (None, [], "object", 1, True):
            with self.subTest(payload=payload):
                self.assert_ci_rejected(payload)
        self.assert_ci_rejected({"total_count": 1, "workflow_runs": [None]})

        expected_fields = (
            "head_sha",
            "head_branch",
            "event",
            "status",
            "conclusion",
            "path",
        )
        for field in expected_fields:
            with self.subTest(field=field, case="missing"):
                run = _valid_run()
                del run[field]
                self.assert_ci_rejected(_payload(run))
            with self.subTest(field=field, case="malformed"):
                self.assert_ci_rejected(_payload(_valid_run(**{field: 1})))

    def test_ci_rejects_every_mismatched_run_property(self) -> None:
        for field, value in (
            ("head_sha", "b" * 40),
            ("head_branch", "side-branch"),
            ("event", "pull_request"),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("path", ".github/workflows/other.yml"),
        ):
            with self.subTest(field=field):
                self.assert_ci_rejected(_payload(_valid_run(**{field: value})))

    def test_ci_rejects_http_timeout_status_and_malformed_json(self) -> None:
        def http_error(request: object, timeout: int) -> _Response:
            raise urllib.error.HTTPError(
                "https://api.github.invalid",
                500,
                "failure",
                {},
                None,
            )

        def timeout(request: object, timeout: int) -> _Response:
            raise TimeoutError("timed out")

        for label, opener in (("http", http_error), ("timeout", timeout)):
            with self.subTest(label=label):
                with self.assertRaises(ReleaseVerificationError):
                    verify_ci(
                        api_url="https://api.github.invalid",
                        github_repository="owner/repository",
                        token="test-token",
                        commit_sha=APPROVED_SHA,
                        opener=opener,
                    )

        with self.assertRaises(ReleaseVerificationError):
            verify_ci(
                api_url="https://api.github.invalid",
                github_repository="owner/repository",
                token="test-token",
                commit_sha=APPROVED_SHA,
                opener=lambda request, timeout: _Response(b"{not-json"),
            )
        self.assert_ci_rejected(_payload(_valid_run()), status=500)


if __name__ == "__main__":
    unittest.main()

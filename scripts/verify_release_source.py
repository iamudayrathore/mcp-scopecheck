#!/usr/bin/env python3
"""Fail closed unless a release tag identifies reviewed, CI-passing main history."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
TAG_PATTERN = re.compile(r"v[0-9]+(?:\.[0-9]+){2}(?:[A-Za-z0-9._+-]*)?")
CI_WORKFLOW_FILE = "ci.yml"
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
NEXT_LINK_PATTERN = re.compile(
    r"\brel\s*=\s*(?:\"[^\"]*\bnext\b[^\"]*\"|'[^']*\bnext\b[^']*'|next\b)",
    re.IGNORECASE,
)


class ReleaseVerificationError(RuntimeError):
    """A release input or its repository evidence failed validation."""


def validate_inputs(tag: str, commit_sha: str) -> None:
    """Require inputs that cannot be abbreviated or interpreted as Git options."""

    if TAG_PATTERN.fullmatch(tag) is None:
        raise ReleaseVerificationError(f"invalid release tag: {tag!r}")
    if SHA_PATTERN.fullmatch(commit_sha) is None:
        raise ReleaseVerificationError("commit SHA must be 40 lowercase hexadecimal characters")


def _git(repository: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=check,
        capture_output=True,
        text=True,
    )


def verify_repository(repository: Path, tag: str, commit_sha: str) -> str:
    """Verify tag type, peeled commit, main ancestry, and package version."""

    validate_inputs(tag, commit_sha)
    _git(
        repository,
        "fetch",
        "--force",
        "--prune",
        "origin",
        "+refs/heads/main:refs/remotes/origin/main",
        f"+refs/tags/{tag}:refs/tags/{tag}",
    )
    tag_ref = f"refs/tags/{tag}"
    if _git(repository, "cat-file", "-t", tag_ref).stdout.strip() != "tag":
        raise ReleaseVerificationError("release tag must be annotated")
    peeled_commit = _git(repository, "rev-parse", f"{tag_ref}^{{commit}}").stdout.strip()
    if peeled_commit != commit_sha:
        raise ReleaseVerificationError("release tag does not peel to the approved commit SHA")
    ancestry = _git(
        repository,
        "merge-base",
        "--is-ancestor",
        commit_sha,
        "refs/remotes/origin/main",
        check=False,
    )
    if ancestry.returncode != 0:
        raise ReleaseVerificationError("approved commit is not reachable from origin/main")
    raw_pyproject = _git(repository, "show", f"{commit_sha}:pyproject.toml").stdout
    try:
        version = tomllib.loads(raw_pyproject)["project"]["version"]
    except (KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseVerificationError(
            "unable to read the package version at approved commit"
        ) from exc
    if not isinstance(version, str) or version != tag.removeprefix("v"):
        raise ReleaseVerificationError("release tag does not match the package version")
    return version


def _successful_ci_run(payload: object, commit_sha: str) -> bool:
    if not isinstance(payload, dict):
        return False
    total_count = payload.get("total_count")
    if type(total_count) is not int or total_count != 1:
        return False
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list) or len(runs) != total_count:
        return False
    run = runs[0]
    if not isinstance(run, dict):
        return False
    return (
        type(run.get("head_sha")) is str
        and run.get("head_sha") == commit_sha
        and type(run.get("head_branch")) is str
        and run.get("head_branch") == "main"
        and type(run.get("event")) is str
        and run.get("event") == "push"
        and type(run.get("status")) is str
        and run.get("status") == "completed"
        and type(run.get("conclusion")) is str
        and run.get("conclusion") == "success"
        and type(run.get("path")) is str
        and run.get("path") == CI_WORKFLOW_PATH
    )


def _response_has_next_page(headers: object) -> bool:
    """Inspect every case-insensitive Link header for a next-page relation."""

    items = getattr(headers, "items", None)
    if not callable(items):
        raise ReleaseVerificationError("unable to inspect CI response headers")
    for name, value in items():
        if not isinstance(name, str):
            raise ReleaseVerificationError("malformed CI response header name")
        if name.casefold() != "link":
            continue
        if not isinstance(value, str):
            raise ReleaseVerificationError("malformed CI Link response header")
        if NEXT_LINK_PATTERN.search(value) is not None:
            return True
    return False


def verify_ci(
    *,
    api_url: str,
    github_repository: str,
    token: str,
    commit_sha: str,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> None:
    """Require a successful completed main-push CI run for exactly commit_sha."""

    query = urllib.parse.urlencode(
        {
            "head_sha": commit_sha,
            "branch": "main",
            "event": "push",
            "status": "success",
            "per_page": 100,
        }
    )
    url = (
        f"{api_url.rstrip('/')}/repos/{github_repository}/actions/workflows/"
        f"{CI_WORKFLOW_FILE}/runs?{query}"
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with opener(request, timeout=30) as response:
            if type(getattr(response, "status", None)) is not int or response.status != 200:
                raise ReleaseVerificationError("CI API request did not return HTTP 200")
            headers = getattr(response, "headers", None)
            if _response_has_next_page(headers):
                raise ReleaseVerificationError("CI API evidence is paginated")
            payload = json.load(response)
    except ReleaseVerificationError:
        raise
    except (
        OSError,
        UnicodeError,
        urllib.error.HTTPError,
        urllib.error.URLError,
        json.JSONDecodeError,
    ) as exc:
        if isinstance(exc, urllib.error.HTTPError):
            exc.close()
        raise ReleaseVerificationError("unable to verify the required CI run") from exc
    if not _successful_ci_run(payload, commit_sha):
        raise ReleaseVerificationError(
            "CI evidence is incomplete, ambiguous, or does not contain exactly one "
            "successful completed main-push run for the approved commit SHA"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit-sha", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        version = verify_repository(args.repository, args.tag, args.commit_sha)
        verify_ci(
            api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
            github_repository=os.environ["GITHUB_REPOSITORY"],
            token=os.environ["GITHUB_TOKEN"],
            commit_sha=args.commit_sha,
        )
    except (KeyError, ReleaseVerificationError, subprocess.CalledProcessError) as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 2
    print(f"verified {args.tag} at {args.commit_sha} for package version {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env bash
# Fail closed when the documented workflow would not run this release.
#
# The README example pins the action by commit SHA and selects the scanner with an
# explicit `version` input. Those are independent: the SHA fixes the action code,
# the input fixes the scanner. If the documented version drifts from the release
# being published, everyone copying the README runs the wrong scanner - for a
# security tool, one with known-missed detections, presented as current.
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repository_root}"

if ! grep -qE 'uses:\s*iamudayrathore/mcp-scopecheck@[0-9a-f]{40}' README.md; then
    echo "check-action-pin: README does not pin the action by full commit SHA" >&2
    exit 2
fi

package_version="$(grep -m1 '^version = ' pyproject.toml | cut -d'"' -f2)"
documented_version="$(grep -oE '^ *version: "[0-9][^"]*"' README.md | head -1 | cut -d'"' -f2 || true)"
if [ -z "${documented_version}" ]; then
    echo "check-action-pin: README does not document an explicit scanner version input" >&2
    exit 2
fi
if [ "${documented_version}" != "${package_version}" ]; then
    echo "check-action-pin: README documents scanner ${documented_version}, but this release is ${package_version}" >&2
    exit 2
fi

echo "check-action-pin: README documents scanner ${documented_version}, matching this release"

# Content comparison: the documented SHA must carry the action code being released.
# Checking only the version input is not enough - 0.2.3 documented a pin whose
# action.yml predated the `--` pip hardening its own release notes advertised, so
# every user copying the README ran an action without the fix.
#
# This runs at release time, not on every pull request. A pull request that changes
# action.yml necessarily makes the existing pin differ, and the commit to repin to
# does not exist until that request merges; enforcing it in CI would deadlock the
# merge. The release ritual is therefore: merge, then repin the README to the merge
# commit, then tag. preflight enforces it before anything is published.
if [ "${CHECK_ACTION_PIN_STRICT:-0}" != "1" ]; then
    exit 0
fi

pinned_commit="$(grep -oE 'mcp-scopecheck@[0-9a-f]{40}' README.md | head -1 | cut -d@ -f2)"
if ! git rev-parse --verify --quiet "${pinned_commit}^{commit}" >/dev/null; then
    echo "check-action-pin: cannot resolve ${pinned_commit}; a full-history checkout is required" >&2
    exit 2
fi
if ! git show "${pinned_commit}:action.yml" | diff -q - action.yml >/dev/null; then
    echo "check-action-pin: README pins ${pinned_commit}, whose action.yml differs from this release" >&2
    echo "check-action-pin: repin the README to the release commit before tagging" >&2
    exit 2
fi
echo "check-action-pin: pinned action.yml matches this release"

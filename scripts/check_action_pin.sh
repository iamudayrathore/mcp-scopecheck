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

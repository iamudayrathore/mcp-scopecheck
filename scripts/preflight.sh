#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_output="$(mktemp -d)"
trap 'rm -rf "${temporary_output}"' EXIT

cd "${repository_root}"

if ! command -v gitleaks >/dev/null 2>&1; then
    echo "preflight: gitleaks is required and was not found" >&2
    exit 2
fi

gitleaks dir . --redact --no-banner
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPYCACHEPREFIX="${temporary_output}/pycache" python3 -m compileall -q src tests examples
python3 -m ruff check .
python3 -m mypy
python3 -m build --no-isolation --outdir "${temporary_output}"

# The README pins this action by commit SHA, and action.yml pins the scanner
# version at that commit. If the pin is stale, everyone who copies the README
# installs an older scanner than the one being released - which, for a security
# tool, means shipping users a version with known-missed detections. Checked here
# rather than in the test suite because it needs full history, which CI's shallow
# checkout does not have.
pinned_commit="$(grep -oE 'mcp-scopecheck@[0-9a-f]{40}' README.md | head -1 | cut -d@ -f2)"
if [ -z "${pinned_commit}" ]; then
    echo "preflight: README does not pin the action by full commit SHA" >&2
    exit 2
fi
package_version="$(grep -m1 '^version = ' pyproject.toml | cut -d'"' -f2)"
pinned_version="$(git show "${pinned_commit}:action.yml" | grep -m1 -E '^    default: "[0-9]' | cut -d'"' -f2)"
if [ "${pinned_version}" != "${package_version}" ]; then
    echo "preflight: README pins ${pinned_commit}, whose action installs ${pinned_version}, but this release is ${package_version}" >&2
    exit 2
fi
echo "preflight: README pin ${pinned_commit} installs ${pinned_version}"

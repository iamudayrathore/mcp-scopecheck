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

# Behavioural validation against the built wheel in a throwaway environment. The
# unit suite and the fixes were written from the same mental model, so it cannot
# be the last gate; this exercises the CLI boundary users consume.
wheel="$(ls "${temporary_output}"/mcp_scopecheck-*.whl)"
python3 -m venv "${temporary_output}/venv"
"${temporary_output}/venv/bin/python" -m pip install --quiet --disable-pip-version-check "${wheel}"
python3 scripts/validate_release.py "${temporary_output}/venv/bin/mcp-scopecheck"

"${repository_root}/scripts/check_action_pin.sh"

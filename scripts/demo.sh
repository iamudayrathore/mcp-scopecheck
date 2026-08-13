#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repository_root}"

run_audit() {
    local target="$1"
    local exit_code

    set +e
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
        python3 -m mcp_scopecheck audit "${target}"
    exit_code=$?
    set -e
    echo "Exit: ${exit_code}"
}

echo "Unsafe source evidence"
sed -n '9,35p' examples/unsafe_docs_server/server.py
echo
echo "Unsafe audit (the server is parsed, never started)"
run_audit examples/unsafe_docs_server

echo
echo "Hardened source evidence"
sed -n '7,24p' examples/hardened_docs_server/server.py
echo
echo "Hardened audit (the server is parsed, never started)"
run_audit examples/hardened_docs_server

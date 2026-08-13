# Contributing

Keep changes small, evidence-backed, and explicit about analysis boundaries.

1. Add or update a minimal fixture that demonstrates the behavior.
2. Add a regression test using `unittest`.
3. Preserve the no-target-execution invariant.
4. Ensure every new finding includes file, line, symbol, explanation, and remediation.
5. Avoid broad keyword rules when an AST-level condition can express the same risk.

Create an isolated development environment and install the pinned release tools:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -r requirements-dev.txt
```

Then run the same local quality gates used by CI:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
PYTHONPYCACHEPREFIX=/tmp/mcp-scopecheck-pycache .venv/bin/python -m compileall -q src tests examples
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy
```

Before opening a release PR, run `scripts/preflight.sh` from the activated pinned environment with `gitleaks` installed. The script runs Gitleaks, tests, compilation, Ruff, strict mypy, and both distribution builds, and it fails closed when any required tool is unavailable.

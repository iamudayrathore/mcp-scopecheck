# MCP ScopeCheck maintenance contract

Read `README.md`, `docs/architecture.md`, `SECURITY.md`, and `CONTRIBUTING.md`
before changing the implementation or its public claims.

## Non-negotiable security invariant

Audited target source is untrusted data. Never import, execute, install, build, or start a target MCP server during analysis or tests. Do not add a fallback that executes target code. Preserve the regression test proving top-level target code does not run.

## Product boundary

- Local Python file or directory input only.
- Python AST analysis only; Python 3.11+.
- Same-file named-helper reachability.
- Plain-text 5-S report and the documented exit-code contract.
- No required runtime dependencies.
- No LLM or network call during an audit.

Do not broaden this boundary or add a production dependency without an explicit,
documented design decision.

## Engineering rules

- Prefer small, reviewable changes backed by a minimal fixture and regression test.
- Every finding must include rule ID, severity, tool, file, line, symbol, explanation, and remediation.
- Capabilities are evidence, not automatically vulnerabilities. Emit findings for a contract mismatch, insufficient constraint, or inherently dangerous reachable behavior.
- Prefer AST conditions over source-text keyword matching when practical. Never imply complete program analysis.
- Do not silently swallow parse or filesystem failures. Report diagnostics or fail explicitly.
- Never restore legacy-project names, code history, dependencies, environment files, or unrelated modules.
- Do not claim AI/LLM semantic analysis. `MSC001` is deterministic pattern matching.
- Do not claim this is the first, only, or comprehensive MCP security scanner.

## Required verification

Run after every code change:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -m compileall -q src tests examples
python3 -m ruff check .
python3 -m mypy
```

Before a release candidate, run `scripts/preflight.sh` from the pinned development
environment. It fails closed unless Gitleaks, tests, compilation, Ruff, strict mypy,
and distribution builds all pass. Never report a missing or unrun check as passing.

Do not push, tag, publish, change remote settings, or perform another irreversible
external action without explicit owner approval.

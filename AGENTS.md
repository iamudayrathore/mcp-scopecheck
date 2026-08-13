# Repository instructions for Codex

## Read first

Before changing files, read these in order:

1. `CODEX_HANDOVER.md`
2. `PLANS.md`
3. `docs/status.md`
4. `docs/decisions.md`
5. `docs/architecture.md`

Treat those files as the project contract. If code and documentation disagree, verify the code, record the discrepancy in `docs/status.md`, and fix the smallest responsible surface.

## Objective

Make MCP ScopeCheck v0.1.0 release-ready. Do not create a remote repository, push, tag, publish a package, or post publicly unless the owner explicitly authorizes that irreversible step.

## Non-negotiable security invariant

Audited target source is untrusted data. Never import, execute, install, build, or start a target MCP server during analysis or tests. Do not add a fallback that executes target code. Preserve the regression test proving top-level target code does not run.

## v0.1 scope

- Local Python file or directory input only.
- Python AST analysis only; Python 3.11+.
- Same-file named-helper reachability.
- Plain-text 5-S report and existing exit-code contract.
- No required runtime dependencies.
- No LLM or network call during an audit.

Defer cross-module analysis, TypeScript, GitHub URL ingestion, JSON/SARIF, snapshot comparison, provenance scoring, and optional semantic/LLM analysis to post-v0.1 unless the owner changes the scope.

## Engineering rules

- Prefer small, reviewable changes backed by a minimal fixture and regression test.
- Every finding must include rule ID, severity, tool, file, line, symbol, explanation, and remediation.
- Capabilities are evidence, not automatically vulnerabilities. Emit findings for a contract mismatch, insufficient constraint, or inherently dangerous reachable behavior.
- Prefer AST conditions over source-text keyword matching when practical. Never imply complete program analysis.
- Do not silently swallow parse or filesystem failures. Report diagnostics or fail explicitly.
- Do not add a production dependency without owner approval and a written rationale in `docs/decisions.md`.
- Never restore legacy-project names, code history, dependencies, environment files, or unrelated modules.
- Do not claim v0.1 uses AI/LLM semantic analysis. `MSC001` is deterministic pattern matching.
- Do not claim this is the first, only, or comprehensive MCP security scanner.

## Required verification

Run after code changes:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -m compileall -q src tests examples
```

Before a release candidate, also run the current lint, type, build, clean-install, fixture, and Gitleaks gates in `PLANS.md` and `RELEASE.md`. Never report a check as passing if the tool was missing or the command was not run.

## Work protocol

- Work one checkpoint from `PLANS.md` at a time.
- Keep `docs/status.md` current with completed work, commands run, evidence, blockers, and the next checkpoint.
- Add durable product or architecture decisions to `docs/decisions.md`.
- Stop and ask the owner only for a decision listed as an owner gate, a new production dependency, a security-boundary change, or an irreversible external action.
- At handoff, summarize changed files, exact validation results, remaining risks, and the next owner action.

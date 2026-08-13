# MCP ScopeCheck — full Codex build handover

Last reconciled: 2026-08-10

## 1. Mission

Ship a clean, credible v0.1.0 of **MCP ScopeCheck**, a pre-install static auditor for Python MCP servers.

The product promise is intentionally narrow:

> Verify what an MCP tool claims it can do against what its source code can actually reach—without importing or executing it.

This repository is meant to be production-code evidence, not a throwaway demo. Accuracy about boundaries is more important than feature count. A small release that is deterministic, tested, installable, and honest is the goal.

## 2. Current reality

- The original `mcp-auditor` concept was never publicly shipped.
- The exact `mcp-auditor` package name is already occupied on PyPI. Do not reuse it.
- A clean standalone implementation now exists here under the provisional name `mcp-scopecheck`.
- The current CLI is functional. It is not the old stub described in the historical handoff.
- The clean implementation was rebuilt as a zero-runtime-dependency Python package. It is not a copy of the broad legacy application.
- v0.1 has been locally validated, but it has not passed every public-release gate and has not been published.

The uploaded legacy archive contained an environment file, a full virtual environment, caches, macOS metadata, and a nested archive. Treat that archive as reference-only and potentially sensitive. Do not put it inside this repository, inspect its environment values, reuse its Git history, or copy its dependency set.

## 3. Product contract

### User

A developer, security engineer, or MCP adopter deciding whether a local Python MCP server deserves deeper review before installation or connection.

### Input

A local `.py` file or directory containing Python source.

### Output

A deterministic plain-text report organized by the 5-S framework:

1. **Source** — files inspected.
2. **Surface** — MCP tools discovered.
3. **Scope** — parameters and declared annotations.
4. **Side effects** — reachable filesystem, environment, network, process, and dynamic-code behavior.
5. **Snapshot** — SHA-256 of the extracted contract and observed capabilities.

### Exit codes

| Code | Contract |
| ---: | --- |
| `0` | No finding met `--fail-on` threshold. |
| `1` | One or more findings met the threshold. |
| `2` | Invalid input, no supported tools, or audit error. |

### Security invariant

The scanner must never import, execute, install, build, or start target code. Parsing target source as text with Python `ast` is allowed. A regression test must keep proving that a real top-level target side effect is not executed.

### Analysis boundary

v0.1 discovers module-level `.tool` decorators and follows direct named helper calls within the same source file. “Reachable” always means reachable under this limited static model. It does not mean complete Python reachability.

## 4. What exists now

| Area | State | Primary file |
| --- | --- | --- |
| Domain models and severities | Implemented | `src/mcp_scopecheck/models.py` |
| Safe source discovery and AST parser | Implemented | `src/mcp_scopecheck/parser.py` |
| Same-file call graph and capability detection | Implemented | `src/mcp_scopecheck/analyzer.py` |
| Claim-versus-capability rules | Implemented | `src/mcp_scopecheck/analyzer.py` |
| Deterministic snapshot and orchestration | Implemented | `src/mcp_scopecheck/auditor.py` |
| 5-S terminal renderer | Implemented | `src/mcp_scopecheck/render.py` |
| `mcp-scopecheck audit` CLI | Implemented | `src/mcp_scopecheck/cli.py` |
| Unsafe and hardened demo pair | Implemented | `examples/` |
| End-to-end regression suite | 10 tests passing locally | `tests/test_audit.py` |
| Package metadata and console script | Implemented | `pyproject.toml` |
| Threat model and release docs | Implemented; release gates remain | `docs/architecture.md`, `RELEASE.md` |
| CI | Implemented for Python 3.11–3.13 tests/build/fixtures | `.github/workflows/ci.yml` |
| Gitleaks | Fail-closed local script exists; real run still required | `scripts/preflight.sh` |

## 5. v0.1 rule inventory

| Rule | Severity | Meaning |
| --- | --- | --- |
| `MSC001` | Critical | Deterministic patterns find agent-directed, concealment, or credential-handling instructions in the tool description. |
| `MSC101` | High/Critical | `readOnlyHint=true` conflicts with reachable write, network, process, or dynamic-code behavior. |
| `MSC102` | High | Reachable network egress is not disclosed in the description. |
| `MSC103` | High | A path-like parameter reaches filesystem behavior without a recognized containment check. |
| `MSC104` | High | A path/root parameter defaults to `/` or `~`. |
| `MSC105` | Critical | Environment-derived data reaches a network call in the same reachable function. |
| `MSC106` | Critical | Process or shell execution is reachable. |
| `MSC107` | Critical | `eval` or `exec` is reachable. |

Important: `MSC001` is regex-based deterministic analysis in v0.1. It is not an LLM judge and must not be marketed as one.

## 6. Existing safety limits

- Symlinked source files are skipped.
- `.git`, environments, caches, build outputs, and dependency trees are skipped.
- A source file is limited to 1 MB.
- A directory is limited to 5,000 Python files.
- Syntax/read/stat problems become visible diagnostics.
- The package has no runtime dependencies and makes no audit-time network call.

## 7. Verified evidence as of handover

The local validation record is `docs/validation-2026-08-10.md`. It records:

- 10/10 standard-library tests passed.
- Source, tests, and examples compiled.
- A wheel built and installed in a fresh virtual environment.
- `pip check` passed in that environment.
- Packaged unsafe fixture exited `1` and included `MSC105`.
- Packaged hardened fixture exited `0` with zero findings.
- The target non-execution regression passed.
- Conservative local secret-shaped checks found no environment file, private key, common live credential prefix, or legacy-project branding in the clean tree.

This evidence does **not** mean Gitleaks, Ruff, mypy, clean-checkout CI, or public name availability passed. Those remain release gates.

## 8. Known technical limitations and likely false-result areas

Codex must preserve these in public documentation until the implementation changes:

- No cross-module call graph.
- No alias-, callback-, higher-order-, or dynamic-dispatch reachability.
- No runtime-only tool registration.
- No JavaScript or TypeScript parsing.
- Capability sinks cover selected standard-library and common client names, not every API.
- `MSC103` recognizes the presence of a containment-related operation; it does not yet prove the guard dominates the filesystem sink or uses the correct trusted root.
- `MSC105` is intentionally narrow and same-function. It does not implement interprocedural or field-sensitive taint analysis.
- Network disclosure is a description keyword check, not proof that destination, payload, and purpose are accurate.
- Tool-poisoning detection is a deterministic pattern set with no measured precision/recall corpus yet.
- A clean result is not proof that a running server is safe.

These are engineering boundaries, not copywriting footnotes. New rules must be evaluated against benign and malicious fixtures before stronger claims are made.

## 9. Public positioning

Lead with:

> MCP ScopeCheck is a pre-install static auditor that compares a Python MCP tool's declared contract with security-relevant behavior reachable from its source—without importing or running the server.

Supporting lines:

- Inspect before you connect.
- A tool name is not a permission boundary.
- Annotations are claims, not enforcement.
- Safe at install does not mean safe forever.
- Correct output can camouflage unsafe side effects.

Do not claim:

- “the first,” “the only,” or “complete MCP scanner”;
- runtime safety or absence of vulnerabilities;
- full data-flow or whole-program analysis;
- AI/LLM semantic analysis in v0.1;
- support for remote URLs, packages, TypeScript, JSON, or SARIF in v0.1.

The exact `mcp-auditor` name is occupied, and the MCP security-tool field is crowded. The defensible wedge is the concrete claim-versus-reachable-capability report, source evidence, no-target-execution invariant, and 5-S teaching frame—not a uniqueness superlative. See `docs/positioning.md`.

## 10. v0.1 release definition

v0.1.0 is ready only when all of the following are true from a fresh checkout:

1. Final project, repository, PyPI package, and CLI names have been owner-approved and rechecked.
2. No legacy branding, unrelated source, environment file, virtual environment, cache, or secret exists in the repository or distributions.
3. Gitleaks passes with its current official CLI on the release candidate.
4. Tests pass on Python 3.11, 3.12, and 3.13.
5. Ruff and strict mypy pass, or an owner-approved, documented exception exists.
6. Wheel and source distribution build cleanly.
7. Distribution contents are reviewed; README, license, and intended package files are present, while private/internal material and build debris are absent.
8. Wheel and sdist install in separate fresh environments without unexpected dependencies.
9. Installed CLI produces the expected unsafe/hardened results and exit codes.
10. README commands work by copy/paste and public claims match measured behavior.
11. CI passes on the exact release commit with actions pinned to reviewed commit SHAs.
12. The owner approves the final diff, repository destination, release notes, and publication.

## 11. Scope control

### Required for public v0.1.0

- Finish the gates above.
- Add or confirm sdist manifest/package-content behavior.
- Make lint/type/build validation reproducible.
- Keep the unsafe and hardened fixtures as tests and demo assets.
- Produce a short, reproducible terminal demo.
- Create a fresh Git history for this standalone project.

### Explicitly deferred to v0.2+

- GitHub URL or package ingestion.
- JSON and SARIF output.
- Cross-module analysis and argument-aware interprocedural flow.
- TypeScript parser.
- Snapshot comparison and rug-pull alerts.
- Cross-server tool shadowing.
- Package provenance scoring.
- Optional semantic/LLM description analysis.
- Large benchmark claims.

Do not let a deferred feature block the initial release unless release hardening exposes a direct correctness or security defect in an existing v0.1 behavior.

## 12. Owner gates

Codex may proceed locally using the recommended defaults below, but must stop before an irreversible external step.

| Gate | Recommended default | Stop required before |
| --- | --- | --- |
| Final brand | `mcp-scopecheck` package and CLI; “MCP ScopeCheck” display name | Renaming public artifacts or reserving names |
| Repository destination | `thellmarchitect/mcp-scopecheck` | Creating/pushing remote repository |
| v0.1 semantic analyzer | Exclude; keep deterministic and offline | Adding an API/LLM dependency or marketing claim |
| Publication | GitHub release and PyPI v0.1.0 after all gates | Tagging or publishing |
| CUSTODY framing | Exclude until ownership/provenance is confirmed | Adding it to public copy |

If the owner changes the brand, update package metadata, import/package naming only if required, CLI, URLs, docs, tests, and artifacts as one atomic migration. Do not partially rename.

## 13. Codex work protocol

1. Read `AGENTS.md`, this handover, `PLANS.md`, `docs/status.md`, `docs/decisions.md`, and `docs/architecture.md` before editing.
2. Reproduce the current tests before changing code.
3. Work one checkpoint from `PLANS.md` at a time.
4. Keep diffs small and preserve the no-target-execution invariant.
5. Record every command actually run and result in `docs/status.md`.
6. Record durable choices and rejected alternatives in `docs/decisions.md`.
7. Never mark missing-tool checks as passed.
8. Stop for owner gates, new production dependencies, or a changed security boundary.
9. Finish with a self-review of correctness, claims, package contents, secret hygiene, and release risk.

## 14. Required Codex handback format

Every checkpoint handback must include:

- Outcome in one sentence.
- Files changed.
- Exact checks run and results.
- Remaining known risks or skipped checks.
- Next checkpoint.
- Any owner decision required, with a recommended default.

“Tests pass” without the command and count is insufficient. “Gitleaks unavailable” is a blocker, not a pass.

## 15. Kickoff prompt to assign to Codex

Start Codex from the repository root. If `/goal` is available, use:

```text
/goal Prepare MCP ScopeCheck v0.1.0 for public release, without performing any external publication, until every locally executable release gate in PLANS.md is complete and documented.

Read AGENTS.md, CODEX_HANDOVER.md, PLANS.md, docs/status.md, docs/decisions.md, and docs/architecture.md before editing. Reproduce the current baseline first. Work checkpoint-by-checkpoint, keep docs/status.md current, and use the acceptance criteria and exact no-target-execution invariant as the contract.

Do not create or push a remote repository, tag a release, publish to PyPI, post publicly, inspect old environment values, import/execute target MCP source, add an LLM/API dependency, or expand v0.1 scope. Stop only for an owner gate, a new production dependency, a security-boundary change, or an external irreversible action. When blocked, give me the evidence, options, and your recommended default.
```

Without `/goal`, use the same text without the first `/goal` token and ask Codex to complete checkpoint R0, then continue one checkpoint per coherent session.

## 16. Definition of a strong career artifact

The repository should let a security-engineering reviewer verify, within minutes:

- the threat model and trust boundary;
- the no-execution safety invariant;
- an unsafe fixture caught with source evidence;
- a hardened equivalent that passes;
- deterministic output and explicit exit codes;
- tests for regressions and known edge cases;
- honest limitations and measured claims;
- repeatable build, CI, and release hygiene.

Do not optimize for the number of features. Optimize for evidence that the author can define a security boundary, implement a focused analysis, test adversarial cases, communicate uncertainty, and ship cleanly.

# Decision log

Last updated: 2026-08-12

Record durable product, architecture, security, dependency, and release decisions here. Do not rewrite history; append a superseding decision when a choice changes.

## Locked decisions

### D001 — clean standalone extraction

Decision: ship from a fresh repository and Git history. Do not move or preserve history from the legacy application.

Reason: the original archive includes unrelated application code, broad dependencies, an environment file, virtual environments, caches, and project-specific branding. A clean history reduces privacy, provenance, licensing, and secret risk.

### D002 — static non-execution boundary

Decision: target code is always untrusted data and is never imported or executed.

Reason: this is the central safety and positioning invariant. Any execution fallback would turn a pre-install inspection into exposure to the code being inspected.

### D003 — narrow v0.1 platform

Decision: v0.1 supports local Python source, Python 3.11+, module-level `.tool` decorators, same-file helper reachability, plain-text output, and no required runtime dependencies.

Reason: this is a coherent, testable vertical slice. Remote acquisition, multi-language parsing, and whole-program analysis materially change the trust boundary and schedule.

### D004 — capabilities are not findings by themselves

Decision: report observed side-effect capabilities separately and create findings only for a claim conflict, insufficient constraint, or inherently high-risk behavior.

Reason: a documentation search tool legitimately reads files. Treating every capability as a vulnerability would create noise and weaken the claim-versus-capability thesis.

### D005 — deterministic v0.1 poisoning check

Decision: `MSC001` remains deterministic pattern matching in v0.1. Optional LLM semantic analysis is deferred.

Reason: the current code has no LLM judge or measured semantic evaluation. Shipping an API-backed analyzer now would add privacy, cost, reliability, and credential boundaries and would make the original “AI-analyzed” claim misleading.

### D006 — honest competitive claim

Decision: describe ScopeCheck as focused on claim-versus-reachable-capability evidence. Do not claim uniqueness, completeness, or first-mover status.

Reason: multiple MCP auditing/scanning tools exist, including projects that perform source analysis or use LLM-based judges.

### D007 — MIT license

Decision: use the MIT license for the clean standalone repository.

### D008 — v0.1 output stability

Decision: preserve the text report and exit-code contract for v0.1. Machine formats come after a versioned schema is designed.

Reason: a rushed JSON shape becomes a compatibility burden. The terminal/CI use case is sufficient for the first release.

### D009 — pinned development and build tools

Decision: keep tests on the standard library and keep the installed package dependency-free. Pin release tooling in `requirements-dev.txt` to build 1.5.0, mypy 2.3.0, Ruff 0.16.2, setuptools 84.0.0, and wheel 0.48.0; pin the PEP 517 build requirements to the same setuptools and wheel versions.

Reason: exact top-level tool versions make local and CI quality gates reviewable and reproducible without moving any dependency into the runtime boundary. These were the current stable PyPI releases reviewed on 2026-08-12, and all declare Python support compatible with the project's Python 3.11+ floor.

### D010 — narrow deterministic path and environment-flow checks

Decision: `MSC103` does not accept `.resolve()` alone as evidence of containment; it requires a recognized containment comparison. `MSC105` remains same-function and deterministic, while respecting lexical assignment order and propagating taint through simple assignments.

Reason: normalization is not a boundary check, and source-order-insensitive assignment collection creates an avoidable false positive when a network call precedes an environment read. The narrowed behavior improves obvious cases without claiming dominance, full control-flow analysis, or interprocedural taint tracking.

## Owner decisions required before external publication

### O001 — final public name

Recommended: approve `mcp-scopecheck` as package and CLI, with “MCP ScopeCheck” as the display name.

Why owner input is required: names and package releases are costly to change after publication. Recheck exact GitHub, PyPI, and command availability immediately before reservation.

### O002 — public repository identity

Recommended: `https://github.com/thellmarchitect/mcp-scopecheck`, matching current package metadata.

Why owner input is required: this is a public identity and ownership choice. Update metadata atomically if the account or organization differs.

### O003 — publication sequence

Recommended: approve one reviewed release candidate, then publish the clean GitHub repository/release and PyPI v0.1.0 in the same controlled release window. Verify a fresh PyPI install before launch posts.

### O004 — CUSTODY framing

Recommended: exclude it from v0.1 public copy unless the owner confirms the framework's authorship, intended use, and public context.

Reason: it is not needed to explain ScopeCheck and unclear provenance would create avoidable risk.

## Pre-approved working defaults

Codex may proceed with all local hardening using these defaults:

- Keep the current provisional name in local files.
- Exclude LLM analysis from v0.1.
- Add development-only tooling when versions and rationale are documented.
- Do not add a runtime dependency.
- Do not perform any remote, tag, PyPI, or social action.

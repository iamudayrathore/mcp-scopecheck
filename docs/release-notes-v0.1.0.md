# MCP ScopeCheck v0.1.0

MCP ScopeCheck is a pre-install static auditor that compares a Python MCP tool's declared contract with security-relevant behavior reachable from its source—without importing or running the server.

## Included

- Local Python file and directory input on Python 3.11+.
- Module-level `.tool` decorator discovery using Python ASTs.
- Direct same-file named-helper reachability.
- Evidence for filesystem, environment, network, process, and dynamic-code capabilities.
- Eight deterministic contract/security rules (`MSC001`, `MSC101`–`MSC107`).
- Plain-text 5-S reports, deterministic snapshots, and CI-friendly exit codes.
- No required runtime dependencies and no audit-time network call.

## Safety boundary

Audited source is untrusted data. ScopeCheck reads it as text and never imports, executes, installs, builds, or starts the target. The regression suite includes a real top-level side effect and proves it does not run during an audit.

## Known limits

- No cross-module, alias-assignment, callback, higher-order, or dynamic-dispatch reachability.
- No runtime-only registration and no JavaScript or TypeScript parsing.
- Capability sinks cover selected standard-library and common client names, not every API.
- `MSC103` recognizes containment operations but does not prove guard dominance or correct-root selection.
- `MSC105` follows direct reads and simple assignment propagation in lexical order within one function; it is not general taint analysis.
- Network disclosure and `MSC001` use deterministic pattern checks with no measured precision/recall corpus yet.
- A clean result is not proof that a running server is safe.

## Reproduce the proof

From the repository root, run `scripts/demo.sh` to show the unsafe source and its six findings, then the hardened source and its clean result. Run `scripts/preflight.sh` from the pinned development environment for tests, compilation, Ruff, strict mypy, Gitleaks, wheel, and source-distribution gates.

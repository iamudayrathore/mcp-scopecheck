# v0.1.1 local release-candidate validation — 2026-08-12

This record covers the repository-identity and release-automation correction only. Scanner behavior, rules, fixtures, CLI contract, security boundary, package name, and runtime dependencies are unchanged from v0.1.0.

## Identity and release controls

- Repository: `https://github.com/iamudayrathore/mcp-scopecheck`.
- Package and CLI: `mcp-scopecheck`.
- Trusted Publisher tuple confirmed by the owner: owner `iamudayrathore`, repository `mcp-scopecheck`, workflow `release.yml`, environment `pypi`.
- `.github/workflows/release.yml` references `pypi` exactly, is manual-only, verifies an annotated tag and matching package version, grants OIDC only to its publish job, and pins every action to a reviewed full commit SHA.
- Read-only GitHub API verification returned `404` for the `pypi` environment. It must be created before Trusted Publishing; this check is not marked as passing.

## Local gates

With the pinned Python 3.13.7 development environment, `scripts/preflight.sh` exited `0`:

- Gitleaks 8.30.1 scanned approximately 178.76 KB and found no leaks.
- 22/22 tests passed, including the top-level target non-execution sentinel and exact fixture-output tests.
- Compilation passed.
- Ruff 0.16.2 reported no issues.
- Strict mypy 2.3.0 reported no issues in eight source files.
- Wheel and source-distribution builds passed.

Manual archive review confirmed that both distributions report version 0.1.1 and contain only intended public files. Wheel and sdist metadata contain the approved repository and issues URLs, the unchanged `mcp-scopecheck` entry point, Python 3.11+, and no runtime dependency.

The wheel and sdist installed offline into separate fresh Python 3.13.7 environments. In both environments:

- only `mcp-scopecheck==0.1.1` and pip remained installed;
- `pip check`, version, top-level help, and audit help passed;
- the unsafe fixture emitted the same six IDs (`MSC001`, `MSC105`, `MSC101`, `MSC102`, `MSC103`, `MSC104`) and exited `1`;
- the hardened fixture emitted zero findings and exited `0`;
- the high-only fixture exited `1` at `--fail-on high` and `0` at `--fail-on critical`.

Exact artifact SHA-256 values from the final committed candidate are reported in the owner handoff.

## v0.1.0 preservation

Before preparation, local and GitHub evidence resolved v0.1.0 to annotated tag object `34913eb59c9297ea37fc3953c45bdea15792059a`, commit `5d174ffee5b1ba529801c84fe4b68268354d4b2c`, and tree `5ab430161e5152dafd24d195b57004f3a4005b0b`. GitHub release assets retained their recorded hashes. No v0.1.0 object or artifact was modified, moved, rebuilt, deleted, or republished.

No commit or tag was pushed, no release was created, no PyPI upload occurred, and no launch content was published during this preparation.

# Validation record — 2026-08-10

This record describes the local v0.1 verification performed before handoff. It is not a substitute for CI on the eventual public repository.

## Passed

- `python3 -m unittest discover -s tests -v` with `PYTHONPATH=src`: **10/10 tests passed**.
- `python3 -m compileall -q src tests examples`: completed successfully.
- Offline wheel build with no dependency resolution: completed successfully.
- Wheel install into a new virtual environment: completed successfully.
- `python -m pip check` in that environment: no broken requirements.
- Packaged CLI version: `mcp-scopecheck 0.1.0`.
- Packaged unsafe fixture: exit `1`, including `MSC105`.
- Packaged hardened fixture: exit `0`, `Findings (0)`.
- Wheel SHA-256: `44c1d66f56ae3df78464b29acbc2fa7b532a02c944a1d5deb9aee862ea89a9b5`.
- Conservative local checks found no `.env`, private-key files, common live credential prefixes, or legacy-project branding in the clean source tree.

## Still required before public release

- Run `scripts/preflight.sh` on a machine with Gitleaks installed. The script fails closed when Gitleaks is unavailable.
- Run Ruff and mypy in the eventual CI/development environment.
- Re-check repository, package, and command-name availability immediately before creating the public repository/package.
- Run the full workflow from a clean checkout, then review the wheel and source-distribution contents.

## Handover reconciliation

After adding the Codex handover and build-plan documents on 2026-08-10:

- The 10-test suite and compile check passed again.
- The unsafe fixture emitted `MSC001`, `MSC105`, `MSC101`, `MSC102`, `MSC103`, and `MSC104`, then exited `1`.
- The hardened fixture reported zero findings and exited `0`.
- Gitleaks, Ruff, and mypy were unavailable in the handover workspace and remain unpassed release gates.

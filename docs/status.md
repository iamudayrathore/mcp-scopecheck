# Project status

Last updated: 2026-08-12

## Current state

MCP ScopeCheck has a functional standalone v0.1 vertical slice. R0 through R2 are complete in the owner's release workspace: the baseline and reproducible quality gates are reconciled, focused correctness gaps are closed, package-content intent is explicit, and the implementation preserves the static no-target-execution boundary. It has not been publicly released.

## Evidence on record

See `docs/validation-2026-08-10.md` for the exact previously completed validation and artifact hash.

## Open release blockers

- Owner approval of the final public name and repository destination.
- Owner approval and final availability/reservation check for GitHub, PyPI package, and CLI names immediately before reservation. A provisional read-only check passed on 2026-08-12.
- Full pinned preflight, including Gitleaks, on the exact clean release candidate.
- Clean wheel/source-distribution installs and installed fixture verification.
- Full workflow from a fresh standalone Git checkout.
- Final public documentation/demo review.
- Owner approval for remote creation, push, tag, PyPI publication, and launch.

## Next checkpoint

R3 in `PLANS.md`: create the fresh standalone local Git history, reproduce the full candidate gates from a clean checkout, install wheel and sdist separately, verify installed behavior, and record artifact contents and checksums.

## Codex progress log

Append entries using this format:

```text
### YYYY-MM-DD — R# short outcome

- Changed: files or behavior
- Verified: exact commands and results
- Skipped/blocked: missing tools or unresolved risks
- Decision: link to docs/decisions.md entry, if any
- Next: one checkpoint or owner action
```

### 2026-08-10 — Handover reconciliation

- Changed: added the Codex operating handover, execution plan, decision log, status log, positioning discipline, launch proof plan, and release checklist updates.
- Verified: `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v` passed 10/10; `python3 -m compileall -q src tests examples` passed; unsafe fixture emitted `MSC001`, `MSC105`, `MSC101`, `MSC102`, `MSC103`, and `MSC104` and exited `1`; hardened fixture reported zero findings and exited `0`.
- Skipped/blocked: Gitleaks, Ruff, and mypy were unavailable in this workspace. They remain release blockers, not passes.
- Decision: existing locked and owner-gate decisions are recorded in `docs/decisions.md`.
- Next: rerun R0 in the release workspace, then complete R1.

### 2026-08-12 — R0 baseline reconciled in release workspace

- Changed: updated this status record only; removed `__pycache__` directories created by the explicit compilation check.
- Verified: `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v` passed 10/10 on Python 3.14.3, including `test_target_module_is_never_executed`; `PYTHONDONTWRITEBYTECODE=1 python3 -m compileall -q src tests examples` exited `0`; `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m mcp_scopecheck audit examples/unsafe_docs_server` emitted exactly `MSC001`, `MSC105`, `MSC101`, `MSC102`, `MSC103`, and `MSC104` and exited `1`; the equivalent hardened-fixture command reported `Findings (0)` and exited `0`.
- Verified: source review found that target files are read as text and passed to `ast.parse`; production and test audit paths contain no target import, execution, installation, build, or server-start fallback. The top-level side-effect sentinel regression supplies behavioral evidence for the invariant.
- Verified: `pyproject.toml`, `.github/workflows/ci.yml`, `scripts/preflight.sh`, `RELEASE.md`, `.gitignore`, and the existing distribution configuration were inspected. The package has no runtime dependencies; CI tests Python 3.11-3.13 with SHA-pinned actions but does not yet run Ruff or mypy; no `MANIFEST.in` or equivalent explicit sdist-content policy exists yet.
- Verified: read-only checks on 2026-08-12 returned HTTP `404` for `https://pypi.org/pypi/mcp-scopecheck/json` and `https://api.github.com/repos/thellmarchitect/mcp-scopecheck`; GitHub's repository search API returned `total_count: 0` for `mcp-scopecheck in:name`; `command -v mcp-scopecheck` found no local command. These checks did not reserve any name and must be repeated immediately before owner-approved reservation.
- Skipped/blocked: this directory is not currently a Git repository, so clean-checkout and history-based gates remain for R3. Python 3.13.7 is installed locally, while Python 3.11 and 3.12 are not; the full version matrix remains a CI gate. Gitleaks 8.30.1 is installed, but Ruff and mypy are not yet installed. No external publication or reservation occurred.
- Decision: no new durable decision was required. O001-O004 in `docs/decisions.md` remain the concise owner decision list, with their existing recommended defaults; none blocks local work through R5.
- Next: complete R1 reproducible quality gates.

### 2026-08-12 — R1 reproducible quality gates complete

- Changed: added `requirements-dev.txt` with exact top-level pins for build 1.5.0, mypy 2.3.0, Ruff 0.16.2, setuptools 84.0.0, and wheel 0.48.0; pinned the PEP 517 backend requirements; added a SHA-pinned CI quality job; expanded `scripts/preflight.sh` to run Ruff, strict mypy, and wheel/sdist builds; reconciled `README.md`, `CONTRIBUTING.md`, and `RELEASE.md`; modernized MIT license metadata; and made lint/type-only source cleanups without changing rule behavior.
- Verified: in a fresh Python 3.13.7 virtual environment, `/private/tmp/mcp-scopecheck-r1.muGuKa/venv/bin/python -m pip install --disable-pip-version-check -r requirements-dev.txt` installed all pinned direct tools successfully and `python -m pip check` reported no broken requirements. The first sandboxed install attempt failed because network access was unavailable; the approved network-enabled retry succeeded.
- Verified: the first pinned Ruff run exposed 27 reported style issues and the first strict mypy run exposed two `ast.AST.lineno` type assumptions. After the focused fixes, `/private/tmp/mcp-scopecheck-r1.muGuKa/venv/bin/python -m ruff check .` reported `All checks passed!`, and `/private/tmp/mcp-scopecheck-r1.muGuKa/venv/bin/python -m mypy` reported `Success: no issues found in 8 source files`.
- Verified: with the pinned environment activated, `scripts/preflight.sh` exited `0`: Gitleaks 8.30.1 scanned approximately 112.59 KB and reported `no leaks found`; 10/10 tests passed; compilation, Ruff, and strict mypy passed; and build 1.5.0 created both `mcp_scopecheck-0.1.0.tar.gz` and `mcp_scopecheck-0.1.0-py3-none-any.whl`. A separate `python -m build --no-isolation` run also succeeded; its initial license-metadata deprecation warnings were eliminated by using the supported SPDX string form and removing the redundant deprecated classifier.
- Verified: the required post-change commands `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v` and `PYTHONDONTWRITEBYTECODE=1 python3 -m compileall -q src tests examples` both exited `0`; 10/10 tests passed, including the target non-execution regression. The unsafe fixture still emitted exactly the six expected rule IDs and exited `1`; the hardened fixture still reported zero findings and exited `0`.
- Verified: `ruby -e 'require "yaml"; YAML.load_file(".github/workflows/ci.yml")'` parsed the workflow; all four action references remain pinned to full commit SHAs; parsed project metadata still has `dependencies = []`; generated caches and egg-info were removed after verification.
- Skipped/blocked: Python 3.11 and 3.12 are not installed locally, so their matrix executions await CI or a later clean environment. This workspace still has no Git history, and the successful Gitleaks run is evidence for the current tree rather than the eventual exact release commit.
- Decision: D009 records the development/build-tool pins and the decision to keep tests standard-library-only and runtime dependencies empty.
- Next: complete R2 correctness and package-content gaps.

### 2026-08-12 — R2 correctness and package-content gaps complete

- Changed: expanded the regression suite from 10 to 22 tests across `tests/test_audit.py`, `tests/test_cli.py`, and `tests/test_parser.py`; added exact normalized fixture reports in `tests/expected/`; made diagnostics produce CLI exit `2`; rejected a symlink supplied directly as the target while continuing to skip discovered symlinked source files; made the file-count limit fail before partial parsing; narrowed `MSC103` so `.resolve()` alone is not treated as containment; made `MSC105` respect lexical assignment order and simple assignment propagation; and added a positive-list `MANIFEST.in` for intended public sdist contents.
- Changed: updated `README.md` and `docs/architecture.md` with the exact `MSC103` and `MSC105` limits, removed internal handover links from the packaged README, and recorded the rule decision as D010 in `docs/decisions.md`.
- Verified: `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src /private/tmp/mcp-scopecheck-r1.muGuKa/venv/bin/python -m unittest discover -s tests -v` passed 22/22. Coverage now locks the exact unsafe and hardened reports, all eight public rule IDs and severities, every required finding field, threshold behavior, missing/no-tool/diagnostic exit `2` cases, decorator metadata, annotations, async tools, import aliases, source-size and file-count limits, symlink behavior, duplicate names, path/order-stable snapshots, the narrowed `MSC103`, ordered/simple `MSC105` flow, and the target non-execution sentinel.
- Verified: `/private/tmp/mcp-scopecheck-r1.muGuKa/venv/bin/python -m ruff check .` reported `All checks passed!`; `/private/tmp/mcp-scopecheck-r1.muGuKa/venv/bin/python -m mypy` reported `Success: no issues found in 8 source files`.
- Verified: with the pinned environment activated, `scripts/preflight.sh` exited `0`: Gitleaks 8.30.1 scanned approximately 134.26 KB with no leaks, 22/22 tests passed, compile/Ruff/strict-mypy passed, and both distributions built successfully. The unsafe fixture still emits exactly `MSC001`, `MSC105`, `MSC101`, `MSC102`, `MSC103`, and `MSC104` and exits `1`; the hardened fixture remains at zero findings and exit `0`.
- Verified: a separate clean-output build created the wheel and sdist without warnings. Manual archive review confirmed the wheel contains only the eight package modules, license, and standard distribution metadata; the sdist contains the package, README, license, changelog, checklist, contribution/security docs, architecture/positioning docs, paired fixtures, tests/expected outputs, pinned development requirements, and preflight script. Internal handover/status/decision/release-control files, caches, environments, and build debris are absent from the sdist by positive-list policy.
- Skipped/blocked: clean installation and installed-command checks intentionally remain R3 work. The current directory still has no Git history, so current Gitleaks evidence is for the tree rather than an exact release commit.
- Decision: D010 records the narrowed deterministic `MSC103` and `MSC105` semantics; no production dependency or security-boundary expansion was introduced.
- Next: complete R3 clean build and install proof.

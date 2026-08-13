# Project status

Last updated: 2026-08-12

## Current state

MCP ScopeCheck v0.1.0 remains published on GitHub and unchanged. A local v0.1.1 release candidate has been prepared solely to correct the GitHub owner identity and add Trusted Publishing automation; PyPI and launch publication have not occurred.

## Evidence on record

See `docs/validation-final-2026-08-12.md` for the final local evidence. Exact final artifact hashes are supplied in the owner handoff; earlier evidence remains in `docs/validation-2026-08-10.md` and `docs/validation-2026-08-12.md`.

## Open release blockers

- The GitHub `pypi` environment must exist and match the configured PyPI pending publisher.
- The owner must separately authorize push, tag, GitHub release, Trusted Publishing, and launch steps.
- Public CI on Python 3.11–3.13 must pass on the exact v0.1.1 release-candidate commit before tagging.

## Next checkpoint

Complete and review the local v0.1.1 release-candidate commit. Then follow the separately authorized sequence: push main, public CI, annotated v0.1.1 tag, GitHub release, Trusted Publishing, and fresh PyPI verification. Launch remains a later owner gate.

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

Entries below are dated historical evidence. Identity, availability, and release-state statements describe the state observed at that time and are not rewritten retroactively.

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

### 2026-08-12 — R3 clean build and install proof complete

- Changed: initialized a fresh standalone local Git repository on `main` and created root commit `fad953b7818ef2ddf07c67fb49fc95f9eb7f9915` using the owner's existing local Git identity; added `docs/validation-2026-08-12.md` with the clean-checkout, archive, install, behavior, and checksum evidence. No remote was created or contacted, and no tag or publication action occurred.
- Verified: a separate `git clone --no-hardlinks` checkout began clean at `fad953b`; a fresh Python 3.13.7 environment installed `requirements-dev.txt`; with that environment activated, `scripts/preflight.sh` exited `0`. Gitleaks 8.30.1 scanned approximately 136.17 KB and found no leaks; 22/22 tests, compile, Ruff 0.16.2, strict mypy 2.3.0, wheel build, and sdist build passed.
- Verified: manually reviewed `tar -tzf` and `unzip -l` listings for the exact artifacts. The wheel contains only the eight package modules, MIT license, and standard metadata. The sdist contains the positive-listed public source, docs, fixtures, tests/expected reports, and release tooling; internal handover/status/decision/release-control files and build debris are absent.
- Verified: the wheel and sdist installed separately and offline into fresh Python 3.13.7 environments. Both final environments contained only `mcp-scopecheck==0.1.0` and pip; `pip check`, `--version`, audit help, unsafe exit `1`, hardened exit `0`, high-threshold exit `1`, and critical-threshold exit `0` all matched the contract.
- Verified: candidate artifact SHA-256 values were `eec62633219e151be98638862cba0ea05db27edc3842361286e7de83cce13978` for the wheel and `8523017a6deabf51885939ea73a4ad0fbe1e71474a5274f6781d9a165dc2819c` for the sdist.
- Skipped/blocked: the first manually seeded sdist build environment failed `pip check` because wheel's build-only `packaging` dependency was deliberately omitted with `--no-deps`; it was discarded, recreated with an offline isolated PEP 517 build, and then passed. Python 3.11/3.12 remain unavailable locally. These R3 hashes become historical when the documentation commit changes; R5 will rebuild and rehash the exact final candidate.
- Decision: no new durable product or security decision was required. The local Git identity matches the proposed `thellmarchitect` repository owner, but public identity and destination still require the existing O002 owner approval.
- Next: complete R4 public documentation and proof-in-60-seconds demo.

### 2026-08-12 — R4 public documentation and demo complete

- Changed: made the README outcome-first with the exact pre-install static-auditor promise, corrected the output excerpt, clarified diagnostic exit `2`, provided fixture-backed copy/paste use commands, and linked the reproducible demo. Added executable `scripts/demo.sh`, public `docs/release-notes-v0.1.0.md`, and unposted `docs/launch-copy-v0.1.0.md`; reconciled `SECURITY.md`, `CHANGELOG.md`, `docs/positioning.md`, `docs/launch-plan.md`, and sdist content.
- Verified: `scripts/demo.sh` exited `0` and displayed real unsafe source evidence, the complete 5-S report with file/line/symbol evidence and unsafe exit `1`, the hardened source contrast, its expected filesystem-read capability, `Findings (0)`, hardened exit `0`, and explicit statements that neither server was started.
- Verified: every literal README command was run. The exact source-install block created `.venv` and installed editable `mcp-scopecheck==0.1.0`; installed unsafe/hardened commands exited `1`/`0`; the exact pinned development-tool install succeeded; the source test command passed 22/22; source unsafe/hardened commands exited `1`/`0`; and the demo command exited `0`. The first sandboxed source and development-tool install attempts failed only because PyPI was unreachable; approved retries of the same commands succeeded.
- Verified: with the README environment activated, `scripts/preflight.sh` exited `0`: Gitleaks 8.30.1 scanned approximately 234.17 KB and found no leaks; 22/22 tests, compile, Ruff, strict mypy, wheel build, and sdist build passed. Generated environments, caches, build output, and egg-info were removed afterward.
- Verified: public rule documentation now matches all eight implemented IDs and severities; the `MSC103` and `MSC105` limits, same-file reachability boundary, deterministic `MSC001` behavior, no-runtime-dependency claim, supported inputs, and clean-result caveat agree across README, architecture, release notes, positioning, and launch copy. No deferred feature is presented as shipped, and no uniqueness or completeness superlative is used.
- Skipped/blocked: launch copy remains explicitly unposted. GitHub private vulnerability reporting cannot be enabled until the owner authorizes repository creation; `SECURITY.md` now gives a non-public fallback without claiming that external configuration already exists.
- Decision: no durable product or architecture decision changed.
- Next: complete R5 final fresh-repository preflight and owner handoff.

### 2026-08-12 — R5 final local preflight complete

- Changed: completed every local checkbox in `RELEASE.md`, reconciled `PLANS.md` and `CODEX_HANDOVER.md` with the current 22-test/release-gate reality, and added `docs/validation-final-2026-08-12.md`. No production or public payload behavior changed during the closure step.
- Verified: a clean no-hardlink clone of payload commit `38f286f3d1fd16d878e5c44a07c7674625e270f7` passed `scripts/preflight.sh`: Gitleaks 8.30.1 scanned approximately 150.22 KB with no leaks; 22/22 tests, compile, Ruff 0.16.2, strict mypy 2.3.0, wheel build, and sdist build passed.
- Verified: wheel/sdist builds, manual content listings, separate offline installs, both `pip check` runs, version/help, unsafe exit `1`, hardened exit `0`, high-threshold exit `1`, and critical-threshold exit `0` all passed. The fixed-epoch wheel compared byte-for-byte across the payload and closure commits; extracted sdist content was identical, while setuptools-generated tar timestamps differed and are not claimed to be reproducible.
- Verified: final read-only name checks returned `404` for the PyPI project and proposed GitHub destination, with zero GitHub repository-name search results. The proposed owner account exists. Official GitHub tag-ref and commit APIs proved both Actions comments and full SHA pins match `actions/checkout@v4.4.0` and `actions/setup-python@v6.3.0`.
- Verified: the complete tracked tree and standalone history were reviewed. No environment file, private key, credential-shaped token, symlink, generated cache, build output, unrelated application module, or transplanted legacy history was found. The only legacy package-name reference is the intentional collision/positioning record.
- Skipped/blocked: Python 3.11 and 3.12 are not locally installed; public matrix execution requires an owner-approved remote. Name reservation, security-setting configuration, remote creation/push, tag, GitHub/PyPI publication, and launch remain owner/external gates and were not performed.
- Decision: no new product/dependency/security-boundary decision was required. Recommended owner default: approve O001-O003, keep O004 excluded, enable GitHub private vulnerability reporting, then publish the exact reviewed candidate only after public CI passes.
- Next: owner approval for R6 external actions.

### 2026-08-13 — local GitHub owner-identity migration prepared

- Changed: updated the local `origin` URL and current package/control references from the former GitHub owner to `iamudayrathore`, without changing the `mcp-scopecheck` repository, package, CLI, project, tag, workflow, or artifact names. Added `.github/workflows/release.yml` as a manual-only, annotated-tag-verified PyPI Trusted Publishing workflow using environment `pypi` and immutable action SHAs. No push, tag, release, PyPI upload, or launch post was performed.
- Preserved: dated validation records and earlier status entries retain the former owner identity because it was the value actually checked or used at that time. The published `v0.1.0` tag and GitHub release were not moved or replaced.
- Decision: D011 records the owner-only rebrand and the intended Trusted Publisher tuple: owner `iamudayrathore`, repository `mcp-scopecheck`, workflow `release.yml`, environment `pypi`.
- Verified: `PATH=/private/tmp/mcp-scopecheck-r5.4gnYpb/dev-venv/bin:$PATH scripts/preflight.sh` exited `0`: Gitleaks 8.30.1 scanned approximately 161.99 KB with no leaks; 22/22 tests, compilation, Ruff 0.16.2, strict mypy 2.3.0, wheel build, and sdist build passed. Ruby parsed both workflow YAML files, and the publishing workflow's checkout, Python setup, and PyPI publishing actions are pinned to reviewed full commit SHAs.
- Verified: read-only GitHub API checks resolve both the new and former repository paths to the public `iamudayrathore/mcp-scopecheck` repository, proving the owner transfer is complete and the former path redirects. Private vulnerability reporting remains enabled. The GitHub `pypi` environment is not configured, and the PyPI project endpoint still returns `404`.
- External follow-up: create/protect the GitHub `pypi` environment, then create or replace the PyPI pending publisher with the D011 tuple after this workflow is reviewed and pushed. Because the immutable v0.1.0 artifacts embed the former repository URL, publish corrected metadata under a new patch version rather than changing the v0.1.0 tag or artifacts.
- Next: wait for explicit authorization before any commit or push.

### 2026-08-12 — v0.1.1 local release candidate validated

- Changed: bumped package and CLI-reported version to 0.1.1; added concise v0.1.1 notes; reconciled current repository URLs, owner/release decisions, checklist, plan, status, and launch plan; and retained the manual-only, annotated-tag-verified Trusted Publishing workflow. No analyzer, parser, auditor, renderer, CLI behavior, model, fixture, test, dependency, or rule-output change was made.
- Verified: the GitHub repository is `iamudayrathore/mcp-scopecheck`, the configured PyPI pending publisher tuple was confirmed by the owner, and `.github/workflows/release.yml` references environment `pypi` exactly. The GitHub environment API returned `404`, so environment creation remains an external blocker rather than a pass.
- Verified: `PATH=/private/tmp/mcp-scopecheck-r5.4gnYpb/dev-venv/bin:$PATH scripts/preflight.sh` exited `0`: Gitleaks 8.30.1 scanned approximately 178.76 KB with no leaks; 22/22 tests including the target non-execution sentinel passed; compilation, Ruff 0.16.2, strict mypy 2.3.0, wheel build, and sdist build passed.
- Verified: manual wheel/sdist listings contained only intended public files. Both metadata records report `mcp-scopecheck` 0.1.1, author Uday Rathore, Python 3.11+, no runtime dependency, the unchanged console entry point, and repository/issues links under `iamudayrathore/mcp-scopecheck`.
- Verified: separate fresh Python 3.13.7 wheel and sdist environments installed offline. Both contained only `mcp-scopecheck==0.1.1` and pip; `pip check`, version, top-level/audit help, unsafe exit `1` with the same six rule IDs, hardened exit `0`, high-threshold exit `1`, and critical-threshold exit `0` passed.
- Preserved: remote and local v0.1.0 still resolve to tag object `34913eb59c9297ea37fc3953c45bdea15792059a`, commit `5d174ffee5b1ba529801c84fe4b68268354d4b2c`, and tree `5ab430161e5152dafd24d195b57004f3a4005b0b`; the GitHub release asset digests remain unchanged.
- Next: after the `pypi` environment exists and the owner authorizes external actions, push main, require public CI, tag v0.1.1, create its GitHub release, use Trusted Publishing, and verify a fresh PyPI install. Do not publish launch content yet.

# Validation record — 2026-08-12

This record covers the local R3 release-candidate proof from the fresh standalone history. It does not claim public CI or publication.

## Candidate

- Local commit: `fad953b7818ef2ddf07c67fb49fc95f9eb7f9915`
- Branch: `main`
- Clean checkout: `/private/tmp/mcp-scopecheck-r3.BVq0hI/checkout`
- Platform: macOS arm64
- Python: 3.13.7
- Gitleaks: 8.30.1
- Ruff: 0.16.2
- mypy: 2.3.0
- build: 1.5.0
- setuptools build backend: 84.0.0
- wheel build backend: 0.48.0

## Clean-checkout gates

The checkout began clean at the commit above. With the fresh pinned development environment activated, `scripts/preflight.sh` exited `0`:

- Gitleaks scanned approximately 136.17 KB and reported `no leaks found`.
- The standard-library suite passed 22/22 tests, including the target non-execution sentinel.
- `compileall` completed successfully.
- Ruff reported `All checks passed!`.
- strict mypy reported `Success: no issues found in 8 source files`.
- build created both the wheel and source distribution.

The first sandboxed development-tool installation attempt could not access PyPI. The same documented pinned install was retried with approved network access and succeeded. No target MCP source was imported, executed, installed, built, or started.

## Artifact contents

The exact candidate artifacts were built separately with:

```bash
python -m build --no-isolation --outdir /private/tmp/mcp-scopecheck-r3.BVq0hI/artifacts
```

Manual `tar -tzf` and `unzip -l` review found:

- Wheel: the eight `mcp_scopecheck` modules, MIT license, and standard distribution metadata only.
- Source distribution: the package, README, license, changelog, checklist, contribution/security docs, architecture/positioning docs, paired fixtures, tests and expected reports, pinned development requirements, and preflight script.
- Internal handover/status/decision/release-control files, environments, caches, `.env`, and build debris are absent from both distributions.

## Clean installations

The wheel and sdist were installed into separate fresh Python 3.13.7 environments.

- Wheel: installed offline with `PIP_NO_INDEX=1 --no-deps`; the environment contained only `mcp-scopecheck==0.1.0` and pip.
- Sdist: installed offline with isolated PEP 517 build dependencies sourced from a temporary wheelhouse containing the declared setuptools 84.0.0 and wheel 0.48.0 backend requirements plus wheel's build-only packaging 26.3 dependency. The final environment contained only `mcp-scopecheck==0.1.0` and pip.
- `pip check` passed in both final environments.
- `mcp-scopecheck --version` returned `mcp-scopecheck 0.1.0` in both.
- `mcp-scopecheck audit --help` succeeded in both.
- The unsafe fixture emitted exactly six findings and exited `1` in both.
- The hardened fixture emitted zero findings and exited `0` in both.
- A temporary one-finding `MSC103` fixture exited `1` at `--fail-on high` and `0` at `--fail-on critical` in both.

An initial manually seeded sdist build environment failed `pip check` because `wheel` had intentionally been installed with `--no-deps`, omitting its own build-only `packaging` dependency. That harness was discarded and recreated using isolated PEP 517 build dependencies; the corrected final environment passed as recorded above.

## Checksums

```text
eec62633219e151be98638862cba0ea05db27edc3842361286e7de83cce13978  mcp_scopecheck-0.1.0-py3-none-any.whl
8523017a6deabf51885939ea73a4ad0fbe1e71474a5274f6781d9a165dc2819c  mcp_scopecheck-0.1.0.tar.gz
```

These hashes identify the R3 proof artifacts from commit `fad953b`; any later release-candidate commit must be rebuilt, rechecked, and rehashed.

## Remaining gates

- R4 public-documentation and reproducible demo review.
- R5 final tree/diff/privacy/metadata/name review and full clean-clone preflight on the exact proposed release commit.
- Python 3.11 and 3.12 matrix execution in CI; only Python 3.13.7 was locally available for this record.
- Owner approval of public name, repository destination, release diff, external actions, and publication.

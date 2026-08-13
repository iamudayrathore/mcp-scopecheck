# Final local validation — 2026-08-12

This record closes every locally executable release gate through R5. It does not authorize or claim a remote repository, public CI result, tag, PyPI release, security-setting change, or launch post.

## Source and environment

- Public distribution payload baseline: local commit `38f286f3d1fd16d878e5c44a07c7674625e270f7`.
- Final local candidate: the commit containing this record; its exact SHA is reported in the owner handoff.
- Fresh no-hardlink checkout used for the final payload proof.
- macOS arm64, Python 3.13.7, pip 25.2.
- Gitleaks 8.30.1, Ruff 0.16.2, mypy 2.3.0, build 1.5.0, setuptools 84.0.0, wheel 0.48.0.
- Wheel reproducibility epoch: `SOURCE_DATE_EPOCH=1786492800` (2026-08-12 00:00:00 UTC).

Only internal control/evidence documents excluded by `MANIFEST.in` change between the payload baseline and the final closure commit. The final clean-clone run confirms the fixed-epoch wheel is byte-for-byte identical and the extracted sdist contents are identical. Setuptools 84.0.0 does not normalize sdist tar member timestamps from `SOURCE_DATE_EPOCH`, so separately built sdist archives are not claimed to be byte-reproducible.

## Exact local gates

From the clean checkout, the pinned development environment installed successfully and `scripts/preflight.sh` exited `0`:

- Gitleaks scanned approximately 150.22 KB and reported no leaks.
- 22/22 tests passed, including exact fixture reports and the target non-execution sentinel.
- Compilation passed.
- Ruff reported no issues.
- strict mypy reported no issues in eight source files.
- Wheel and source distribution builds succeeded.

Official GitHub API checks confirmed that the workflow pins are the exact tag commits for:

- `actions/checkout@v4.4.0`: `11d5960a326750d5838078e36cf38b85af677262`.
- `actions/setup-python@v6.3.0`: `ece7cb06caefa5fff74198d8649806c4678c61a1`.

## Names, identity, and metadata

- PyPI JSON returned `404` for `mcp-scopecheck`.
- The proposed GitHub repository API returned `404` for `thellmarchitect/mcp-scopecheck`.
- GitHub repository search returned zero names matching `mcp-scopecheck`.
- The `thellmarchitect` GitHub account exists; final public ownership and author presentation remain owner gates.
- Package, import, CLI, and display names are internally consistent.
- Version is `0.1.0` in package metadata and `mcp_scopecheck.__version__`.
- Metadata declares Python 3.11+, SPDX `MIT`, the intended repository/issues URLs, and `dependencies = []`.
- The local history contains only standalone project commits authored with the existing `thellmarchitect` no-reply Git identity; no legacy history was transplanted.

Availability is ephemeral and no name was reserved. Recheck immediately before any owner-approved reservation.

## Artifacts and contents

The exact final clean-clone artifact SHA-256 values are reported in the owner handoff. The fixed-epoch wheel was also compared byte-for-byte across the payload and closure commits. For the sdist, extracted files compared byte-for-byte while tar metadata timestamps differed; no broader reproducible-build claim is made.

Manual archive listing review confirmed:

- Wheel: the eight package modules, MIT license, and standard distribution metadata only.
- Sdist: the positive-listed public source, README/license, public docs, paired fixtures, test evidence, pinned development requirements, demo, and preflight.
- No environment files, virtual environments, caches, private keys, internal handover/status/decision/release-control documents, or build debris are present in either artifact.

## Installed behavior

The wheel and sdist installed offline into separate fresh Python 3.13.7 environments. The sdist used an isolated PEP 517 build with only its reviewed build-backend wheelhouse. In each final environment:

- only `mcp-scopecheck==0.1.0` and pip remained installed;
- `pip check` passed;
- `mcp-scopecheck --version` returned `mcp-scopecheck 0.1.0`;
- audit help succeeded;
- the unsafe fixture emitted exactly six expected findings and exited `1`;
- the hardened fixture emitted zero findings and exited `0`;
- the temporary high-only fixture exited `1` at `--fail-on high` and `0` at `--fail-on critical`.

## Remaining owner/external gates

- Approve the `mcp-scopecheck` name and `thellmarchitect/mcp-scopecheck` destination.
- Approve the final author/owner presentation and private security-reporting configuration.
- Approve remote creation and push; then require public CI on Python 3.11–3.13 to pass on this exact candidate.
- Approve the final diff, release notes, tag, GitHub release, PyPI publication, and launch copy.
- Recheck and reserve names immediately before the approved external sequence.

# v0.1.1 release checklist

Do not publish until every item is complete. Preserve v0.1.0 exactly.

- [x] Confirm the approved `iamudayrathore/mcp-scopecheck` identity and unchanged package/CLI names.
- [x] Confirm v0.1.0 tag, release, and artifact digests before preparing the patch.
- [ ] Confirm the GitHub `pypi` environment exists and matches `.github/workflows/release.yml`.
- [x] Confirm the PyPI pending Trusted Publisher tuple with the owner.
- [x] Review the final v0.1.1 diff for identity/version-only scope.
- [x] Run Gitleaks, 22 tests, compile, Ruff, strict mypy, wheel, and sdist gates.
- [x] Inspect both archives and confirm version, URLs, dependencies, and intended contents.
- [x] Install wheel and sdist separately and verify `pip check`, version, help, thresholds, and fixtures.
- [x] Generate and record final artifact SHA-256 checksums.
- [x] Create the single local v0.1.1 release-candidate commit.
- [ ] Push the reviewed release-candidate commit only after explicit authorization.
- [ ] Require public CI on Python 3.11-3.13 to pass on the exact commit.
- [ ] Create annotated `v0.1.1` only after explicit authorization; never move v0.1.0.
- [ ] Create the GitHub v0.1.1 release with reviewed artifacts and checksums.
- [ ] Publish through the configured PyPI Trusted Publisher.
- [ ] Verify a cache-disabled fresh PyPI installation before any launch content.

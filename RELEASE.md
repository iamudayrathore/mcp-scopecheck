# Release checklist

Do not publish until every item is complete.

- [ ] Re-check the project, repository, PyPI package, and CLI names for collisions.
- [ ] Obtain owner approval for the final name and repository destination in `docs/decisions.md`.
- [ ] Review every diff for legacy-project branding or unrelated code.
- [ ] Create a fresh environment and install the pinned tools with `.venv/bin/python -m pip install --disable-pip-version-check -r requirements-dev.txt`.
- [ ] Run `scripts/preflight.sh` locally with `gitleaks` installed.
- [ ] Confirm the preflight's unit-test, compile, Ruff, strict mypy, wheel, and source-distribution gates all pass in the pinned development environment.
- [ ] Confirm the unsafe fixture exits `1` with the expected rule IDs.
- [ ] Confirm the hardened fixture exits `0`.
- [ ] Build wheel and source distribution from a clean checkout.
- [ ] Install wheel and source distribution into separate fresh environments.
- [ ] Run both fixtures and `pip check` from each fresh installed distribution.
- [ ] Review the generated package contents; exclude caches, environments, `.env`, and demo artifacts not intended for release.
- [ ] Generate and record artifact SHA-256 checksums.
- [ ] Confirm CI actions remain pinned to reviewed commit SHAs.
- [ ] Confirm README commands and public claims match the release candidate.
- [ ] Tag `v0.1.0` only after CI passes from the release commit.
- [ ] Publish release notes that state supported inputs and known blind spots.
- [ ] Obtain explicit owner approval before remote creation/push, tag, PyPI publication, or launch post.

# Release checklist

Do not publish until every item is complete.

- [x] Re-check the project, repository, PyPI package, and CLI names for collisions.
- [ ] Obtain owner approval for the final name and repository destination in `docs/decisions.md`.
- [x] Review every diff for legacy-project branding or unrelated code.
- [x] Create a fresh environment and install the pinned tools with `.venv/bin/python -m pip install --disable-pip-version-check -r requirements-dev.txt`.
- [x] Run `scripts/preflight.sh` locally with `gitleaks` installed.
- [x] Confirm the preflight's unit-test, compile, Ruff, strict mypy, wheel, and source-distribution gates all pass in the pinned development environment.
- [x] Confirm the unsafe fixture exits `1` with the expected rule IDs.
- [x] Confirm the hardened fixture exits `0`.
- [x] Build wheel and source distribution from a clean checkout.
- [x] Install wheel and source distribution into separate fresh environments.
- [x] Run both fixtures and `pip check` from each fresh installed distribution.
- [x] Review the generated package contents; exclude caches, environments, `.env`, and demo artifacts not intended for release.
- [x] Generate and record artifact SHA-256 checksums.
- [x] Confirm CI actions remain pinned to reviewed commit SHAs.
- [x] Confirm README commands and public claims match the release candidate.
- [ ] Enable GitHub private vulnerability reporting or approve a durable private security contact.
- [ ] Tag `v0.1.0` only after CI passes from the release commit.
- [ ] Publish release notes that state supported inputs and known blind spots.
- [ ] Obtain explicit owner approval before remote creation/push, tag, PyPI publication, or launch post.

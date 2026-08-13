# MCP ScopeCheck execution plan

Last updated: 2026-08-12

## Objective and stopping condition

Objective: prepare v0.1.0 for public release as a clean, reproducible, evidence-backed Python security tool.

Local-build stopping condition: every locally executable gate through R5 passes from a clean checkout and is recorded in `docs/status.md`.

Publication stopping condition: R6 completes only after the owner explicitly approves the final name, repository destination, release diff, tag, and PyPI publication.

Work one checkpoint at a time. Do not begin v0.2 work while a v0.1 gate is open.

## Plan status

| Checkpoint | Outcome | State at handover |
| --- | --- | --- |
| R0 | Reconcile baseline and owner gates | Complete |
| R1 | Make quality checks reproducible | Complete |
| R2 | Close correctness and packaging gaps | Complete |
| R3 | Prove clean install and release candidate | Complete |
| R4 | Finish public documentation and demo | Complete |
| R5 | Fresh repository preflight | Complete locally; public CI awaits owner-approved remote |
| R6 | Owner-approved publication | Blocked on owner approval |
| P1+ | Post-release product roadmap | Deferred |

## R0 — baseline reconciliation and decisions

Goal: prove the handover matches the current tree and isolate decisions that actually need the owner.

Tasks:

1. Read the repository instructions and handover files.
2. Run the baseline unit tests, compile check, unsafe fixture, and hardened fixture.
3. Inspect `pyproject.toml`, CI, release script, and distribution configuration.
4. Confirm no target code is imported or executed anywhere in production/test paths.
5. Check final project/package/CLI/repository name availability immediately before reservation. Do not rely on the 2026-08-10 search alone.
6. Update `docs/status.md` with observed facts, not assumptions.
7. Ask the owner only for unresolved gates in `docs/decisions.md`.

Acceptance:

- Baseline commands and exit codes are recorded.
- Any mismatch between code and handover is documented.
- The owner has a short decision list with recommended defaults.
- No remote or publication action has occurred.

## R1 — reproducible quality gates

Goal: make every claimed quality check runnable locally and in CI.

Tasks:

1. Choose and pin reviewed development-tool versions for Ruff, mypy, package build, and test support. Keep them development-only.
2. Add one documented bootstrap command or dev extra; do not add runtime dependencies.
3. Run Ruff and strict mypy; fix real issues with minimal changes.
4. Keep unit tests on Python 3.11–3.13 in CI.
5. Add lint and type gates to CI without unpinning GitHub Actions.
6. Keep Gitleaks fail-closed. Verify the script against the installed current CLI.
7. Make local commands, CI commands, `CONTRIBUTING.md`, and `RELEASE.md` agree.

Acceptance:

- One fresh environment can install development tools using documented commands.
- Unit tests, compile, Ruff, and strict mypy pass.
- CI contains equivalent test/lint/type gates.
- No new runtime dependency exists.
- Missing Gitleaks is reported as a blocker, never a pass.

## R2 — correctness and package-content gaps

Goal: close high-value v0.1 gaps without expanding the product surface.

Tasks:

1. Add exact output/rule regression assertions for the unsafe and hardened fixtures so unexpected findings are visible.
2. Test CLI threshold behavior and exit `2` cases.
3. Add focused parser tests for decorator metadata, annotations, async tools, aliases already claimed as supported, size/file-count diagnostics where practical, and symlink skipping.
4. Add adversarial tests for duplicate tool names and deterministic snapshots across path/order variations.
5. Review `MSC103` guard handling. If it can suppress a finding merely because any unrelated `.resolve()` exists, either narrow the rule safely or document/test the limitation. Do not pretend to have dominance analysis.
6. Review `MSC105` ordering and assignment behavior for obvious false negatives/positives; keep its same-function claim.
7. Ensure exceptions are narrow and diagnostics remain visible.
8. Add `MANIFEST.in` or equivalent packaging configuration if required so the source distribution contains intended public files and excludes private/build debris.

Acceptance:

- Tests demonstrate every public rule and exit-code claim.
- Hardened fixture remains clean for the right reason.
- Unsafe fixture emits the intended rule set with evidence.
- The no-execution regression still passes.
- Package-content intent is encoded, not left to local directory state.

Scope stop: do not implement cross-module analysis, JSON/SARIF, TypeScript, remote ingestion, or LLM analysis here.

## R3 — clean build and install proof

Goal: create a release candidate reproducibly from a clean checkout.

Tasks:

1. Create a fresh standalone Git repository/history; do not transplant legacy-project history.
2. From a clean checkout, run all tests, compile, lint, type, and Gitleaks gates.
3. Build both wheel and source distribution using the current standard packaging workflow.
4. List and review archive contents.
5. Install wheel and sdist into separate fresh virtual environments.
6. Run `pip check`, `--version`, help, unsafe fixture, hardened fixture, and threshold cases from the installed command.
7. Generate checksums for release artifacts.
8. Update the dated validation record with environment versions and exact evidence.

Acceptance:

- Gitleaks passes on the exact candidate tree.
- Wheel and sdist build and install without unexpected dependencies.
- Installed behavior matches source behavior.
- Artifact contents and checksums are recorded.
- No environment files, secrets, caches, old branding, or unrelated code are present.

## R4 — public documentation and proof-in-60-seconds demo

Goal: make the value and boundaries obvious to a reviewer in under five minutes.

Tasks:

1. Re-run every README command by copy/paste.
2. Keep the top of README outcome-first: one-sentence promise, unsafe output, hardened contrast, install, use, boundaries.
3. Ensure rule docs match exact implementation and severity.
4. Ensure architecture, threat model, security policy, contribution guide, checklist, changelog, and release notes agree.
5. Create a short reproducible terminal demo using the paired fixtures. Do not fake output.
6. Show unsafe source evidence, the 5-S output, the hardened change, and exit-code behavior.
7. Add a concise limitations section and avoid competitor superlatives.
8. Prepare the v0.1.0 release notes and launch copy, but do not post.

Acceptance:

- A new user can install and reproduce the demo.
- Every public claim is supported by code/test evidence.
- No v0.2 feature is presented as shipped.
- The demo uses clearly fake canary values and cannot trigger secret hygiene failures.

## R5 — final fresh-repository preflight

Goal: produce the exact commit the owner can approve for publication.

Tasks:

1. Review the full diff and complete tree for provenance, privacy, licenses, and unwanted files.
2. Confirm final name availability again and reserve only with owner approval.
3. Verify CI actions and any release actions are pinned to reviewed commit SHAs.
4. Run the full release checklist and validation from a clean clone.
5. Confirm repository URLs, author identity, issue/security contacts, license, package metadata, and version.
6. Produce an owner handoff containing artifact hashes, test matrix, Gitleaks result, known limitations, and the exact external actions proposed.

Acceptance:

- `RELEASE.md` has no unchecked local gate.
- CI is green on the exact proposed release commit, if a private remote is used.
- The only remaining work is explicitly owner-approved external publication.

## R6 — publication, only after explicit owner approval

Goal: publish exactly the reviewed candidate, once.

Tasks:

1. Create or confirm the public repository at the approved destination.
2. Push the clean standalone history.
3. Confirm public CI and security checks pass.
4. Create signed/annotated `v0.1.0` tag according to the chosen policy.
5. Create the GitHub release with the reviewed notes and checksums.
6. Publish to PyPI using current trusted-publishing guidance where possible.
7. Install from PyPI in a fresh environment and rerun the two fixtures.
8. Publish the prepared launch assets only after package verification.

Acceptance:

- Public repository, tag, release, and PyPI metadata point to the same source/version.
- Fresh public install reproduces expected behavior.
- Final links and evidence are recorded in `docs/status.md`.

Rollback rule: package releases are effectively immutable. If verification fails after publication, stop launch activity, document the issue, and prepare a new patch version; never silently replace source behind a released version.

## Post-release roadmap — not v0.1 blockers

Order future work by evidence and user value:

### P1 — evaluation corpus and stable machine schema

- Build labeled benign/malicious fixtures from public patterns and synthetic cases.
- Measure rule-level precision/recall and publish methodology, not inflated aggregate claims.
- Define a versioned internal finding schema.
- Add JSON, then SARIF, without breaking text output.

### P2 — deeper Python reachability

- Cross-module imports and calls.
- Argument-aware interprocedural flow.
- Guard dominance/root matching for filesystem containment.
- Destination/payload-aware network disclosure checks.

### P3 — snapshot drift

- Persist normalized manifests and capabilities.
- Compare description/schema/annotation/capability changes.
- Treat unexpected server-side tool-definition drift as re-review, not automatic proof of attack.

### P4 — TypeScript and acquisition

- TypeScript parser backed by a real syntax tree.
- Local package/archive input with strict extraction limits.
- GitHub URL acquisition only with pinning, provenance display, size limits, and an explicit network boundary.

### P5 — optional semantic analyzer

- Add only after a deterministic benchmark exists.
- Make it opt-in with explicit provider, model, data-sent, cost, retention, timeout, and failure behavior.
- Never send arbitrary source or secrets by default.
- Keep deterministic rules usable offline.

## Rabbit-hole guardrails

- No UI before the CLI release is reproducible.
- No framework rewrite because the current standard-library core is small and testable.
- No generic SAST ambition; stay focused on MCP tool contracts and reachable capabilities.
- No new rule without a benign fixture, malicious fixture, evidence model, remediation, and documented limitation.
- No public benchmark number until the corpus and method are committed.
- No launch before clean-install and secret-scan evidence exists.

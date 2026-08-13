# v0.1 launch and career-evidence plan

This plan starts only after R5 in `PLANS.md` passes. It does not authorize publication.

## Proof package

The public release should contain five reviewable proofs:

1. **Trust-boundary proof:** architecture document and a regression test showing target top-level code is never executed.
2. **Detection proof:** unsafe fixture produces the expected evidence-backed rule set and exit `1`.
3. **Precision proof:** behaviorally equivalent hardened fixture keeps its expected file-read capability but produces zero findings and exit `0`.
4. **Engineering proof:** Python 3.11–3.13 CI, lint, strict typing, clean build/install, pinned actions, Gitleaks, artifact checksums.
5. **Judgment proof:** explicit non-goals, limitations, threat model, remediation, and restrained competitive claims.

## Proof-in-60-seconds terminal demo

Use the two committed examples; do not stage or fake output.

1. Show `search_project_docs` in the unsafe source: broad root, misleading read-only claim, undisclosed telemetry, and environment-derived value.
2. Run `mcp-scopecheck audit examples/unsafe_docs_server`.
3. Pause on the file/line/symbol evidence and exit `1`.
4. Show the hardened source: fixed root, containment, no telemetry/network, honest description.
5. Run `mcp-scopecheck audit examples/hardened_docs_server`.
6. Show the expected filesystem-read capability, zero findings, deterministic snapshot, and exit `0`.
7. Close with: “Inspect before you connect.”

The demo should visibly state that ScopeCheck did not start either server.

## README reviewer path

A hiring reviewer should be able to scan in this order:

1. One-sentence product promise.
2. Unsafe output and hardened contrast.
3. No-execution invariant.
4. Install and copy/paste use.
5. Rules and evidence shape.
6. Threat model and limitations.
7. CI/release status.
8. Roadmap.

## Launch sequence

1. Owner reviews the exact release commit and evidence handoff.
2. Publish the repository and GitHub release.
3. Publish and verify PyPI v0.1.1 from a fresh environment.
4. Add verified public links to README/release metadata if needed through a patch release-safe process.
5. Publish the short demo video/post.
6. Pin a concise call to action: run it on a local Python MCP server, open issues with minimal fixtures, and treat clean output as a starting point rather than proof of safety.
7. Collect concrete false-positive/false-negative examples for the evaluation corpus.

The v0.1.0 launch copy remains an unposted historical draft and must not be reused automatically. v0.1.1 release notes are in `docs/release-notes-v0.1.1.md`; any later launch content requires separate owner approval and must be checked against the published package.

## Interview narrative

Keep the story technical and verifiable:

- The risk: untrusted tool metadata and code cross an agent trust boundary.
- The decision: static pre-install analysis avoids executing the code under review.
- The design: tool declarations become claims; reachable source behavior becomes evidence; rules compare the two.
- The hard parts: safe parsing, reachability boundaries, false-positive control, evidence, deterministic output, and honest limitations.
- The proof: unsafe/hardened fixtures, no-execution regression, CI, clean distribution, and security preflight.
- The roadmap: evaluation before complexity, then deeper flow, snapshots, TypeScript, and optional semantic analysis.

Avoid presenting deferred features as work already completed. The strongest signal is disciplined scope and evidence, not inflated breadth.

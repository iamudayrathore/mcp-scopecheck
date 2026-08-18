# Changelog

## 0.2.0 - 2026-08-15

- Added explicit `complete`, `partial`, and `failed` analysis states with exit
  `2` precedence for incomplete analysis, including when supported findings are
  also present.
- Added deterministic ledgers for resolved and unresolved reachable local calls
  plus statically visible unsupported registration forms.
- Added bounded resolution for static in-root relative/absolute imports, direct
  imported functions and aliases, qualified module calls, cycles, and one named
  package re-export hop.
- Propagated cross-module filesystem, environment, network, process, and dynamic
  code capabilities with shortest explainable source paths.
- Kept `MSC105` same-function and suppressed `MSC103` when cross-boundary
  argument or guard lineage is unresolved.
- Reduced the three corpus-confirmed `MSC102` disclosure false positives through
  a qualified, context-bound external-target disclosure check: an interaction
  action and an external target must appear together in one sentence, and bare
  `URL`, bare `endpoint`, unrelated named-service mentions, and generic verbs no
  longer count as disclosure on their own. All six confirmed baseline detections
  are retained.
- Added deterministic SARIF 2.1.0 output with findings as results and
  incompleteness as non-finding tool execution notifications.
- Added explicit graph, path, unresolved-edge, and potential-registration
  resource limits that fail closed.
- Preserved Python 3.11+, zero runtime dependencies, local-source-only analysis,
  and the no-target-execution invariant.

## 0.1.2 - 2026-08-14

- Escaped terminal control, line-forging, and bidirectional text from every
  target-controlled report and normal CLI-error field.
- Bounded static metadata decoding, cumulative source/AST work, AST depth, and
  diagnostic collection; incomplete audits continue to exit `2`.
- Replaced lossy UTF-8 source decoding with strict PEP 263 encoding detection;
  malformed bytes and encoding declarations now fail incomplete with exit `2`.
- Added flow-sensitive network-client sinks and same-function environment-flow
  evidence for `httpx.Client`, `httpx.AsyncClient`, and `requests.Session`.
- Replaced blanket network-module prefix matching with explicit direct sinks;
  constructors, utilities, and unsupported context-manager factories stay clean.
- Added the eight explicit `requests.api` request functions to the same sink and
  rule semantics as their supported `requests` counterparts.
- Made reachability and import resolution lexical and statement-aware, including
  directly called nested sync/async helpers and function-local imports.
- Replaced suffix-based filesystem detection with qualified APIs, proven
  `pathlib.Path` receivers, and static open modes/`os.open` flags.
- Correlated `MSC103` guards with the path value reaching the sink and made
  `MSC104` distinguish actual root/home expansion from bounded home subdirectories.
- Normalized MCP annotation aliases and separated read-only conflicts from
  `openWorldHint=false` network conflicts.
- Strengthened deterministic `MSC001`/`MSC102` description checks with a labeled
  corpus, contradiction handling, and narrow static destination evidence.
- Defined and tested a no-follow symlink policy across Python 3.11–3.13, and made
  single-file reports display the requested file.
- Bound manual publication to an owner-approved full commit SHA on `main` with
  successful CI for that exact SHA, and isolated OIDC from source and build jobs.
- Made the publication gate reject paginated, count-inconsistent, incomplete, or
  multiple GitHub Actions results instead of accepting ambiguous CI evidence.
- Kept the CLI, plain-text report format, exit-code contract, and zero runtime
  dependencies compatible with `0.1.1`.

## 0.1.1 - 2026-08-13

- Updated repository metadata for the `iamudayrathore` GitHub owner identity.
- Added a manual, tag-verified PyPI Trusted Publishing workflow.
- No scanner behavior, rule output, CLI contract, or runtime dependency changed.

## 0.1.0 - 2026-08-13

- Added non-executing Python AST tool discovery.
- Added same-file helper-call reachability.
- Added six capability classes and eight contract/security rules.
- Added deterministic 5-S snapshot reporting.
- Added paired unsafe and hardened demo fixtures.
- Added regression coverage for the no-target-execution invariant.
- Added explicit error exits for incomplete audits, safety limits, and symlink handling.
- Added pinned local/CI quality gates and reproducible wheel/source-distribution builds.

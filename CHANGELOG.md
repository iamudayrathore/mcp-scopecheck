# Changelog

## 0.1.2 - 2026-08-14

- Escaped terminal control, line-forging, and bidirectional text from every
  target-controlled report and normal CLI-error field.
- Bounded static metadata decoding, cumulative source/AST work, AST depth, and
  diagnostic collection; incomplete audits continue to exit `2`.
- Added flow-sensitive network-client sinks and same-function environment-flow
  evidence for `httpx.Client`, `httpx.AsyncClient`, and `requests.Session`.
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

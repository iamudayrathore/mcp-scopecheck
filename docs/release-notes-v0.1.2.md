# MCP ScopeCheck v0.1.2

This release hardens ScopeCheck's non-executing audit boundary and makes its
deterministic findings more precise without adding runtime dependencies or
network calls.

## Security boundary

- Target-controlled terminal controls, forged lines, and bidirectional markers
  are rendered inert throughout reports and normal CLI errors.
- Tool metadata is decoded by a bounded JSON-like AST evaluator rather than
  `ast.literal_eval`; unsupported or over-budget values produce diagnostics.
- Audits now enforce cumulative source-byte, AST-node, AST-depth, and diagnostic
  limits in addition to the existing file caps. Any overrun is incomplete and
  exits `2`.
- Direct symlink targets are rejected. Symlinked files and directories inside a
  directory target are skipped with link following disabled; the regression
  passes on Python 3.11, 3.12, and 3.13.
- The regression proving that top-level target code never executes remains in
  the release suite.
- Manual publication requires an annotated tag that peels to an owner-approved
  full commit SHA on `main` and a successful CI run for that exact SHA. Source
  verification and the single build run without OIDC; only the source-free
  publishing job can request a Trusted Publishing token for the checksummed
  artifact.

## Analyzer correctness

- Network egress and `MSC105` now recognize request methods on flow-proven
  `httpx.Client`, `httpx.AsyncClient`, `requests.Session`, and
  `requests.sessions.Session` instances. Construction alone is not egress, and
  reassignment or deletion kills the binding.
- Lexical reachability excludes uncalled nested functions, lambdas, and class
  methods while following directly called nested sync/async helpers. Local import
  aliases and statement-order shadowing are resolved.
- Filesystem evidence now comes from qualified builtins/modules or proven
  `pathlib.Path` values. Static modes and `os.open` flags distinguish reads from
  writes; unrelated `.open()` and `.replace()` methods remain clean.
- MCP snake_case and camelCase annotation spellings normalize to one model.
  `readOnlyHint=true` is compared with justified state changes, while
  `openWorldHint=false` uses the separate `MSC108` rule.
- `MSC103` correlates guards with the value reaching the filesystem sink.
  `MSC104` recognizes true POSIX/home roots without treating every `~/subdir` as
  the whole home directory.

## Description contracts

- `MSC001` adds measured deterministic indicator families for override,
  concealment, covert transfer, credential/context collection, and related
  wording. It reports the matched family and retains benign discussion cases in
  a labeled regression corpus.
- `MSC102` no longer accepts a lone word such as `API`, `web`, `network`, or
  `remote` as disclosure. Explicit denials are contradictions; supported literal
  destinations preserve host evidence for a narrow named-service comparison.

These checks are deterministic patterns, not semantic or LLM analysis. They do
not prove intent or understand arbitrary paraphrases.

## Compatibility and limits

- The `mcp-scopecheck audit TARGET [--fail-on ...]` interface, exit codes, 5-S
  plain-text format, and unsafe/hardened example snapshots remain compatible.
- Python 3.11, 3.12, and 3.13 are tested. The package still has no required
  runtime dependencies and performs no network call during an audit.
- Cross-module calls, callback/function aliases, dynamic dispatch, general
  points-to analysis, and interprocedural environment taint remain outside v0.1.
- A clean result remains static evidence, not proof that a running server is
  safe.

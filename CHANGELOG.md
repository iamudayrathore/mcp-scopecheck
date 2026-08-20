# Changelog

## 0.2.3 - 2026-08-20

- Preserve the exact function object captured by each supported tool decorator.
  A later module-level definition with the same Python name no longer replaces an
  earlier registered tool's analysis root and hide its reachable capabilities.
- Model statically selected module-level branches and fail closed when module or
  function control flow leaves an import, path, client, or nested-function binding
  ambiguous at a reachable call. These cases now produce an explicit unresolved
  edge, partial completeness, and exit `2` instead of a complete clean audit.
- Do not classify calls already proven to target project-local functions as
  built-in or third-party capability sinks. A benign same-file helper named `eval`
  no longer produces a false Critical `MSC107` finding; the helper body remains
  reachable and is analyzed normally.
- Added unit and installed-wheel behavioural regressions for duplicate registered
  function names, compound-statement imports, ambiguous control-flow bindings, and
  local helpers whose names collide with modeled sinks.
- No change to the no-target-execution invariant, runtime dependency boundary,
  rule catalogue, SARIF schema, resource limits, or exit-code contract.

## 0.2.2 - 2026-08-20

- Withdrew `MSC103` (filesystem scope) and `MSC104` (dangerous filesystem default),
  along with the containment machinery behind them and their SARIF catalogue
  entries. Both decided whether caller-controlled filesystem access was constrained,
  and 0.2.1 decided it by matching the parameter's *name* against a fixed list, so a
  traversal through a differently named parameter produced completeness `complete`,
  no findings, and exit `0`. Four attempts to fix the rule failed in alternating
  directions; the model could not express containment across Python's control flow.
  A rule that cannot decide a property reliably must not claim to.
- Kept filesystem capability reporting and its evidence path, which the call graph
  decides. A report states that a tool reaches a filesystem operation and how; it no
  longer states whether the path is contained, and the documentation says plainly
  that a clean audit is not evidence filesystem access is bounded.
- Capability reporting no longer depends on how code is spelled. A path built inside
  a local helper or reached through a chain of calls is observed rather than
  silently dropped, and semantically identical code no longer produces different
  verdicts depending on line breaks.
- A path stored in a container and retrieved by subscript is deliberately not
  tracked, in place of a heuristic that invented filesystem capabilities on ordinary
  in-memory code. Documented and pinned by tests.
- Fixed an unhandled `LookupError` for a declared codec that exists but is not a text
  encoding (`rot13`, `base64`, `hex`, `bz2`, `zlib`, `quopri`, `uu`). A crafted
  coding cookie crashed the audit with exit `1` and no output, which the exit
  contract defines as "complete, findings at threshold". Present since 0.1.2 and live
  in 0.2.1.
- Added `scripts/validate_release.py`, 164 behavioural checks against an installed
  wheel, run by `scripts/preflight.sh` as a release gate. Its integrity checks
  require the contract digest to be invariant under edits that change source bytes
  without changing the contract, so a build that does not analyze cannot satisfy it.
- Published a composite GitHub Action, refreshed all workflow action pins, and added
  a release-time check that the action commit documented in the README carries the
  version being released.
- No change to the exit-code contract, the no-execution invariant, the resource
  limits, the SARIF schema, or the snapshot digest payload.

## 0.2.1 - 2026-08-19

Correctness patch for filesystem-scope analysis. Upgrading is recommended for
every 0.2.0 user: 0.2.0 could report `complete` with no findings and exit `0`
for a tool that read or wrote arbitrary caller-supplied paths.

- `MSC103` and `MSC104` no longer depend on parameter naming. Path tracking is
  now seeded from every declared tool parameter, and the existing flow analysis
  decides participation: `_sink_value` reads only path positions (the receiver,
  argument 0, argument 1 of a two-path call, and the `file`/`filename`/`path`/
  `src`/`dst` keywords), so a parameter becomes a sink source only when it
  genuinely occupies a path position. In 0.2.0 a traversal through a parameter
  named `filepath`, `pathname`, `dirpath`, `target`, `dest`, `src`, `uri`,
  `location`, or `name` was silently missed; only 8 exact names and 5 suffixes
  were tracked. Data arguments beside a path (`write_text(body)`) and separators
  or prefixes that never reach a filesystem sink (`sep: str = "/"`) remain clean.
- `MSC104` additionally qualifies a differently named parameter that is proven to
  reach a filesystem sink, while still not treating an unrelated `"/"` default as
  a filesystem root. Its evidence now points at the parameter default rather than
  at the tool description line.
- `MSC103` suppression is scoped per sink. 0.2.0 withheld the rule whenever the
  tool contained any unresolved reachable call, so an unrelated dynamic import
  could hide a proven traversal. A sink is now withheld only when unresolved work
  could actually own its guard: decorator/wrapper indirection, which observes
  every argument before the body runs, or an unresolved call that actually
  receives the path value. Sinks with fully proven lineage are reported even when
  the tool has other unresolved calls, and the analysis still reports `partial`
  with exit `2`.
- Constructing a locally defined class is reported as `unsupported instance/class
  dispatch` instead of `higher-order call`. A local class shadows into the module
  alias table with an empty target, which previously routed it to the variable
  call branch.
- An empty finding list under `partial` or `failed` completeness no longer renders
  as "No contract mismatches or high-risk behavior detected"; it now states that
  there are no findings within an incomplete analysis.
- The `MSC103-GUARD-UNKNOWN` notification is gated on proven filesystem
  participation or a path-like parameter name rather than naming alone, and its
  message no longer claims lineage that may not exist.
- `MSC001` severity is now assigned per indicator family instead of always being
  Critical. The `credential-handling instruction` and `cross-call instruction`
  families report High, because a verb near a credential noun and sequencing
  wording both appear in accurate self-descriptions of credential, authentication,
  and workflow tools; reporting them at Critical made honest tools
  indistinguishable from poisoned ones. Unambiguous directive families - override,
  concealment, hidden action, covert transfer, privileged-role impersonation, and
  hidden-token markers - remain Critical. When a description matches several
  families the strongest is now reported rather than the first in declaration
  order. Detection is unchanged; no description that was flagged before is
  unflagged now.
- No change to the exit-code contract, the no-execution invariant, the resource
  limits, the SARIF schema, or the snapshot digest payload.

## 0.2.0 - 2026-08-19

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
- Reworked `MSC102` into a conservative external-egress review rule. For modeled
  network sinks, neither a tool's prose nor a matching service hostname suppresses
  the finding, and no reachable external destination is treated as a clean pass.
  Reachable egress is always reported as an observed capability. MSC102 flags it
  unless it targets only local/loopback/private hosts (`localhost`, `127.0.0.1`,
  RFC1918/ULA, IP literals parsed with the `ipaddress` module so lookalike
  hostnames stay external). A resolved external host is flagged even when its
  registrable domain matches a service the description names, because services host
  attacker-controllable content (repos, gists, snippets, buckets, webhooks) on the
  same hosts as their APIs; the service comparison is used only to choose the
  destination-mismatch subtype. A dynamic or computed destination is always flagged
  for review. An explicit offline/no-network denial is reported as a contradiction
  (best-effort — a missed denial still flags). Modeled egress detection now includes
  `http.client`, raw sockets, `aiohttp.ClientSession`, and `urllib3` pools; egress
  through unmodeled clients is not detected. This is a deliberate
  recall-over-precision stance: every modeled reachable external network call whose
  destination cannot be verified is surfaced for a human to confirm. The generic
  finding is titled `External network egress requires review`.
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

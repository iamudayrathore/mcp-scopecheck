# Changelog

## 0.2.5 - 2026-08-19

Withdraws `MSC103` and `MSC104`. 0.2.2, 0.2.3, and 0.2.4 were never published.

Both rules decided whether caller-controlled filesystem access was constrained.
Across four consecutive release candidates they got that wrong in alternating
directions - too permissive, too strict, permissive again through new mechanisms,
and finally still gated on whether a parameter was named `path` rather than
`title`, which is the mechanism the project's own draft advisory is written about.
Each fix was correct for the case that motivated it, and the class survived every
time. A rule that cannot decide a property reliably must not claim to.

- Removed `MSC103` and `MSC104`, the containment machinery behind them (about 1,000
  lines), the `MSC103-GUARD-UNKNOWN` and `MSC103-LINEAGE-UNPROVEN` notifications,
  and their entries in the SARIF rule catalogue. Restoring them needs path-aware
  dataflow rather than the token-set model that failed; that is a design change.
- Kept filesystem capability reporting and its evidence path, which are decided by
  the call graph rather than by the guard model. A report still states that a tool
  reaches a filesystem operation and how; it no longer states whether the path is
  contained, and the documentation says so plainly.
- Fixed a capability that vanished when a helper built the path itself:
  `def _resolve(n): return ROOT / n` followed by `_resolve(name).write_text(body)`
  reported `Observed: none` under a `complete` audit - an arbitrary
  caller-controlled write, denied outright, and the denial changed with the
  parameter's name. A resolvable project-local callee that returns a path
  expression is now recognised as returning a path.
- Stopped inventing filesystem capabilities. A receiver the analyzer only infers to
  be a path must be used with a pathlib-exclusive method before a capability is
  asserted, so an in-memory cache calling `ENTRIES[key].touch()` is no longer
  reported as a filesystem write, and no longer produces a `readOnlyHint` conflict.
- `scripts/validate_release.py` drops the containment groups and grows its
  capability-visibility and benign coverage: 108 checks, including the routes that
  previously denied a capability and the in-memory shapes that previously invented
  one.
- No change to the exit-code contract, the no-execution invariant, the resource
  limits, the SARIF schema, or the snapshot digest payload.


## 0.2.4 - never published

Superseded by 0.2.5 before release. A fifth pre-release audit obtained exit `0`
with completeness `complete` on real traversal four ways, and found the outcome
still decided by parameter name. The changes below shipped as part of 0.2.5.


Rewrites the `MSC103` containment model. 0.2.2 and 0.2.3 were never published.

Containment was a mark that spread: a check set a flag and every propagation rule
had to remember not to carry it. Each rule that was touched got that wrong in a
different way, so three consecutive releases oscillated - 0.2.1 too permissive,
0.2.2 too strict, 0.2.3 permissive again through new mechanisms. Containment is now
a fact that must be proven to survive each step, and the default is that it does
not.

- A containment check establishes nothing when its failure can be swallowed. A
  `relative_to` inside a `try` whose handler continues, or inside
  `contextlib.suppress`, no longer clears the sink - that handler is reached
  precisely when the check fails. An exception handler now starts from the try
  body's bindings without the proofs that body established, because it can be
  entered from any point in the body including the check itself.
- Containment no longer transfers to derived values. It survives pure normalization
  (`resolve`, `absolute`) and rebinding, and is dropped by anything that adds a path
  component or changes the root, so `t / ".." / "etc" / "passwd"`,
  `t.joinpath(...)`, and `t.expanduser()` are unguarded again after `t` is proven
  contained. `_derived` now requires containment preservation to be declared per
  derivation and defaults to dropping it.
- Stores through a call now fail closed regardless of spelling.
  `d.__setitem__(k, p)`, `operator.setitem(d, k, p)`, `heapq.heappush(q, p)`, and
  `deque.appendleft(p)` degrade the audit exactly as `d[k] = p` already did, instead
  of silently discarding the value. Any unfollowable call that receives tool input
  and discards its result records an escape rather than being allowlisted by name.
- Escapes are reported only when the tool has a modeled filesystem capability or a
  path-shaped parameter. 0.2.3 failed audits of tools that never open a file for
  storing a parameter in a dict, which is one of the most common lines in Python.
- Fixed an unhandled `LookupError` for a declared codec that exists but is not a
  text encoding (`rot13`, `base64`, `hex`, `bz2`, `zlib`, `quopri`, `uu`). CPython
  raises it from `tokenize.detect_encoding` rather than from `.decode`, so a crafted
  coding cookie crashed the audit with exit `1` and no output - which the exit
  contract defines as "complete, findings at threshold". Present since 0.1.2 and
  live in published 0.2.1.
- `scripts/check_action_pin.sh` gained a release-time mode that compares the
  README's pinned commit's `action.yml` against the release. 0.2.3 documented a pin
  whose action predated the `--` pip hardening its own notes advertised.
- `scripts/validate_release.py` grew to 129 checks, adding defeated-guard and
  untracked-store groups. Against the unfixed 0.2.3 build it now fails 17 checks; it
  previously passed that build 107/107.
- README, `docs/architecture.md`, and `docs/limitations.md` now describe the model
  the code implements. The previous text asserted that guards intersect at joins,
  which had not been true since 0.2.3.
- Fixed a capability vanishing entirely when a path reached a filesystem call by a
  route the analyzer did not model. A path returned from a local helper, taken out
  of a container, or handed to a callback produced `Observed: none` under a
  `complete` audit - an arbitrary caller-controlled write reported as a tool with no
  capabilities at all. Present in 0.2.1 and every unpublished release since.
- Added `visit_While` to the path-flow visitor. A containment check inside a loop
  body that may never execute was kept unconditionally; every other construct
  already merged against the not-taken path.
- A `finally` block containing `return`, `break`, or `continue` now drops what the
  try body proved, because such a transfer discards an in-flight exception exactly
  as `except: pass` would.
- An `assert` no longer establishes containment; `python -O` strips it.
- An escape is recorded for a method call on a local object whether or not its
  result is bound. `d.__setitem__(k, p)` degraded the audit while
  `x = d.__setitem__(k, p)` did not, and binding the result is the realistic form
  for `pool.submit(...)`.
- `target.parent`, `target.glob`/`iterdir`/`rglob` children, and
  `target.with_suffix(...)` preserve containment. Requiring proof to survive every
  derivation had made the shapes MSC103's own remediation recommends - validate a
  directory then iterate it, validate a file then write beside it - report as
  unconstrained. `with_name` is excluded: its argument can contain separators.
- `scripts/validate_release.py` now asserts why a case was reported, not merely that
  the exit was non-zero, and requires the fixture to have been analyzed at all. The
  previous gate was satisfied 90/129 by a stub that only ever exited `2`; the
  hardened gate fails 100 of 146 against that same stub. Grown to 146 checks with
  capability-visibility cases and every reproduction from the fourth audit.
- No change to the exit-code contract, the no-execution invariant, the resource
  limits, the SARIF schema, or the snapshot digest payload.


## 0.2.3 - never published

Superseded by 0.2.4 before release. A pre-release audit found the guard model
cleared real traversal through three mechanisms and its escape reporting failed
ordinary servers. The changes below shipped as part of 0.2.4.


Closes the path-taint gaps that 0.2.2 left open, and the false positive 0.2.2
introduced. 0.2.2 was never published.

- Fixed generator expressions hiding every capability inside them. Both visitors
  read only the first iterable, so a call in the element expression was never
  observed: `"".join(subprocess.check_output(cmd, shell=True) for _ in ...)` on a
  `readOnlyHint=true` tool reported `Side effects: 0`, `Observed: none`,
  `complete`, exit `0` - an affirmative denial of a capability the tool has. Both
  now use the same traversal already used for list, set, and dict comprehensions.
- Fixed taint being dropped for assignment targets the analyzer does not track.
  `_assigned_names` returned nothing for subscript and attribute targets, so
  `_assign` bound nothing and the fail-closed path added in 0.2.2 never engaged.
  Storing tool input in `d["k"]`, `obj.attr`, or a `global` now records an escape,
  degrading the audit to `partial` with an `MSC103-LINEAGE-UNPROVEN` notification.
- Added `match` statement capture binding, so `case str() as target:` carries the
  subject's taint instead of losing it.
- Added container mutation tracking: `queue.append(path)` taints `queue`, so a
  later `queue[0]` reaching a filesystem call is reported.
- Fixed a false positive introduced by 0.2.2's union-at-join. A branch that
  rebinds a name to an untainted value no longer dissolves the guard established
  by the branch that carries the taint, so the canonical containment idiom - guard
  in `try`, fixed path in `except` - is clean again.
- Fixed a longer-standing guard gap: `target.resolve().relative_to(ROOT)` now
  establishes containment for `target` itself. Guarding only the normalized
  temporary reported correct containment code as unconstrained, in 0.2.1 and
  earlier as well.
- `action.yml` passes `--` to `pip install`, so a package value beginning with a
  dash cannot be parsed as a pip option.
- The documented workflow now sets the scanner `version` explicitly rather than
  inheriting it from the pinned commit's `action.yml`. A pinned SHA carries
  whatever version was current when it was written, which silently tied users to
  an older scanner. A unit test and `scripts/check_action_pin.sh`, now run in CI,
  fail the build when the documented version drifts from the release.
- Added `scripts/validate_release.py`: 107 behavioural checks against an installed
  wheel covering path lineage, execution sinks, benign servers, the no-execution
  invariant, hostile input, output forgery, exit codes, and SARIF.
  `scripts/preflight.sh` builds a wheel, installs it in a throwaway environment,
  and runs them.
- No change to the exit-code contract, the no-execution invariant, the resource
  limits, the SARIF schema, or the snapshot digest payload.


## 0.2.2 - never published

Superseded by 0.2.3 before release. A pre-release audit found it did not close the
failure class it was written to close: generator expressions hid every capability
inside them, and storing tool input in a subscript, an attribute, a `match`
capture, or a module global dropped the taint silently, so a `readOnlyHint=true`
tool doing unrestricted caller-controlled I/O still reported `complete`, no
findings, exit `0`. Its claims "None returns a clean result" and "No new false
positives were found" were both wrong. The changes below shipped as part of 0.2.3.


Second correctness patch for filesystem-scope analysis, plus process and
dynamic-code sink coverage. Required for anyone relying on a clean 0.2.1 result.

- Fixed path-taint propagation. 0.2.1 fixed which parameters were seeded into the
  filesystem dataflow but not how taint propagated, so one ordinary string
  operation still laundered a caller-controlled path into a clean audit:
  `open(path.strip("/"))` produced completeness `complete`, no findings, and exit
  `0`. Taint now propagates through `%` formatting, `.format`, `.join`,
  `os.sep.join`, `posixpath.join`, the string-deriving method family
  (`.strip`/`.lstrip`/`.rstrip`/`.replace`/`.removeprefix`/`.removesuffix`/
  `.encode`/`.decode` and peers), `urllib.parse.unquote`, subscripting, slicing,
  conditional expressions, walrus bindings, container literals, starred arguments,
  and tuple unpacking.
- Fixed control-flow joins. The join previously intersected bindings, so
  `try:`/`except:` assignment, a `for` loop that may not execute, and augmented
  assignment silently untainted a value. Taint now unions across joined branches
  and guards intersect: a value tainted on any reachable branch is tainted after
  the join, and a guard survives only when every joined branch established it.
- Unfollowed path lineage now fails closed. An expression form outside the model
  no longer clears the value; the sink is reported as `MSC103-LINEAGE-UNPROVEN`,
  the audit becomes `partial`, and the exit status is `2`. `MSC103` itself is
  withheld there because the rule asserts a path is unguarded, which cannot be
  claimed about lineage that was not followed.
- Expanded `MSC106` process sinks to `os.exec*`, `os.spawn*`, `os.posix_spawn*`,
  `os.fork`, `os.forkpty`, `os.startfile`, `pty.spawn`, `pty.fork`, `pty.openpty`,
  and `multiprocessing.Process`. A tool declaring `readOnlyHint=true` and calling
  `pty.spawn` previously reported `Observed: none` and exit `0`, affirmatively
  denying a capability it had.
- Expanded `MSC107` dynamic-code sinks to `compile`, `runpy.run_path`,
  `runpy.run_module`, `code.interact`, `code.InteractiveInterpreter`, and
  `types.FunctionType`.
- Documented that sink coverage is an allowlist for every capability, not only
  network. `Observed: none` means none that are modeled.
- No change to the exit-code contract, the no-execution invariant, the resource
  limits, the SARIF schema, or the snapshot digest payload. Expect materially more
  findings and more `partial` results on unchanged source; both are corrections.


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

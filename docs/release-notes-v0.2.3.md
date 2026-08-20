# MCP ScopeCheck v0.2.3

Correctness release for tool identity, control-flow bindings, and local-call
classification. Upgrading is recommended before relying on a clean v0.2 audit.

## What changed

**Registered tools retain their exact function body.** Python decorators receive a
function object when its definition executes. If a module later defines another
function with the same Python name, that later global binding does not change the
function object already registered as an MCP tool. ScopeCheck previously keyed tool
roots only by file and function name, so the later definition replaced the earlier
analysis root. A registered tool reaching process execution could consequently
report `Observed: none`, completeness `complete`, no findings, and exit `0`.

Tool registrations are now bound to the exact parsed function record. Name-based
resolution remains in place for calls made through module globals, matching Python's
runtime lookup behavior after module initialization.

**Ambiguous control-flow bindings fail closed.** Static `True` and `False` branches
are selected without executing target code. Other `if`, loop, `try`/`except`,
`except*`, and `match` paths are joined conservatively for imports, proven paths,
network clients, and nested functions. If those paths disagree and the ambiguous
name is called from reachable code, the completeness ledger reports an
`ambiguous control-flow binding`, the audit is partial, and the CLI exits `2`.

The conservative join includes loop-carried values and abrupt exits, exception
prefixes, exception-suppressing context managers, sequential `except*` handlers,
failed match-guard side effects, loop-carried tests, short-circuit and conditional
expressions, chained comparisons, and enclosing-scope assignment expressions.
Structured assignments that contain an imported module, path, client, class, or
helper also fail closed instead of dropping the tracked value. These paths
previously had spellings where a later benign assignment erased a reachable
dangerous binding and produced a complete clean result.

This closes complete-clean results for supported sinks reached through imports in
compound statements. It does not claim path-sensitive program analysis or infer a
capability when the target cannot be justified.

**Local calls take precedence over sink spelling.** A call resolved to a same-file
or in-root helper is no longer classified merely because its name is also a modeled
built-in or third-party sink. For example, a benign local function named `eval` is
analyzed as local code instead of producing `MSC107`. If that helper actually calls
the built-in `eval`, the reachable built-in call is still reported.

**Definition-time behavior and unsupported dispatch stay visible.** Modeled sinks
in a tool's defaults, decorators, and non-deferred annotations are analyzed at the
bindings that existed when the definition was encountered. Definition-time local
helper calls, decorated reachable helpers, direct local-class dispatch, and nested
callbacks or callable expressions now enter the unresolved ledger rather than
trusting a raw function body or omitting the edge. This makes the result partial
when runtime transformation or dispatch cannot be justified statically. Direct
helpers that write declared `global` or `nonlocal` bindings likewise fail closed
because caller binding state is not propagated across a helper edge.

**Binding analysis is resource-bounded.** Unchanged import environments reuse an
immutable snapshot, branch joins stream rather than retaining every full state, and
250,000 copied or compared binding entries per module or reachable function is a
hard fail-closed limit. This prevents compact adversarial source from expanding
into hundreds of megabytes of binding maps.

## Security and compatibility

The target remains untrusted data and is never imported, executed, installed,
built, or started. The release adds no runtime dependency and makes no network or
LLM call during an audit.

There is no change to the seven-rule catalogue, SARIF schema, finding fields, or
exit-code contract. The new binding-work resource limit uses the existing failed
analysis/exit-`2` contract. Some previously clean audits may now exit `2`
when a reachable call depends on a control-flow-ambiguous binding. False `MSC107`
findings caused only by a proven local helper named `eval` are removed.

## Verification

The source suite includes regressions for each corrected behavior and retains the
top-level side-effect test proving target code does not run. Release preflight runs
Gitleaks, the complete unit suite, compilation, Ruff, strict mypy, both distribution
builds, installed-wheel behavioral validation, and action/version pin checks.

See [limitations](limitations.md) for the bounded analysis model and known blind
spots.

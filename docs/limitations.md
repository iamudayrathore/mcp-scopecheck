# Limitations

MCP ScopeCheck v0.2.3 performs bounded Python AST analysis over a local file or
directory. It never imports or executes audited source, starts an MCP server,
installs target dependencies, or inspects installed packages.

## Meaning of complete and clean

`complete` means that supported registrations and reachable project-local calls
were analyzed within the documented syntax and resource limits. It does not mean
that every behavior possible at runtime was modeled. A clean exit `0` additionally
means that no finding met the configured threshold. Neither state proves that a
server is safe.

`partial` means ScopeCheck recognized a reachable local edge or potential tool
registration that it could not analyze without guessing. `failed` means source,
filesystem, parser, encoding, or resource-budget failure prevented a trustworthy
bounded result. Both states exit `2`; findings already supported by evidence are
still reported.

## Supported local calls

Cross-module resolution is limited to static relative or absolute in-root Python
imports, direct imported functions and aliases, qualified local-module function
calls, and one explicit named `__init__.py` re-export. A target must resolve to
exactly one accepted source file and one module-level function. Cycles terminate
through visited-state tracking.

The following remain unresolved and make relevant analysis partial when they are
statically recognizable:

- class and instance dispatch;
- callbacks, closures, lambdas, partials, assigned function aliases, and other
  higher-order calls;
- direct helpers that write a declared `global` or `nonlocal` binding;
- wrapper or decorator transformations;
- wildcard and dynamic imports;
- ambiguous or missing local targets and deeper re-export chains;
- runtime, low-level Tool-list, `add_tool`, nested, and class-owned registration
  forms.

Definition-time calls through project-local helper names are also unresolved. A
later definition can reuse the same module name, so the final name table does not
prove which function object a default, decorator, or annotation called while the
tool was being defined. Direct modeled sinks in these expressions are still
reported. Annotations are not evaluated when `from __future__ import annotations`
defers them.

## Rule boundaries

Cross-module capability facts can inform `MSC101`, `MSC102`, `MSC106`, `MSC107`,
and `MSC108`. `MSC105` remains same-function. v0.2.3 does not implement
cross-module environment-to-network taint or general interprocedural data flow.

Sink coverage is an allowlist for **every** capability, not only network.
Filesystem, process, and dynamic-code sinks are modeled sets of APIs, and an API
outside a set is not reported at all - the tool will state `Observed: none` for a
capability it does not model. v0.2.3 covers `subprocess.*`,
`asyncio.create_subprocess_*`, `os.system`/`popen`/`startfile`, `os.exec*`,
`os.spawn*`, `os.posix_spawn*`, `os.fork`/`forkpty`, `pty.spawn`/`fork`/`openpty`,
and `multiprocessing.Process` for process execution, and `eval`, `exec`,
`compile`, `runpy.run_path`/`run_module`, `code.interact`/`InteractiveInterpreter`,
and `types.FunctionType` for dynamic code. Execution reached through `ctypes`, a
C extension, or any other unmodeled route is not detected. Releases before 0.2.2
modeled only `subprocess.*`, `asyncio.create_subprocess_*`, `os.system`,
`os.popen`, `eval`, and `exec`.

**Filesystem containment is not analyzed.** `MSC103` and `MSC104` were withdrawn
in 0.2.2. They decided whether caller-controlled filesystem access was constrained,
and did so incorrectly across four consecutive release candidates in alternating
directions: too permissive, then too strict, then permissive again through new
mechanisms, and finally still gated on whether a parameter was named `path` rather
than `title`. Each fix was correct for the case that motivated it and the class
survived.

What remains is sound and is what ScopeCheck now reports: a tool reaches a
filesystem operation, and here is the call path to it. Whether the path is
contained beneath an intended root is left to the reader. Do not infer from a clean
audit that a tool's filesystem access is bounded — ScopeCheck does not evaluate
that, and says so rather than guessing.

Restoring these rules requires path-aware dataflow that can express "this value is
provably beneath this root" across control flow and derivation, rather than the
token-set model that failed. That is a design change, not a patch.

Capability detection is itself bounded, and `Observed: none` means "none that were
modeled", not "none". A path reaching a filesystem call through a route outside the
model - a class method, a module-level singleton, a callback the analyzer cannot
follow - may not be reported at all. Do not read `Observed: none` as a guarantee.

A path stored in a container and retrieved by subscript is **not tracked**:
`paths["docs"].read_text()` reports no capability. Whether `D[k]` holds a path is
not knowable statically here, and every attempt to have it both ways produced a
verdict that changed with the spelling - treating a subscript as a path invented
filesystem writes on in-memory caches, and gating that on method names made
`D[k].touch()` and `entry = D[k]; entry.touch()` disagree. This is a bounded false
negative, preferred to an unbounded false positive on ordinary code, and it is
pinned by a test so it cannot change silently.

Control-flow handling is a bounded binding analysis, not path-sensitive execution.
Literal boolean branches are selected statically. At modeled `if`, loop,
`try`/`except`, `except*`, and `match` joins, a binding used as a reachable call
target is resolved only when the analyzed paths agree; disagreement is reported as
an unresolved edge and makes the audit partial. Loop-carried writes, `break` and
`continue` prefixes, exception prefixes, exception-suppressing context managers,
sequential `except*` handlers, and side effects from failed match guards are kept
ambiguous until a definite later assignment replaces them. Conditional values,
short-circuit boolean expressions, chained comparisons, loop-carried tests, and
comprehension assignment expressions use the same conservative join. Assigning an
imported module or local class/helper object to another name is treated as
unresolved aliasing rather than a proven direct binding. This does not prove which
runtime path executes or infer the capability of an ambiguous receiver.

Binding-state copying and comparison is limited to 250,000 work entries per module
or reachable function. Exceeding that bound makes the audit incomplete with exit
`2`; unchanged import environments reuse one immutable snapshot rather than one
full map per AST event.

For the same reason `str(path)` yields a string, not a path: `str.replace` and
`Path.replace` share a name, and the latter renames a file.

`MSC001` matches deterministic wording families, and those families differ in
precision. Unambiguous directive families are Critical. The `credential-handling
instruction` and `cross-call instruction` families are High because the same
wording appears in honest descriptions of credential, authentication, and
workflow tools. The `concealment instruction` family is Critical but can fire on a
prohibition phrased as a safety guarantee. `MSC001` has not been benchmarked for
precision or recall against a large corpus of real tool descriptions; the bundled
corpus is a regression fixture. A lone `MSC001` finding warrants reading the
description, not an automatic rejection.

Capabilities are evidence, not automatic vulnerabilities. ScopeCheck does not
prove authorization correctness, SSRF safety, SQL safety, shell safety, symlink
safety, time-of-check/time-of-use safety, or runtime policy enforcement. Network
and filesystem sink coverage is deliberately allowlisted and incomplete: egress
through unmodeled clients (for example `pycurl`, `smtplib`, `ftplib`, `websockets`,
or DNS resolvers) is not detected, so `MSC102` cannot review it.

`MSC102` is an external-egress review signal for modeled network sinks. Neither
description prose nor a matching service hostname suppresses it, and no modeled
external destination is treated as a clean pass; the only exemption is a
destination classified as local, loopback, or private
(`localhost`/loopback/RFC1918/IPv6 ULA, by explicit IP-address parsing). Those
local/loopback/private destinations remain visible as observed network
capabilities but do not produce an `MSC102` finding. That exemption is a
precision choice, not a safety judgment: egress to local, loopback, or private
addresses can still be security-relevant — local proxies, lateral movement,
access to internal services, or SSRF-style behavior — and may warrant human
review even without an `MSC102` finding.

## Language and output boundaries

Only Python 3.11+ syntax is supported. JavaScript, TypeScript, manifests, package
metadata, dependency internals, and running services are outside the analyzer.
Plain text and SARIF expose the same findings and completeness state; SARIF
execution notifications are not vulnerability findings.

The v0.2 design was informed by a curated 15-repository corpus containing 420
statically visible tools, of which v0.1.2 discovered 377. These measurements are
bounded design evidence, not ecosystem-wide precision, recall, or prevalence
claims.

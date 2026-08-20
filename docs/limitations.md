# Limitations

MCP ScopeCheck v0.2.4 performs bounded Python AST analysis over a local file or
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
- wrapper or decorator transformations;
- wildcard and dynamic imports;
- ambiguous or missing local targets and deeper re-export chains;
- runtime, low-level Tool-list, `add_tool`, nested, and class-owned registration
  forms.

## Rule boundaries

Cross-module capability facts can inform `MSC101`, `MSC102`, `MSC106`, `MSC107`,
and `MSC108`. `MSC103` requires supported argument lineage and recognized guard
state across the path. Suppression is per sink and applies only when unresolved
work could own that sink's guard: wrapper/decorator indirection, or an unresolved
call that actually receives the path value. Unrelated unresolved calls elsewhere
in the tool no longer suppress the rule, and incompleteness is still reported. `MSC105` remains same-function. v0.2.4 does not implement
cross-module environment-to-network taint or general interprocedural data flow.

Sink coverage is an allowlist for **every** capability, not only network.
Filesystem, process, and dynamic-code sinks are modeled sets of APIs, and an API
outside a set is not reported at all - the tool will state `Observed: none` for a
capability it does not model. v0.2.4 covers `subprocess.*`,
`asyncio.create_subprocess_*`, `os.system`/`popen`/`startfile`, `os.exec*`,
`os.spawn*`, `os.posix_spawn*`, `os.fork`/`forkpty`, `pty.spawn`/`fork`/`openpty`,
and `multiprocessing.Process` for process execution, and `eval`, `exec`,
`compile`, `runpy.run_path`/`run_module`, `code.interact`/`InteractiveInterpreter`,
and `types.FunctionType` for dynamic code. Execution reached through `ctypes`, a
C extension, or any other unmodeled route is not detected. Releases before 0.2.2
modeled only `subprocess.*`, `asyncio.create_subprocess_*`, `os.system`,
`os.popen`, `eval`, and `exec`.

Path taint propagates through ordinary construction and through control-flow
joins, and fails closed when it cannot. An expression form outside the modeled
set does not clear the value: the sink is recorded as `MSC103-LINEAGE-UNPROVEN`,
the audit becomes partial, and the exit status is `2`. `MSC103` is withheld in
that case because the rule asserts a path is *unguarded*, which cannot be claimed
about lineage that was not followed. Releases before 0.2.2 dropped such taint
silently and could report `complete` with no findings and exit `0` for a tool
performing unrestricted caller-controlled file access.

Guard recognition is deliberately narrow, and narrow in the safe direction. A
containment proof is established only by a recognized check whose failure path
cannot be swallowed, and is dropped by any derivation that adds a component or
changes the root. Correct code using an unrecognized guard form - a literal
allowlist, or `realpath` plus `startswith(root + os.sep)` - is therefore reported.
That is a false positive, and it is preferred over the alternative: a guard model
that spreads optimistically reported real traversal as clean in 0.2.1, 0.2.2, and
0.2.3 by three different mechanisms.

A path that reaches a filesystem call through a route the analyzer does not model
- returned from a local helper, taken out of a container, handed to a callback -
is reported as incompleteness rather than silently omitted. Releases before 0.2.4
reported `Observed: none` for such tools, denying a capability they have.

Lambda bodies are not visited, and a tool whose only capability is inside a lambda
is currently reported as `complete` rather than `partial`. A module-level instance
of a same-file class (`_runner = Runner()` then `_runner.run(x)`) is likewise not
recorded as an unresolved edge. Both are known gaps where the analysis is not
fail-closed.

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

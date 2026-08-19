# MCP ScopeCheck v0.2.0

This trust-first reachability release analyzes more project-local Python behavior
without silently implying that unsupported behavior was checked. It retains the
non-executing AST boundary and adds no runtime dependency.

## Analysis completeness

Every report now carries one of three states:

- `complete`: supported registrations and reachable local edges resolved within
  the bounded model;
- `partial`: a recognizable local edge or potential MCP registration remained
  unsupported; or
- `failed`: source, parser, filesystem, encoding, or resource-budget failure
  prevented a trustworthy bounded result.

Exit `0` means complete with no threshold finding, exit `1` means complete with a
threshold finding, and exit `2` takes precedence for partial or failed analysis.
Supported findings remain visible in partial or failed reports.

The text report lists resolved and unresolved local edges with source, line,
caller, call expression, candidate, and a stable reason. It also counts supported
and unresolved registration forms. Static low-level Tool lists, `add_tool`, and
nested/class-owned registrations are detected as unsupported rather than claimed
as analyzed.

## Bounded local reachability

v0.2.0 follows:

- relative and absolute imports that resolve uniquely to accepted source inside
  the audit root;
- direct imported-function calls and aliases;
- qualified local-module function calls;
- one explicit named `__init__.py` re-export; and
- module cycles with visited-state protection.

Filesystem read/write, environment read, network egress, process execution, and
dynamic-code capabilities propagate along those supported edges. Each capability
retains a shortest path from registered tool to sink.

Class/instance methods, callbacks, closures, lambdas, partials, wrappers,
higher-order dispatch, dynamic/wildcard imports, installed packages, ambiguous
targets, and deeper re-exports are not resolved. They are reported as incomplete
when relevant and recognizable.

## Conservative rule consumption

`MSC101`, `MSC102`, `MSC106`, `MSC107`, and `MSC108` may consume unambiguous
cross-module capability facts. `MSC103` requires supported path lineage and guard
state across the traversed calls; otherwise the inference is suppressed and the
report explains the incompleteness. `MSC105` remains same-function. This release
does not implement cross-module taint or general interprocedural data flow.

## SARIF 2.1.0

Use:

```bash
mcp-scopecheck audit path/to/server --format sarif
```

SARIF stdout remains valid JSON for exits `0`, `1`, and `2`. Security and contract
findings are SARIF results. Diagnostics, unresolved edges, unsupported
registrations, and budget failures are tool execution notifications rather than
vulnerability findings. See [SARIF output](sarif.md) for field details and a
SHA-pinned GitHub code-scanning example.

## Curated-corpus acceptance

The private, pinned 15-repository design corpus contained 420 statically visible
tools. v0.2.0 retained discovery of 377/420 supported decorator tools and exposed
all 43 unsupported registration gaps as incomplete rather than silent. Four
formerly clean reports with manually observed unresolved local behavior no longer
return clean exit `0`, and four repositories gained meaningful cross-module
capability visibility.

On this corpus v0.2.0 reports the six confirmed process-execution detections
(`MSC106`) plus eleven `MSC102` network-egress flags — every reachable-egress tool
in the corpus (eight in a Google Workspace server, two in a YouTube server, and one
`aiohttp` documentation lookup in a Redis server). Each builds its request URL
through a client library or an interpolated string, so the destination is not a
plain string literal ScopeCheck's endpoint extractor can read, and the tool is
flagged for review rather than trusted. `MSC102` cannot be suppressed by a tool's
prose by design, and no reachable external destination is treated as a clean pass
even when the description names a matching service — a service host can serve
attacker-controlled content indistinguishable by hostname. The eleven flags are
the deliberate recall-over-precision consequence of that choice, not missed egress;
each names a genuinely reachable network call whose destination ScopeCheck cannot
verify. These are curated-corpus observations, not ecosystem-wide precision or
recall claims.

## Compatibility and limits

Python 3.11, 3.12, and 3.13 remain supported. Plain text remains the default.
The package has no runtime dependencies and audits make no network call. A clean
report means complete within the documented bounded model; it is not proof of
runtime safety. See [limitations](limitations.md).

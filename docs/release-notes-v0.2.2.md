# MCP ScopeCheck v0.2.2

> **Publication note:** v0.2.2 was tagged in GitHub but was not published to
> PyPI. Its changes first became installable from PyPI in v0.2.3.

Withdraws `MSC103` and `MSC104`, and fixes a crash on crafted source encodings.

**If you are on 0.2.1, upgrading changes what this tool claims.** Read the first
section before you rely on a clean result from either version.

## What 0.2.1 got wrong

`MSC103` and `MSC104` decided whether a tool's caller-controlled filesystem access
was *constrained* — whether a supplied path could escape an intended root. They did
so by matching the parameter's **name** against a fixed list. A traversal through a
parameter named `filepath`, `target`, `title` or `name` was not analyzed at all, and
the audit reported:

```console
$ mcp-scopecheck audit ./server
  Completeness: complete
Findings (0)
$ echo $?
0
```

for a tool performing unrestricted caller-controlled file reads and writes. Exit `0`
with completeness `complete` is this tool's strongest statement, and it was wrong.

Four successive attempts to fix the rule failed in alternating directions — too
permissive, then reporting correct containment code as unsafe, then permissive again
through new mechanisms. Each fix was right for the case that prompted it; the class
survived every time. The underlying model could not express *"this value is provably
beneath this root"* across Python's control flow.

**So the rules are withdrawn rather than patched.** A rule that cannot decide a
property reliably should not claim to.

## What that means for you

ScopeCheck still reports **that** a tool reaches a filesystem operation, and the call
path to it:

```
    Observed:    filesystem_write
    Evidence:    filesystem_write: write_note (server.py:12) -> _resolve (server.py:6)
                 -> path.write_text (server.py:7)
```

It no longer reports whether that path is contained. **A clean audit is not evidence
that a tool's filesystem access is bounded** — read the evidence trace and judge it
yourself. The [5-S pre-install checklist](review-checklist.md) covers what to look
for.

Seven rules remain: `MSC001`, `MSC101`, `MSC102`, `MSC105`, `MSC106`, `MSC107`,
`MSC108`.

Expect **fewer findings** than 0.2.1 on the same source. That is not approval of your
code; it is the tool declining to give an opinion it could not support.

## Also fixed

**A crash on crafted source encodings.** A declared codec that exists but is not a
text encoding (`rot13`, `base64`, `hex`, `bz2`, `zlib`, `quopri`, `uu`) raised an
unhandled exception, producing exit `1` with no output — which the exit contract
defines as "complete, findings at threshold". A workflow branching on the exit code
read a crash as a scan result, and SARIF output was empty despite the documented
promise that stdout is JSON on every nonzero exit. Present since 0.1.2 and live in
0.2.1.

**Capability reporting no longer depends on how code is spelled.** A path built
inside a local helper, or reached through a chain of calls, is now observed rather
than silently dropped; and semantically identical code no longer produces different
verdicts depending on whether it was written on one line or two.

**A path stored in a container and retrieved by subscript is not tracked** —
`paths["docs"].read_text()` reports no capability. This is a deliberate, bounded
blind spot, documented in [limitations](limitations.md) and pinned by tests, chosen
over a heuristic that invented filesystem capabilities on ordinary in-memory code.

## Verification

`scripts/validate_release.py` runs 164 behavioural checks against an installed wheel
— path routes, execution sinks, benign servers, the no-execution invariant, hostile
input, output forgery, exit codes and SARIF. `scripts/preflight.sh` builds a wheel,
installs it in a throwaway environment and runs them, so it gates the release rather
than depending on anyone remembering.

Read a green run as *nothing regressed in the shapes enumerated*, not as evidence of
correctness. The gate is checked against builds that do not analyze at all: a
pattern-matcher that hashes source text scores 130/164, a print-and-exit stub 55/164.
Those describe the two fakes that were built, not a bound.

Unit suite: 171 tests.

## Compatibility

No change to the exit-code contract, the no-execution invariant, the resource limits,
the SARIF schema, or the snapshot digest payload. `MSC103` and `MSC104` no longer
appear in the SARIF rule catalogue.

## Known limitations

See [limitations](limitations.md) in full. In brief: containment is not analyzed;
`Observed: none` means "none that were modeled"; sink coverage is an allowlist for
every capability; lambda bodies and module-level instance dispatch are not followed;
`MSC001` is deterministic pattern matching and has not been benchmarked.

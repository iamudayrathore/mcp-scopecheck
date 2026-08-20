# MCP ScopeCheck v0.2.2

> **This version was never published.** A pre-release audit found that it did not
> close the failure class it was written to close, and two of the claims below are
> wrong: "None returns a clean result" and "No new false positives were found".
> Generator expressions hid every capability inside them, and storing tool input in
> a subscript, an attribute, a `match` capture, or a module global dropped the taint
> silently. The count "All 15 process and dynamic-code primitives" is also wrong -
> the same paragraph names 16. Superseded by
> [v0.2.3](release-notes-v0.2.3.md), which closes those gaps and pins every claim to
> a check in the repository. Retained for the record.

Second correctness patch for filesystem-scope analysis, plus process and
dynamic-code sink coverage. **Upgrading is required for anyone relying on a clean
0.2.1 result.**

## Why this release exists

v0.2.1 fixed which tool parameters were *seeded* into the filesystem dataflow. It
did not fix how taint *propagated*. An independent pre-launch audit found that the
user-visible failure mode was still present: one ordinary string operation
laundered a caller-controlled path and produced a clean audit.

```python
@mcp.tool(annotations={"readOnlyHint": True})
def read_doc(path: str) -> str:
    """Read a bundled documentation file from the fixed docs root."""
    target = path.strip("/")
    return open(target).read()
```

```console
$ mcp-scopecheck audit ./server        # 0.2.1
  Completeness: complete
Findings (0)
$ echo $?
0
```

Twenty-four of twenty-six ordinary path-construction idioms behaved this way,
including `.replace("..", "")` and `.strip("/")` - the *broken* sanitizers a
scanner most needs to report.

`docs/release-notes-v0.2.1.md` said "A scanner whose central promise is that it
reports what it cannot prove must not go silent." It still went silent. That is
the defect this release closes, and the earlier claim of closure was wrong.

## What changed

**Taint propagates through ordinary path construction.** `%` formatting,
`.format`, `.join`, `os.sep.join`, `posixpath.join`, the string-deriving method
family (`.strip`, `.lstrip`, `.replace`, `.removeprefix`, `.encode`/`.decode` and
peers), `urllib.parse.unquote`, subscripting, slicing, conditional expressions,
walrus bindings, container literals, starred arguments, and tuple unpacking.

**Control-flow joins union taint and intersect guards.** Before 0.2.2 the join
*intersected* bindings, so `try: p = name / except: p = DEFAULT`, a `for` loop
that might not execute, and `root += name` all silently untainted the value. A
value tainted on any reachable branch is now tainted after the join; a guard
survives only when every joined branch established it.

**Unfollowed lineage fails closed.** An expression form outside the model no
longer clears the value. The sink is recorded, the audit becomes `partial`, the
exit status is `2`, and the completeness ledger names the location:

```
Notification MSC103-LINEAGE-UNPROVEN at server.py:9: filesystem scope was not
inferred for tool 'read_doc': tool input reaches open through an expression form
outside the supported model
```

`MSC103` is deliberately withheld there rather than reported. The rule asserts a
path is *unguarded*, and that assertion cannot be made about lineage the analyzer
did not follow. Incompleteness is the honest answer; silence was not.

**Process and dynamic-code sink coverage.** `MSC106` and `MSC107` are both
Critical, but their sink sets were four entries each. A tool declaring
`readOnlyHint=true` and calling `pty.spawn(["/bin/sh", "-c", cmd])` reported
`Side effects: 0`, `Observed: none`, `complete`, exit `0` - not merely a missing
rule, but an affirmative denial of a capability the tool has.

Now modeled: `os.exec*`, `os.spawn*`, `os.posix_spawn*`, `os.fork`, `os.forkpty`,
`os.startfile`, `pty.spawn`, `pty.fork`, `pty.openpty`, `multiprocessing.Process`,
and for dynamic code `compile`, `runpy.run_path`, `runpy.run_module`,
`code.interact`, `code.InteractiveInterpreter`, `types.FunctionType`.

**Sink coverage is now documented as an allowlist for every capability**, not just
network. README and `docs/limitations.md` state plainly that an unmodeled sink is
not reported and that `Observed: none` means "none that are modeled".

## Results

All 26 path-construction forms from the audit matrix: 22 now report `MSC103` and
exit `1`; the remaining 4 fail closed to `partial` and exit `2`. **None returns a
clean result.** All 15 process and dynamic-code primitives report their capability
and the corresponding Critical rule.

No new false positives were found: recognized guards still clear a constructed
path, string operations on data that never reaches a filesystem sink stay clean,
and a derived value written to a fixed path stays clean.

## Compatibility

No change to the exit-code contract, the no-execution invariant, the resource
limits, the SARIF schema, or the snapshot digest payload.

Expect **materially more** findings and materially more `partial` results on
unchanged source. A tool that previously exited `0` may now exit `1` because the
finding was always true, or `2` because the analysis was never complete. Both are
corrections, not regressions.

## Advisory

`GHSA-jx85-6p69-j94f` describes the pre-0.2.1 naming-based false negative. Its
patched version must read **0.2.2**, not 0.2.1: the class of failure it describes
was not fully closed until this release.

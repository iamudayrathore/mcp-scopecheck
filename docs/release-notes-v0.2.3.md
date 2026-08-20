# MCP ScopeCheck v0.2.3

Closes the path-taint gaps 0.2.2 left open, and the false positive 0.2.2
introduced. **0.2.2 was never published.**

Every number in this document is reproducible from the repository. That is
deliberate: the 0.2.2 notes cited a matrix that existed only in a scratch
directory, so a reader could not check them - and two of the claims were wrong.

## Why this release exists

A pre-release audit of 0.2.2 found the failure class it was written to close was
still open through two different paths.

**Generator expressions hid everything inside them.** Both visitors read only the
first iterable and never the element expression:

```python
@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": False})
def grep_docs(pattern: str) -> str:
    """Search the bundled documentation for a pattern and return matching lines."""
    return "".join(subprocess.check_output(pattern, shell=True).decode() for _ in range(1))
```

```console
  Side effects: 0 reachable capability site(s)
  Completeness: complete
    Observed:    none
Findings (0)                       # exit 0
```

That is the same output 0.2.2's own notes cite as the reason its process-sink work
was needed - reached through a different wrapper.

**Storing tool input where the analyzer does not track it dropped the taint.**
`_assigned_names` returned nothing for subscript and attribute targets, so
`_assign` bound nothing and the fail-closed path 0.2.2 added never engaged. Four
idioms produced `complete`, no findings, exit `0` for unrestricted caller-controlled
file reads: `request["target"] = path`, `obj.attr = path`, `match path: case str()
as target:`, and `global _PENDING`.

The dict case was the worst - the report showed `Observed: filesystem_read`,
correlated no parameter to it, and still asserted `complete`.

## What changed

**Generator expressions** now use the same traversal as list, set, and dict
comprehensions, on both the capability visitor and the path-flow visitor.

**Untrackable stores fail closed.** When a tainted value is assigned to a target
whose storage the analyzer does not model, it records an escape: the audit becomes
`partial`, the exit status is `2`, and the ledger names the location.

```
Notification MSC103-LINEAGE-UNPROVEN at server.py:12: filesystem scope was not
inferred for tool 'read_doc': tool input is stored in a location outside the
supported model (_PENDING)
```

**`match` captures and container mutation are now modeled.** `case str() as
target:` carries the subject's taint, and `queue.append(path)` taints `queue`, so a
later `queue[0]` reaching a filesystem call is reported.

**Two guard fixes.** 0.2.2's union-at-join let a branch that rebinds a name to an
untainted value dissolve the guard established by the branch carrying the taint, so
the canonical containment idiom was reported as unconstrained. And, since well
before 0.2.2, guarding a normalized temporary did not establish containment for its
receiver:

```python
target.resolve().relative_to(ROOT.resolve())   # proves containment
target.read_text()                             # ...was still reported
```

Both are clean now, and an unguarded join is still reported.

## Results

`scripts/validate_release.py` runs **107 checks against an installed wheel** - not
the source tree, so it exercises what users receive. All pass:

| Group | Checks | Property asserted |
| --- | ---: | --- |
| Path lineage | 34 | Never a clean result on caller-controlled input |
| Execution sinks | 46 | Capability reported, rule fires, never `Observed: none` |
| Benign servers | 8 | Correct code is not reported |
| No-execution invariant | 4 | Top level, decorator, class body, metaclass |
| Hostile input and limits | 6 | Fails closed to exit `2` |
| Output forgery | 4 | No control sequence reaches the stream |
| Exit-code contract | 3 | Thresholds behave as documented |
| SARIF | 2 | Valid on both findings and failure paths |

`scripts/preflight.sh` builds a wheel, installs it in a throwaway environment, and
runs them, so this is a release gate rather than something a maintainer remembers.
The unit suite is 194 tests.

## Supply chain

`action.yml` passes `--` to `pip install`, so a package value beginning with a dash
cannot be parsed as a pip option.

The documented workflow now sets the scanner `version` explicitly instead of
inheriting it from the pinned commit's `action.yml`. A pinned SHA carries whatever
version was current when it was written, so relying on that default silently ties a
user to an older scanner - for a security tool, one with known-missed detections,
presented as current. A unit test and `scripts/check_action_pin.sh`, now run in CI,
fail the build if the documented version drifts from the release.

## Compatibility

No change to the exit-code contract, the no-execution invariant, the resource
limits, the SARIF schema, or the snapshot digest payload.

Expect more findings and more `partial` results on unchanged source. A tool that
previously exited `0` may now exit `1` because the finding was always true, or `2`
because the analysis was never complete.

## Advisory

`GHSA-jx85-6p69-j94f` describes the pre-0.2.1 naming-based false negative. Its
patched version is **0.2.3**. It was not amended to name 0.2.1 or 0.2.2, because
the class it describes reproduced on both.

## Known limitations, unchanged

- Sink coverage is an allowlist for every capability. `multiprocessing.Pool`,
  `concurrent.futures`, and `ctypes` are not modeled; `Observed: none` means none
  that are modeled.
- `MSC103` still reports a literal-allowlist membership check and a `realpath` +
  `startswith(root + os.sep)` guard as unconstrained.
- `MSC001` does not inspect `Annotated[..., Field(description=...)]` parameter
  descriptions, which the host model also receives.
- `MSC001` has not been benchmarked for precision or recall.

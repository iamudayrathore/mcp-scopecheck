# MCP ScopeCheck v0.2.4

> **This version was never published.** A fifth pre-release audit obtained exit `0`
> with completeness `complete` on genuine traversal four separate ways - a path
> built inside a helper, a caller-controlled `glob` pattern escaping the proven
> root, a short-circuited guard, and `open(**kwargs)` - and showed the outcome was
> still decided by parameter name. Superseded by
> [v0.2.5](release-notes-v0.2.5.md), which withdraws `MSC103` and `MSC104` rather
> than patching them a fifth time. Retained for the record.

Rewrites the `MSC103` containment model. **0.2.2 and 0.2.3 were never published.**

## Why the model was rewritten rather than patched

Three consecutive releases got containment wrong, in alternating directions:

| Release | Failure |
| --- | --- |
| 0.2.1 (published) | Too permissive — traversal through an unusually named parameter reported clean |
| 0.2.2 (never published) | Too strict — the canonical `try`/`except` containment idiom reported as unconstrained |
| 0.2.3 (never published) | Too permissive again — a swallowed exception, and containment inherited by derived paths |

The cause was structural, not three separate oversights. Containment was represented
as a *mark that spreads*: a check added a token to a `guarded` set, and every
propagation rule had to remember not to carry that token forward. Each rule touched
got it wrong differently, so fixing one direction opened the other.

0.2.4 inverts the default. Containment is a **fact that must be proven to survive
each step**, and the default is that it does not:

- **Established** only by a recognized check whose failure cannot be swallowed.
- **Survives** pure normalization (`resolve`, `absolute`) and rebinding.
- **Dropped** by anything that adds a path component or changes the root, and by
  every derivation not explicitly declared to preserve it.

## What that fixes

**A swallowed exception establishes nothing.** The handler is reached precisely when
the check fails, so it now starts from the try body's bindings *without* the proofs
that body established:

```python
try:
    target = ROOT / name
    target.relative_to(ROOT)     # 0.2.3: counted as a guard
except ValueError:
    pass                         # ...reached exactly when it failed
return target.read_text()        # 0.2.3: complete, exit 0
```

Same for `contextlib.suppress(ValueError)`, which reaches the same result through a
different mechanism.

**Containment does not transfer to derived values.** Proving `t` is contained proves
nothing about `t / x`:

```python
t = ROOT / name
t.resolve().relative_to(ROOT)                 # proves containment of t
(t / ".." / ".." / "etc" / "passwd").read_text()   # 0.2.3: complete, exit 0
```

`joinpath` and `expanduser` behaved the same way — `expanduser` despite being
deliberately excluded from the normalization walk, because it inherited the proof
through a second path.

**The canonical idiom still passes.** A branch that rebinds the name to an untainted
value contributes no tainted lineage and does not dissolve the other branch's proof:

```python
try:
    target = ROOT / "sections" / (name + ".md")
    target.resolve().relative_to(ROOT.resolve())
except ValueError:
    target = ROOT / "index.md"    # untainted rebind
return target.read_text()          # clean, correctly
```

## Found by the fourth audit, fixed here

The guard rewrite held under 60 adversarial servers, but the audit found three
ways to reach a clean verdict that predate this release, and one that did not.

**A capability could vanish entirely.** A path returned from a local helper was
not recognised as a path, so the sink was never registered:

```python
def _pick(value):
    return value

@mcp.tool()
def write_note(name: str, body: str) -> str:
    """Save a note."""
    _pick(Path(name)).write_text(body)   # Observed: none, complete, exit 0
```

Arbitrary caller-controlled write, reported as a tool with no capabilities at
all. A call receiving a path may return one, so this now fails closed; the same
applies to a path taken back out of a container. A project-local function passed
as a callback is recorded as an unresolved edge rather than disappearing.

**Two guard forms could not constrain anything.** There was no `visit_While`, so
a check inside a loop that may never run was kept unconditionally; and `finally:`
containing `return` discards an in-flight exception, which the model did not know.
An `assert` used as a check is now ignored too, because `python -O` strips it.

**An escape depended on discarding the result.** `d.__setitem__(k, p)` degraded
the audit but `x = d.__setitem__(k, p)` did not, and binding the result is the
realistic spelling for `pool.submit(...)`. A method call on a local object now
records the escape either way.

**Three false positives on correct containment** came from making containment
harder to establish: `target.parent.mkdir(...)`, iterating `target.glob("*.md")`,
and `target.with_suffix(".bak")` after a proven check. All stay beneath a
validated root and are now preserving. `with_name` deliberately is not, because it
takes a caller-supplied name that can contain separators.

## Also fixed

**Untracked stores fail closed regardless of spelling.** `d[k] = p` already degraded
the audit; `d.__setitem__(k, p)`, `operator.setitem(d, k, p)`, `heapq.heappush(q, p)`
and `deque.appendleft(p)` did not. Rather than extending an allowlist of method
names, any unfollowable call that receives tool input and discards its result now
records an escape.

**Escapes are reported only when the tool touches the filesystem.** 0.2.3 failed
audits of tools with no filesystem capability at all for storing a parameter in a
dict — one of the most common lines in Python.

**Non-text codecs no longer crash the audit.** A declared codec that exists but is
not a text encoding (`rot13`, `base64`, `hex`, `bz2`, `zlib`, `quopri`, `uu`) raised
an unhandled `LookupError` from `tokenize.detect_encoding`, producing exit `1` with
no output — which the exit contract defines as "complete, findings at threshold".
Present since 0.1.2 and live in published 0.2.1.

**The release gate compares the pinned action.** 0.2.3's README documented a pin
whose `action.yml` predated the `--` pip hardening its own notes advertised, so every
user copying the workflow would have run an action without the fix.

## Results

`scripts/validate_release.py` runs **146 checks against an installed wheel**. All
pass. The differential matters more than the total:

| Build | Result |
| --- | ---: |
| 0.2.4 (this release) | **146 pass, 0 fail** |
| 0.2.4 before the final audit's findings | 134 pass, **12 fail** |
| 0.2.3 | 119 pass, **27 fail** |
| 0.2.1 published | 55 pass, **91 fail** |
| A stub that only ever exits `2` | 46 pass, **100 fail** |

That last row is the one that was missing. The previous gate asserted only that a
dangerous case produced a non-zero exit, so a build that had stopped analyzing
entirely would have satisfied 90 of its 129 checks. Cases now assert the *reason*:
the tool must actually be discovered, and the verdict must name the filesystem-scope
rule or its incompleteness notification. Asserting the wanted outcome instead of the
reason for it is the same blind spot that let three releases through.

| Group | Checks |
| --- | ---: |
| Path lineage | 34 |
| Defeated guards | 12 |
| Untracked stores | 8 |
| Capability visibility | 6 |
| Execution sinks | 46 |
| Benign servers | 14 |
| No-execution invariant | 8 |
| Hostile input and limits | 9 |
| Output forgery | 4 |
| Exit-code contract | 3 |
| SARIF | 2 |

Unit suite: 203 tests.

## Documentation

README, `docs/architecture.md`, and `docs/limitations.md` described guards
intersecting at control-flow joins, which had not been true since 0.2.3. They now
describe the model the code implements, including that guard recognition is narrow
in the safe direction: correct code using an unrecognized guard form is reported.
That is a false positive, and it is preferred to a model that spreads optimistically.

## Compatibility

No change to the exit-code contract, the no-execution invariant, the resource limits,
the SARIF schema, or the snapshot digest payload.

Expect more findings and more `partial` results than 0.2.1 on unchanged source.

## Advisory

`GHSA-jx85-6p69-j94f` names **0.2.4** as the patched version. It was not amended to
name 0.2.1, 0.2.2, or 0.2.3: the class it describes reproduced on all three by
different mechanisms, including through the capability-visibility gap closed here.

## Known limitations, unchanged

- Lambda bodies are not visited, and a tool whose only capability is inside one is
  reported `complete` rather than `partial`.
- A module-level instance of a same-file class is not recorded as an unresolved edge.
- Sink coverage is an allowlist for every capability; `multiprocessing.Pool`,
  `concurrent.futures`, and `ctypes` are unmodeled.
- `MSC103` reports literal-allowlist and `realpath` + `startswith` guards as
  unconstrained.
- `MSC001` does not inspect `Annotated[..., Field(description=...)]`, and has not
  been benchmarked for precision or recall.

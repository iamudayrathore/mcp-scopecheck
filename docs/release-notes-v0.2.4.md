# MCP ScopeCheck v0.2.4

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

`scripts/validate_release.py` runs **129 checks against an installed wheel**. All
pass. The number that matters more:

| Build | Result |
| --- | ---: |
| 0.2.4 (this release) | **129 pass, 0 fail** |
| 0.2.3 unfixed | 112 pass, **17 fail** |
| 0.2.1 published | 48 pass, **81 fail** |

The same gate passed the unfixed 0.2.3 build 107/107. The new defeated-guard and
untracked-store groups are what catch it, and every case in them is a reproduction
from an audit rather than a case invented alongside the fix — which is the specific
failure mode that let three releases through.

| Group | Checks |
| --- | ---: |
| Path lineage | 34 |
| Defeated guards | 9 |
| Untracked stores | 7 |
| Execution sinks | 46 |
| Benign servers | 11 |
| No-execution invariant | 4 |
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

`GHSA-jx85-6p69-j94f` should name **0.2.4** as the patched version. It was not
amended to name 0.2.1, 0.2.2, or 0.2.3: the class it describes reproduced on all
three by different mechanisms.

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

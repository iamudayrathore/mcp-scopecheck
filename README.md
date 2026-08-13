# MCP ScopeCheck

**Inspect before you connect.** MCP ScopeCheck is a pre-install static auditor that compares a Python MCP tool's declared contract with security-relevant behavior reachable from its source—without importing or running the server.

```console
$ mcp-scopecheck audit examples/unsafe_docs_server

[CRITICAL] MSC001 Agent-directed instruction in tool description
[CRITICAL] MSC105 Environment data reaches network egress
[HIGH] MSC101 Read-only claim conflicts with reachable behavior
[HIGH] MSC102 Network egress is not disclosed
[HIGH] MSC103 Filesystem scope is not constrained
[HIGH] MSC104 Dangerous filesystem default
```

The paired hardened fixture retains its intended filesystem-read capability but returns `Findings (0)` and exits `0`.

> Status: v0.1 vertical slice. The project is functional and tested, but has not been published to PyPI.

## Why this exists

An MCP tool description and its annotations are claims. They do not enforce a permission boundary. A tool named `search_project_docs` can still contain code that reads `/`, accesses environment values, starts a process, or sends data over the network.

ScopeCheck asks a narrow, evidence-backed question:

> Does the tool's declared contract agree with behavior reachable from the tool's source?

That focus complements manifest scanners and runtime testing tools. It does not replace either.

## Security invariant

ScopeCheck reads source as text and parses it with Python's `ast` module. Target modules are never imported, decorators are never invoked, and MCP servers are never started. A regression test places a real top-level side effect in a fixture and proves it does not execute during an audit.

## Install from source

Python 3.11 or newer is required. The scanner has no runtime dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Use

```bash
mcp-scopecheck audit examples/unsafe_docs_server
mcp-scopecheck audit examples/hardened_docs_server
```

Audit any local Python file or directory by replacing the target path. Use `--fail-on high` (or `low`, `medium`, or `critical`) to set the exit-`1` threshold.

Exit codes:

| Code | Meaning |
| ---: | --- |
| `0` | No finding met the configured threshold |
| `1` | One or more findings met the configured threshold |
| `2` | Invalid input, no supported tools, diagnostics, or another audit error |

## What v0.1 detects

| Rule | Severity | What it means |
| --- | --- | --- |
| `MSC001` | Critical | Tool description contains instructions aimed at controlling or concealing behavior from the host model/user |
| `MSC101` | High/Critical | `readOnlyHint=true` conflicts with reachable write, network, process, or dynamic-code behavior; process and dynamic code conflicts are Critical |
| `MSC102` | High | Reachable network egress is missing from the tool description |
| `MSC103` | High | Path-like input reaches filesystem operations without a recognized containment check |
| `MSC104` | High | A path/root parameter defaults to `/` or `~` |
| `MSC105` | Critical | Environment-derived data reaches a network call in the same reachable function |
| `MSC106` | Critical | Process or shell execution is reachable |
| `MSC107` | Critical | `eval` or `exec` is reachable |

Observed capabilities are reported separately from findings. Filesystem reads are not automatically vulnerabilities; the contract comparison determines whether the behavior is inconsistent or insufficiently constrained.

## The 5-S report

Every audit is organized around:

- **Source** — what local source was inspected.
- **Surface** — which MCP tools were discovered.
- **Scope** — parameters and declared annotations.
- **Side effects** — filesystem, environment, network, process, and dynamic-code capabilities reachable from each tool.
- **Snapshot** — a deterministic SHA-256 digest of the extracted contract and capabilities.

## Current boundaries

v0.1 intentionally supports:

- Local Python files/directories
- Module-level `@mcp.tool`, `@mcp.tool()`, and equivalent `.tool` decorators
- Same-file helper-call reachability
- Direct standard-library and common HTTP-client sinks

It does **not** yet prove:

- Cross-module or dynamically dispatched call paths
- Runtime-only tool registration
- TypeScript/JavaScript behavior
- Authorization correctness
- Whether all observed data actually leaves the process, except the narrow same-function flow implemented by `MSC105`
- Safety of a running MCP server

`MSC103` requires a recognized containment comparison; `.resolve()` by itself is only normalization and does not suppress the finding. `MSC105` follows direct and simple assignment propagation in lexical order within one function, but it does not model complete Python control flow.

A clean report is not proof of safe runtime behavior. See [architecture and threat model](docs/architecture.md).

## Develop

The test suite uses only the Python standard library. Release tooling is development-only and pinned in `requirements-dev.txt`:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -r requirements-dev.txt
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
PYTHONPATH=src .venv/bin/python -m mcp_scopecheck audit examples/unsafe_docs_server
PYTHONPATH=src .venv/bin/python -m mcp_scopecheck audit examples/hardened_docs_server
```

Before a public release, activate that environment and run `scripts/preflight.sh`. It runs the same test, compile, Ruff, strict mypy, and build gates as CI; it additionally requires Gitleaks and fails closed if the scanner is unavailable.

For the source-evidence, unsafe/hardened, and exit-code demo:

```bash
scripts/demo.sh
```

## Roadmap

- Cross-module call graph and argument-aware data flow
- TypeScript parser backed by a real syntax tree
- JSON/SARIF output and stable rule schema
- Snapshot comparison for tool-definition drift
- Optional semantic description analysis with an explicit privacy boundary
- Reproducible benchmark corpus with measured precision and recall

## License

MIT

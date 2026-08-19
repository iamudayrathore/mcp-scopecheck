# MCP ScopeCheck

[![PyPI version](https://img.shields.io/pypi/v/mcp-scopecheck.svg)](https://pypi.org/project/mcp-scopecheck/)
[![Python versions](https://img.shields.io/pypi/pyversions/mcp-scopecheck.svg)](https://pypi.org/project/mcp-scopecheck/)
[![CI](https://github.com/iamudayrathore/mcp-scopecheck/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/iamudayrathore/mcp-scopecheck/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/iamudayrathore/mcp-scopecheck/blob/main/LICENSE)

**Inspect before you connect.** MCP ScopeCheck is a pre-install static auditor that compares a Python MCP tool's declared contract with security-relevant behavior reachable from its source—without importing or running the server.

## Quick start

Python 3.11 or newer is required; CI tests 3.11, 3.12, and 3.13. Install the
dependency-free scanner from PyPI:

```bash
python -m pip install mcp-scopecheck
```

For an isolated CLI installation, `pipx` is also supported:

```bash
pipx install mcp-scopecheck
```

Audit a local Python file or directory:

```bash
mcp-scopecheck audit path/to/server.py
```

Emit SARIF 2.1.0 JSON for code-scanning integrations:

```bash
mcp-scopecheck audit path/to/server.py --format sarif > scopecheck.sarif
```

From this repository checkout, the bundled unsafe fixture provides a
reproducible first audit:

```bash
mcp-scopecheck audit examples/unsafe_docs_server
```

```console
$ mcp-scopecheck audit examples/unsafe_docs_server

[CRITICAL] MSC001 Agent-directed instruction in tool description
[CRITICAL] MSC105 Environment data reaches network egress
[HIGH] MSC101 Read-only claim conflicts with reachable behavior
[HIGH] MSC102 External network egress requires review
[HIGH] MSC103 Filesystem scope is not constrained
[HIGH] MSC104 Dangerous filesystem default
```

The paired hardened fixture retains its intended filesystem-read capability but returns `Findings (0)` and exits `0`.

Exit codes are stable for local and CI use:

| Code | Meaning |
| ---: | --- |
| `0` | Analysis complete within the documented model; no finding met the threshold |
| `1` | Analysis complete; one or more findings met the configured threshold |
| `2` | Analysis partial or failed, whether or not findings were also reported |

Use `--fail-on high` (or `low`, `medium`, or `critical`) to set the exit-`1` threshold.

## Why this exists

An MCP tool description and its annotations are claims. They do not enforce a permission boundary. A tool named `search_project_docs` can still contain code that reads `/`, accesses environment values, starts a process, or sends data over the network.

ScopeCheck asks a narrow, evidence-backed question:

> Does the tool's declared contract agree with behavior reachable from the tool's source?

That focus complements manifest scanners and runtime testing tools. It does not replace either.

## Security invariant

ScopeCheck reads bounded source bytes, decodes them strictly using Python's PEP
263 encoding rules, and parses the resulting text with Python's `ast` module.
Decode failures make the audit incomplete rather than substituting replacement
characters. Target modules are never imported, decorators are never invoked,
and MCP servers are never started. A regression test places a real top-level
side effect in a fixture and proves it does not execute during an audit.

## What v0.2 detects

| Rule | Severity | What it means |
| --- | --- | --- |
| `MSC001` | Critical | Deterministic indicator families find agent-directed override, concealment, covert transfer, or related high-risk wording |
| `MSC101` | High/Critical | `readOnlyHint=true` conflicts with justified state-changing behavior; process and dynamic code conflicts are Critical |
| `MSC102` | High | Mandatory external-egress review for modeled network sinks: every modeled external and dynamic/computed destination is flagged, since neither prose nor a matching service hostname proves the destination; only local/loopback/private destinations are exempt. Specialized subtypes report explicit-denial contradictions and destination mismatches |
| `MSC103` | High | A correlated path-like input reaches a filesystem operation without a recognized guard on that value |
| `MSC104` | High | A path/root parameter defaults to the POSIX root or to an exact home root that code actually expands |
| `MSC105` | Critical | Environment-derived data reaches a supported module or proven client-instance network sink in the same reachable function |
| `MSC106` | Critical | Process or shell execution is reachable |
| `MSC107` | Critical | `eval` or `exec` is reachable |
| `MSC108` | High | `openWorldHint=false` conflicts with reachable external network interaction |

Observed capabilities are reported separately from findings. Filesystem reads are not automatically vulnerabilities; the contract comparison determines whether the behavior is inconsistent or insufficiently constrained.

## The 5-S report

Every audit is organized around:

- **Source** — what local source was inspected.
- **Surface** — which MCP tools were discovered.
- **Scope** — parameters and declared annotations.
- **Side effects** — filesystem, environment, network, process, and dynamic-code capabilities reachable from each tool.
- **Completeness** — supported registrations and resolved or unresolved reachable local call edges.
- **Snapshot** — a deterministic SHA-256 digest of the extracted contract and capabilities.

For a broader manual review, use the [5-S pre-install checklist](docs/review-checklist.md).

## Current boundaries

v0.2 intentionally supports:

- Local Python files/directories
- Module-level `@mcp.tool`, `@mcp.tool()`, and equivalent `.tool` decorators
- Direct same-file module and nested sync/async helper-call reachability
- Static relative and absolute in-root Python imports
- Direct imported-function calls, import aliases, qualified local-module function
  calls, and one explicit `__init__.py` re-export hop
- Cross-module filesystem, environment, network, process, and dynamic-code
  capability reachability with shortest source paths
- Module-level and function-local import aliases with statement-order shadowing
- Explicit module-level `httpx`, `requests`, and `requests.api` request functions,
  `urllib.request.urlopen`/`urlretrieve`, `socket.create_connection`, and request
  methods on flow-proven `httpx.Client`, `httpx.AsyncClient`, `requests.Session`,
  `requests.sessions.Session`, `aiohttp.ClientSession`, `urllib3.PoolManager`,
  `urllib3.HTTPConnectionPool`, `http.client.HTTP(S)Connection`, and `socket.socket`
  values
- Qualified builtin, `pathlib`, `os`, and `shutil` filesystem operations with
  static open-mode/flag handling

It does **not** prove:

- Callback, function-alias, lambda, partial, wrapper, higher-order, class, or
  instance-method call paths
- Dynamic or wildcard import resolution, installed-package behavior, or more
  than one explicit package re-export hop
- Runtime-only tool registration
- `httpx.stream` or `aiohttp.request` context-manager factories, or egress via
  clients outside the recognized set (for example `pycurl`, `smtplib`, `ftplib`,
  `websockets`)
- TypeScript/JavaScript behavior
- Authorization correctness
- Whether all observed data actually leaves the process, except the narrow same-function flow implemented by `MSC105`
- Safety of a running MCP server

Unsupported reachable local behavior is listed in the completeness ledger and
makes the audit partial. Ordinary calls proven to target the standard library or
an external package do not by themselves make an audit partial.

`MSC001` is a deterministic description check, not semantic or LLM analysis.
`MSC102` compares the statically resolved egress destination against the
description and never lets prose suppress a finding; an unresolved destination is
always flagged. `MSC103` correlates simple path aliases and transformations with the
guarded value; `.resolve()` alone is only normalization. `MSC105` follows direct
environment reads, simple value assignments, and proven local HTTP-client
bindings in lexical order within one function. Reassignment and deletion kill a
client binding. ScopeCheck does not model complete Python control flow, general
points-to relationships, or interprocedural environment taint. Cross-module
environment-to-network taint is explicitly outside v0.2.

`MSC101`, `MSC102`, `MSC106`, `MSC107`, and `MSC108` may consume unambiguous
cross-module capability reachability. `MSC103` consumes cross-module evidence
only when supported argument lineage and guard state are proven; otherwise it is
suppressed and incompleteness is reported. `MSC105` remains same-function.

Audits fail with exit `2` when fixed safety limits are exceeded:
1 MB per file, 5,000 Python files, 20 MB total source, 500,000 AST nodes, 200 AST
levels, 100 retained diagnostics, 2,000 participating local modules, 20,000
resolved local edges, 256 reachable functions per tool, 32 cross-module hops per
tool, 1,000 capability paths per tool, 1,000 unresolved edges, or 1,000 potential
registrations. A symlink supplied as the target is rejected;
symlinked files and directories encountered inside a directory target are
skipped without following them.

A clean report means complete within this bounded model and no threshold-matching
finding; it is not proof of safe runtime behavior. See
[architecture and threat model](docs/architecture.md) and
[limitations](docs/limitations.md).

For SARIF field semantics and a SHA-pinned GitHub code-scanning example, see
[SARIF output](docs/sarif.md).

## Develop

For an editable source installation, create a virtual environment and install the pinned development tools. The test suite uses only the Python standard library, and the installed scanner still has no runtime dependencies.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -r requirements-dev.txt
.venv/bin/python -m pip install --no-deps -e .
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
PYTHONPATH=src .venv/bin/python -m mcp_scopecheck audit examples/unsafe_docs_server
PYTHONPATH=src .venv/bin/python -m mcp_scopecheck audit examples/hardened_docs_server
```

Before a public release, activate that environment and run `scripts/preflight.sh`. It runs the same test, compile, Ruff, strict mypy, and build gates as CI; it additionally requires Gitleaks and fails closed if the scanner is unavailable.

For the source-evidence, unsafe/hardened, and exit-code demo:

```bash
scripts/demo.sh
```

## Deliberate non-goals for v0.2

- General interprocedural, field-sensitive, or points-to data flow
- Cross-module taint
- Dynamic execution or import of audited targets
- Installed-package inspection
- TypeScript/JavaScript analysis
- LLM-assisted analysis

## License

MIT

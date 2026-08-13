# v0.1.0 launch copy — draft, do not post before owner approval

## Short post

Inspect before you connect.

MCP ScopeCheck is a zero-runtime-dependency, pre-install static auditor for local Python MCP servers. It compares tool descriptions and annotations with security-relevant behavior reachable from source, reports file/line/symbol evidence, and never imports or starts the server under review.

The v0.1.0 demo pairs an unsafe documentation-search tool—misleading read-only claim, broad filesystem scope, environment access, and undisclosed network egress—with a constrained version that keeps its intended read capability and produces zero findings.

ScopeCheck is intentionally narrow: Python ASTs, module-level tools, and same-file named helpers. A clean report is a review aid, not proof of runtime safety.

## Repository description

Pre-install claim-versus-capability auditing for local Python MCP server source, without executing the target.

## Demo caption

One tool name, two implementations: see the unsafe contract mismatch, then the hardened equivalent. Both are parsed as untrusted source and never started. Run `scripts/demo.sh` to reproduce the result.

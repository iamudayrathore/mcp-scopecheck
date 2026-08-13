# Product positioning and claim discipline

Last reviewed: 2026-08-10

## Category

Pre-install static security analysis for MCP server source.

## One-sentence position

MCP ScopeCheck compares what a Python MCP tool claims it can do with security-relevant behavior reachable from its source code—without importing or running the server.

## Why a user should care

MCP hosts display names, descriptions, schemas, and annotations, but those declarations are not permission enforcement. ScopeCheck gives a reviewer source locations for reachable capabilities and highlights concrete mismatches before the server is connected.

## Differentiated wedge

The strongest defensible combination is:

- pre-install and source-first;
- no target execution;
- claim-versus-reachable-capability comparison;
- evidence at file, line, and symbol;
- unsafe/hardened paired proof;
- deterministic snapshot and CI-friendly exit codes;
- the 5-S review frame: Source, Surface, Scope, Side effects, Snapshot.

This is a wedge, not a claim that competitors cannot or do not implement overlapping features.

## Competitive reality

As of 2026-08-10, the exact `mcp-auditor` name is occupied on PyPI, and multiple MCP scanning/auditing projects exist. Examples include Cisco AI Defense's MCP Scanner and APIsec's `mcp-audit`. Some tools already advertise static/source analysis, dynamic checks, proxying, or LLM-assisted analysis.

Primary references:

- <https://pypi.org/project/mcp-auditor/>
- <https://github.com/cisco-ai-defense/mcp-scanner>
- <https://github.com/apisec-inc/mcp-audit>

Recheck current product capabilities before publishing a comparison table. Do not freeze competitive claims from this document into marketing without verification.

## Messaging hierarchy

1. **Inspect before you connect.**
2. Show the unsafe tool's honest-looking name and dishonest/reachable side effects.
3. Show the finding evidence and non-execution mode.
4. Show the hardened equivalent passing.
5. Explain the 5-S mental model.
6. State limitations and complementary controls.

## Approved phrases

- A tool name is not a permission boundary.
- Annotations are claims, not enforcement.
- Correct output can camouflage unsafe side effects.
- Safe at install does not mean safe forever.
- Inspect before you connect.

## Prohibited or unsupported v0.1 claims

- “AI-analyzed tool poisoning.”
- “Complete MCP security.”
- “Proves an MCP server is safe.”
- “Whole-program data-flow analysis.”
- “Supports every MCP SDK or language.”
- “Scans GitHub URLs/packages.”
- “The first/only MCP static auditor.”

## Future semantic-analysis position

If an optional LLM analyzer is built after v0.1, position it as an additional semantic signal, not ground truth. Publish the provider/privacy boundary, model and prompt version, cost behavior, failure mode, and benchmark method. Keep the deterministic offline engine independently useful.

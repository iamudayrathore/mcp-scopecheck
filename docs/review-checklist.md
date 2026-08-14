# The 5-S MCP pre-install checklist

Use this checklist before connecting an unfamiliar MCP server. ScopeCheck automates a narrow subset; human review remains necessary.

## 1. Source

- Who owns and maintains the server?
- Is the package/repository identity unambiguous?
- Is the reviewed commit or package version pinned?
- Are install scripts, generated binaries, and dependencies accounted for?
- Is the source you reviewed the source that will execute?
- Did the audit complete without diagnostics or a safety-budget overrun?

## 2. Surface

- Read every tool name and the complete description.
- Review prompts, resources, and server-level instructions—not only tools.
- Look for instructions directed at the model rather than an honest user-facing description.
- Require descriptions to state real external interaction and purpose; a lone word such as “API” is not disclosure.
- Treat “offline” or “never sends” as a contradiction when reachable code has network egress.
- Identify duplicate or shadowing tool names across connected servers.
- Treat annotations as claims, not enforcement.

## 3. Scope

- Which files, directories, domains, APIs, databases, and accounts are reachable?
- Can a model-controlled parameter widen that scope?
- Are path inputs resolved and proven to remain below a fixed root?
- Are symlink behavior and broad root/home defaults explicit?
- Are schemas closed to unknown properties and constrained with enums, bounds, and formats?
- Do credentials carry the minimum required permissions?

## 4. Side effects

- Can the tool write/delete files, run commands, mutate data, send messages, or make purchases?
- Is network egress required, documented, and allowlisted?
- Can environment variables or local credentials reach outbound requests?
- Are destructive or externally visible operations gated by explicit approval?
- Can outputs from an untrusted read tool trigger a privileged write tool?

## 5. Snapshot

- Record the exact source revision and normalized tool manifest.
- Compare descriptions, schemas, annotations, and capabilities on update/reconnect.
- Treat unexpected drift as a new security review.
- Re-run the audit after dependency or transport changes.
- Remember: safe at install does not mean safe forever.

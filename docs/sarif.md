# SARIF output

MCP ScopeCheck emits deterministic SARIF 2.1.0 when `--format sarif` is selected:

```bash
mcp-scopecheck audit path/to/python/server --format sarif > scopecheck.sarif
```

SARIF stdout contains JSON only, including when ScopeCheck exits nonzero. Exit `1`
means complete analysis with findings at or above the configured threshold. Exit `2`
means analysis was partial or failed. Findings remain under `runs[].results`; parse
diagnostics, unsupported registrations, unresolved local calls, and resource failures
appear as non-finding entries under
`runs[].invocations[].toolExecutionNotifications`.

## GitHub code scanning

The following push-only example retains the ScopeCheck exit status, uploads SARIF even
for exits `1` and `2`, and then fails the job with the original status. The official
upload action is pinned to the immutable commit for `v4.36.0`; review and update action
pins deliberately as part of normal dependency maintenance.

```yaml
name: MCP ScopeCheck

on:
  push:

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Check out source
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          persist-credentials: false

      - name: Set up Python
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6.3.0
        with:
          python-version: "3.13"

      - name: Install ScopeCheck without dependencies
        run: python -m pip install --no-deps mcp-scopecheck==0.2.0

      - name: Audit and retain exit status
        id: scopecheck
        shell: bash
        run: |
          set +e
          mcp-scopecheck audit path/to/python/server --format sarif > scopecheck.sarif
          scopecheck_exit=$?
          set -e
          printf 'exit_code=%s\n' "${scopecheck_exit}" >> "${GITHUB_OUTPUT}"
          test -s scopecheck.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@7211b7c8077ea37d8641b6271f6a365a22a5fbfa # v4.36.0
        with:
          sarif_file: scopecheck.sarif

      - name: Propagate ScopeCheck status
        if: always()
        env:
          SCOPECHECK_EXIT: ${{ steps.scopecheck.outputs.exit_code }}
        shell: bash
        run: exit "${SCOPECHECK_EXIT}"
```

This example intentionally does not use a custom action. For pull-request workflows,
review GitHub's token and fork permission model before granting `security-events: write`.

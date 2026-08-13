"""Plain-text report rendering for terminals and CI logs."""

from __future__ import annotations

from .models import AuditReport


def _clip(value: str, width: int) -> str:
    return value if len(value) <= width else f"{value[: width - 1]}…"


def render_report(report: AuditReport) -> str:
    """Render a compact 5-S audit report without terminal-specific markup."""

    parameter_count = sum(len(tool.parameters) for tool in report.tools)
    capability_count = sum(len(items) for items in report.capabilities.values())
    lines = [
        "MCP ScopeCheck",
        "==============",
        f"Target: {report.target}",
        "Mode: static source analysis (target code was not imported or executed)",
        "",
        "5-S summary",
        f"  Source:       {report.files_scanned} Python file(s) read",
        f"  Surface:      {len(report.tools)} MCP tool(s) discovered",
        f"  Scope:        {parameter_count} declared parameter(s)",
        f"  Side effects: {capability_count} reachable capability site(s)",
        f"  Snapshot:     sha256:{report.snapshot}",
        "",
    ]

    if report.tools:
        lines.append("Tools")
        for tool in report.tools:
            parameters = ", ".join(parameter.name for parameter in tool.parameters) or "none"
            claims = []
            if tool.read_only_claimed:
                claims.append("readOnlyHint=true")
            claim_text = ", ".join(claims) or "none"
            capabilities = sorted(
                {item.capability.value for item in report.capabilities.get(tool.key, [])}
            )
            lines.extend(
                [
                    f"  {tool.name} ({tool.source_file}:{tool.line_number})",
                    f"    Description: {_clip(tool.description or '[empty]', 100)}",
                    f"    Parameters:  {parameters}",
                    f"    Claims:      {claim_text}",
                    f"    Observed:    {', '.join(capabilities) or 'none'}",
                ]
            )
        lines.append("")

    lines.append(f"Findings ({len(report.findings)})")
    if not report.findings:
        lines.append("  No contract mismatches or high-risk behavior detected by the v0.1 rules.")
    else:
        for finding in report.findings:
            lines.extend(
                [
                    f"  [{finding.severity.name}] {finding.rule_id} {finding.title}",
                    f"    Tool:     {finding.tool_name}",
                    f"    Evidence: {finding.evidence.location} ({finding.evidence.symbol})",
                    f"    Why:      {finding.message}",
                    f"    Fix:      {finding.remediation}",
                ]
            )

    if report.diagnostics:
        lines.extend(["", f"Diagnostics ({len(report.diagnostics)})"])
        for diagnostic in report.diagnostics:
            location = diagnostic.source_file
            if diagnostic.line_number:
                location = f"{location}:{diagnostic.line_number}"
            lines.append(f"  {location}: {diagnostic.message}")

    lines.extend(
        [
            "",
            "Limit: a clean static scan is not proof of safe runtime behavior.",
        ]
    )
    return "\n".join(lines)

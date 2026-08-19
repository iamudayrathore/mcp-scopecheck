"""Plain-text report rendering for terminals and CI logs."""

from __future__ import annotations

from .models import AnalysisStatus, AuditReport

_BIDI_CONTROLS = frozenset(
    {
        "\u061c",  # Arabic letter mark
        "\u200e",  # Left-to-right mark
        "\u200f",  # Right-to-left mark
        "\u202a",  # Left-to-right embedding
        "\u202b",  # Right-to-left embedding
        "\u202c",  # Pop directional formatting
        "\u202d",  # Left-to-right override
        "\u202e",  # Right-to-left override
        "\u2066",  # Left-to-right isolate
        "\u2067",  # Right-to-left isolate
        "\u2068",  # First-strong isolate
        "\u2069",  # Pop directional isolate
    }
)
_UNICODE_LINE_CONTROLS = frozenset({"\u2028", "\u2029"})
_DISPLAYED_HINTS = (
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
)


def escape_terminal_text(value: object) -> str:
    """Render untrusted text without allowing it to control terminal presentation."""

    escaped: list[str] = []
    for character in str(value):
        codepoint = ord(character)
        if (
            codepoint <= 0x1F
            or 0x7F <= codepoint <= 0x9F
            or 0xD800 <= codepoint <= 0xDFFF
            or character in _BIDI_CONTROLS
            or character in _UNICODE_LINE_CONTROLS
        ):
            escaped.append(f"\\u{codepoint:04X}")
        else:
            escaped.append(character)
    return "".join(escaped)


def _clip(value: str, width: int) -> str:
    escaped = escape_terminal_text(value)
    return escaped if len(escaped) <= width else f"{escaped[: width - 1]}…"


def render_report(report: AuditReport) -> str:
    """Render a compact 5-S audit report without terminal-specific markup."""

    parameter_count = sum(len(tool.parameters) for tool in report.tools)
    capability_count = sum(len(items) for items in report.capabilities.values())
    display = escape_terminal_text
    lines = [
        "MCP ScopeCheck",
        "==============",
        f"Target: {display(report.target)}",
        "Mode: static source analysis (target code was not imported or executed)",
        "",
        "5-S summary",
        f"  Source:       {report.files_scanned} Python file(s) read",
        f"  Surface:      {len(report.tools)} MCP tool(s) discovered",
        f"  Scope:        {parameter_count} declared parameter(s)",
        f"  Side effects: {capability_count} reachable capability site(s)",
        f"  Completeness: {report.completeness.status.value}",
        f"  Snapshot:     sha256:{report.snapshot}",
        "",
    ]

    if report.tools:
        lines.append("Tools")
        for tool in report.tools:
            parameters = (
                ", ".join(display(parameter.name) for parameter in tool.parameters) or "none"
            )
            claims = [
                f"{key}={str(tool.annotations[key]).lower()}"
                for key in _DISPLAYED_HINTS
                if isinstance(tool.annotations.get(key), bool)
            ]
            claim_text = ", ".join(claims) or "none"
            capabilities = sorted(
                {item.capability.value for item in report.capabilities.get(tool.key, [])}
            )
            capability_text = ", ".join(display(item) for item in capabilities) or "none"
            lines.extend(
                [
                    f"  {display(tool.name)} ({display(tool.source_file)}:{tool.line_number})",
                    f"    Description: {_clip(tool.description or '[empty]', 100)}",
                    f"    Parameters:  {parameters}",
                    f"    Claims:      {claim_text}",
                    f"    Observed:    {capability_text}",
                ]
            )
            for item in report.capabilities.get(tool.key, []):
                if not item.evidence.path:
                    continue
                path = " -> ".join(
                    f"{display(step.symbol)} ({display(step.source_file)}:{step.line_number})"
                    for step in item.evidence.path
                )
                lines.append(
                    f"    Evidence:    {display(item.capability.value)}: {path}"
                )
        lines.append("")

    completeness = report.completeness
    lines.extend(
        [
            f"Completeness ({completeness.status.value})",
            f"  Registrations: {completeness.supported_registrations} supported, "
            f"{completeness.unresolved_registrations} unresolved",
            f"  Resolved reachable local call edges ({len(completeness.resolved_edges)})",
        ]
    )
    if not completeness.resolved_edges:
        lines.append("    none")
    else:
        for resolved_edge in completeness.resolved_edges:
            lines.append(
                f"    {display(resolved_edge.tool_name)}: "
                f"{display(resolved_edge.caller)} -> "
                f"{display(resolved_edge.target_symbol)} at "
                f"{display(resolved_edge.source_file)}:{resolved_edge.line_number} "
                f"[{display(resolved_edge.call_expression)}; target "
                f"{display(resolved_edge.target_file)}]"
            )

    lines.append(
        f"  Unresolved reachable local call edges ({len(completeness.unresolved_edges)})"
    )
    if not completeness.unresolved_edges:
        lines.append("    none")
    else:
        for unresolved_edge in completeness.unresolved_edges:
            candidate = (
                f"; candidate {display(unresolved_edge.candidate)}"
                if unresolved_edge.candidate
                else ""
            )
            lines.extend(
                [
                    f"    {display(unresolved_edge.tool_name)}: "
                    f"{display(unresolved_edge.caller)} at "
                    f"{display(unresolved_edge.source_file)}:{unresolved_edge.line_number}",
                    f"      Call: {display(unresolved_edge.call_expression)}",
                    f"      Reason: {display(unresolved_edge.reason.value)}{candidate}",
                ]
            )

    if completeness.potential_registrations:
        lines.append(
            "  Potential unsupported MCP registrations "
            f"({completeness.unresolved_registrations})"
        )
        for registration in completeness.potential_registrations:
            lines.append(
                f"    {display(registration.source_file)}:{registration.line_number} "
                f"{display(registration.expression)} "
                f"[{display(registration.reason)}]"
            )
    for notification in completeness.notifications:
        location = display(notification.source_file)
        if notification.line_number:
            location = f"{location}:{notification.line_number}"
        lines.append(
            f"  Notification {display(notification.code)} at {location}: "
            f"{display(notification.message)}"
        )
    lines.append("")

    lines.append(f"Findings ({len(report.findings)})")
    if not report.findings:
        if report.completeness.status is AnalysisStatus.COMPLETE:
            lines.append(
                "  No contract mismatches or high-risk behavior detected by the v0.2 rules."
            )
        else:
            # An empty finding list inside an incomplete analysis is not a clean
            # result. Never let it read like one.
            lines.append(
                "  No findings within an incomplete analysis "
                f"(completeness: {report.completeness.status.value}); "
                "unreviewed behavior may remain."
            )
    else:
        for finding in report.findings:
            lines.extend(
                [
                    f"  [{display(finding.severity.name)}] {display(finding.rule_id)} "
                    f"{display(finding.title)}",
                    f"    Tool:     {display(finding.tool_name)}",
                    f"    Evidence: {display(finding.evidence.location)} "
                    f"({display(finding.evidence.symbol)})",
                    f"    Why:      {display(finding.message)}",
                    f"    Fix:      {display(finding.remediation)}",
                ]
            )

    if report.diagnostics:
        lines.extend(["", f"Diagnostics ({len(report.diagnostics)})"])
        for diagnostic in report.diagnostics:
            location = display(diagnostic.source_file)
            if diagnostic.line_number:
                location = f"{location}:{diagnostic.line_number}"
            lines.append(f"  {location}: {display(diagnostic.message)}")

    lines.extend(
        [
            "",
            "Limit: a clean static scan is not proof of safe runtime behavior.",
        ]
    )
    return "\n".join(lines)

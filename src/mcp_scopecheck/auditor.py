"""Top-level audit orchestration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .analyzer import (
    MAX_RESOLVED_LOCAL_EDGES,
    MAX_UNRESOLVED_LOCAL_EDGES,
    _is_path_parameter_name,
    analyze_capabilities,
    analyze_contract,
    analyze_reachability,
    path_lineage_unproven,
    path_sink_parameters,
)
from .models import (
    AnalysisCompleteness,
    AnalysisNotification,
    AnalysisStatus,
    AuditReport,
)
from .parser import parse_project


def _snapshot_payload(report: AuditReport) -> bytes:
    tools = []
    for tool in report.tools:
        tools.append(
            {
                "name": tool.name,
                "function": tool.function_name,
                "description": tool.description,
                "source": tool.source_file,
                "line": tool.line_number,
                "annotations": tool.annotations,
                "parameters": [
                    {
                        "name": parameter.name,
                        "annotation": parameter.annotation,
                        "default": parameter.default,
                        "required": parameter.required,
                    }
                    for parameter in tool.parameters
                ],
                "capabilities": [
                    {
                        "name": item.capability.value,
                        "source": item.evidence.source_file,
                        "line": item.evidence.line_number,
                        "symbol": item.evidence.symbol,
                        "path": [
                            {
                                "source": step.source_file,
                                "line": step.line_number,
                                "symbol": step.symbol,
                            }
                            for step in item.evidence.path
                        ],
                    }
                    for item in report.capabilities.get(tool.key, [])
                ],
            }
        )
    payload = {
        "tools": tools,
        "completeness": {
            "status": report.completeness.status.value,
            "supported_registrations": report.completeness.supported_registrations,
            "unresolved_registrations": report.completeness.unresolved_registrations,
            "resolved_edges": [
                {
                    "tool": edge.tool_name,
                    "source": edge.source_file,
                    "line": edge.line_number,
                    "caller": edge.caller,
                    "call": edge.call_expression,
                    "target_source": edge.target_file,
                    "target_symbol": edge.target_symbol,
                }
                for edge in report.completeness.resolved_edges
            ],
            "unresolved_edges": [
                {
                    "tool": edge.tool_name,
                    "source": edge.source_file,
                    "line": edge.line_number,
                    "caller": edge.caller,
                    "call": edge.call_expression,
                    "reason": edge.reason.value,
                    "candidate": edge.candidate,
                }
                for edge in report.completeness.unresolved_edges
            ],
        },
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def audit(target: str | Path) -> AuditReport:
    """Audit a local Python source target without importing or executing it."""

    project = parse_project(target)
    capabilities = {}
    findings = []
    resolved_edges = []
    unresolved_edges = []
    graph_budget_exceeded = False
    capability_budget_exceeded = False
    for tool in project.tools:
        tool_resolved, tool_unresolved, tool_budget_exceeded = analyze_reachability(
            project,
            tool,
        )
        resolved_edges.extend(tool_resolved)
        unresolved_edges.extend(tool_unresolved)
        graph_budget_exceeded = graph_budget_exceeded or tool_budget_exceeded
        tool_capabilities, tool_capability_budget = analyze_capabilities(project, tool)
        capability_budget_exceeded = (
            capability_budget_exceeded or tool_capability_budget
        )
        capabilities[tool.key] = tool_capabilities
        findings.extend(
            analyze_contract(
                project,
                tool,
                tool_capabilities,
                tool_unresolved,
            )
        )

    findings.sort(key=lambda item: (-int(item.severity), item.rule_id, item.tool_name))
    resolved_edges = list(
        {
            (
                edge.tool_name,
                edge.source_file,
                edge.line_number,
                edge.caller,
                edge.call_expression,
                edge.target_file,
                edge.target_symbol,
            ): edge
            for edge in resolved_edges
        }.values()
    )
    unresolved_edges = list(
        {
            (
                edge.tool_name,
                edge.source_file,
                edge.line_number,
                edge.caller,
                edge.call_expression,
                edge.reason,
                edge.candidate,
            ): edge
            for edge in unresolved_edges
        }.values()
    )
    resolved_edges.sort(
        key=lambda edge: (
            edge.tool_name,
            edge.source_file,
            edge.line_number,
            edge.caller,
            edge.target_file,
            edge.target_symbol,
        )
    )
    unresolved_edges.sort(
        key=lambda edge: (
            edge.tool_name,
            edge.source_file,
            edge.line_number,
            edge.caller,
            edge.reason.value,
            edge.call_expression,
        )
    )
    if (
        len(resolved_edges) > MAX_RESOLVED_LOCAL_EDGES
        or len(unresolved_edges) > MAX_UNRESOLVED_LOCAL_EDGES
    ):
        graph_budget_exceeded = True
    resolved_edges = resolved_edges[:MAX_RESOLVED_LOCAL_EDGES]
    unresolved_edges = unresolved_edges[:MAX_UNRESOLVED_LOCAL_EDGES]
    notifications = []
    tools_by_name = {tool.name: tool for tool in project.tools}
    # Notify when a tool's unresolved work could hide filesystem-scope evidence.
    # Two disjoint cases qualify, and both are needed:
    #   1. A parameter is proven to reach an unguarded filesystem sink. This is
    #      exactly the condition under which `analyze_contract` withholds MSC103,
    #      and it is name-independent, so it now covers `filepath`/`target`/`name`.
    #   2. The tool declares a path-like parameter but no sink was proven, because
    #      the lineage itself runs through the unresolved call. Naming is the only
    #      signal left when the flow cannot be followed, so it is retained here as
    #      a fallback rather than as the primary gate.
    # A tool with neither has no filesystem-scope inference to report on; its
    # unresolved edges are already listed in the ledger above.
    path_relevant: dict[str, bool] = {}
    for edge in unresolved_edges:
        unresolved_tool = tools_by_name.get(edge.tool_name)
        if unresolved_tool is None:
            continue
        relevant = path_relevant.get(unresolved_tool.key)
        if relevant is None:
            relevant = bool(path_sink_parameters(project, unresolved_tool)) or any(
                _is_path_parameter_name(parameter.name)
                for parameter in unresolved_tool.parameters
            )
            path_relevant[unresolved_tool.key] = relevant
        if not relevant:
            continue
        notifications.append(
            AnalysisNotification(
                "MSC103-GUARD-UNKNOWN",
                "MSC103 filesystem-scope inference may be incomplete for tool "
                f"{unresolved_tool.name!r}: an unresolved reachable call could "
                "carry guard state",
                edge.source_file,
                edge.line_number,
            )
        )
    # A filesystem sink reached through an expression form the analyzer does not
    # model must never render as a clean audit. Surfacing it here keeps the
    # "report what cannot be proven" contract that the exit-code and completeness
    # states depend on.
    unproven_lineage = False
    for tool in project.tools:
        for evidence in path_lineage_unproven(project, tool):
            unproven_lineage = True
            notifications.append(
                AnalysisNotification(
                    "MSC103-LINEAGE-UNPROVEN",
                    "filesystem scope was not inferred for tool "
                    f"{tool.name!r}: tool input reaches {evidence.symbol} through "
                    "an expression form outside the supported model",
                    evidence.source_file,
                    evidence.line_number,
                )
            )

    failed_diagnostic = any(
        diagnostic.status is AnalysisStatus.FAILED for diagnostic in project.diagnostics
    )
    partial_diagnostic = any(
        diagnostic.status is AnalysisStatus.PARTIAL for diagnostic in project.diagnostics
    )
    if graph_budget_exceeded or capability_budget_exceeded:
        notifications.append(
            AnalysisNotification(
                "MSC-ANALYSIS-BUDGET",
                "analysis failed because the local call-edge budget was exhausted",
            )
        )
    notifications = list(
        {
            (
                item.code,
                item.message,
                item.source_file,
                item.line_number,
            ): item
            for item in notifications
        }.values()
    )
    notifications.sort(
        key=lambda item: (item.code, item.source_file, item.line_number, item.message)
    )
    if failed_diagnostic or graph_budget_exceeded or capability_budget_exceeded:
        status = AnalysisStatus.FAILED
    elif (
        partial_diagnostic
        or unresolved_edges
        or unproven_lineage
        or project.potential_registrations
    ):
        status = AnalysisStatus.PARTIAL
    elif not project.tools:
        status = AnalysisStatus.FAILED
        notifications.append(
            AnalysisNotification(
                "MSC-NO-SUPPORTED-TOOLS",
                "analysis failed because no supported MCP tool registrations were found",
            )
        )
    else:
        status = AnalysisStatus.COMPLETE
    completeness = AnalysisCompleteness(
        status=status,
        supported_registrations=len(project.tools),
        unresolved_registrations=sum(
            item.potential_tool_count for item in project.potential_registrations
        ),
        resolved_edges=resolved_edges,
        unresolved_edges=unresolved_edges,
        potential_registrations=project.potential_registrations,
        notifications=notifications,
    )
    report = AuditReport(
        target=project.root,
        files_scanned=project.files_scanned,
        tools=project.tools,
        capabilities=capabilities,
        findings=findings,
        diagnostics=project.diagnostics,
        completeness=completeness,
        snapshot="",
    )
    report.snapshot = hashlib.sha256(_snapshot_payload(report)).hexdigest()
    return report

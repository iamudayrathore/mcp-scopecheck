"""Top-level audit orchestration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .analyzer import analyze_capabilities, analyze_contract
from .models import AuditReport
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
                    }
                    for item in report.capabilities.get(tool.key, [])
                ],
            }
        )
    return json.dumps(tools, sort_keys=True, separators=(",", ":")).encode("utf-8")


def audit(target: str | Path) -> AuditReport:
    """Audit a local Python source target without importing or executing it."""

    project = parse_project(target)
    capabilities = {}
    findings = []
    for tool in project.tools:
        tool_capabilities = analyze_capabilities(project, tool)
        capabilities[tool.key] = tool_capabilities
        findings.extend(analyze_contract(project, tool, tool_capabilities))

    findings.sort(key=lambda item: (-int(item.severity), item.rule_id, item.tool_name))
    report = AuditReport(
        target=project.root,
        files_scanned=project.files_scanned,
        tools=project.tools,
        capabilities=capabilities,
        findings=findings,
        diagnostics=project.diagnostics,
        snapshot="",
    )
    report.snapshot = hashlib.sha256(_snapshot_payload(report)).hexdigest()
    return report

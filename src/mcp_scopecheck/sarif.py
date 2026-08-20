"""Deterministic SARIF 2.1.0 rendering."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

from . import __version__
from .models import AnalysisStatus, AuditReport, Finding, Severity
from .render import escape_terminal_text

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "123e95847b13fbdd4cbe2120fa5e33355d4a042b/Schemata/sarif-schema-2.1.0.json"
)

RULE_METADATA: dict[str, tuple[str, str, Severity]] = {
    "MSC001": (
        "Agent-directed instruction in tool description",
        "Deterministic high-risk instruction wording appears in MCP tool metadata.",
        Severity.CRITICAL,
    ),
    "MSC101": (
        "Read-only claim conflicts with reachable behavior",
        "A read-only annotation conflicts with justified state-changing capability evidence.",
        Severity.HIGH,
    ),
    "MSC102": (
        "External network egress requires review",
        "A modeled reachable external network call was found; prose or a matching "
        "service hostname is not treated as proof of the intended destination. "
        "Specialized subtypes report explicit denial contradictions and "
        "destination mismatches.",
        Severity.HIGH,
    ),
    "MSC105": (
        "Environment data reaches network egress",
        "Environment-derived data reaches a network sink within one reachable function.",
        Severity.CRITICAL,
    ),
    "MSC106": (
        "Process execution is reachable",
        "A registered tool can reach a supported process or shell execution sink.",
        Severity.CRITICAL,
    ),
    "MSC107": (
        "Dynamic code execution is reachable",
        "A registered tool can reach eval or exec under the bounded call model.",
        Severity.CRITICAL,
    ),
    "MSC108": (
        "Closed-world claim conflicts with network egress",
        "An openWorldHint=false annotation conflicts with reachable external interaction.",
        Severity.HIGH,
    ),
}


def _level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _safe(value: object) -> str:
    return escape_terminal_text(value)


def _safe_properties(value: Any) -> Any:
    if isinstance(value, str):
        return _safe(value)
    if isinstance(value, list):
        return [_safe_properties(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_properties(item) for item in value]
    if isinstance(value, dict):
        return {_safe(key): _safe_properties(item) for key, item in value.items()}
    return value


def _artifact_uri(source_file: str) -> str:
    return quote(_safe(source_file), safe="/-._~")


def _location(source_file: str, line_number: int) -> dict[str, Any]:
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": _artifact_uri(source_file)},
    }
    if line_number > 0:
        physical["region"] = {"startLine": line_number}
    return {"physicalLocation": physical}


def _driver() -> dict[str, Any]:
    rules = []
    for rule_id, (title, description, severity) in sorted(RULE_METADATA.items()):
        rules.append(
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": title},
                "fullDescription": {"text": description},
                "defaultConfiguration": {"level": _level(severity)},
                "properties": {"security-severity": severity.name.lower()},
            }
        )
    return {
        "name": "MCP ScopeCheck",
        "fullName": "MCP ScopeCheck static security and contract analysis",
        "informationUri": "https://github.com/iamudayrathore/mcp-scopecheck",
        "version": __version__,
        "semanticVersion": __version__,
        "rules": rules,
    }


def _result(finding: Finding, rule_indexes: dict[str, int]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_indexes[finding.rule_id],
        "level": _level(finding.severity),
        "message": {
            "text": _safe(f"{finding.title}: {finding.message}"),
        },
        "locations": [
            _location(finding.evidence.source_file, finding.evidence.line_number)
        ],
        "properties": _safe_properties(
            {
                "scopecheck": {
                    "severity": finding.severity.name.lower(),
                    "tool": finding.tool_name,
                    "symbol": finding.evidence.symbol,
                    "remediation": finding.remediation,
                }
            }
        ),
    }
    if finding.evidence.path:
        result["relatedLocations"] = [
            {
                "id": index,
                "message": {"text": _safe(step.symbol)},
                **_location(step.source_file, step.line_number),
            }
            for index, step in enumerate(finding.evidence.path, start=1)
        ]
    return result


def _notification(
    code: str,
    message: str,
    *,
    level: str,
    source_file: str = "",
    line_number: int = 0,
    properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    notification: dict[str, Any] = {
        "descriptor": {"id": code},
        "level": level,
        "message": {"text": _safe(message)},
    }
    if source_file and source_file != "<target>":
        notification["locations"] = [_location(source_file, line_number)]
    if properties:
        notification["properties"] = _safe_properties(properties)
    return notification


def _notifications(report: AuditReport) -> list[dict[str, Any]]:
    level = "error" if report.completeness.status is AnalysisStatus.FAILED else "warning"
    items: list[dict[str, Any]] = []
    for edge in report.completeness.unresolved_edges:
        items.append(
            _notification(
                "MSC-INCOMPLETE-EDGE",
                f"Unresolved reachable local call: {edge.reason.value}",
                level=level,
                source_file=edge.source_file,
                line_number=edge.line_number,
                properties={
                    "tool": edge.tool_name,
                    "caller": edge.caller,
                    "callExpression": edge.call_expression,
                    "reason": edge.reason.value,
                    "candidate": edge.candidate,
                },
            )
        )
    for registration in report.completeness.potential_registrations:
        items.append(
            _notification(
                "MSC-UNSUPPORTED-REGISTRATION",
                f"Potential MCP registration was not analyzed: {registration.reason}",
                level=level,
                source_file=registration.source_file,
                line_number=registration.line_number,
                properties={
                    "expression": registration.expression,
                    "potentialToolCount": registration.potential_tool_count,
                },
            )
        )
    for diagnostic in report.diagnostics:
        diagnostic_level = (
            "error" if diagnostic.status is AnalysisStatus.FAILED else "warning"
        )
        items.append(
            _notification(
                "MSC-DIAGNOSTIC",
                diagnostic.message,
                level=diagnostic_level,
                source_file=diagnostic.source_file,
                line_number=diagnostic.line_number,
            )
        )
    for item in report.completeness.notifications:
        items.append(
            _notification(
                item.code,
                item.message,
                level=level,
                source_file=item.source_file,
                line_number=item.line_number,
            )
        )
    return items


def render_sarif(report: AuditReport, exit_code: int) -> str:
    """Render a complete deterministic SARIF log for an audit report."""

    rule_indexes = {
        rule_id: index for index, rule_id in enumerate(sorted(RULE_METADATA))
    }
    invocation = {
        "executionSuccessful": report.completeness.status is AnalysisStatus.COMPLETE,
        "exitCode": exit_code,
        "toolExecutionNotifications": _notifications(report),
        "properties": {
            "scopecheck": {
                "completeness": {
                    "status": report.completeness.status.value,
                    "supportedRegistrations": report.completeness.supported_registrations,
                    "unresolvedRegistrations": report.completeness.unresolved_registrations,
                    "resolvedLocalEdges": len(report.completeness.resolved_edges),
                    "unresolvedLocalEdges": len(report.completeness.unresolved_edges),
                },
                "snapshot": f"sha256:{report.snapshot}",
            }
        },
    }
    log = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": _driver()},
                "results": [_result(item, rule_indexes) for item in report.findings],
                "invocations": [invocation],
                "properties": {
                    "scopecheck": {
                        "target": _safe(report.target),
                        "filesScanned": report.files_scanned,
                    }
                },
            }
        ],
    }
    return json.dumps(log, indent=2, sort_keys=True, ensure_ascii=True)


def render_sarif_failure(target: object, message: object) -> str:
    """Render a valid SARIF log when no AuditReport could be constructed."""

    notification = _notification(
        "MSC-AUDIT-FAILED",
        f"Audit failed: {message}",
        level="error",
        properties={"target": _safe(target)},
    )
    log = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": _driver()},
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": False,
                        "exitCode": 2,
                        "toolExecutionNotifications": [notification],
                        "properties": {
                            "scopecheck": {"completeness": {"status": "failed"}}
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(log, indent=2, sort_keys=True, ensure_ascii=True)

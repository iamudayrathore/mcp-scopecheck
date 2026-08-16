"""Domain models for MCP ScopeCheck."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any


class Severity(IntEnum):
    """Finding severity ordered for threshold comparisons."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(item.name.lower() for item in cls)
            raise ValueError(f"invalid severity '{value}'; choose one of: {choices}") from exc


class Capability(StrEnum):
    """Source-level side effects observed in code reachable from a tool."""

    CODE_EXECUTION = "code_execution"
    ENVIRONMENT_READ = "environment_read"
    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    NETWORK_EGRESS = "network_egress"
    PROCESS_EXECUTION = "process_execution"


class AnalysisStatus(StrEnum):
    """Trust state for the bounded static analysis."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class UnresolvedReason(StrEnum):
    """Stable categories for project-local behavior that was not followed."""

    AMBIGUOUS_LOCAL_TARGET = "ambiguous local target"
    DYNAMIC_IMPORT = "dynamic import"
    GRAPH_RESOURCE_BUDGET = "graph/resource budget"
    HIGHER_ORDER_CALL = "higher-order call"
    MISSING_LOCAL_TARGET = "missing local target"
    UNRESOLVED_REEXPORT = "unresolved re-export"
    UNSUPPORTED_INSTANCE_DISPATCH = "unsupported instance/class dispatch"
    WILDCARD_IMPORT = "wildcard import"
    WRAPPER_INDIRECTION = "wrapper/decorator indirection"


@dataclass(frozen=True)
class Parameter:
    """A statically extracted Python tool parameter."""

    name: str
    annotation: str = ""
    default: str | None = None
    required: bool = True


@dataclass(frozen=True)
class ToolDefinition:
    """A statically discovered MCP tool definition."""

    name: str
    function_name: str
    description: str
    source_file: str
    line_number: int
    end_line: int
    parameters: tuple[Parameter, ...] = ()
    annotations: dict[str, Any] = field(default_factory=dict)
    wrapper_expressions: tuple[tuple[int, str], ...] = ()

    @property
    def read_only_claimed(self) -> bool:
        return self.annotations.get("readOnlyHint") is True

    @property
    def closed_world_claimed(self) -> bool:
        return self.annotations.get("openWorldHint") is False

    @property
    def key(self) -> str:
        """Stable per-report identity that does not assume tool names are unique."""

        return f"{self.source_file}:{self.line_number}:{self.name}"


@dataclass(frozen=True)
class Evidence:
    """A source location supporting an observed capability or finding."""

    source_file: str
    line_number: int
    symbol: str
    detail: str

    @property
    def location(self) -> str:
        return f"{self.source_file}:{self.line_number}"


@dataclass(frozen=True)
class ObservedCapability:
    """A capability observed in code reachable from an MCP tool."""

    capability: Capability
    evidence: Evidence


@dataclass(frozen=True)
class Finding:
    """An evidence-backed mismatch or security concern."""

    rule_id: str
    title: str
    severity: Severity
    tool_name: str
    message: str
    remediation: str
    evidence: Evidence


@dataclass(frozen=True)
class Diagnostic:
    """A non-finding problem encountered while parsing the target."""

    source_file: str
    message: str
    line_number: int = 0
    status: AnalysisStatus = AnalysisStatus.FAILED


@dataclass(frozen=True)
class ResolvedCallEdge:
    """A reachable, statically resolved project-local call."""

    tool_name: str
    source_file: str
    line_number: int
    caller: str
    call_expression: str
    target_file: str
    target_symbol: str


@dataclass(frozen=True)
class UnresolvedCallEdge:
    """A reachable call that may enter project-local code but was not resolved."""

    tool_name: str
    source_file: str
    line_number: int
    caller: str
    call_expression: str
    reason: UnresolvedReason
    candidate: str = ""


@dataclass(frozen=True)
class PotentialRegistration:
    """A statically visible MCP registration form outside the supported model."""

    source_file: str
    line_number: int
    expression: str
    reason: str
    potential_tool_count: int = 1


@dataclass(frozen=True)
class AnalysisNotification:
    """A non-vulnerability notification about analysis completeness."""

    code: str
    message: str
    source_file: str = "<target>"
    line_number: int = 0


@dataclass
class AnalysisCompleteness:
    """Deterministic ledger of supported and unresolved analysis work."""

    status: AnalysisStatus
    supported_registrations: int
    unresolved_registrations: int
    resolved_edges: list[ResolvedCallEdge] = field(default_factory=list)
    unresolved_edges: list[UnresolvedCallEdge] = field(default_factory=list)
    potential_registrations: list[PotentialRegistration] = field(default_factory=list)
    notifications: list[AnalysisNotification] = field(default_factory=list)


@dataclass
class AuditReport:
    """Complete result of a static audit."""

    target: Path
    files_scanned: int
    tools: list[ToolDefinition]
    capabilities: dict[str, list[ObservedCapability]]
    findings: list[Finding]
    diagnostics: list[Diagnostic]
    completeness: AnalysisCompleteness
    snapshot: str

    def findings_at_or_above(self, threshold: Severity) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity >= threshold]

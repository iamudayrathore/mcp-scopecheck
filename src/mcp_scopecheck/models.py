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

    @property
    def read_only_claimed(self) -> bool:
        return self.annotations.get("readOnlyHint") is True

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


@dataclass
class AuditReport:
    """Complete result of a static audit."""

    target: Path
    files_scanned: int
    tools: list[ToolDefinition]
    capabilities: dict[str, list[ObservedCapability]]
    findings: list[Finding]
    diagnostics: list[Diagnostic]
    snapshot: str

    def findings_at_or_above(self, threshold: Severity) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity >= threshold]

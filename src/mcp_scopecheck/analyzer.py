"""Reachability-aware capability and contract analysis."""

from __future__ import annotations

import ast
import re
from collections import deque
from collections.abc import Iterable

from .models import (
    Capability,
    Evidence,
    Finding,
    ObservedCapability,
    Severity,
    ToolDefinition,
)
from .parser import FunctionRecord, ParsedProject

FILE_READ_SUFFIXES = (
    ".glob",
    ".iterdir",
    ".read_bytes",
    ".read_text",
    ".rglob",
)
FILE_WRITE_SUFFIXES = (
    ".chmod",
    ".mkdir",
    ".rename",
    ".replace",
    ".rmdir",
    ".touch",
    ".unlink",
    ".write_bytes",
    ".write_text",
)
FILE_WRITE_CALLS = {
    "os.makedirs",
    "os.mkdir",
    "os.remove",
    "os.rename",
    "os.replace",
    "os.rmdir",
    "os.unlink",
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
    "shutil.move",
    "shutil.rmtree",
}
NETWORK_PREFIXES = (
    "aiohttp.",
    "http.client.",
    "httpx.",
    "requests.",
    "socket.",
    "urllib.request.",
)
NETWORK_READ_METHODS = {"get", "head", "options"}
NETWORK_WRITE_METHODS = {"delete", "patch", "post", "put"}
PROCESS_PREFIXES = ("asyncio.create_subprocess_", "subprocess.")
PROCESS_CALLS = {"os.popen", "os.system"}
PATH_GUARDS = {
    "os.path.commonpath",
    "pathlib.Path.is_relative_to",
    "pathlib.Path.relative_to",
}
PATH_PARAMETER_NAMES = {
    "dir",
    "directory",
    "file",
    "file_path",
    "filename",
    "folder",
    "path",
    "root",
}

POISONING_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?)", re.I),
        "instruction override",
    ),
    (
        re.compile(
            r"(?:do\s+not|don't|never)\s+(?:tell|show|mention|reveal)\s+(?:the\s+)?user",
            re.I,
        ),
        "concealment instruction",
    ),
    (re.compile(r"secret(?:ly)?\s+(?:collect|do|perform|send|execute)", re.I), "hidden action"),
    (
        re.compile(
            r"(?:before|after)\s+(?:any|all|every)\s+(?:call|request|response|tool)",
            re.I,
        ),
        "cross-call instruction",
    ),
    (
        re.compile(
            r"(?:collect|read|send|upload|exfiltrate).{0,40}"
            r"(?:credential|secret|token|api[_ -]?key)",
            re.I | re.S,
        ),
        "credential-handling instruction",
    ),
    (re.compile(r"<\|.*?\|>", re.S), "hidden-token marker"),
)


def _qualified_name(node: ast.AST, imports: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return imports.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value, imports)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        prefix = _qualified_name(node.func, imports)
        return f"{prefix}()" if prefix else ""
    return ""


def _local_calls(record: FunctionRecord, project: ParsedProject) -> Iterable[FunctionRecord]:
    for node in ast.walk(record.node):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        target = project.functions.get((record.source_file, node.func.id))
        if target is not None:
            yield target


def reachable_functions(project: ParsedProject, tool: ToolDefinition) -> list[FunctionRecord]:
    """Return same-file functions reachable from a tool, without executing code."""

    root = project.functions.get((tool.source_file, tool.function_name))
    if root is None:
        return []
    queue: deque[FunctionRecord] = deque([root])
    visited: set[tuple[str, str]] = set()
    records: list[FunctionRecord] = []
    while queue:
        record = queue.popleft()
        key = (record.source_file, record.node.name)
        if key in visited:
            continue
        visited.add(key)
        records.append(record)
        queue.extend(_local_calls(record, project))
    return records


def _open_capability(call: ast.Call, name: str) -> Capability | None:
    if name not in {"open", "builtins.open", "io.open"} and not name.endswith(".open"):
        return None
    mode_node: ast.AST | None = None
    if len(call.args) >= 2:
        mode_node = call.args[1]
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    mode = "r"
    if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
        mode = mode_node.value
    return (
        Capability.FILESYSTEM_WRITE
        if any(char in mode for char in "wax+")
        else Capability.FILESYSTEM_READ
    )


def _call_capability(call: ast.Call, name: str) -> Capability | None:
    opened = _open_capability(call, name)
    if opened is not None:
        return opened
    if name.endswith(FILE_READ_SUFFIXES):
        return Capability.FILESYSTEM_READ
    if name in FILE_WRITE_CALLS or name.endswith(FILE_WRITE_SUFFIXES):
        return Capability.FILESYSTEM_WRITE
    if name == "os.getenv" or name.endswith(".environ.get"):
        return Capability.ENVIRONMENT_READ
    if name.startswith(NETWORK_PREFIXES):
        return Capability.NETWORK_EGRESS
    if name in PROCESS_CALLS or name.startswith(PROCESS_PREFIXES):
        return Capability.PROCESS_EXECUTION
    if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
        return Capability.CODE_EXECUTION
    return None


def _network_method_kind(symbol: str) -> str:
    if not symbol.startswith(("aiohttp.", "httpx.", "requests.")):
        return "unknown"
    method = symbol.rsplit(".", 1)[-1].lower()
    if method in NETWORK_READ_METHODS:
        return "read"
    if method in NETWORK_WRITE_METHODS:
        return "write"
    return "unknown"


def _environment_subscript(node: ast.Subscript, imports: dict[str, str]) -> bool:
    return _qualified_name(node.value, imports) in {"os.environ", "environ"}


def _line_number(node: ast.AST) -> int:
    line_number = getattr(node, "lineno", 0)
    return line_number if isinstance(line_number, int) else 0


def analyze_capabilities(
    project: ParsedProject,
    tool: ToolDefinition,
) -> list[ObservedCapability]:
    """Find side effects in code reachable from one MCP tool."""

    observed: list[ObservedCapability] = []
    seen: set[tuple[Capability, str, int, str]] = set()
    for record in reachable_functions(project, tool):
        for node in ast.walk(record.node):
            capability: Capability | None = None
            symbol = ""
            if isinstance(node, ast.Call):
                symbol = _qualified_name(node.func, record.imports)
                capability = _call_capability(node, symbol)
            elif isinstance(node, ast.Subscript) and _environment_subscript(node, record.imports):
                symbol = _qualified_name(node.value, record.imports)
                capability = Capability.ENVIRONMENT_READ
            if capability is None:
                continue
            line_number = _line_number(node)
            key = (capability, record.source_file, line_number, symbol)
            if key in seen:
                continue
            seen.add(key)
            observed.append(
                ObservedCapability(
                    capability,
                    Evidence(
                        record.source_file,
                        line_number,
                        symbol,
                        f"reachable from {tool.function_name}()",
                    ),
                )
            )
    observed.sort(
        key=lambda item: (
            item.capability.value,
            item.evidence.location,
            item.evidence.symbol,
        )
    )
    return observed


def _has_path_guard(records: Iterable[FunctionRecord]) -> bool:
    for record in records:
        for node in ast.walk(record.node):
            if not isinstance(node, ast.Call):
                continue
            name = _qualified_name(node.func, record.imports)
            if name in PATH_GUARDS or name.endswith((".is_relative_to", ".relative_to")):
                return True
    return False


def _reads_environment(node: ast.AST, imports: dict[str, str]) -> bool:
    return any(
        (
            isinstance(child, ast.Call)
            and _call_capability(child, _qualified_name(child.func, imports))
            == Capability.ENVIRONMENT_READ
        )
        or (isinstance(child, ast.Subscript) and _environment_subscript(child, imports))
        for child in ast.walk(node)
    )


def _names(node: ast.AST) -> set[str]:
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _source_position(node: ast.AST) -> tuple[int, int, int]:
    assignment_first = 0 if isinstance(node, (ast.Assign, ast.AnnAssign)) else 1
    return (
        _line_number(node),
        getattr(node, "col_offset", 0),
        assignment_first,
    )


def _tainted_environment_to_network(record: FunctionRecord) -> Evidence | None:
    tainted: set[str] = set()
    for node in sorted(ast.walk(record.node), key=_source_position):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            assigned = {name for target in targets for name in _names(target)}
            value_is_tainted = _reads_environment(value, record.imports) or bool(
                _names(value) & tainted
            )
            tainted.difference_update(assigned)
            if value_is_tainted:
                tainted.update(assigned)
            continue

        if not isinstance(node, ast.Call):
            continue
        name = _qualified_name(node.func, record.imports)
        if _call_capability(node, name) != Capability.NETWORK_EGRESS:
            continue
        if _names(node) & tainted or _reads_environment(node, record.imports):
            return Evidence(
                record.source_file,
                _line_number(node),
                name,
                "environment-derived data reaches a network call in the same function",
            )
    return None


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    tool: ToolDefinition,
    message: str,
    remediation: str,
    evidence: Evidence,
) -> Finding:
    return Finding(rule_id, title, severity, tool.name, message, remediation, evidence)


def analyze_contract(
    project: ParsedProject,
    tool: ToolDefinition,
    observed: list[ObservedCapability],
) -> list[Finding]:
    """Compare declared tool behavior with statically observed capabilities."""

    findings: list[Finding] = []
    capabilities = {item.capability for item in observed}
    by_capability = {item.capability: item.evidence for item in observed}
    description_evidence = Evidence(
        tool.source_file,
        tool.line_number,
        "tool description",
        tool.description[:160] or "empty description",
    )

    for pattern, label in POISONING_PATTERNS:
        match = pattern.search(tool.description)
        if match:
            findings.append(
                _finding(
                    "MSC001",
                    "Agent-directed instruction in tool description",
                    Severity.CRITICAL,
                    tool,
                    f"The tool description contains a {label}: {match.group(0)!r}.",
                    "Describe the tool's behavior and constraints; remove instructions "
                    "aimed at controlling the host model.",
                    description_evidence,
                )
            )
            break

    state_changing = {
        Capability.CODE_EXECUTION,
        Capability.FILESYSTEM_WRITE,
        Capability.PROCESS_EXECUTION,
    }
    if tool.read_only_claimed:
        conflicts = {
            capability: by_capability[capability]
            for capability in capabilities & state_changing
        }
        for item in observed:
            if (
                item.capability == Capability.NETWORK_EGRESS
                and _network_method_kind(item.evidence.symbol) == "write"
            ):
                conflicts.setdefault(Capability.NETWORK_EGRESS, item.evidence)
        for capability, evidence in sorted(
            conflicts.items(),
            key=lambda item: item[0].value,
        ):
            severity = Severity.CRITICAL if capability in {
                Capability.CODE_EXECUTION,
                Capability.PROCESS_EXECUTION,
            } else Severity.HIGH
            findings.append(
                _finding(
                    "MSC101",
                    "Read-only claim conflicts with reachable behavior",
                    severity,
                    tool,
                    f"readOnlyHint is true, but {capability.value.replace('_', ' ')} is reachable.",
                    "Remove the side effect or correct the annotation and require "
                    "explicit user approval.",
                    evidence,
                )
            )

    if tool.closed_world_claimed and Capability.NETWORK_EGRESS in capabilities:
        findings.append(
            _finding(
                "MSC108",
                "Closed-world claim conflicts with network egress",
                Severity.HIGH,
                tool,
                "openWorldHint is false, but external network interaction is reachable.",
                "Remove external interaction or correct the annotation and disclose "
                "the destination and data purpose.",
                by_capability[Capability.NETWORK_EGRESS],
            )
        )

    if Capability.NETWORK_EGRESS in capabilities:
        disclosed = re.search(
            r"\b(api|http|network|remote|send|telemetry|upload|webhook)\b",
            tool.description,
            re.I,
        )
        if not disclosed:
            findings.append(
                _finding(
                    "MSC102",
                    "Network egress is not disclosed",
                    Severity.HIGH,
                    tool,
                    "A reachable network call is absent from the tool's description.",
                    "State the destination and data purpose, or remove network access.",
                    by_capability[Capability.NETWORK_EGRESS],
                )
            )

    path_parameters = {
        parameter.name
        for parameter in tool.parameters
        if parameter.name.lstrip("*").lower() in PATH_PARAMETER_NAMES
    }
    records = reachable_functions(project, tool)
    if path_parameters and capabilities & {
        Capability.FILESYSTEM_READ,
        Capability.FILESYSTEM_WRITE,
    } and not _has_path_guard(records):
        filesystem_capability = (
            Capability.FILESYSTEM_WRITE
            if Capability.FILESYSTEM_WRITE in capabilities
            else Capability.FILESYSTEM_READ
        )
        findings.append(
            _finding(
                "MSC103",
                "Filesystem scope is not constrained",
                Severity.HIGH,
                tool,
                f"Path-like parameter(s) {sorted(path_parameters)} reach filesystem "
                "operations without a recognized containment check.",
                "Resolve the candidate path and prove it remains beneath a fixed, "
                "trusted root before access.",
                by_capability[filesystem_capability],
            )
        )

    for parameter in tool.parameters:
        if parameter.name.lstrip("*").lower() not in PATH_PARAMETER_NAMES:
            continue
        if parameter.default in {"'/'", '"/"', "'~'", '"~"'}:
            findings.append(
                _finding(
                    "MSC104",
                    "Dangerous filesystem default",
                    Severity.HIGH,
                    tool,
                    f"Parameter '{parameter.name}' defaults to {parameter.default}, "
                    "expanding access beyond a project root.",
                    "Remove the caller-controlled root and bind access to a fixed "
                    "application directory.",
                    description_evidence,
                )
            )

    for record in records:
        flow = _tainted_environment_to_network(record)
        if flow:
            findings.append(
                _finding(
                    "MSC105",
                    "Environment data reaches network egress",
                    Severity.CRITICAL,
                    tool,
                    "Environment-derived data flows into a network call in reachable code.",
                    "Do not transmit environment values; use explicit allowlists and "
                    "redact sensitive fields.",
                    flow,
                )
            )
            break

    if Capability.PROCESS_EXECUTION in capabilities:
        findings.append(
            _finding(
                "MSC106",
                "Process execution is reachable",
                Severity.CRITICAL,
                tool,
                "The tool can launch a process or shell command.",
                "Remove process execution or enforce a fixed command allowlist outside "
                "model control.",
                by_capability[Capability.PROCESS_EXECUTION],
            )
        )
    if Capability.CODE_EXECUTION in capabilities:
        findings.append(
            _finding(
                "MSC107",
                "Dynamic code execution is reachable",
                Severity.CRITICAL,
                tool,
                "The tool can evaluate dynamically supplied code.",
                "Remove eval/exec and use a constrained parser or explicit operation mapping.",
                by_capability[Capability.CODE_EXECUTION],
            )
        )

    unique = {
        (item.rule_id, item.tool_name, item.evidence.location, item.evidence.symbol): item
        for item in findings
    }
    return sorted(
        unique.values(),
        key=lambda item: (-int(item.severity), item.rule_id, item.evidence.location),
    )

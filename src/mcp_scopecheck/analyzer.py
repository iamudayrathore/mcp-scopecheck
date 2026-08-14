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

PATH_READ_METHODS = {"glob", "iterdir", "read_bytes", "read_text", "rglob"}
PATH_WRITE_METHODS = {
    "chmod",
    "mkdir",
    "rename",
    "replace",
    "rmdir",
    "touch",
    "unlink",
    "write_bytes",
    "write_text",
}
PATH_RETURNING_METHODS = {
    "absolute",
    "expanduser",
    "joinpath",
    "resolve",
    "with_name",
    "with_suffix",
}
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
OS_OPEN_WRITE_FLAGS = {
    "os.O_APPEND",
    "os.O_CREAT",
    "os.O_RDWR",
    "os.O_TRUNC",
    "os.O_WRONLY",
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
NETWORK_CLIENT_METHODS = {
    "httpx.Client": frozenset(
        {"delete", "get", "head", "options", "patch", "post", "put", "request", "send", "stream"}
    ),
    "httpx.AsyncClient": frozenset(
        {"delete", "get", "head", "options", "patch", "post", "put", "request", "send", "stream"}
    ),
    "requests.Session": frozenset(
        {"delete", "get", "head", "options", "patch", "post", "put", "request", "send"}
    ),
    "requests.sessions.Session": frozenset(
        {"delete", "get", "head", "options", "patch", "post", "put", "request", "send"}
    ),
}
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


def _mode_capability(call: ast.Call, positional_index: int) -> Capability:
    mode_node: ast.AST | None = None
    if len(call.args) > positional_index:
        mode_node = call.args[positional_index]
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


def _os_open_writes(node: ast.AST, imports: dict[str, str]) -> bool | None:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _os_open_writes(node.left, imports)
        right = _os_open_writes(node.right, imports)
        if left is True or right is True:
            return True
        if left is False and right is False:
            return False
        return None
    name = _qualified_name(node, imports)
    if name in OS_OPEN_WRITE_FLAGS:
        return True
    if name == "os.O_RDONLY":
        return False
    if isinstance(node, ast.Constant) and node.value == 0:
        return False
    return None


def _os_open_capability(call: ast.Call, imports: dict[str, str]) -> Capability:
    flags: ast.AST | None = call.args[1] if len(call.args) >= 2 else None
    for keyword in call.keywords:
        if keyword.arg == "flags":
            flags = keyword.value
    writes = _os_open_writes(flags, imports) if flags is not None else None
    return Capability.FILESYSTEM_WRITE if writes is True else Capability.FILESYSTEM_READ


def _call_capability(
    call: ast.Call,
    name: str,
    imports: dict[str, str] | None = None,
) -> Capability | None:
    resolved_imports = imports or {}
    if name in {"open", "builtins.open", "io.open"}:
        return _mode_capability(call, 1)
    if name == "os.open":
        return _os_open_capability(call, resolved_imports)
    if name in FILE_WRITE_CALLS:
        return Capability.FILESYSTEM_WRITE
    if name == "os.getenv" or name.endswith(".environ.get"):
        return Capability.ENVIRONMENT_READ
    if name in NETWORK_CLIENT_METHODS:
        return None
    for constructor, methods in NETWORK_CLIENT_METHODS.items():
        instance_prefix = f"{constructor}()."
        if name.startswith(instance_prefix):
            method = name.removeprefix(instance_prefix)
            return Capability.NETWORK_EGRESS if method in methods else None
    if name.startswith(NETWORK_PREFIXES):
        return Capability.NETWORK_EGRESS
    if name in PROCESS_CALLS or name.startswith(PROCESS_PREFIXES):
        return Capability.PROCESS_EXECUTION
    if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
        return Capability.CODE_EXECUTION
    return None


def _network_method_kind(symbol: str) -> str:
    method = symbol.rsplit(".", 1)[-1].lower()
    if method in NETWORK_READ_METHODS:
        return "read"
    if method in NETWORK_WRITE_METHODS:
        return "write"
    return "unknown"


def _assigned_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.List, ast.Tuple)):
        return {
            name
            for item in node.elts
            for name in _assigned_names(item)
        }
    return set()


class _ClientBindingVisitor(ast.NodeVisitor):
    """Track a narrow set of proven network-client names in statement order."""

    def __init__(self, imports: dict[str, str]) -> None:
        self.imports = imports
        self.bindings: dict[str, str] = {}
        self.network_calls: list[tuple[ast.Call, str]] = []

    def scan(self, statements: list[ast.stmt]) -> list[tuple[ast.Call, str]]:
        for statement in statements:
            self.visit(statement)
        return self.network_calls

    def _binding_from_value(self, value: ast.AST) -> str | None:
        if isinstance(value, ast.Name):
            return self.bindings.get(value.id)
        if not isinstance(value, ast.Call):
            return None
        constructor = _qualified_name(value.func, self.imports)
        return constructor if constructor in NETWORK_CLIENT_METHODS else None

    def _update_targets(self, targets: Iterable[ast.AST], binding: str | None) -> None:
        for target in targets:
            for name in _assigned_names(target):
                if binding is None:
                    self.bindings.pop(name, None)
                else:
                    self.bindings[name] = binding

    def _instance_symbol(self, call: ast.Call) -> str | None:
        if not isinstance(call.func, ast.Attribute):
            return None
        method = call.func.attr
        receiver = call.func.value
        if isinstance(receiver, ast.Name):
            constructor = self.bindings.get(receiver.id)
            if constructor and method in NETWORK_CLIENT_METHODS[constructor]:
                return f"{receiver.id}.{method}"
            return None
        if isinstance(receiver, ast.Call):
            constructor = _qualified_name(receiver.func, self.imports)
            if (
                constructor in NETWORK_CLIENT_METHODS
                and method in NETWORK_CLIENT_METHODS[constructor]
            ):
                return f"{constructor}().{method}"
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        self._update_targets(node.targets, self._binding_from_value(node.value))

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        binding = self._binding_from_value(node.value) if node.value is not None else None
        self._update_targets([node.target], binding)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._update_targets([node.target], self._binding_from_value(node.value))

    def visit_Delete(self, node: ast.Delete) -> None:
        self._update_targets(node.targets, None)

    def _visit_for(
        self,
        iterator: ast.AST,
        target: ast.AST,
        body: list[ast.stmt],
        orelse: list[ast.stmt],
    ) -> None:
        self.visit(iterator)
        self._update_targets([target], None)
        for statement in [*body, *orelse]:
            self.visit(statement)

    def visit_For(self, node: ast.For) -> None:
        self._visit_for(node.iter, node.target, node.body, node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_for(node.iter, node.target, node.body, node.orelse)

    def _visit_with(self, items: list[ast.withitem], body: list[ast.stmt]) -> None:
        for item in items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._update_targets(
                    [item.optional_vars],
                    self._binding_from_value(item.context_expr),
                )
        for statement in body:
            self.visit(statement)

    def visit_With(self, node: ast.With) -> None:
        self._visit_with(node.items, node.body)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with(node.items, node.body)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.bindings.pop(node.name, None)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.bindings.pop(node.name, None)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.bindings.pop(node.name, None)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            self.bindings.pop(item.asname or item.name.split(".")[0], None)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            self.bindings.pop(item.asname or item.name, None)

    def visit_Call(self, node: ast.Call) -> None:
        symbol = self._instance_symbol(node)
        if symbol is not None:
            self.network_calls.append((node, symbol))
        self.generic_visit(node)


def _instance_network_calls(record: FunctionRecord) -> list[tuple[ast.Call, str]]:
    return _ClientBindingVisitor(record.imports).scan(record.node.body)


class _PathBindingVisitor(ast.NodeVisitor):
    """Classify pathlib operations only on statically proven Path values."""

    def __init__(self, record: FunctionRecord) -> None:
        self.imports = record.imports
        self.bindings = set(record.path_bindings)
        self.filesystem_calls: list[tuple[ast.Call, str, Capability]] = []

    def scan(self, statements: list[ast.stmt]) -> list[tuple[ast.Call, str, Capability]]:
        for statement in statements:
            self.visit(statement)
        return self.filesystem_calls

    def _is_path_value(self, value: ast.AST) -> bool:
        if isinstance(value, ast.Name):
            return value.id in self.bindings
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div):
            return self._is_path_value(value.left)
        if isinstance(value, ast.Attribute) and value.attr == "parent":
            return self._is_path_value(value.value)
        if not isinstance(value, ast.Call):
            return False
        if _qualified_name(value.func, self.imports) == "pathlib.Path":
            return True
        return (
            isinstance(value.func, ast.Attribute)
            and value.func.attr in PATH_RETURNING_METHODS
            and self._is_path_value(value.func.value)
        )

    def _update_targets(self, targets: Iterable[ast.AST], is_path: bool) -> None:
        for target in targets:
            for name in _assigned_names(target):
                self.bindings.discard(name)
                if is_path:
                    self.bindings.add(name)

    def _path_call(self, call: ast.Call) -> tuple[str, Capability] | None:
        if not isinstance(call.func, ast.Attribute):
            return None
        if not self._is_path_value(call.func.value):
            return None
        method = call.func.attr
        symbol = _qualified_name(call.func, self.imports)
        if method in PATH_READ_METHODS:
            return symbol, Capability.FILESYSTEM_READ
        if method in PATH_WRITE_METHODS:
            return symbol, Capability.FILESYSTEM_WRITE
        if method == "open":
            return symbol, _mode_capability(call, 0)
        return None

    def _is_path_iterator(self, value: ast.AST) -> bool:
        return (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr in {"glob", "iterdir", "rglob"}
            and self._is_path_value(value.func.value)
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        self._update_targets(node.targets, self._is_path_value(node.value))

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        is_path = node.value is not None and self._is_path_value(node.value)
        self._update_targets([node.target], is_path)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._update_targets([node.target], self._is_path_value(node.value))

    def visit_Delete(self, node: ast.Delete) -> None:
        self._update_targets(node.targets, False)

    def _visit_for(
        self,
        iterator: ast.AST,
        target: ast.AST,
        body: list[ast.stmt],
        orelse: list[ast.stmt],
    ) -> None:
        self.visit(iterator)
        self._update_targets([target], self._is_path_iterator(iterator))
        for statement in [*body, *orelse]:
            self.visit(statement)

    def visit_For(self, node: ast.For) -> None:
        self._visit_for(node.iter, node.target, node.body, node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_for(node.iter, node.target, node.body, node.orelse)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.bindings.discard(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.bindings.discard(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.bindings.discard(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            self.bindings.discard(item.asname or item.name.split(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            self.bindings.discard(item.asname or item.name)

    def visit_Call(self, node: ast.Call) -> None:
        path_call = self._path_call(node)
        if path_call is not None:
            symbol, capability = path_call
            self.filesystem_calls.append((node, symbol, capability))
        self.generic_visit(node)


def _path_filesystem_calls(
    record: FunctionRecord,
) -> list[tuple[ast.Call, str, Capability]]:
    return _PathBindingVisitor(record).scan(record.node.body)


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
        instance_network_calls = {
            id(call): symbol
            for call, symbol in _instance_network_calls(record)
        }
        path_filesystem_calls = {
            id(call): (symbol, capability)
            for call, symbol, capability in _path_filesystem_calls(record)
        }
        for node in ast.walk(record.node):
            capability: Capability | None = None
            symbol = ""
            if isinstance(node, ast.Call):
                instance_symbol = instance_network_calls.get(id(node))
                path_call = path_filesystem_calls.get(id(node))
                if path_call is not None:
                    symbol, capability = path_call
                elif instance_symbol is not None:
                    symbol = instance_symbol
                    capability = Capability.NETWORK_EGRESS
                else:
                    symbol = _qualified_name(node.func, record.imports)
                    capability = _call_capability(node, symbol, record.imports)
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
            and _call_capability(child, _qualified_name(child.func, imports), imports)
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
    instance_network_calls = {
        id(call): symbol
        for call, symbol in _instance_network_calls(record)
    }
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
        name = instance_network_calls.get(id(node))
        if name is None:
            name = _qualified_name(node.func, record.imports)
        if (
            id(node) not in instance_network_calls
            and _call_capability(node, name, record.imports) != Capability.NETWORK_EGRESS
        ):
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

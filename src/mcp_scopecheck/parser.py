"""Non-executing Python source discovery for MCP tools."""

from __future__ import annotations

import ast
import inspect
import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeAlias

from .models import Diagnostic, Parameter, ToolDefinition

SKIP_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}
MAX_SOURCE_BYTES = 1_000_000
MAX_SOURCE_FILES = 5_000
MAX_METADATA_NODES = 256
MAX_METADATA_DEPTH = 12
MAX_METADATA_STRING_BYTES = 16_384
MAX_METADATA_INTEGER_BITS = 256
MAX_METADATA_COLLECTION_ITEMS = 128

MetadataValue: TypeAlias = (
    None
    | bool
    | int
    | float
    | str
    | list["MetadataValue"]
    | dict[str, "MetadataValue"]
)

_BOOLEAN_ANNOTATIONS = {
    "destructiveHint",
    "destructive_hint",
    "idempotentHint",
    "idempotent_hint",
    "openWorldHint",
    "open_world_hint",
    "readOnlyHint",
    "read_only_hint",
}


class ParseTargetError(ValueError):
    """Raised when an audit target cannot be read safely."""


class MetadataDecodeError(ValueError):
    """Raised when static tool metadata is unsupported or exceeds its budget."""


@dataclass
class _MetadataBudget:
    nodes: int = 0
    string_bytes: int = 0
    collection_items: int = 0

    def consume_node(self, depth: int) -> None:
        if depth > MAX_METADATA_DEPTH:
            raise MetadataDecodeError(
                f"metadata exceeds maximum nesting depth of {MAX_METADATA_DEPTH}"
            )
        if self.nodes + 1 > MAX_METADATA_NODES:
            raise MetadataDecodeError(
                f"metadata exceeds {MAX_METADATA_NODES} decoded nodes"
            )
        self.nodes += 1

    def consume_string(self, value: str) -> None:
        encoded_size = len(value.encode("utf-8", errors="surrogatepass"))
        if self.string_bytes + encoded_size > MAX_METADATA_STRING_BYTES:
            raise MetadataDecodeError(
                f"metadata strings exceed {MAX_METADATA_STRING_BYTES} UTF-8 bytes"
            )
        self.string_bytes += encoded_size

    def consume_collection(self, size: int) -> None:
        if self.collection_items + size > MAX_METADATA_COLLECTION_ITEMS:
            raise MetadataDecodeError(
                f"metadata collections exceed {MAX_METADATA_COLLECTION_ITEMS} items"
            )
        self.collection_items += size


@dataclass
class FunctionRecord:
    """Internal representation of a function in a parsed source file."""

    source_file: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    imports: dict[str, str]


@dataclass
class ParsedProject:
    """Static project representation used by capability analysis."""

    root: Path
    files_scanned: int = 0
    tools: list[ToolDefinition] = field(default_factory=list)
    functions: dict[tuple[str, str], FunctionRecord] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)


def _safe_unparse(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _node_line_number(node: ast.AST) -> int:
    line_number = getattr(node, "lineno", 0)
    return line_number if isinstance(line_number, int) else 0


def _decode_metadata(
    node: ast.AST,
    budget: _MetadataBudget,
    depth: int = 0,
) -> MetadataValue:
    budget.consume_node(depth)

    if isinstance(node, ast.Constant):
        constant_value = node.value
        if constant_value is None or isinstance(constant_value, bool):
            return constant_value
        if isinstance(constant_value, str):
            budget.consume_string(constant_value)
            return constant_value
        if isinstance(constant_value, int):
            if abs(constant_value).bit_length() > MAX_METADATA_INTEGER_BITS:
                raise MetadataDecodeError(
                    f"metadata integer exceeds {MAX_METADATA_INTEGER_BITS} bits"
                )
            return constant_value
        if isinstance(constant_value, float):
            if not math.isfinite(constant_value):
                raise MetadataDecodeError("metadata numbers must be finite")
            return constant_value
        raise MetadataDecodeError(
            f"unsupported metadata value type: {type(constant_value).__name__}"
        )

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        operand_value = _decode_metadata(node.operand, budget, depth + 1)
        if isinstance(operand_value, bool) or not isinstance(operand_value, (int, float)):
            raise MetadataDecodeError("unary metadata values must be numbers")
        numeric_result = operand_value if isinstance(node.op, ast.UAdd) else -operand_value
        if (
            isinstance(numeric_result, int)
            and abs(numeric_result).bit_length() > MAX_METADATA_INTEGER_BITS
        ):
            raise MetadataDecodeError(
                f"metadata integer exceeds {MAX_METADATA_INTEGER_BITS} bits"
            )
        if isinstance(numeric_result, float) and not math.isfinite(numeric_result):
            raise MetadataDecodeError("metadata numbers must be finite")
        return numeric_result

    if isinstance(node, (ast.List, ast.Tuple)):
        budget.consume_collection(len(node.elts))
        return [
            _decode_metadata(item, budget, depth + 1)
            for item in node.elts
        ]

    if isinstance(node, ast.Dict):
        budget.consume_collection(len(node.keys))
        mapping: dict[str, MetadataValue] = {}
        for key_node, value_node in zip(node.keys, node.values, strict=True):
            if key_node is None:
                raise MetadataDecodeError("metadata dictionary expansion is not supported")
            key = _decode_metadata(key_node, budget, depth + 1)
            if not isinstance(key, str):
                raise MetadataDecodeError("metadata dictionary keys must be strings")
            mapping[key] = _decode_metadata(value_node, budget, depth + 1)
        return mapping

    raise MetadataDecodeError(f"unsupported metadata syntax: {type(node).__name__}")


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        prefix = _call_name(node.func)
        return f"{prefix}()" if prefix else ""
    return ""


def _is_tool_decorator(node: ast.AST) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    name = _call_name(target)
    return name == "tool" or name.endswith(".tool")


def _tool_metadata(
    decorator: ast.AST,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, str, dict[str, Any], list[str]]:
    name = function.name
    description = ""
    annotations: dict[str, Any] = {}
    errors: list[str] = []
    budget = _MetadataBudget()
    explicit_description = False

    if isinstance(decorator, ast.Call):
        if len(decorator.args) > 1:
            errors.append("tool decorator accepts at most one positional metadata value")
        if decorator.args:
            try:
                first = _decode_metadata(decorator.args[0], budget)
                if isinstance(first, str):
                    name = first
                else:
                    errors.append("positional tool name must be a string")
            except MetadataDecodeError as exc:
                errors.append(f"positional tool name: {exc}")

        for keyword in decorator.keywords:
            if keyword.arg is None:
                errors.append("tool metadata keyword expansion is not supported")
                continue
            if keyword.arg == "name":
                try:
                    value = _decode_metadata(keyword.value, budget)
                    if isinstance(value, str):
                        name = value
                    else:
                        errors.append("tool name must be a string")
                except MetadataDecodeError as exc:
                    errors.append(f"tool name: {exc}")
            elif keyword.arg == "description":
                try:
                    value = _decode_metadata(keyword.value, budget)
                    if isinstance(value, str):
                        description = inspect.cleandoc(value)
                        explicit_description = True
                    else:
                        errors.append("tool description must be a string")
                except MetadataDecodeError as exc:
                    errors.append(f"tool description: {exc}")
            elif keyword.arg == "annotations":
                try:
                    values = _decode_annotations(keyword.value, budget)
                except MetadataDecodeError as exc:
                    errors.append(f"annotations: {exc}")
                    continue
                for key, value in values.items():
                    if key in _BOOLEAN_ANNOTATIONS and not isinstance(value, bool):
                        errors.append(f"annotation {key!r} must be a boolean")
                        continue
                    annotations[key] = value

    if not explicit_description:
        raw_description = ast.get_docstring(function, clean=False) or ""
        try:
            budget.consume_string(raw_description)
            description = inspect.cleandoc(raw_description)
        except MetadataDecodeError as exc:
            errors.append(f"tool description: {exc}")

    return name, description, annotations, errors


def _decode_annotations(
    node: ast.AST,
    budget: _MetadataBudget,
) -> dict[str, MetadataValue]:
    if isinstance(node, ast.Dict):
        value = _decode_metadata(node, budget)
        if not isinstance(value, dict):
            raise MetadataDecodeError("annotations must be a dictionary")
        return value

    if not isinstance(node, ast.Call):
        raise MetadataDecodeError("annotations must be a dictionary or ToolAnnotations(...)")
    constructor = _call_name(node.func)
    if constructor != "ToolAnnotations" and not constructor.endswith(".ToolAnnotations"):
        raise MetadataDecodeError("unsupported annotations constructor")
    budget.consume_node(0)
    if node.args:
        raise MetadataDecodeError("ToolAnnotations positional values are not supported")
    budget.consume_collection(len(node.keywords))
    result: dict[str, MetadataValue] = {}
    for keyword in node.keywords:
        if keyword.arg is None:
            raise MetadataDecodeError("ToolAnnotations keyword expansion is not supported")
        budget.consume_string(keyword.arg)
        result[keyword.arg] = _decode_metadata(keyword.value, budget, 1)
    return result


def _extract_parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[Parameter, ...]:
    positional = [*function.args.posonlyargs, *function.args.args]
    default_offset = len(positional) - len(function.args.defaults)
    defaults: dict[str, ast.AST] = {
        argument.arg: function.args.defaults[index - default_offset]
        for index, argument in enumerate(positional)
        if index >= default_offset
    }
    defaults.update(
        {
            argument.arg: default
            for argument, default in zip(
                function.args.kwonlyargs,
                function.args.kw_defaults,
                strict=True,
            )
            if default is not None
        }
    )

    parameters: list[Parameter] = []
    for argument in [*positional, *function.args.kwonlyargs]:
        if argument.arg in {"self", "cls"}:
            continue
        default_node = defaults.get(argument.arg)
        parameters.append(
            Parameter(
                name=argument.arg,
                annotation=_safe_unparse(argument.annotation),
                default=_safe_unparse(default_node) if default_node is not None else None,
                required=default_node is None,
            )
        )

    if function.args.vararg:
        parameters.append(
            Parameter(
                name=f"*{function.args.vararg.arg}",
                annotation=_safe_unparse(function.args.vararg.annotation),
                required=False,
            )
        )
    if function.args.kwarg:
        parameters.append(
            Parameter(
                name=f"**{function.args.kwarg.arg}",
                annotation=_safe_unparse(function.args.kwarg.annotation),
                required=False,
            )
        )
    return tuple(parameters)


def _imports(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def _candidate_files(target: Path) -> Iterable[Path]:
    if target.is_file():
        if target.suffix != ".py":
            raise ParseTargetError("v0.1 accepts a Python file or a directory containing Python")
        yield target
        return

    candidates: list[Path] = []
    for path in target.rglob("*.py"):
        relative = path.relative_to(target)
        if any(part in SKIP_DIRECTORIES for part in relative.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        candidates.append(path)
        if len(candidates) > MAX_SOURCE_FILES:
            raise ParseTargetError(f"target exceeds the {MAX_SOURCE_FILES}-file safety limit")

    yield from sorted(candidates)


def parse_project(target: str | Path) -> ParsedProject:
    """Parse MCP tool declarations without importing or executing target code."""

    requested = Path(target).expanduser()
    if requested.is_symlink():
        raise ParseTargetError(f"target must not be a symlink: {requested}")
    if not requested.exists():
        raise ParseTargetError(f"target does not exist: {requested}")
    root = requested.resolve()
    if not root.is_file() and not root.is_dir():
        raise ParseTargetError(f"target is not a regular file or directory: {requested}")
    project_root = root.parent if root.is_file() else root
    project = ParsedProject(root=project_root)

    for path in _candidate_files(root):
        relative = path.relative_to(project_root).as_posix()
        try:
            size = path.stat().st_size
        except OSError as exc:
            project.diagnostics.append(Diagnostic(relative, f"unable to stat file: {exc}"))
            continue
        if size > MAX_SOURCE_BYTES:
            project.diagnostics.append(
                Diagnostic(relative, f"skipped: file exceeds {MAX_SOURCE_BYTES} bytes")
            )
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            project.diagnostics.append(Diagnostic(relative, f"unable to read file: {exc}"))
            continue

        project.files_scanned += 1
        try:
            tree = ast.parse(content, filename=relative)
        except SyntaxError as exc:
            project.diagnostics.append(
                Diagnostic(relative, exc.msg, line_number=exc.lineno or 0)
            )
            continue

        aliases = _imports(tree)
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            project.functions[(relative, node.name)] = FunctionRecord(relative, node, aliases)
            for decorator in node.decorator_list:
                if not _is_tool_decorator(decorator):
                    continue
                name, description, annotations, metadata_errors = _tool_metadata(
                    decorator,
                    node,
                )
                for message in metadata_errors:
                    project.diagnostics.append(
                        Diagnostic(
                            relative,
                            f"invalid tool metadata: {message}",
                            line_number=_node_line_number(decorator),
                        )
                    )
                project.tools.append(
                    ToolDefinition(
                        name=name,
                        function_name=node.name,
                        description=description,
                        source_file=relative,
                        line_number=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        parameters=_extract_parameters(node),
                        annotations=annotations,
                    )
                )
                break

    project.tools.sort(key=lambda item: (item.source_file, item.line_number, item.name))
    return project

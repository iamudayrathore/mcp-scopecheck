"""Non-executing Python source discovery for MCP tools."""

from __future__ import annotations

import ast
import inspect
import io
import math
import os
import tokenize
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
MAX_TOTAL_SOURCE_BYTES = 20_000_000
MAX_TOTAL_AST_NODES = 500_000
MAX_AST_DEPTH = 200
MAX_DIAGNOSTICS = 100
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

_ANNOTATION_ALIASES = {
    "readOnlyHint": ("readOnlyHint", "read_only_hint"),
    "destructiveHint": ("destructiveHint", "destructive_hint"),
    "idempotentHint": ("idempotentHint", "idempotent_hint"),
    "openWorldHint": ("openWorldHint", "open_world_hint"),
}
_BOOLEAN_ANNOTATIONS = frozenset(
    alias
    for aliases in _ANNOTATION_ALIASES.values()
    for alias in aliases
)


class ParseTargetError(ValueError):
    """Raised when an audit target cannot be read safely."""


class MetadataDecodeError(ValueError):
    """Raised when static tool metadata is unsupported or exceeds its budget."""


class AnalysisBudgetExceeded(ValueError):
    """Raised internally when a total static-analysis budget is exhausted."""


class SourceDecodeError(ValueError):
    """Raised when Python source bytes cannot be decoded without loss."""


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
    path_bindings: frozenset[str] = frozenset()
    client_bindings: dict[str, str] = field(default_factory=dict)


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


def _decode_python_source(source: bytes) -> str:
    """Decode Python bytes according to PEP 263 without replacement characters."""

    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(source).readline)
    except (SyntaxError, UnicodeDecodeError) as exc:
        detail = exc.msg if isinstance(exc, SyntaxError) else str(exc)
        raise SourceDecodeError(f"invalid Python source encoding: {detail}") from exc
    try:
        return source.decode(encoding, errors="strict")
    except LookupError as exc:
        raise SourceDecodeError(f"invalid Python source encoding: unknown {encoding!r}") from exc
    except UnicodeDecodeError as exc:
        raise SourceDecodeError(
            f"invalid Python source encoding: cannot decode as {encoding} "
            f"at byte offset {exc.start}"
        ) from exc


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
    decoded_annotations: dict[str, Any] = {}
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
                    decoded_annotations[key] = value

    if not explicit_description:
        raw_description = ast.get_docstring(function, clean=False) or ""
        try:
            budget.consume_string(raw_description)
            description = inspect.cleandoc(raw_description)
        except MetadataDecodeError as exc:
            errors.append(f"tool description: {exc}")

    annotations, alias_errors = _normalize_annotations(decoded_annotations)
    errors.extend(alias_errors)
    return name, description, annotations, errors


def _normalize_annotations(
    values: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    aliases = {
        alias
        for annotation_aliases in _ANNOTATION_ALIASES.values()
        for alias in annotation_aliases
    }
    normalized = {
        key: value
        for key, value in values.items()
        if key not in aliases
    }
    errors: list[str] = []
    for canonical, (camel_case, snake_case) in _ANNOTATION_ALIASES.items():
        present = [alias for alias in (camel_case, snake_case) if alias in values]
        if not present:
            continue
        if len(present) == 2 and values[camel_case] != values[snake_case]:
            errors.append(
                f"conflicting annotation aliases for {canonical!r}: "
                f"{camel_case}={values[camel_case]!r}, "
                f"{snake_case}={values[snake_case]!r}"
            )
            continue
        normalized[canonical] = values[present[0]]
    return normalized, errors


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
                bound_name = item.asname or item.name.split(".")[0]
                aliases[bound_name] = item.name if item.asname else bound_name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    aliases[target.id] = ""
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            aliases.pop(node.name, None)
        elif isinstance(node, ast.ClassDef):
            aliases[node.name] = ""
    return aliases


def _import_qualified_name(node: ast.AST, imports: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return imports.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = _import_qualified_name(node.value, imports)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _is_path_expression(
    node: ast.AST,
    imports: dict[str, str],
    path_bindings: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in path_bindings
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _is_path_expression(node.left, imports, path_bindings)
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        return _is_path_expression(node.value, imports, path_bindings)
    if not isinstance(node, ast.Call):
        return False
    if _import_qualified_name(node.func, imports) == "pathlib.Path":
        return True
    if isinstance(node.func, ast.Attribute) and node.func.attr in {
        "absolute",
        "expanduser",
        "joinpath",
        "resolve",
        "with_name",
        "with_suffix",
    }:
        return _is_path_expression(node.func.value, imports, path_bindings)
    return False


def _module_path_bindings(tree: ast.Module, imports: dict[str, str]) -> frozenset[str]:
    bindings: set[str] = set()
    for node in tree.body:
        targets: list[ast.AST] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        if not targets:
            continue
        assigned = {
            target.id
            for target in targets
            if isinstance(target, ast.Name)
        }
        is_path = value is not None and _is_path_expression(value, imports, bindings)
        bindings.difference_update(assigned)
        if is_path:
            bindings.update(assigned)
    return frozenset(bindings)


def _candidate_files(target: Path) -> Iterable[Path]:
    if target.is_file():
        if target.suffix != ".py":
            raise ParseTargetError("v0.1 accepts a Python file or a directory containing Python")
        yield target
        return

    def raise_walk_error(error: OSError) -> None:
        raise error

    candidates: list[Path] = []
    for current, directories, files in os.walk(
        target,
        topdown=True,
        onerror=raise_walk_error,
        followlinks=False,
    ):
        current_path = Path(current)
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in SKIP_DIRECTORIES
            and not (current_path / directory).is_symlink()
        )
        for filename in sorted(files):
            if not filename.endswith(".py"):
                continue
            path = current_path / filename
            if path.is_symlink() or not path.is_file():
                continue
            candidates.append(path)
            if len(candidates) > MAX_SOURCE_FILES:
                raise AnalysisBudgetExceeded(
                    "analysis incomplete: Python source file count exceeds "
                    f"limit of {MAX_SOURCE_FILES}"
                )

    yield from sorted(candidates)


def _add_diagnostic(project: ParsedProject, diagnostic: Diagnostic) -> bool:
    """Append a diagnostic without allowing hostile targets to grow it unbounded."""

    if len(project.diagnostics) < MAX_DIAGNOSTICS:
        project.diagnostics.append(diagnostic)
        return True
    limit = Diagnostic(
        "<target>",
        f"analysis incomplete: diagnostic limit of {MAX_DIAGNOSTICS} reached",
    )
    if project.diagnostics:
        project.diagnostics[-1] = limit
    else:
        project.diagnostics.append(limit)
    return False


def _ast_metrics(tree: ast.AST, remaining_nodes: int) -> tuple[int, int]:
    count = 0
    maximum_depth = 0
    stack: list[tuple[ast.AST, int]] = [(tree, 1)]
    while stack:
        node, depth = stack.pop()
        count += 1
        maximum_depth = max(maximum_depth, depth)
        if count > remaining_nodes:
            raise AnalysisBudgetExceeded(
                "analysis incomplete: total AST node count exceeds "
                f"limit of {MAX_TOTAL_AST_NODES}"
            )
        if depth > MAX_AST_DEPTH:
            raise AnalysisBudgetExceeded(
                f"analysis incomplete: AST depth exceeds limit of {MAX_AST_DEPTH}"
            )
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return count, maximum_depth


def _finish_project(project: ParsedProject) -> ParsedProject:
    project.tools.sort(key=lambda item: (item.source_file, item.line_number, item.name))
    return project


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
    project = ParsedProject(root=root)

    try:
        candidates = list(_candidate_files(root))
    except AnalysisBudgetExceeded as exc:
        _add_diagnostic(project, Diagnostic("<target>", str(exc)))
        return _finish_project(project)
    except OSError as exc:
        _add_diagnostic(
            project,
            Diagnostic("<target>", f"unable to enumerate target: {exc}"),
        )
        return _finish_project(project)

    total_source_bytes = 0
    total_ast_nodes = 0
    for path in candidates:
        relative = path.relative_to(project_root).as_posix()
        try:
            size = path.stat().st_size
        except OSError as exc:
            if not _add_diagnostic(
                project,
                Diagnostic(relative, f"unable to stat file: {exc}"),
            ):
                return _finish_project(project)
            continue
        if size > MAX_SOURCE_BYTES:
            if not _add_diagnostic(
                project,
                Diagnostic(relative, f"skipped: file exceeds {MAX_SOURCE_BYTES} bytes"),
            ):
                return _finish_project(project)
            continue
        try:
            with path.open("rb") as source_file:
                source = source_file.read(MAX_SOURCE_BYTES + 1)
        except OSError as exc:
            if not _add_diagnostic(
                project,
                Diagnostic(relative, f"unable to read file: {exc}"),
            ):
                return _finish_project(project)
            continue
        if len(source) > MAX_SOURCE_BYTES:
            if not _add_diagnostic(
                project,
                Diagnostic(relative, f"skipped: file exceeds {MAX_SOURCE_BYTES} bytes"),
            ):
                return _finish_project(project)
            continue
        if total_source_bytes + len(source) > MAX_TOTAL_SOURCE_BYTES:
            _add_diagnostic(
                project,
                Diagnostic(
                    relative,
                    "analysis incomplete: total Python source bytes exceed "
                    f"limit of {MAX_TOTAL_SOURCE_BYTES}",
                ),
            )
            return _finish_project(project)
        total_source_bytes += len(source)

        project.files_scanned += 1
        try:
            content = _decode_python_source(source)
        except SourceDecodeError as exc:
            if not _add_diagnostic(project, Diagnostic(relative, str(exc))):
                return _finish_project(project)
            continue
        try:
            tree = ast.parse(content, filename=relative)
        except SyntaxError as exc:
            if not _add_diagnostic(
                project,
                Diagnostic(relative, exc.msg, line_number=exc.lineno or 0),
            ):
                return _finish_project(project)
            continue
        except RecursionError:
            _add_diagnostic(
                project,
                Diagnostic(
                    relative,
                    "analysis incomplete: Python parser recursion limit exceeded",
                ),
            )
            return _finish_project(project)

        try:
            node_count, _ = _ast_metrics(
                tree,
                MAX_TOTAL_AST_NODES - total_ast_nodes,
            )
        except AnalysisBudgetExceeded as exc:
            _add_diagnostic(project, Diagnostic(relative, str(exc)))
            return _finish_project(project)
        total_ast_nodes += node_count

        aliases = _imports(tree)
        path_bindings = _module_path_bindings(tree, aliases)
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            project.functions[(relative, node.name)] = FunctionRecord(
                relative,
                node,
                aliases,
                path_bindings,
            )
            for decorator in node.decorator_list:
                if not _is_tool_decorator(decorator):
                    continue
                name, description, annotations, metadata_errors = _tool_metadata(
                    decorator,
                    node,
                )
                for message in metadata_errors:
                    if not _add_diagnostic(
                        project,
                        Diagnostic(
                            relative,
                            f"invalid tool metadata: {message}",
                            line_number=_node_line_number(decorator),
                        ),
                    ):
                        return _finish_project(project)
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

    return _finish_project(project)

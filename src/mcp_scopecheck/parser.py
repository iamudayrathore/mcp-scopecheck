"""Non-executing Python source discovery for MCP tools."""

from __future__ import annotations

import ast
import inspect
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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


class ParseTargetError(ValueError):
    """Raised when an audit target cannot be read safely."""


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


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return None


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
) -> tuple[str, str, dict[str, Any]]:
    name = function.name
    description = inspect.cleandoc(ast.get_docstring(function, clean=False) or "")
    annotations: dict[str, Any] = {}

    if not isinstance(decorator, ast.Call):
        return name, description, annotations

    if decorator.args:
        first = _literal(decorator.args[0])
        if isinstance(first, str):
            name = first

    for keyword in decorator.keywords:
        if keyword.arg == "name":
            value = _literal(keyword.value)
            if isinstance(value, str):
                name = value
        elif keyword.arg == "description":
            value = _literal(keyword.value)
            if isinstance(value, str):
                description = inspect.cleandoc(value)
        elif keyword.arg == "annotations":
            value = _literal(keyword.value)
            if isinstance(value, dict):
                annotations = {str(key): item for key, item in value.items()}
            elif isinstance(keyword.value, ast.Call):
                annotations = {
                    item.arg: _literal(item.value)
                    for item in keyword.value.keywords
                    if item.arg is not None
                }

    return name, description, annotations


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
                name, description, annotations = _tool_metadata(decorator, node)
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

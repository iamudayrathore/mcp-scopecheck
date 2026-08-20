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

from .models import (
    AnalysisStatus,
    Diagnostic,
    Parameter,
    PotentialRegistration,
    ToolDefinition,
)

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
MAX_POTENTIAL_REGISTRATIONS = 1_000
MAX_METADATA_NODES = 256
MAX_METADATA_DEPTH = 12
MAX_METADATA_STRING_BYTES = 16_384
MAX_METADATA_INTEGER_BITS = 256
MAX_METADATA_COLLECTION_ITEMS = 128
MAX_BINDING_STATE_WORK = 250_000

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


@dataclass
class _BindingWorkBudget:
    entries: int = 0

    def consume(self, entries: int) -> None:
        self.entries += entries
        if self.entries > MAX_BINDING_STATE_WORK:
            raise AnalysisBudgetExceeded(
                "analysis incomplete: binding-state work exceeds maximum of "
                f"{MAX_BINDING_STATE_WORK:,} entries"
            )


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
    wildcard_imports: tuple[tuple[int, str], ...] = ()
    ambiguous_bindings: frozenset[str] = frozenset()
    definition_imports: dict[str, str] | None = None
    definition_path_bindings: frozenset[str] = frozenset()
    definition_ambiguous_bindings: frozenset[str] = frozenset()
    wrapper_decorators: tuple[ast.expr, ...] = ()
    analyze_definition_expressions: bool = False
    class_bindings: frozenset[str] = frozenset()
    annotations_deferred: bool = False
    outer_scope_writes: frozenset[str] = frozenset()


@dataclass
class ParsedProject:
    """Static project representation used by capability analysis."""

    root: Path
    files_scanned: int = 0
    tools: list[ToolDefinition] = field(default_factory=list)
    functions: dict[tuple[str, str], FunctionRecord] = field(default_factory=dict)
    tool_functions: dict[str, FunctionRecord] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    potential_registrations: list[PotentialRegistration] = field(default_factory=list)
    module_files: dict[str, tuple[str, ...]] = field(default_factory=dict)
    file_modules: dict[str, tuple[str, ...]] = field(default_factory=dict)
    module_imports: dict[str, dict[str, str]] = field(default_factory=dict)
    classes: set[tuple[str, str]] = field(default_factory=set)


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
    except LookupError as exc:
        # A declared codec that exists but is not a text encoding - `rot13`,
        # `base64`, `hex`, `bz2`, `zlib`, `quopri`, `uu`. CPython raises here rather
        # than at decode time, so catching it only around `.decode` let a crafted
        # coding cookie crash the audit with exit 1 and no output, which the exit
        # contract defines as "complete, findings at threshold".
        raise SourceDecodeError(f"invalid Python source encoding: {exc}") from exc
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


def _potential_registrations(
    tree: ast.Module,
    source_file: str,
) -> list[PotentialRegistration]:
    """Detect bounded MCP registration syntax that is intentionally unsupported."""

    registrations: list[PotentialRegistration] = []
    top_level_ids = {
        id(node)
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    decorator_ids = {
        id(decorator)
        for function in ast.walk(tree)
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        for decorator in function.decorator_list
    }

    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        tool_decorators = [
            decorator for decorator in function.decorator_list if _is_tool_decorator(decorator)
        ]
        if tool_decorators and id(function) not in top_level_ids:
            decorator = tool_decorators[0]
            registrations.append(
                PotentialRegistration(
                    source_file,
                    _node_line_number(decorator),
                    _safe_unparse(decorator),
                    "nested or class-owned tool decorator",
                )
            )

        low_level = any(
            _call_name(decorator.func if isinstance(decorator, ast.Call) else decorator).endswith(
                ".list_tools"
            )
            for decorator in function.decorator_list
        )
        if low_level:
            static_tools = [
                call
                for call in ast.walk(function)
                if isinstance(call, ast.Call)
                and _call_name(call.func).rsplit(".", 1)[-1] == "Tool"
            ]
            if static_tools:
                registrations.extend(
                    PotentialRegistration(
                        source_file,
                        _node_line_number(call),
                        _safe_unparse(call),
                        "low-level static Tool list",
                    )
                    for call in static_tools
                )
            else:
                decorator = next(
                    item
                    for item in function.decorator_list
                    if _call_name(item.func if isinstance(item, ast.Call) else item).endswith(
                        ".list_tools"
                    )
                )
                registrations.append(
                    PotentialRegistration(
                        source_file,
                        _node_line_number(decorator),
                        _safe_unparse(decorator),
                        "low-level list_tools registration",
                        potential_tool_count=0,
                    )
                )

    for statement in tree.body:
        value: ast.AST | None = None
        if isinstance(statement, ast.Assign):
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            value = statement.value
        if not isinstance(value, (ast.List, ast.Tuple)):
            continue
        for call in value.elts:
            if not isinstance(call, ast.Call):
                continue
            if _call_name(call.func).rsplit(".", 1)[-1] != "Tool":
                continue
            registrations.append(
                PotentialRegistration(
                    source_file,
                    _node_line_number(call),
                    _safe_unparse(call),
                    "importable static Tool collection",
                )
            )

    for walked_node in ast.walk(tree):
        if not isinstance(walked_node, ast.Call) or id(walked_node) in decorator_ids:
            continue
        name = _call_name(walked_node.func)
        if name.endswith(".add_tool"):
            reason = "add_tool registration"
        elif name.endswith(".tool") and walked_node.args:
            reason = "runtime tool registration"
        else:
            continue
        registrations.append(
                PotentialRegistration(
                    source_file,
                    _node_line_number(walked_node),
                    _safe_unparse(walked_node.func),
                reason,
            )
        )

    unique = {
        (item.source_file, item.line_number, item.expression, item.reason): item
        for item in registrations
    }
    return sorted(
        unique.values(),
        key=lambda item: (item.source_file, item.line_number, item.expression, item.reason),
    )


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


def _relative_import_name(node: ast.ImportFrom, item: ast.alias) -> str:
    prefix = "." * node.level
    module = node.module or ""
    base = f"{prefix}{module}"
    separator = "" if base.endswith(".") else "."
    return f"{base}{separator}{item.name}" if base else item.name


@dataclass
class _ModuleBindingState:
    aliases: dict[str, str] = field(default_factory=dict)
    paths: set[str] = field(default_factory=set)
    ambiguous: set[str] = field(default_factory=set)
    wildcard_imports: set[tuple[int, str]] = field(default_factory=set)
    budget: _BindingWorkBudget = field(default_factory=_BindingWorkBudget)
    annotations_deferred: bool = False

    def clone(self) -> _ModuleBindingState:
        self.budget.consume(
            len(self.aliases)
            + len(self.paths)
            + len(self.ambiguous)
            + len(self.wildcard_imports)
        )
        return _ModuleBindingState(
            dict(self.aliases),
            set(self.paths),
            set(self.ambiguous),
            set(self.wildcard_imports),
            self.budget,
            self.annotations_deferred,
        )


@dataclass
class _StatementEffects:
    bound_names: set[str] = field(default_factory=set)
    has_break: bool = False
    has_continue: bool = False


class _StatementEffectsVisitor(ast.NodeVisitor):
    """Collect bindings and abrupt loop exits without entering deferred scopes."""

    def __init__(self) -> None:
        self.effects = _StatementEffects()
        self.loop_depth = 0

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.effects.bound_names.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            self.effects.bound_names.add(item.asname or item.name.split(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            if item.name != "*":
                self.effects.bound_names.add(item.asname or item.name)

    def _visit_definition_expressions(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        self.effects.bound_names.add(node.name)
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        arguments = [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
        if node.args.vararg is not None:
            arguments.append(node.args.vararg)
        if node.args.kwarg is not None:
            arguments.append(node.args.kwarg)
        for argument in arguments:
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if node.returns is not None:
            self.visit(node.returns)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_definition_expressions(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_definition_expressions(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.effects.bound_names.add(node.name)
        for expression in [*node.decorator_list, *node.bases]:
            self.visit(expression)
        for keyword in node.keywords:
            self.visit(keyword.value)

    def _visit_nested_loop(
        self,
        iterator_or_test: ast.AST,
        target: ast.AST | None,
        body: list[ast.stmt],
        orelse: list[ast.stmt],
    ) -> None:
        self.visit(iterator_or_test)
        if target is not None:
            self.visit(target)
        self.loop_depth += 1
        for statement in [*body, *orelse]:
            self.visit(statement)
        self.loop_depth -= 1

    def visit_For(self, node: ast.For) -> None:
        self._visit_nested_loop(node.iter, node.target, node.body, node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_nested_loop(node.iter, node.target, node.body, node.orelse)

    def visit_While(self, node: ast.While) -> None:
        self._visit_nested_loop(node.test, None, node.body, node.orelse)

    def visit_Break(self, node: ast.Break) -> None:
        if self.loop_depth == 0:
            self.effects.has_break = True

    def visit_Continue(self, node: ast.Continue) -> None:
        if self.loop_depth == 0:
            self.effects.has_continue = True

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self.visit(node.generators[0].iter)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self.visit(node.generators[0].iter)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self.visit(node.generators[0].iter)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self.visit(node.generators[0].iter)


def _statement_effects(statements: list[ast.stmt]) -> _StatementEffects:
    visitor = _StatementEffectsVisitor()
    for statement in statements:
        visitor.visit(statement)
    return visitor.effects


class _OuterScopeDeclarationVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Global(self, node: ast.Global) -> None:
        self.names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.names.update(node.names)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


def _outer_scope_writes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> frozenset[str]:
    declarations = _OuterScopeDeclarationVisitor()
    for statement in node.body:
        declarations.visit(statement)
    return frozenset(
        declarations.names & _statement_effects(node.body).bound_names
    )


def _named_expression_names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {
        name
        for child in ast.walk(node)
        if isinstance(child, ast.NamedExpr)
        for name in _module_assigned_names(child.target)
    }


def _module_assigned_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Starred):
        return _module_assigned_names(node.value)
    if isinstance(node, (ast.List, ast.Tuple)):
        return {
            name
            for item in node.elts
            for name in _module_assigned_names(item)
        }
    return set()


def _set_module_binding(
    state: _ModuleBindingState,
    name: str,
    value: str,
    *,
    is_path: bool = False,
) -> None:
    state.aliases[name] = value
    state.paths.discard(name)
    if is_path:
        state.paths.add(name)
    state.ambiguous.discard(name)


def _join_module_states(states: list[_ModuleBindingState]) -> _ModuleBindingState:
    if not states:
        return _ModuleBindingState()
    budget = states[0].budget
    budget.consume(
        sum(
            len(state.aliases)
            + len(state.paths)
            + len(state.ambiguous)
            + len(state.wildcard_imports)
            for state in states
        )
    )
    missing = object()
    aliases: dict[str, str] = {}
    paths = set.intersection(*(state.paths for state in states))
    ambiguous = set().union(*(state.ambiguous for state in states))
    wildcard_imports = set().union(*(state.wildcard_imports for state in states))
    names = set().union(*(state.aliases.keys() for state in states))
    for name in names:
        values = [state.aliases.get(name, missing) for state in states]
        first = values[0]
        if all(value == first for value in values) and first is not missing:
            aliases[name] = first  # type: ignore[assignment]
        else:
            aliases[name] = ""
            ambiguous.add(name)
        if any((name in state.paths) != (name in states[0].paths) for state in states[1:]):
            ambiguous.add(name)
    return _ModuleBindingState(
        aliases,
        paths,
        ambiguous,
        wildcard_imports,
        budget,
        states[0].annotations_deferred,
    )


def _mark_module_bindings_ambiguous(
    state: _ModuleBindingState,
    names: set[str],
) -> None:
    for name in names:
        state.aliases[name] = ""
        state.paths.discard(name)
        state.ambiguous.add(name)


def _mark_module_expression_bindings(
    state: _ModuleBindingState,
    expressions: Iterable[ast.AST | None],
) -> None:
    names = {
        name
        for expression in expressions
        for name in _named_expression_names(expression)
    }
    _mark_module_bindings_ambiguous(state, names)


def _module_path_options(
    value: ast.AST,
    state: _ModuleBindingState,
) -> set[bool]:
    if isinstance(value, ast.IfExp):
        return _module_path_options(value.body, state) | _module_path_options(
            value.orelse,
            state,
        )
    if isinstance(value, ast.BoolOp):
        return {
            option
            for item in value.values
            for option in _module_path_options(item, state)
        }
    return {_is_path_expression(value, state.aliases, state.paths)}


def _module_import_references(
    value: ast.AST,
    state: _ModuleBindingState,
) -> set[str]:
    if isinstance(value, ast.IfExp):
        return _module_import_references(value.body, state) | _module_import_references(
            value.orelse,
            state,
        )
    if isinstance(value, ast.BoolOp):
        return {
            reference
            for item in value.values
            for reference in _module_import_references(item, state)
        }
    base = value
    while isinstance(base, ast.Attribute):
        base = base.value
    if not isinstance(base, ast.Name) or base.id not in state.aliases:
        return set()
    return {_import_qualified_name(value, state.aliases)}


def _module_structured_binding(
    value: ast.AST,
    state: _ModuleBindingState,
) -> bool:
    if not isinstance(value, (ast.List, ast.Tuple)):
        return False
    elements = [
        child
        for child in ast.walk(value)
        if not isinstance(child, (ast.List, ast.Tuple, ast.Load, ast.Store))
    ]
    return any(
        True in _module_path_options(element, state)
        or bool(_module_import_references(element, state))
        for element in elements
    )


def _module_bindings_for_statements(
    statements: list[ast.stmt],
    initial: _ModuleBindingState | None = None,
    *,
    direct_module_body: bool = False,
    definition_states: dict[int, _ModuleBindingState] | None = None,
) -> _ModuleBindingState:
    state = initial.clone() if initial is not None else _ModuleBindingState()
    for node in statements:
        if isinstance(node, ast.Import):
            for item in node.names:
                bound_name = item.asname or item.name.split(".")[0]
                _set_module_binding(
                    state,
                    bound_name,
                    item.name if item.asname else bound_name,
                )
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                if item.name == "*":
                    state.wildcard_imports.add(
                        (_node_line_number(node), node.module or "." * node.level)
                    )
                    continue
                _set_module_binding(
                    state,
                    item.asname or item.name,
                    _relative_import_name(node, item),
                )
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
            _mark_module_expression_bindings(state, [node.value])
            path_options = (
                _module_path_options(value, state) if value is not None else set()
            )
            import_references = (
                _module_import_references(value, state) if value is not None else set()
            )
            structured_target = any(
                isinstance(target, (ast.List, ast.Tuple)) for target in targets
            )
            structured_binding = (
                structured_target
                and value is not None
                and _module_structured_binding(value, state)
            )
            is_path = value is not None and _is_path_expression(
                value,
                state.aliases,
                state.paths,
            )
            for target in targets:
                for name in _module_assigned_names(target):
                    _set_module_binding(state, name, "", is_path=is_path)
            if (
                len(path_options) > 1
                or import_references
                or structured_binding
            ):
                _mark_module_bindings_ambiguous(
                    state,
                    {
                        name
                        for target in targets
                        for name in _module_assigned_names(target)
                    },
                )
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                for name in _module_assigned_names(target):
                    _set_module_binding(state, name, "")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if direct_module_body:
                if definition_states is not None:
                    definition_states[id(node)] = state.clone()
                _mark_module_expression_bindings(
                    state,
                    [
                        *node.decorator_list,
                        *node.args.defaults,
                        *node.args.kw_defaults,
                        *(
                            []
                            if state.annotations_deferred
                            else [
                                *[
                                    argument.annotation
                                    for argument in [
                                        *node.args.posonlyargs,
                                        *node.args.args,
                                        *node.args.kwonlyargs,
                                    ]
                                ],
                                node.args.vararg.annotation if node.args.vararg else None,
                                node.args.kwarg.annotation if node.args.kwarg else None,
                                node.returns,
                            ]
                        ),
                    ],
                )
                state.aliases.pop(node.name, None)
                state.paths.discard(node.name)
                state.ambiguous.discard(node.name)
            else:
                _set_module_binding(state, node.name, "")
                state.ambiguous.add(node.name)
        elif isinstance(node, ast.ClassDef):
            _mark_module_expression_bindings(
                state,
                [
                    *node.decorator_list,
                    *node.bases,
                    *[keyword.value for keyword in node.keywords],
                ],
            )
            _set_module_binding(state, node.name, "")
            if not direct_module_body:
                state.ambiguous.add(node.name)
        elif isinstance(node, ast.If):
            _mark_module_expression_bindings(state, [node.test])
            if isinstance(node.test, ast.Constant) and isinstance(node.test.value, bool):
                selected = node.body if node.test.value else node.orelse
                state = _module_bindings_for_statements(selected, state)
            else:
                state = _join_module_states(
                    [
                        _module_bindings_for_statements(node.body, state),
                        _module_bindings_for_statements(node.orelse, state),
                    ]
                )
        elif isinstance(node, (ast.Try, ast.TryStar)):
            success = _module_bindings_for_statements(node.body, state)
            success = _module_bindings_for_statements(node.orelse, success)
            merged = success
            try_effects = _statement_effects(node.body)
            handler_entry = state.clone()
            _mark_module_bindings_ambiguous(
                handler_entry,
                try_effects.bound_names,
            )
            for handler in node.handlers:
                handler_state = handler_entry.clone()
                if handler.name:
                    _set_module_binding(handler_state, handler.name, "")
                branch = _module_bindings_for_statements(handler.body, handler_state)
                merged = _join_module_states([merged, branch])
                if isinstance(node, ast.TryStar):
                    handler_entry = _join_module_states([handler_entry, branch])
            state = merged
            state = _module_bindings_for_statements(node.finalbody, state)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            _mark_module_expression_bindings(
                state,
                [node.iter if isinstance(node, (ast.For, ast.AsyncFor)) else node.test],
            )
            before_loop = state.clone()
            loop_state = state.clone()
            loop_effects = _statement_effects(node.body)
            _mark_module_bindings_ambiguous(
                loop_state,
                loop_effects.bound_names,
            )
            if isinstance(node, (ast.For, ast.AsyncFor)):
                for name in _module_assigned_names(node.target):
                    _set_module_binding(loop_state, name, "")
                    loop_effects.bound_names.add(name)
            loop_state = _module_bindings_for_statements(node.body, loop_state)
            exhausted = _join_module_states([before_loop, loop_state])
            _mark_module_bindings_ambiguous(exhausted, loop_effects.bound_names)
            exhausted = _module_bindings_for_statements(node.orelse, exhausted)
            if loop_effects.has_break:
                broken = loop_state.clone()
                _mark_module_bindings_ambiguous(broken, loop_effects.bound_names)
                state = _join_module_states([exhausted, broken])
            else:
                state = exhausted
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for with_item in node.items:
                _mark_module_expression_bindings(state, [with_item.context_expr])
                if with_item.optional_vars is None:
                    continue
                is_path = _is_path_expression(
                    with_item.context_expr,
                    state.aliases,
                    state.paths,
                )
                for bound_name in _module_assigned_names(with_item.optional_vars):
                    _set_module_binding(state, bound_name, "", is_path=is_path)
            state = _module_bindings_for_statements(node.body, state)
            _mark_module_bindings_ambiguous(
                state,
                _statement_effects(node.body).bound_names,
            )
        elif isinstance(node, ast.Match):
            _mark_module_bindings_ambiguous(
                state,
                _named_expression_names(node.subject),
            )
            outcomes = state.clone()
            fallthrough = state.clone()
            for case in node.cases:
                case_state = fallthrough.clone()
                for pattern in ast.walk(case.pattern):
                    pattern_name = getattr(pattern, "name", None)
                    if isinstance(pattern_name, str):
                        _set_module_binding(case_state, pattern_name, "")
                _mark_module_bindings_ambiguous(
                    case_state,
                    _named_expression_names(case.guard),
                )
                guard_state = case_state.clone()
                branch = _module_bindings_for_statements(case.body, case_state)
                outcomes = _join_module_states([outcomes, branch])
                if case.guard is not None:
                    fallthrough = _join_module_states([fallthrough, guard_state])
            state = _join_module_states([outcomes, fallthrough])
        elif isinstance(node, ast.Expr):
            _mark_module_expression_bindings(state, [node.value])
        elif isinstance(node, ast.Assert):
            _mark_module_expression_bindings(state, [node.test, node.msg])
        elif isinstance(node, ast.Raise):
            _mark_module_expression_bindings(state, [node.exc, node.cause])
    return state


def _imports(
    tree: ast.Module,
    annotations_deferred: bool,
) -> tuple[
    dict[str, str],
    frozenset[str],
    frozenset[str],
    tuple[tuple[int, str], ...],
    dict[int, _ModuleBindingState],
]:
    definition_states: dict[int, _ModuleBindingState] = {}
    state = _module_bindings_for_statements(
        tree.body,
        _ModuleBindingState(annotations_deferred=annotations_deferred),
        direct_module_body=True,
        definition_states=definition_states,
    )
    return (
        state.aliases,
        frozenset(state.ambiguous),
        frozenset(state.paths),
        tuple(sorted(state.wildcard_imports)),
        definition_states,
    )


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


def _candidate_files(target: Path) -> Iterable[Path]:
    if target.is_file():
        if target.suffix != ".py":
            raise ParseTargetError("v0.2 accepts a Python file or a directory containing Python")
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
    unique_registrations = {
        (item.source_file, item.line_number, item.expression, item.reason): item
        for item in project.potential_registrations
    }
    project.potential_registrations = sorted(
        unique_registrations.values(),
        key=lambda item: (item.source_file, item.line_number, item.expression, item.reason),
    )
    if len(project.potential_registrations) > MAX_POTENTIAL_REGISTRATIONS:
        project.potential_registrations = project.potential_registrations[
            :MAX_POTENTIAL_REGISTRATIONS
        ]
        message = (
            "analysis incomplete: potential MCP registration count exceeds "
            f"limit of {MAX_POTENTIAL_REGISTRATIONS}"
        )
        if not any(item.message == message for item in project.diagnostics):
            _add_diagnostic(project, Diagnostic("<target>", message))
    return project


def _module_names(source_file: str) -> tuple[str, ...]:
    path = Path(source_file)
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    names: set[str] = set()
    if parts:
        names.add(".".join(parts))
    for index, part in enumerate(parts):
        if part == "src" and index + 1 < len(parts):
            names.add(".".join(parts[index + 1 :]))
    return tuple(sorted(names, key=lambda item: (item.count("."), len(item), item)))


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

    module_sources: dict[str, list[str]] = {}
    for candidate in candidates:
        relative = candidate.relative_to(project_root).as_posix()
        names = _module_names(relative)
        project.file_modules[relative] = names
        for name in names:
            module_sources.setdefault(name, []).append(relative)
    project.module_files = {
        name: tuple(sorted(set(files)))
        for name, files in sorted(module_sources.items())
    }

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
        annotations_deferred = any(
            isinstance(statement, ast.ImportFrom)
            and statement.module == "__future__"
            and any(item.name == "annotations" for item in statement.names)
            for statement in tree.body
        )

        try:
            (
                aliases,
                ambiguous_bindings,
                path_bindings,
                wildcard_imports,
                definition_states,
            ) = _imports(tree, annotations_deferred)
        except AnalysisBudgetExceeded as exc:
            _add_diagnostic(project, Diagnostic(relative, str(exc)))
            return _finish_project(project)
        project.module_imports[relative] = aliases
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                project.classes.add((relative, node.name))
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            definition_state = definition_states.get(id(node))
            wrapper_decorators = tuple(
                decorator
                for decorator in node.decorator_list
                if not _is_tool_decorator(decorator)
            )
            record = FunctionRecord(
                relative,
                node,
                aliases,
                path_bindings,
                wildcard_imports=wildcard_imports,
                ambiguous_bindings=ambiguous_bindings,
                definition_imports=(
                    dict(definition_state.aliases)
                    if definition_state is not None
                    else None
                ),
                definition_path_bindings=(
                    frozenset(definition_state.paths)
                    if definition_state is not None
                    else frozenset()
                ),
                definition_ambiguous_bindings=(
                    frozenset(definition_state.ambiguous)
                    if definition_state is not None
                    else frozenset()
                ),
                wrapper_decorators=wrapper_decorators,
                annotations_deferred=annotations_deferred,
                outer_scope_writes=_outer_scope_writes(node),
            )
            project.functions[(relative, node.name)] = record
            for decorator in node.decorator_list:
                if not _is_tool_decorator(decorator):
                    continue
                name, description, annotations, metadata_errors = _tool_metadata(
                    decorator,
                    node,
                )
                for message in metadata_errors:
                    diagnostic_status = (
                        AnalysisStatus.FAILED
                        if "exceeds" in message
                        else AnalysisStatus.PARTIAL
                    )
                    if not _add_diagnostic(
                        project,
                        Diagnostic(
                            relative,
                            f"invalid tool metadata: {message}",
                            line_number=_node_line_number(decorator),
                            status=diagnostic_status,
                        ),
                    ):
                        return _finish_project(project)
                tool = ToolDefinition(
                        name=name,
                        function_name=node.name,
                        description=description,
                        source_file=relative,
                        line_number=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                        parameters=_extract_parameters(node),
                        annotations=annotations,
                        wrapper_expressions=tuple(
                            (_node_line_number(item), _safe_unparse(item))
                            for item in node.decorator_list
                            if item is not decorator
                        ),
                    )
                project.tools.append(tool)
                project.tool_functions[tool.key] = record
                record.analyze_definition_expressions = True
                break

        project.potential_registrations.extend(_potential_registrations(tree, relative))

    return _finish_project(project)

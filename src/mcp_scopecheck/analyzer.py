"""Reachability-aware capability and contract analysis."""

from __future__ import annotations

import ast
import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .models import (
    Capability,
    Evidence,
    Finding,
    ObservedCapability,
    ResolvedCallEdge,
    Severity,
    ToolDefinition,
    TraceStep,
    UnresolvedCallEdge,
    UnresolvedReason,
)
from .parser import FunctionRecord, ParsedProject, _relative_import_name

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
NETWORK_READ_METHODS = {"get", "head", "options"}
NETWORK_WRITE_METHODS = {"delete", "patch", "post", "put"}
NETWORK_DIRECT_SINKS = frozenset(
    {
        "httpx.delete",
        "httpx.get",
        "httpx.head",
        "httpx.options",
        "httpx.patch",
        "httpx.post",
        "httpx.put",
        "httpx.request",
        "requests.delete",
        "requests.get",
        "requests.head",
        "requests.options",
        "requests.patch",
        "requests.post",
        "requests.put",
        "requests.request",
        "requests.api.delete",
        "requests.api.get",
        "requests.api.head",
        "requests.api.options",
        "requests.api.patch",
        "requests.api.post",
        "requests.api.put",
        "requests.api.request",
        "socket.create_connection",
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
    }
)
NETWORK_CONTEXT_FACTORIES = frozenset({"aiohttp.request", "httpx.stream"})
NETWORK_CLIENT_CONSTRUCTORS = {
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
PATH_PARAMETER_SUFFIXES = ("_dir", "_directory", "_file", "_folder", "_path")

POISONING_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?)", re.I),
        "instruction override",
    ),
    (
        re.compile(
            r"(?:disregard|override|bypass|forget)\s+(?:all\s+)?"
            r"(?:previous|prior|earlier|system|developer)\s+"
            r"(?:guidance|instructions?|messages?|policies|rules?)",
            re.I,
        ),
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
            r"(?:covertly|quietly|secretly|silently).{0,32}"
            r"(?:collect|forward|send|transmit|upload).{0,48}"
            r"(?:chat|context|conversation|credential|history|prompt|secret|token)",
            re.I | re.S,
        ),
        "covert sensitive-data transfer",
    ),
    (
        re.compile(
            r"(?:before|after)\s+(?:any|all|every)\s+(?:call|request|response|tool)",
            re.I,
        ),
        "cross-call instruction",
    ),
    (
        re.compile(
            r"(?:collect|forward|read|send|transmit|upload|exfiltrate).{0,48}"
            r"(?:chat\s+history|conversation\s+context|credential|secret|"
            r"system\s+prompt|token|api[_ -]?key)",
            re.I | re.S,
        ),
        "credential-handling instruction",
    ),
    (
        re.compile(
            r"(?:act|behave|respond)\s+as\s+(?:the\s+)?"
            r"(?:administrator|developer|system)(?:\s+(?:message|role))?",
            re.I,
        ),
        "privileged-role impersonation",
    ),
    (re.compile(r"<\|.*?\|>", re.S), "hidden-token marker"),
)

BENIGN_SECURITY_DISCUSSION = re.compile(
    r"(?:\b(?:analy[sz]e|detect|discuss|document|explain|identify|scan|teach|warn)\w*\b"
    r".{0,100}\b(?:prompt\s+injection|malicious\s+(?:instructions?|prompts?)|security)\b|"
    r"\b(?:prompt\s+injection|malicious\s+(?:instructions?|prompts?)|security)\b"
    r".{0,100}\b(?:analy[sz]e|detect|discuss|document|explain|identify|scan|teach|warn)\w*\b)",
    re.I | re.S,
)

# --- MSC102 network-egress disclosure (conservative, fail-safe) ---
# ScopeCheck proves reachable network egress from the call graph; that fact is
# always reported as an observed capability. Deciding whether a natural-language
# description *discloses* that egress cannot be done reliably by pattern matching,
# so this check errs toward flagging: reachable egress is treated as undisclosed
# unless the description explicitly denies it, names a mismatched destination, or
# clearly and affirmatively describes the egress. Over-flagging a call that was
# in fact disclosed is a safe, correctable error a reader dismisses at a glance;
# staying silent on a hidden call is the failure a security scanner must avoid.
_SERVICE_NAMES = ("discord", "github", "gitlab", "gmail", "google", "slack")
KNOWN_DESTINATIONS = frozenset(_SERVICE_NAMES)
_SERVICE_ALT = "|".join(_SERVICE_NAMES)

# Sentence segmentation used for negation scoping. Newlines are boundaries so an
# unpunctuated bullet/argument block does not merge into one span.
_SENTENCE_SPLIT = re.compile(r"[.!?;\n\r]+")
_NEGATION = re.compile(
    r"\b(?:not|never|no|without|cannot|can't|won't|will\s+not|shall\s+not|"
    r"does\s+not|doesn't|do\s+not|don't|didn't|isn't|aren't|n't)\b",
    re.I,
)

# Explicit denial of network access -> a contradiction when egress is reachable.
# The negation must attach to the egress verb (0-1 words apart) so unrelated
# negations such as "does not require an API key to access the endpoint" do not
# read as denials.
_DENIAL_VERB = (
    r"(?:access(?:es|ed|ing)?|call(?:s|ed|ing)?|connect(?:s|ed|ing)?|"
    r"contact(?:s|ed|ing)?|download(?:s|ed|ing)?|fetch(?:es|ed|ing)?|"
    r"quer(?:y|ies|ied|ying)|reach(?:es|ed|ing)?|request(?:s|ed|ing)?|"
    r"send(?:s|ing)?|sent|talk(?:s|ed|ing)?|transmit(?:s|ted|ting)?|"
    r"upload(?:s|ed|ing)?|us(?:e|es|ed|ing))"
)
_DENIAL_TARGET = (
    r"(?:internet|network|remote|external|online|endpoint|server|cloud|web|url|"
    r"outbound|" + _SERVICE_ALT + r")"
)
NETWORK_DENIAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:never|not|cannot|can't|won't|will\s+not|shall\s+not|"
        r"do(?:es)?\s+not|don't|doesn't)\s+(?:\w+\s+){0,1}"
        + _DENIAL_VERB + r"\s+(?:\w+\s+){0,4}?" + _DENIAL_TARGET + r"\b",
        re.I,
    ),
    re.compile(
        r"\b(?:no|without)\s+"
        r"(?:external\s+|internet\s+|network\s+|remote\s+|outbound\s+)?"
        r"(?:access|connection|egress|requests?|traffic)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:fully\s+local|local[- ]only|offline(?:[- ]only)?|air[- ]gapped|"
        r"runs?\s+(?:locally|offline)(?:\s+only)?|"
        r"(?:no\s+data|nothing)\s+(?:ever\s+)?leaves|"
        r"stays?\s+(?:entirely\s+|fully\s+)?on\s+(?:your|the\s+local)|"
        r"no\s+outbound\s+traffic)\b",
        re.I,
    ),
)

# High-precision affirmative descriptions of external network egress. A benign,
# local-only tool essentially never contains these; matching one (when not
# negated in the same sentence) is treated as clear disclosure.
NETWORK_DISCLOSURE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bover\s+the\s+(?:internet|network|wire|web)\b", re.I),
    re.compile(
        r"\b(?:make|makes|making|made|issue|issues|issuing|issued|"
        r"perform|performs|performing|performed|open|opens|opening|opened|"
        r"send|sends|sending|sent)\s+(?:an?\s+|a\s+new\s+|out\s+)?"
        r"(?:https?|network|web|rest|api|outbound|remote|external|"
        r"outgoing)\s+(?:requests?|calls?|connections?|quer(?:y|ies))\b",
        re.I,
    ),
    re.compile(
        r"\b(?:connect|connects|connecting|connected)\s+to\s+"
        r"(?:a\s+|an\s+|the\s+)?(?:remote|external|internet|cloud|" + _SERVICE_ALT + r")\b",
        re.I,
    ),
    re.compile(
        r"\b(?:download|downloads|downloading|downloaded|fetch|fetches|fetching|"
        r"fetched|retrieve|retrieves|retrieving|retrieved|pull|pulls|pulling|"
        r"pulled|import|imports|importing|imported|get|gets|getting|got|"
        r"receive|receives|receiving|received)\b[^.!?;]{0,40}?\bfrom\s+"
        r"(?:the\s+|a\s+|an\s+|its\s+|your\s+|this\s+|that\s+)?(?:\w+\s+){0,2}?"
        r"(?:internet|web|network|remote|external|online|hosted|public|"
        r"third[- ]party|cloud|upstream|url|" + _SERVICE_ALT + r")\b",
        re.I,
    ),
    re.compile(
        r"\b(?:upload|uploads|uploading|uploaded|post|posts|posting|posted|"
        r"publish|publishes|publishing|published|transmit|transmits|transmitting|"
        r"transmitted|push|pushes|pushing|pushed|sync|syncs|syncing|synced|"
        r"forward|forwards|forwarding|forwarded|send|sends|sending|sent)\b"
        r"[^.!?;]{0,40}?\bto\s+(?:the\s+|a\s+|an\s+|your\s+)?(?:internet|cloud|"
        r"network|remote|external|online|third[- ]party|hosted|public|upstream|"
        + _SERVICE_ALT + r")\b",
        re.I,
    ),
    re.compile(
        r"\bsends?\s+(?:an?\s+|the\s+|out\s+)?(?:email|message|notification|"
        r"webhook|payload)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:" + _SERVICE_ALT + r")(?:'s|’s)?\s+"
        r"(?:accounts?|drives?|inbox(?:es)?|mailbox(?:es)?|workspaces?|channels?)\b",
        re.I,
    ),
)
MAX_RESOLVED_LOCAL_EDGES = 20_000
MAX_UNRESOLVED_LOCAL_EDGES = 1_000
MAX_LOCAL_MODULES = 2_000
MAX_REACHABLE_FUNCTIONS_PER_TOOL = 256
MAX_CROSS_MODULE_HOPS = 32
MAX_CAPABILITY_PATHS_PER_TOOL = 1_000


@dataclass(frozen=True)
class _DescriptionIndicator:
    family: str
    excerpt: str


@dataclass(frozen=True)
class _DisclosureAssessment:
    disclosed: bool
    reason: str
    contradiction: bool = False


def _poisoning_indicator(description: str) -> _DescriptionIndicator | None:
    normalized = " ".join(description.split())
    matches = [
        _DescriptionIndicator(label, match.group(0))
        for pattern, label in POISONING_PATTERNS
        if (match := pattern.search(normalized)) is not None
    ]
    if not matches:
        return None
    if (
        BENIGN_SECURITY_DISCUSSION.search(normalized)
        and not {
            "covert sensitive-data transfer",
            "cross-call instruction",
            "hidden action",
            "hidden-token marker",
        }
        & {match.family for match in matches}
    ):
        return None
    return matches[0]


# Public registrable domains for each named service. A reachable host discloses a
# named service only when its registrable domain (eTLD+1) is on that service's
# list, so a typosquat or subdomain-prefix host (github.evil-collector.example,
# gmail-x.attacker.example) never matches while api.github.com, hooks.slack.com,
# and gmail.googleapis.com do.
_SERVICE_DOMAINS: dict[str, frozenset[str]] = {
    "discord": frozenset({"discord.com", "discordapp.com", "discord.gg"}),
    "github": frozenset({"github.com", "github.io", "githubusercontent.com"}),
    "gitlab": frozenset({"gitlab.com", "gitlab.io"}),
    "gmail": frozenset({"gmail.com", "google.com", "googleapis.com", "googleusercontent.com"}),
    "google": frozenset({"google.com", "googleapis.com", "googleusercontent.com", "gstatic.com"}),
    "slack": frozenset({"slack.com", "slack-edge.com", "slackb.com"}),
}


def _registrable_domain(host: str) -> str:
    """Approximate the registrable domain (eTLD+1) as the last two DNS labels."""

    labels = [label for label in host.lower().split(".") if label]
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _host_matches_service(host: str, service: str) -> bool:
    """True when a reachable host's registrable domain belongs to a named service."""

    return _registrable_domain(host) in _SERVICE_DOMAINS.get(service, frozenset())


def _sentences(description: str) -> list[str]:
    return [
        " ".join(fragment.split())
        for fragment in _SENTENCE_SPLIT.split(description)
        if fragment.strip()
    ]


def _assess_network_disclosure(
    description: str,
    static_hosts: Iterable[str] = (),
) -> _DisclosureAssessment:
    sentences = _sentences(description)
    normalized = " ".join(description.split())
    normalized_lower = normalized.lower()

    # 1. Explicit denial of network access, scoped to a sentence -> contradiction.
    for sentence in sentences:
        for pattern in NETWORK_DENIAL_PATTERNS:
            denial = pattern.search(sentence)
            if denial is not None:
                return _DisclosureAssessment(
                    False,
                    "description contradicts reachable egress with denial "
                    f"{denial.group(0)!r}",
                    contradiction=True,
                )

    hosts = tuple(sorted({host.lower() for host in static_hosts if host}))
    described = sorted(
        service
        for service in KNOWN_DESTINATIONS
        if re.search(rf"\b{service}\b", normalized, re.I)
    )

    # 2. A named destination that matches no reachable host -> mismatch.
    if hosts and described and not any(
        _host_matches_service(host, service) for service in described for host in hosts
    ):
        return _DisclosureAssessment(
            False,
            f"described destination {described!r} does not match "
            f"static host(s) {list(hosts)!r}",
        )

    # 3. Strongest disclosure: the description names the reachable destination.
    if hosts and (
        any(host in normalized_lower for host in hosts)
        or any(
            _host_matches_service(host, service)
            for service in described
            for host in hosts
        )
    ):
        return _DisclosureAssessment(True, "description names the reachable destination")

    # 4. Clear affirmative egress phrasing that is not negated within its sentence.
    for sentence in sentences:
        if _NEGATION.search(sentence):
            continue
        for pattern in NETWORK_DISCLOSURE_PATTERNS:
            match = pattern.search(sentence)
            if match is not None:
                return _DisclosureAssessment(
                    True,
                    f"description states external network egress: {match.group(0)!r}",
                )

    # 5. Fail safe: reachable egress is not clearly disclosed.
    return _DisclosureAssessment(
        False,
        "description does not clearly disclose the reachable network egress",
    )


def _qualified_name(node: ast.AST, imports: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return imports.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value, imports)
        return f"{prefix}.{node.attr}" if prefix else ""
    if isinstance(node, ast.Call):
        prefix = _qualified_name(node.func, imports)
        return f"{prefix}()" if prefix else ""
    return ""


def _display_name(node: ast.AST, imports: dict[str, str]) -> str:
    """Return a readable symbol while preserving unresolved local receivers."""

    if isinstance(node, ast.Name):
        return imports.get(node.id) or node.id
    if isinstance(node, ast.Attribute):
        prefix = _display_name(node.value, imports)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        prefix = _display_name(node.func, imports)
        return f"{prefix}()" if prefix else ""
    return ""


def _local_calls(record: FunctionRecord, project: ParsedProject) -> Iterable[FunctionRecord]:
    yield from _execution(record, project).call_edges


def reachable_functions(project: ParsedProject, tool: ToolDefinition) -> list[FunctionRecord]:
    """Return bounded local functions reachable from a tool, without executing code."""

    root = project.functions.get((tool.source_file, tool.function_name))
    if root is None:
        return []
    queue: deque[FunctionRecord] = deque([root])
    visited: set[int] = set()
    records: list[FunctionRecord] = []
    while queue and len(records) < MAX_REACHABLE_FUNCTIONS_PER_TOOL:
        record = queue.popleft()
        key = id(record.node)
        if key in visited:
            continue
        visited.add(key)
        records.append(record)
        queue.extend(_local_calls(record, project))
    return records


def _reachable_function_paths(
    project: ParsedProject,
    tool: ToolDefinition,
) -> dict[int, tuple[TraceStep, ...]]:
    root = project.functions.get((tool.source_file, tool.function_name))
    if root is None:
        return {}
    root_path = (TraceStep(tool.source_file, tool.line_number, tool.function_name),)
    queue: deque[tuple[FunctionRecord, tuple[TraceStep, ...]]] = deque([(root, root_path)])
    paths: dict[int, tuple[TraceStep, ...]] = {}
    while queue and len(paths) < MAX_REACHABLE_FUNCTIONS_PER_TOOL:
        record, path = queue.popleft()
        identity = id(record.node)
        if identity in paths:
            continue
        paths[identity] = path
        execution = _execution(record, project)
        for _, callee in sorted(
            (
                (node, execution.call_edges_by_call[id(node)])
                for node in execution.nodes
                if isinstance(node, ast.Call) and id(node) in execution.call_edges_by_call
            ),
            key=lambda item: (_line_number(item[0]), item[1].source_file, item[1].node.name),
        ):
            queue.append(
                (
                    callee,
                    path
                    + (
                        TraceStep(
                            callee.source_file,
                            _line_number(callee.node),
                            callee.node.name,
                        ),
                    ),
                )
            )
    return paths


def _call_expression(node: ast.AST) -> str:
    try:
        value = ast.unparse(node)
    except Exception:
        value = type(node).__name__
    return value if len(value) <= 240 else f"{value[:239]}…"


@dataclass(frozen=True)
class _LocalCallResolution:
    target: FunctionRecord | None = None
    reason: UnresolvedReason | None = None
    candidate: str = ""


def _absolute_import_name(
    project: ParsedProject,
    source_file: str,
    name: str,
) -> str:
    if not name.startswith("."):
        return name
    level = len(name) - len(name.lstrip("."))
    suffix = name[level:]
    modules = project.file_modules.get(source_file, ())
    if not modules:
        return suffix
    current = modules[0]
    package = current.split(".")
    if not source_file.endswith("/__init__.py") and source_file != "__init__.py":
        package = package[:-1]
    remove = max(level - 1, 0)
    if remove > len(package):
        return suffix
    if remove:
        package = package[:-remove]
    if suffix:
        package.extend(part for part in suffix.split(".") if part)
    return ".".join(package)


def _resolve_qualified_local(
    project: ParsedProject,
    source_file: str,
    qualified: str,
    *,
    allow_reexport: bool = True,
    direct_symbol: bool = False,
) -> _LocalCallResolution:
    candidate = _absolute_import_name(project, source_file, qualified)
    parts = [part for part in candidate.split(".") if part]
    for boundary in range(len(parts) - 1, 0, -1):
        module = ".".join(parts[:boundary])
        files = project.module_files.get(module)
        if not files:
            continue
        remainder = parts[boundary:]
        if len(files) != 1:
            return _LocalCallResolution(
                reason=UnresolvedReason.AMBIGUOUS_LOCAL_TARGET,
                candidate=candidate,
            )
        target_file = files[0]
        if len(remainder) != 1:
            return _LocalCallResolution(
                reason=(
                    UnresolvedReason.MISSING_LOCAL_TARGET
                    if direct_symbol
                    else UnresolvedReason.UNSUPPORTED_INSTANCE_DISPATCH
                ),
                candidate=candidate,
            )
        symbol = remainder[0]
        target = project.functions.get((target_file, symbol))
        if target is not None:
            return _LocalCallResolution(target=target, candidate=candidate)
        if (target_file, symbol) in project.classes:
            return _LocalCallResolution(
                reason=UnresolvedReason.UNSUPPORTED_INSTANCE_DISPATCH,
                candidate=candidate,
            )
        if allow_reexport and target_file.endswith("__init__.py"):
            imported = project.module_imports.get(target_file, {}).get(symbol)
            if imported:
                resolved = _resolve_qualified_local(
                    project,
                    target_file,
                    imported,
                    allow_reexport=False,
                    direct_symbol=True,
                )
                if resolved.target is not None:
                    return resolved
                return _LocalCallResolution(
                    reason=UnresolvedReason.UNRESOLVED_REEXPORT,
                    candidate=candidate,
                )
        return _LocalCallResolution(
            reason=UnresolvedReason.MISSING_LOCAL_TARGET,
            candidate=candidate,
        )

    local_roots = {name.split(".", 1)[0] for name in project.module_files}
    if qualified.startswith(".") or (parts and parts[0] in local_roots):
        return _LocalCallResolution(
            reason=UnresolvedReason.MISSING_LOCAL_TARGET,
            candidate=candidate,
        )
    return _LocalCallResolution()


def _resolve_local_call(
    project: ParsedProject,
    record: FunctionRecord,
    call: ast.Call,
    imports: dict[str, str],
) -> _LocalCallResolution:
    if isinstance(call.func, ast.Name):
        name = call.func.id
        if name not in imports:
            target = project.functions.get((record.source_file, name))
            if target is not None:
                return _LocalCallResolution(target=target)
            return _LocalCallResolution()
        imported = imports.get(name, "")
        if not imported:
            return _LocalCallResolution()
        return _resolve_qualified_local(
            project,
            record.source_file,
            imported,
            direct_symbol=True,
        )

    if not isinstance(call.func, ast.Attribute):
        return _LocalCallResolution()
    base = call.func.value
    while isinstance(base, ast.Attribute):
        base = base.value
    if not isinstance(base, ast.Name) or not imports.get(base.id):
        return _LocalCallResolution()
    qualified = _qualified_name(call.func, imports)
    return _resolve_qualified_local(project, record.source_file, qualified)


def analyze_reachability(
    project: ParsedProject,
    tool: ToolDefinition,
) -> tuple[list[ResolvedCallEdge], list[UnresolvedCallEdge], bool]:
    """Build a bounded honesty ledger for one registered tool."""

    root = project.functions.get((tool.source_file, tool.function_name))
    if root is None:
        return [], [], False
    queue: deque[tuple[FunctionRecord, int]] = deque([(root, 0)])
    visited: set[int] = set()
    participating_modules: set[str] = set()
    resolved: dict[tuple[object, ...], ResolvedCallEdge] = {}
    unresolved: dict[tuple[object, ...], UnresolvedCallEdge] = {}
    budget_exceeded = False

    def add_unresolved(
        record: FunctionRecord,
        node: ast.AST,
        reason: UnresolvedReason,
        candidate: str = "",
    ) -> None:
        nonlocal budget_exceeded
        edge = UnresolvedCallEdge(
            tool.name,
            record.source_file,
            _line_number(node),
            record.node.name,
            _call_expression(node),
            reason,
            candidate,
        )
        key = (
            edge.tool_name,
            edge.source_file,
            edge.line_number,
            edge.caller,
            edge.call_expression,
            edge.reason,
            edge.candidate,
        )
        unresolved[key] = edge
        if len(unresolved) > MAX_UNRESOLVED_LOCAL_EDGES:
            budget_exceeded = True

    for line_number, expression in tool.wrapper_expressions:
        edge = UnresolvedCallEdge(
            tool.name,
            tool.source_file,
            line_number,
            tool.function_name,
            expression,
            UnresolvedReason.WRAPPER_INDIRECTION,
        )
        unresolved[
            (
                edge.tool_name,
                edge.source_file,
                edge.line_number,
                edge.caller,
                edge.call_expression,
                edge.reason,
                edge.candidate,
            )
        ] = edge

    for line_number, module in root.wildcard_imports:
        edge = UnresolvedCallEdge(
            tool.name,
            root.source_file,
            line_number,
            root.node.name,
            f"from {module} import *",
            UnresolvedReason.WILDCARD_IMPORT,
            module,
        )
        unresolved[
            (
                edge.tool_name,
                edge.source_file,
                edge.line_number,
                edge.caller,
                edge.call_expression,
                edge.reason,
                edge.candidate,
            )
        ] = edge

    while queue and not budget_exceeded:
        record, cross_module_hops = queue.popleft()
        identity = id(record.node)
        if identity in visited:
            continue
        visited.add(identity)
        participating_modules.add(record.source_file)
        if (
            len(visited) > MAX_REACHABLE_FUNCTIONS_PER_TOOL
            or len(participating_modules) > MAX_LOCAL_MODULES
        ):
            budget_exceeded = True
            break
        execution = _execution(record, project)
        parameters = _parameter_names(record.node)
        for node in execution.nodes:
            if isinstance(node, ast.ImportFrom) and any(
                item.name == "*" for item in node.names
            ):
                add_unresolved(
                    record,
                    node,
                    UnresolvedReason.WILDCARD_IMPORT,
                    node.module or "",
                )
                continue
            if not isinstance(node, ast.Call):
                continue
            callee = execution.call_edges_by_call.get(id(node))
            if callee is not None:
                resolved_edge = ResolvedCallEdge(
                    tool.name,
                    record.source_file,
                    _line_number(node),
                    record.node.name,
                    _call_expression(node),
                    callee.source_file,
                    callee.node.name,
                )
                resolved[
                    (
                        resolved_edge.tool_name,
                        resolved_edge.source_file,
                        resolved_edge.line_number,
                        resolved_edge.caller,
                        resolved_edge.call_expression,
                        resolved_edge.target_file,
                        resolved_edge.target_symbol,
                    )
                ] = resolved_edge
                next_hops = cross_module_hops + int(callee.source_file != record.source_file)
                if callee.source_file != record.source_file and (
                    any(isinstance(argument, ast.Starred) for argument in node.args)
                    or any(keyword.arg is None for keyword in node.keywords)
                ):
                    add_unresolved(
                        record,
                        node,
                        UnresolvedReason.UNRESOLVED_ARGUMENT_LINEAGE,
                        f"{callee.source_file}:{callee.node.name}",
                    )
                if next_hops > MAX_CROSS_MODULE_HOPS:
                    add_unresolved(
                        record,
                        node,
                        UnresolvedReason.GRAPH_RESOURCE_BUDGET,
                        f"maximum cross-module depth {MAX_CROSS_MODULE_HOPS}",
                    )
                    budget_exceeded = True
                    break
                queue.append((callee, next_hops))
                if len(resolved) > MAX_RESOLVED_LOCAL_EDGES:
                    budget_exceeded = True
                continue

            imports = execution.imports_for(node)
            local_unresolved = execution.unresolved_local_calls.get(id(node))
            if local_unresolved is not None:
                reason, candidate = local_unresolved
                add_unresolved(record, node, reason, candidate)
                continue
            name = _qualified_name(node.func, imports)
            if name in {"importlib.import_module", "__import__", "builtins.__import__"}:
                add_unresolved(record, node, UnresolvedReason.DYNAMIC_IMPORT, name)
            elif isinstance(node.func, ast.Name) and (
                node.func.id in parameters or imports.get(node.func.id) == ""
            ):
                add_unresolved(
                    record,
                    node,
                    UnresolvedReason.HIGHER_ORDER_CALL,
                    node.func.id,
                )
            elif (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and (
                    node.func.value.id in {"self", "cls"}
                    or (
                        node.func.value.id in parameters
                        and _parameter_has_local_class_annotation(
                            project,
                            record,
                            node.func.value.id,
                        )
                    )
                )
            ):
                add_unresolved(
                    record,
                    node,
                    UnresolvedReason.UNSUPPORTED_INSTANCE_DISPATCH,
                    _call_expression(node.func),
                )

    resolved_values = sorted(
        resolved.values(),
        key=lambda item: (
            item.tool_name,
            item.source_file,
            item.line_number,
            item.caller,
            item.target_file,
            item.target_symbol,
        ),
    )[:MAX_RESOLVED_LOCAL_EDGES]
    unresolved_values = sorted(
        unresolved.values(),
        key=lambda item: (
            item.tool_name,
            item.source_file,
            item.line_number,
            item.caller,
            item.reason.value,
            item.call_expression,
        ),
    )[:MAX_UNRESOLVED_LOCAL_EDGES]
    return resolved_values, unresolved_values, budget_exceeded


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
    if name in NETWORK_DIRECT_SINKS:
        return Capability.NETWORK_EGRESS
    if name in NETWORK_CLIENT_CONSTRUCTORS or name in NETWORK_CONTEXT_FACTORIES:
        return None
    for constructor, methods in NETWORK_CLIENT_CONSTRUCTORS.items():
        instance_prefix = f"{constructor}()."
        if name.startswith(instance_prefix):
            method = name.removeprefix(instance_prefix)
            return Capability.NETWORK_EGRESS if method in methods else None
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


def _is_path_parameter_name(name: str) -> bool:
    normalized = name.lstrip("*").lower()
    return normalized in PATH_PARAMETER_NAMES or normalized.endswith(PATH_PARAMETER_SUFFIXES)


@dataclass
class _ExecutionResult:
    """Executable nodes and lexical resolutions for one function body."""

    nodes: list[ast.AST] = field(default_factory=list)
    events: list[ast.AST] = field(default_factory=list)
    visited_ids: set[int] = field(default_factory=set)
    imports_by_node: dict[int, dict[str, str]] = field(default_factory=dict)
    call_edges: list[FunctionRecord] = field(default_factory=list)
    call_edges_by_call: dict[int, FunctionRecord] = field(default_factory=dict)
    unresolved_local_calls: dict[int, tuple[UnresolvedReason, str]] = field(
        default_factory=dict
    )
    nested_call_ids: set[int] = field(default_factory=set)
    instance_network_calls: dict[int, str] = field(default_factory=dict)
    path_filesystem_calls: dict[int, tuple[str, Capability]] = field(default_factory=dict)

    def imports_for(self, node: ast.AST) -> dict[str, str]:
        return self.imports_by_node.get(id(node), {})


@dataclass
class _BindingState:
    imports: dict[str, str]
    paths: set[str]
    clients: dict[str, str]
    nested: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]


def _parameter_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    arguments = node.args
    names = {
        argument.arg
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        ]
    }
    if arguments.vararg is not None:
        names.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        names.add(arguments.kwarg.arg)
    return names


def _parameter_has_local_class_annotation(
    project: ParsedProject,
    record: FunctionRecord,
    parameter_name: str,
) -> bool:
    arguments = [
        *record.node.args.posonlyargs,
        *record.node.args.args,
        *record.node.args.kwonlyargs,
    ]
    argument = next((item for item in arguments if item.arg == parameter_name), None)
    if argument is None or argument.annotation is None:
        return False
    qualified = _qualified_name(argument.annotation, record.imports)
    candidate = _absolute_import_name(project, record.source_file, qualified)
    if (record.source_file, candidate) in project.classes:
        return True
    for source_file, symbol in project.classes:
        if symbol != candidate.rsplit(".", 1)[-1]:
            continue
        for module in project.file_modules.get(source_file, ()):
            if candidate == f"{module}.{symbol}":
                return True
    return False


class _ExecutionVisitor(ast.NodeVisitor):
    """Follow executable lexical scopes without importing target code."""

    def __init__(self, record: FunctionRecord, project: ParsedProject) -> None:
        self.record = record
        self.project = project
        self.imports = dict(record.imports)
        self.paths = set(record.path_bindings)
        self.clients = dict(record.client_bindings)
        self.nested: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.result = _ExecutionResult()
        for name in _parameter_names(record.node):
            self._shadow_name(name)

    def scan(self) -> _ExecutionResult:
        for statement in self.record.node.body:
            self.visit(statement)
        return self.result

    def _remember(self, node: ast.AST, *, event: bool = False) -> None:
        self.result.nodes.append(node)
        self.result.visited_ids.add(id(node))
        self.result.imports_by_node[id(node)] = dict(self.imports)
        if event:
            self.result.events.append(node)

    def _shadow_name(self, name: str) -> None:
        self.imports[name] = ""
        self.paths.discard(name)
        self.clients.pop(name, None)
        self.nested.pop(name, None)

    def _update_targets(
        self,
        targets: Iterable[ast.AST],
        *,
        is_path: bool = False,
        client: str | None = None,
    ) -> None:
        for target in targets:
            for name in _assigned_names(target):
                self._shadow_name(name)
                if is_path:
                    self.paths.add(name)
                if client is not None:
                    self.clients[name] = client

    def _imports_for_value(self, value: ast.AST) -> dict[str, str]:
        return self.result.imports_by_node.get(id(value), self.imports)

    def _client_from_value(self, value: ast.AST) -> str | None:
        if isinstance(value, ast.Name):
            return self.clients.get(value.id)
        if not isinstance(value, ast.Call):
            return None
        constructor = _qualified_name(value.func, self._imports_for_value(value))
        return constructor if constructor in NETWORK_CLIENT_CONSTRUCTORS else None

    def _is_path_value(
        self,
        value: ast.AST,
        imports: dict[str, str] | None = None,
    ) -> bool:
        resolved_imports = imports or self._imports_for_value(value)
        if isinstance(value, ast.Name):
            return value.id in self.paths
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div):
            return self._is_path_value(value.left, resolved_imports)
        if isinstance(value, ast.Attribute) and value.attr == "parent":
            return self._is_path_value(value.value, resolved_imports)
        if not isinstance(value, ast.Call):
            return False
        if _qualified_name(value.func, resolved_imports) == "pathlib.Path":
            return True
        return (
            isinstance(value.func, ast.Attribute)
            and value.func.attr in PATH_RETURNING_METHODS
            and self._is_path_value(value.func.value, resolved_imports)
        )

    def _path_call(
        self,
        call: ast.Call,
        imports: dict[str, str],
    ) -> tuple[str, Capability] | None:
        if not isinstance(call.func, ast.Attribute):
            return None
        if not self._is_path_value(call.func.value, imports):
            return None
        method = call.func.attr
        symbol = _display_name(call.func, imports)
        if method in PATH_READ_METHODS:
            return symbol, Capability.FILESYSTEM_READ
        if method in PATH_WRITE_METHODS:
            return symbol, Capability.FILESYSTEM_WRITE
        if method == "open":
            return symbol, _mode_capability(call, 0)
        return None

    def _path_iterator(self, value: ast.AST) -> bool:
        return (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr in {"glob", "iterdir", "rglob"}
            and self._is_path_value(value.func.value, self._imports_for_value(value))
        )

    def _instance_symbol(self, call: ast.Call, imports: dict[str, str]) -> str | None:
        if not isinstance(call.func, ast.Attribute):
            return None
        method = call.func.attr
        receiver = call.func.value
        if isinstance(receiver, ast.Name):
            constructor = self.clients.get(receiver.id)
            if constructor and method in NETWORK_CLIENT_CONSTRUCTORS[constructor]:
                return f"{receiver.id}.{method}"
            return None
        if isinstance(receiver, ast.Call):
            constructor = _qualified_name(receiver.func, imports)
            if (
                constructor in NETWORK_CLIENT_CONSTRUCTORS
                and method in NETWORK_CLIENT_CONSTRUCTORS[constructor]
            ):
                return f"{constructor}().{method}"
        return None

    def _nested_record(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> FunctionRecord:
        return FunctionRecord(
            self.record.source_file,
            node,
            dict(self.imports),
            frozenset(self.paths),
            dict(self.clients),
            self.record.wildcard_imports,
        )

    def _direct_call_resolution(self, call: ast.Call) -> _LocalCallResolution:
        if isinstance(call.func, ast.Name):
            nested = self.nested.get(call.func.id)
            if nested is not None:
                return _LocalCallResolution(target=self._nested_record(nested))
        return _resolve_local_call(self.project, self.record, call, self.result.imports_for(call))

    def _state(self) -> _BindingState:
        return _BindingState(
            dict(self.imports),
            set(self.paths),
            dict(self.clients),
            dict(self.nested),
        )

    def _restore(self, state: _BindingState) -> None:
        self.imports = dict(state.imports)
        self.paths = set(state.paths)
        self.clients = dict(state.clients)
        self.nested = dict(state.nested)

    def _merge_states(self, first: _BindingState, second: _BindingState) -> None:
        missing = object()
        imports: dict[str, str] = {}
        for name in first.imports.keys() | second.imports.keys():
            first_value = first.imports.get(name, missing)
            second_value = second.imports.get(name, missing)
            if first_value == second_value and first_value is not missing:
                imports[name] = first_value  # type: ignore[assignment]
            elif first_value != second_value:
                imports[name] = ""
        clients = {
            name: constructor
            for name, constructor in first.clients.items()
            if second.clients.get(name) == constructor
        }
        nested = {
            name: function
            for name, function in first.nested.items()
            if second.nested.get(name) is function
        }
        self.imports = imports
        self.paths = first.paths & second.paths
        self.clients = clients
        self.nested = nested

    def visit_Name(self, node: ast.Name) -> None:
        self.result.visited_ids.add(id(node))

    def visit_Call(self, node: ast.Call) -> None:
        self._remember(node, event=True)
        imports = self.result.imports_for(node)
        resolution = self._direct_call_resolution(node)
        edge = resolution.target
        is_nested_edge = (
            isinstance(node.func, ast.Name) and node.func.id in self.nested
        )
        instance_symbol = self._instance_symbol(node, imports)
        if instance_symbol is not None:
            self.result.instance_network_calls[id(node)] = instance_symbol
        path_call = self._path_call(node, imports)
        if path_call is not None:
            self.result.path_filesystem_calls[id(node)] = path_call
        self.generic_visit(node)
        if edge is not None:
            self.result.call_edges.append(edge)
            self.result.call_edges_by_call[id(node)] = edge
            if is_nested_edge:
                self.result.nested_call_ids.add(id(node))
        elif resolution.reason is not None:
            self.result.unresolved_local_calls[id(node)] = (
                resolution.reason,
                resolution.candidate,
            )

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self._remember(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._remember(node)
        self.visit(node.value)
        self.result.events.append(node)
        self._update_targets(
            node.targets,
            is_path=self._is_path_value(node.value),
            client=self._client_from_value(node.value),
        )

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._remember(node)
        if node.value is not None:
            self.visit(node.value)
        self.result.events.append(node)
        self._update_targets(
            [node.target],
            is_path=node.value is not None and self._is_path_value(node.value),
            client=self._client_from_value(node.value) if node.value is not None else None,
        )

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._remember(node)
        self.visit(node.value)
        self.result.events.append(node)
        self._update_targets(
            [node.target],
            is_path=self._is_path_value(node.value),
            client=self._client_from_value(node.value),
        )

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.target)
        self.visit(node.value)
        self._update_targets([node.target])

    def visit_Delete(self, node: ast.Delete) -> None:
        self._update_targets(node.targets)

    def visit_Import(self, node: ast.Import) -> None:
        self._remember(node)
        for item in node.names:
            name = item.asname or item.name.split(".")[0]
            self._shadow_name(name)
            self.imports[name] = item.name if item.asname else name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self._remember(node)
        for item in node.names:
            name = item.asname or item.name
            self._shadow_name(name)
            self.imports[name] = _relative_import_name(node, item)

    def _definition_expressions(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)

    def _visit_function_definition(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        self._definition_expressions(node)
        self._shadow_name(node.name)
        self.nested[node.name] = node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_definition(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_definition(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in [*node.decorator_list, *node.bases]:
            self.visit(expression)
        for keyword in node.keywords:
            self.visit(keyword.value)
        outer = self._state()
        self.nested = {}
        for statement in node.body:
            self.visit(statement)
        self._restore(outer)
        self._shadow_name(node.name)

    def _visit_with(self, items: list[ast.withitem], body: list[ast.stmt]) -> None:
        for item in items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._update_targets(
                    [item.optional_vars],
                    is_path=self._is_path_value(item.context_expr),
                    client=self._client_from_value(item.context_expr),
                )
        for statement in body:
            self.visit(statement)

    def visit_With(self, node: ast.With) -> None:
        self._visit_with(node.items, node.body)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with(node.items, node.body)

    def _visit_for(
        self,
        iterator: ast.AST,
        target: ast.AST,
        body: list[ast.stmt],
        orelse: list[ast.stmt],
    ) -> None:
        self.visit(iterator)
        before_body = self._state()
        self._update_targets([target], is_path=self._path_iterator(iterator))
        for statement in body:
            self.visit(statement)
        after_body = self._state()
        self._merge_states(before_body, after_body)
        for statement in orelse:
            self.visit(statement)

    def visit_For(self, node: ast.For) -> None:
        self._visit_for(node.iter, node.target, node.body, node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_for(node.iter, node.target, node.body, node.orelse)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        before = self._state()
        for statement in node.body:
            self.visit(statement)
        body_state = self._state()
        self._restore(before)
        for statement in node.orelse:
            self.visit(statement)
        else_state = self._state()
        self._merge_states(body_state, else_state)

    def _visit_comprehension(
        self,
        generators: list[ast.comprehension],
        values: list[ast.AST],
    ) -> None:
        outer = self._state()
        for generator in generators:
            self.visit(generator.iter)
            self._update_targets([generator.target])
            for condition in generator.ifs:
                self.visit(condition)
        for value in values:
            self.visit(value)
        self._restore(outer)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators, [node.key, node.value])

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        if node.generators:
            self.visit(node.generators[0].iter)


def _execution(record: FunctionRecord, project: ParsedProject) -> _ExecutionResult:
    return _ExecutionVisitor(record, project).scan()


def _environment_subscript(node: ast.Subscript, imports: dict[str, str]) -> bool:
    return _qualified_name(node.value, imports) in {"os.environ", "environ"}


def _line_number(node: ast.AST) -> int:
    line_number = getattr(node, "lineno", 0)
    return line_number if isinstance(line_number, int) else 0


def _static_network_endpoint(call: ast.Call, symbol: str) -> str | None:
    method = symbol.rsplit(".", 1)[-1].lower()
    index = 1 if method == "request" else 0
    candidate: ast.AST | None = call.args[index] if len(call.args) > index else None
    for keyword in call.keywords:
        if keyword.arg in {"url", "uri"}:
            candidate = keyword.value
    if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
        return candidate.value
    return None


def _static_network_hosts(project: ParsedProject, tool: ToolDefinition) -> tuple[str, ...]:
    hosts: set[str] = set()
    for record in reachable_functions(project, tool):
        execution = _execution(record, project)
        for node in execution.nodes:
            if not isinstance(node, ast.Call):
                continue
            imports = execution.imports_for(node)
            symbol = execution.instance_network_calls.get(id(node))
            if symbol is None:
                symbol = _qualified_name(node.func, imports)
                if _call_capability(node, symbol, imports) != Capability.NETWORK_EGRESS:
                    continue
            endpoint = _static_network_endpoint(node, symbol)
            if endpoint is None:
                continue
            host = urlsplit(endpoint).hostname
            if host:
                hosts.add(host.lower())
    return tuple(sorted(hosts))


def analyze_capabilities(
    project: ParsedProject,
    tool: ToolDefinition,
) -> tuple[list[ObservedCapability], bool]:
    """Find side effects in code reachable from one MCP tool."""

    observed: list[ObservedCapability] = []
    seen: set[tuple[Capability, str, int, str]] = set()
    paths = _reachable_function_paths(project, tool)
    budget_exceeded = False
    for record in reachable_functions(project, tool):
        execution = _execution(record, project)
        for node in execution.nodes:
            capability: Capability | None = None
            symbol = ""
            if isinstance(node, ast.Call):
                imports = execution.imports_for(node)
                instance_symbol = execution.instance_network_calls.get(id(node))
                path_call = execution.path_filesystem_calls.get(id(node))
                if path_call is not None:
                    symbol, capability = path_call
                elif instance_symbol is not None:
                    symbol = instance_symbol
                    capability = Capability.NETWORK_EGRESS
                else:
                    symbol = _qualified_name(node.func, imports)
                    capability = _call_capability(node, symbol, imports)
            elif isinstance(node, ast.Subscript):
                imports = execution.imports_for(node)
                if not _environment_subscript(node, imports):
                    continue
                symbol = _qualified_name(node.value, imports)
                capability = Capability.ENVIRONMENT_READ
            if capability is None:
                continue
            line_number = _line_number(node)
            key = (capability, record.source_file, line_number, symbol)
            if key in seen:
                continue
            seen.add(key)
            detail = f"reachable from {tool.function_name}()"
            if capability == Capability.NETWORK_EGRESS and isinstance(node, ast.Call):
                endpoint = _static_network_endpoint(node, symbol)
                if endpoint is not None:
                    detail = f"{detail}; static destination {endpoint!r}"
            observed.append(
                ObservedCapability(
                    capability,
                    Evidence(
                        record.source_file,
                        line_number,
                        symbol,
                        detail,
                        paths.get(
                            id(record.node),
                            (TraceStep(tool.source_file, tool.line_number, tool.function_name),),
                        )
                        + (TraceStep(record.source_file, line_number, symbol),),
                    ),
                )
            )
            if len(observed) > MAX_CAPABILITY_PATHS_PER_TOOL:
                budget_exceeded = True
                break
        if budget_exceeded:
            break
    observed.sort(
        key=lambda item: (
            item.capability.value,
            item.evidence.location,
            item.evidence.symbol,
        )
    )
    return observed[:MAX_CAPABILITY_PATHS_PER_TOOL], budget_exceeded


@dataclass(frozen=True)
class _PathValue:
    sources: frozenset[str] = frozenset()
    tokens: frozenset[int] = frozenset()


@dataclass
class _PathFlowState:
    bindings: dict[str, _PathValue]
    guarded: set[int]


@dataclass(frozen=True)
class _PathSinkFlow:
    sources: frozenset[str]
    evidence: Evidence


@dataclass
class _PathScopeResult:
    sinks: list[_PathSinkFlow] = field(default_factory=list)
    expanded_sources: set[str] = field(default_factory=set)


PATH_TRANSFORM_CALLS = {
    "os.fspath",
    "os.path.abspath",
    "os.path.expanduser",
    "os.path.join",
    "os.path.normpath",
    "os.path.realpath",
    "pathlib.Path",
    "str",
}
TWO_PATH_CALLS = {
    "os.rename",
    "os.replace",
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
    "shutil.move",
}


class _PathFlowVisitor(ast.NodeVisitor):
    """Correlate path-like tool inputs, guards, and filesystem sinks."""

    def __init__(
        self,
        record: FunctionRecord,
        project: ParsedProject,
        bindings: dict[str, _PathValue],
        guarded: set[int],
        result: _PathScopeResult,
        active: set[int],
    ) -> None:
        self.record = record
        self.project = project
        self.execution = _execution(record, project)
        self.bindings = dict(bindings)
        self.guarded = set(guarded)
        self.result = result
        self.active = active

    def scan(self) -> set[int]:
        identity = id(self.record.node)
        if identity in self.active:
            return set(self.guarded)
        self.active.add(identity)
        try:
            for statement in self.record.node.body:
                self.visit(statement)
        finally:
            self.active.remove(identity)
        return set(self.guarded)

    def _state(self) -> _PathFlowState:
        return _PathFlowState(dict(self.bindings), set(self.guarded))

    def _restore(self, state: _PathFlowState) -> None:
        self.bindings = dict(state.bindings)
        self.guarded = set(state.guarded)

    def _merge_states(self, first: _PathFlowState, second: _PathFlowState) -> None:
        self.bindings = {
            name: value
            for name, value in first.bindings.items()
            if second.bindings.get(name) == value
        }
        self.guarded = first.guarded & second.guarded

    def _derived(self, node: ast.AST, values: Iterable[_PathValue]) -> _PathValue:
        items = list(values)
        sources = frozenset(source for value in items for source in value.sources)
        if not sources:
            return _PathValue()
        token = id(node)
        original_tokens = {item for value in items for item in value.tokens}
        if original_tokens and original_tokens <= self.guarded:
            self.guarded.add(token)
        return _PathValue(sources, frozenset({token}))

    def _value(self, node: ast.AST) -> _PathValue:
        if isinstance(node, ast.Name):
            return self.bindings.get(node.id, _PathValue())
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
            return self._derived(node, [self._value(node.left), self._value(node.right)])
        if isinstance(node, ast.JoinedStr):
            return self._derived(
                node,
                [self._value(value) for value in node.values],
            )
        if isinstance(node, ast.FormattedValue):
            return self._value(node.value)
        if isinstance(node, ast.Attribute) and node.attr == "parent":
            return self._derived(node, [self._value(node.value)])
        if not isinstance(node, ast.Call):
            return _PathValue()
        imports = self.execution.imports_for(node)
        name = _qualified_name(node.func, imports)
        if name in {"os.fspath", "str"}:
            values = [self._value(argument) for argument in node.args]
            return _PathValue(
                frozenset(source for value in values for source in value.sources),
                frozenset(token for value in values for token in value.tokens),
            )
        if name in PATH_TRANSFORM_CALLS:
            return self._derived(node, [self._value(argument) for argument in node.args])
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            *PATH_RETURNING_METHODS,
            "glob",
            "iterdir",
            "relative_to",
            "rglob",
        }:
            return self._derived(
                node,
                [self._value(node.func.value), *[self._value(arg) for arg in node.args]],
            )
        return _PathValue()

    def _assign(self, targets: Iterable[ast.AST], value: _PathValue) -> None:
        for target in targets:
            for name in _assigned_names(target):
                if value.sources:
                    self.bindings[name] = value
                else:
                    self.bindings.pop(name, None)

    def _guard_tokens(self, call: ast.Call) -> set[int]:
        if not isinstance(call.func, ast.Attribute) or not call.args:
            return set()
        if call.func.attr not in {"is_relative_to", "relative_to"}:
            return set()
        candidate = self._value(call.func.value)
        trusted_root = self._value(call.args[0])
        if not candidate.sources or trusted_root.sources:
            return set()
        return set(candidate.tokens)

    def _commonpath_guard_tokens(self, node: ast.Compare, truthy: bool) -> set[int]:
        if len(node.ops) != 1:
            return set()
        equality_holds = (
            isinstance(node.ops[0], ast.Eq) and truthy
        ) or (
            isinstance(node.ops[0], ast.NotEq) and not truthy
        )
        if not equality_holds:
            return set()
        if len(node.comparators) != 1:
            return set()
        sides = (node.left, node.comparators[0])
        for commonpath, root in (sides, reversed(sides)):
            if not isinstance(commonpath, ast.Call) or not commonpath.args:
                continue
            imports = self.execution.imports_for(commonpath)
            if _qualified_name(commonpath.func, imports) != "os.path.commonpath":
                continue
            if self._value(root).sources:
                continue
            paths = commonpath.args[0]
            if not isinstance(paths, (ast.List, ast.Tuple)):
                continue
            candidates = [self._value(item) for item in paths.elts]
            tainted = [candidate for candidate in candidates if candidate.sources]
            if len(tainted) == 1:
                return set(tainted[0].tokens)
        return set()

    def _conditional_guard_tokens(self, node: ast.AST, truthy: bool) -> set[int]:
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self._conditional_guard_tokens(node.operand, not truthy)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And) and truthy:
            return {
                token
                for value in node.values
                for token in self._conditional_guard_tokens(value, True)
            }
        if isinstance(node, ast.Call) and truthy:
            if isinstance(node.func, ast.Attribute) and node.func.attr == "is_relative_to":
                return self._guard_tokens(node)
        if isinstance(node, ast.Compare):
            return self._commonpath_guard_tokens(node, truthy)
        return set()

    def _sink_value(self, call: ast.Call) -> _PathValue:
        path_call = self.execution.path_filesystem_calls.get(id(call))
        if path_call is not None and isinstance(call.func, ast.Attribute):
            values = [self._value(call.func.value)]
            if call.func.attr in {"rename", "replace"} and call.args:
                values.append(self._value(call.args[0]))
            sources = frozenset(
                source for value in values for source in value.sources
            )
            tokens = frozenset(token for value in values for token in value.tokens)
            return _PathValue(sources, tokens)

        imports = self.execution.imports_for(call)
        name = _qualified_name(call.func, imports)
        indexes = (0, 1) if name in TWO_PATH_CALLS else (0,)
        values = [self._value(call.args[index]) for index in indexes if len(call.args) > index]
        for keyword in call.keywords:
            if keyword.arg in {"file", "filename", "path", "src", "dst"}:
                values.append(self._value(keyword.value))
        sources = frozenset(source for value in values for source in value.sources)
        tokens = frozenset(token for value in values for token in value.tokens)
        return _PathValue(sources, tokens)

    def _record_sink(self, call: ast.Call) -> None:
        path_call = self.execution.path_filesystem_calls.get(id(call))
        imports = self.execution.imports_for(call)
        name = _qualified_name(call.func, imports)
        capability: Capability | None
        if path_call is not None:
            symbol, capability = path_call
        else:
            capability = _call_capability(call, name, imports)
            symbol = name
        if capability not in {Capability.FILESYSTEM_READ, Capability.FILESYSTEM_WRITE}:
            return
        value = self._sink_value(call)
        if not value.sources or value.tokens <= self.guarded:
            return
        self.result.sinks.append(
            _PathSinkFlow(
                value.sources,
                Evidence(
                    self.record.source_file,
                    _line_number(call),
                    symbol or _display_name(call.func, imports),
                    "path-like tool input reaches this filesystem operation",
                ),
            )
        )

    def _record_expansion(self, call: ast.Call) -> None:
        imports = self.execution.imports_for(call)
        name = _qualified_name(call.func, imports)
        value = _PathValue()
        if name == "os.path.expanduser" and call.args:
            value = self._value(call.args[0])
        elif isinstance(call.func, ast.Attribute) and call.func.attr == "expanduser":
            value = self._value(call.func.value)
        self.result.expanded_sources.update(value.sources)

    def _callee_bindings(self, call: ast.Call, callee: FunctionRecord) -> dict[str, _PathValue]:
        bindings = dict(self.bindings) if id(call) in self.execution.nested_call_ids else {}
        parameters = [
            *callee.node.args.posonlyargs,
            *callee.node.args.args,
            *callee.node.args.kwonlyargs,
        ]
        by_name = {parameter.arg: parameter for parameter in parameters}
        positional = [*callee.node.args.posonlyargs, *callee.node.args.args]
        for parameter, argument in zip(positional, call.args, strict=False):
            if not isinstance(argument, ast.Starred):
                value = self._value(argument)
                if value.sources:
                    bindings[parameter.arg] = value
        for keyword in call.keywords:
            if keyword.arg is None or keyword.arg not in by_name:
                continue
            value = self._value(keyword.value)
            if value.sources:
                bindings[keyword.arg] = value
        return bindings

    def _follow_call(self, call: ast.Call) -> None:
        callee = self.execution.call_edges_by_call.get(id(call))
        if callee is None:
            return
        visitor = _PathFlowVisitor(
            callee,
            self.project,
            self._callee_bindings(call, callee),
            self.guarded,
            self.result,
            self.active,
        )
        self.guarded.update(visitor.scan())

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        self._record_expansion(node)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "relative_to":
            self.guarded.update(self._guard_tokens(node))
        self._record_sink(node)
        self._follow_call(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        self._assign(node.targets, self._value(node.value))

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            self._assign([node.target], self._value(node.value))
        else:
            self._assign([node.target], _PathValue())

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._assign([node.target], self._value(node.value))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.target)
        self.visit(node.value)
        self._assign([node.target], _PathValue())

    def visit_Delete(self, node: ast.Delete) -> None:
        self._assign(node.targets, _PathValue())

    def _definition_expressions(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._definition_expressions(node)
        self.bindings.pop(node.name, None)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._definition_expressions(node)
        self.bindings.pop(node.name, None)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in [*node.decorator_list, *node.bases]:
            self.visit(expression)
        for keyword in node.keywords:
            self.visit(keyword.value)
        outer = self._state()
        for statement in node.body:
            self.visit(statement)
        self._restore(outer)
        self.bindings.pop(node.name, None)

    def _visit_with(self, items: list[ast.withitem], body: list[ast.stmt]) -> None:
        for item in items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._assign([item.optional_vars], _PathValue())
        for statement in body:
            self.visit(statement)

    def visit_With(self, node: ast.With) -> None:
        self._visit_with(node.items, node.body)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with(node.items, node.body)

    def _visit_for(
        self,
        iterator: ast.AST,
        target: ast.AST,
        body: list[ast.stmt],
        orelse: list[ast.stmt],
    ) -> None:
        self.visit(iterator)
        before = self._state()
        target_value = self._derived(iterator, [self._value(iterator)])
        self._assign([target], target_value)
        for statement in body:
            self.visit(statement)
        body_state = self._state()
        self._merge_states(before, body_state)
        for statement in orelse:
            self.visit(statement)

    def visit_For(self, node: ast.For) -> None:
        self._visit_for(node.iter, node.target, node.body, node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_for(node.iter, node.target, node.body, node.orelse)

    @staticmethod
    def _terminates(statements: list[ast.stmt]) -> bool:
        return bool(statements) and isinstance(statements[-1], (ast.Raise, ast.Return))

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        before = self._state()

        self.guarded.update(self._conditional_guard_tokens(node.test, True))
        for statement in node.body:
            self.visit(statement)
        body_state = self._state()

        self._restore(before)
        self.guarded.update(self._conditional_guard_tokens(node.test, False))
        for statement in node.orelse:
            self.visit(statement)
        else_state = self._state()

        body_continues = not self._terminates(node.body)
        else_continues = not self._terminates(node.orelse)
        if body_continues and else_continues:
            self._merge_states(body_state, else_state)
        elif body_continues:
            self._restore(body_state)
        elif else_continues:
            self._restore(else_state)
        else:
            self._restore(before)

    def _visit_try(
        self,
        body: list[ast.stmt],
        handlers: list[ast.ExceptHandler],
        orelse: list[ast.stmt],
        finalbody: list[ast.stmt],
    ) -> None:
        before = self._state()
        for statement in body:
            self.visit(statement)
        for statement in orelse:
            self.visit(statement)
        continuing = [] if self._terminates(orelse or body) else [self._state()]

        for handler in handlers:
            self._restore(before)
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name is not None:
                self.bindings.pop(handler.name, None)
            for statement in handler.body:
                self.visit(statement)
            if not self._terminates(handler.body):
                continuing.append(self._state())

        if continuing:
            merged = continuing[0]
            for state in continuing[1:]:
                self._restore(merged)
                self._merge_states(merged, state)
                merged = self._state()
            self._restore(merged)
        else:
            self._restore(before)
        for statement in finalbody:
            self.visit(statement)

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_try(node.body, node.handlers, node.orelse, node.finalbody)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self._visit_try(node.body, node.handlers, node.orelse, node.finalbody)

    def _visit_comprehension(
        self,
        generators: list[ast.comprehension],
        values: list[ast.AST],
    ) -> None:
        outer = self._state()
        for generator in generators:
            self.visit(generator.iter)
            self._assign(
                [generator.target],
                self._derived(generator.iter, [self._value(generator.iter)]),
            )
            for condition in generator.ifs:
                self.visit(condition)
        for value in values:
            self.visit(value)
        self._restore(outer)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, [node.elt])

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators, [node.key, node.value])

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        if node.generators:
            self.visit(node.generators[0].iter)


def _path_scope_result(
    project: ParsedProject,
    tool: ToolDefinition,
    path_parameters: set[str],
) -> _PathScopeResult:
    result = _PathScopeResult()
    record = project.functions.get((tool.source_file, tool.function_name))
    if record is None:
        return result
    bindings = {
        name: _PathValue(frozenset({name}), frozenset({-(index + 1)}))
        for index, name in enumerate(sorted(path_parameters))
    }
    _PathFlowVisitor(record, project, bindings, set(), result, set()).scan()
    return result


def _reads_environment(node: ast.AST, execution: _ExecutionResult) -> bool:
    return any(
        (
            isinstance(child, ast.Call)
            and id(child) in execution.visited_ids
            and _call_capability(
                child,
                _qualified_name(child.func, execution.imports_for(child)),
                execution.imports_for(child),
            )
            == Capability.ENVIRONMENT_READ
        )
        or (
            isinstance(child, ast.Subscript)
            and id(child) in execution.visited_ids
            and _environment_subscript(child, execution.imports_for(child))
        )
        for child in ast.walk(node)
    )


def _names(node: ast.AST, execution: _ExecutionResult) -> set[str]:
    return {
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and id(child) in execution.visited_ids
    }


def _tainted_environment_to_network(
    record: FunctionRecord,
    project: ParsedProject,
) -> Evidence | None:
    tainted: set[str] = set()
    execution = _execution(record, project)
    for node in execution.events:
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            assigned = {
                name
                for target in targets
                for name in _assigned_names(target)
            }
            value_is_tainted = _reads_environment(value, execution) or bool(
                _names(value, execution) & tainted
            )
            tainted.difference_update(assigned)
            if value_is_tainted:
                tainted.update(assigned)
            continue

        if not isinstance(node, ast.Call):
            continue
        imports = execution.imports_for(node)
        name = execution.instance_network_calls.get(id(node))
        if name is None:
            name = _qualified_name(node.func, imports)
        if (
            id(node) not in execution.instance_network_calls
            and _call_capability(node, name, imports) != Capability.NETWORK_EGRESS
        ):
            continue
        if _names(node, execution) & tainted or _reads_environment(node, execution):
            return Evidence(
                record.source_file,
                _line_number(node),
                name,
                "environment-derived data reaches a network call in the same function",
            )
    return None


@dataclass(frozen=True)
class _StaticPathDefault:
    value: str
    expands_home: bool = False


def _parameter_default_nodes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, ast.AST]:
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults: dict[str, ast.AST] = {
        argument.arg: default
        for argument, default in zip(
            positional[-len(node.args.defaults) :],
            node.args.defaults,
            strict=True,
        )
    } if node.args.defaults else {}
    defaults.update(
        {
            argument.arg: default
            for argument, default in zip(
                node.args.kwonlyargs,
                node.args.kw_defaults,
                strict=True,
            )
            if default is not None
        }
    )
    return defaults


def _static_path_default(
    node: ast.AST,
    imports: dict[str, str],
) -> _StaticPathDefault | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _StaticPathDefault(node.value)
    if not isinstance(node, ast.Call):
        return None
    name = _qualified_name(node.func, imports)
    if name == "pathlib.Path.home" and not node.args and not node.keywords:
        return _StaticPathDefault("~", expands_home=True)
    if name == "os.path.expanduser" and node.args:
        value = _static_path_default(node.args[0], imports)
        return (
            _StaticPathDefault(value.value, expands_home=True)
            if value is not None
            else None
        )
    if isinstance(node.func, ast.Attribute) and node.func.attr == "expanduser":
        value = _static_path_default(node.func.value, imports)
        return (
            _StaticPathDefault(value.value, expands_home=True)
            if value is not None
            else None
        )
    if name == "pathlib.Path" and node.args:
        return _static_path_default(node.args[0], imports)
    return None


def _dangerous_path_default(
    node: ast.AST,
    imports: dict[str, str],
    expanded_in_body: bool,
) -> str | None:
    default = _static_path_default(node, imports)
    if default is None:
        return None
    if default.value and set(default.value) == {"/"}:
        return "the POSIX filesystem root"
    if default.value in {"~", "~/"} and (
        default.expands_home or expanded_in_body
    ):
        return "the user's home directory"
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
    unresolved_edges: Iterable[UnresolvedCallEdge] = (),
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

    indicator = _poisoning_indicator(tool.description)
    if indicator is not None:
        findings.append(
            _finding(
                "MSC001",
                "Agent-directed instruction in tool description",
                Severity.CRITICAL,
                tool,
                f"The tool description contains a {indicator.family}: "
                f"{indicator.excerpt!r}.",
                "Describe the tool's behavior and constraints; remove instructions "
                "aimed at controlling the host model.",
                description_evidence,
            )
        )

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
        assessment = _assess_network_disclosure(
            tool.description,
            _static_network_hosts(project, tool),
        )
        network_evidence = by_capability[Capability.NETWORK_EGRESS]
        disclosure_detail = f"description check: {assessment.reason}"
        for index, item in enumerate(observed):
            if item.capability != Capability.NETWORK_EGRESS:
                continue
            observed[index] = ObservedCapability(
                item.capability,
                Evidence(
                    item.evidence.source_file,
                    item.evidence.line_number,
                    item.evidence.symbol,
                    f"{item.evidence.detail}; {disclosure_detail}",
                    item.evidence.path,
                ),
            )
        if not assessment.disclosed:
            if assessment.contradiction:
                title = "Network behavior contradicts tool description"
                message = (
                    "Reachable network egress contradicts the description's explicit "
                    f"denial. Deterministic check: {assessment.reason}."
                )
            elif "does not match static host" in assessment.reason:
                title = "Described network destination does not match reachable egress"
                message = (
                    "A reachable static destination conflicts with the destination named "
                    f"in the description. Deterministic check: {assessment.reason}."
                )
            else:
                title = "Network egress is not disclosed"
                message = "A reachable network call is absent from the tool's description."
            findings.append(
                _finding(
                    "MSC102",
                    title,
                    Severity.HIGH,
                    tool,
                    message,
                    "State the destination and data purpose, or remove network access.",
                    Evidence(
                        network_evidence.source_file,
                        network_evidence.line_number,
                        network_evidence.symbol,
                        f"{network_evidence.detail}; {disclosure_detail}",
                        network_evidence.path,
                    ),
                )
            )

    path_parameters = {
        parameter.name
        for parameter in tool.parameters
        if _is_path_parameter_name(parameter.name)
    }
    records = reachable_functions(project, tool)
    path_scope = _path_scope_result(project, tool, path_parameters)
    path_guard_state_unresolved = bool(path_parameters) and any(unresolved_edges)
    if path_scope.sinks and not path_guard_state_unresolved:
        unguarded_parameters = sorted(
            source
            for sink in path_scope.sinks
            for source in sink.sources
        )
        evidence = max(
            path_scope.sinks,
            key=lambda sink: (
                sink.evidence.source_file,
                sink.evidence.line_number,
                sink.evidence.symbol,
            ),
        ).evidence
        matching_capability = next(
            (
                item.evidence
                for item in observed
                if item.capability
                in {Capability.FILESYSTEM_READ, Capability.FILESYSTEM_WRITE}
                and item.evidence.source_file == evidence.source_file
                and item.evidence.line_number == evidence.line_number
                and item.evidence.symbol == evidence.symbol
            ),
            None,
        )
        if matching_capability is not None:
            evidence = Evidence(
                evidence.source_file,
                evidence.line_number,
                evidence.symbol,
                evidence.detail,
                matching_capability.path,
            )
        findings.append(
            _finding(
                "MSC103",
                "Filesystem scope is not constrained",
                Severity.HIGH,
                tool,
                f"Path-like parameter(s) {sorted(set(unguarded_parameters))} reach filesystem "
                "operations without a recognized containment check.",
                "Resolve the candidate path and prove it remains beneath a fixed, "
                "trusted root before access.",
                evidence,
            )
        )

    tool_record = project.functions.get((tool.source_file, tool.function_name))
    default_nodes = (
        _parameter_default_nodes(tool_record.node)
        if tool_record is not None
        else {}
    )
    for parameter in tool.parameters:
        if not _is_path_parameter_name(parameter.name):
            continue
        default_node = default_nodes.get(parameter.name)
        if default_node is None or tool_record is None:
            continue
        dangerous_default = _dangerous_path_default(
            default_node,
            tool_record.imports,
            parameter.name in path_scope.expanded_sources,
        )
        if dangerous_default is not None:
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
        flow = _tainted_environment_to_network(record, project)
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

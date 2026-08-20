"""Reachability-aware capability and contract analysis."""

from __future__ import annotations

import ast
import ipaddress
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
    "http.client.HTTPConnection": frozenset(
        {"connect", "request", "putrequest", "send", "endheaders"}
    ),
    "http.client.HTTPSConnection": frozenset(
        {"connect", "request", "putrequest", "send", "endheaders"}
    ),
    "socket.socket": frozenset({"connect", "connect_ex", "sendall", "sendto"}),
    "aiohttp.ClientSession": frozenset(
        {"delete", "get", "head", "options", "patch", "post", "put", "request", "ws_connect"}
    ),
    "urllib3.PoolManager": frozenset(
        {"request", "urlopen", "request_encode_url", "request_encode_body"}
    ),
    "urllib3.HTTPConnectionPool": frozenset({"request", "urlopen"}),
}
# Process-launching sinks. This is an allowlist, and it is documented as one:
# anything absent is not reported, so additions belong here rather than in a rule.
# `os.exec*`, `os.spawn*`, `pty.*`, and `multiprocessing.Process` all launch a
# program just as plainly as `subprocess.run`, and reporting `Observed: none` for
# them is worse than reporting nothing at all - it affirmatively denies a
# capability the tool has.
PROCESS_PREFIXES = (
    "asyncio.create_subprocess_",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.posix_spawn",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "subprocess.",
)
PROCESS_CALLS = {
    "multiprocessing.Process",
    "multiprocessing.pool.Pool",
    "os.fork",
    "os.forkpty",
    "os.popen",
    "os.startfile",
    "os.system",
    "pty.fork",
    "pty.openpty",
    "pty.spawn",
}
# Dynamic code execution. `runpy` executes a file or module as __main__ and
# `types.FunctionType(compile(...))` reconstitutes a callable from source, both of
# which are code execution by any reading of the term.
CODE_EXECUTION_CALLS = {
    "builtins.compile",
    "builtins.eval",
    "builtins.exec",
    "code.InteractiveInterpreter",
    "code.interact",
    "compile",
    "eval",
    "exec",
    "runpy.run_module",
    "runpy.run_path",
    "types.FunctionType",
}

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

# --- MSC102 external-network-egress review (conservative, fail-safe) ---
# ScopeCheck proves reachable network egress from the call graph and always reports
# it as an observed capability. For modeled network sinks, MSC102 is a mandatory
# external-egress review signal: no modeled external destination is ever cleared,
# because neither description prose nor a matching service hostname proves the
# intended destination (services host attacker-controllable content on the same
# hosts as their APIs, and prose is an adversarial surface). A dynamic/computed
# destination is likewise flagged. The ONLY exemption is a destination classified
# as local/loopback/private by explicit IP-address parsing (see `_is_local_host`).
# Service matching below is used only to select the more informative
# destination-mismatch subtype, never to suppress a finding. An explicit network
# denial produces the contradiction subtype; denial detection is best-effort,
# because a missed denial still falls through to the generic review finding rather
# than to silence. Discord is intentionally absent from the service set: its
# webhook endpoint shares the discord.com host with its API, so a host match would
# be meaningless there.
_SERVICE_NAMES = ("github", "gitlab", "gmail", "google", "slack")
KNOWN_DESTINATIONS = frozenset(_SERVICE_NAMES)

# Sentence segmentation used for negation scoping. Newlines are boundaries so an
# unpunctuated bullet/argument block does not merge into one span; terminal
# punctuation splits only when followed by whitespace or end of text, so a dotted
# hostname or version number is not fragmented mid-token.
_SENTENCE_SPLIT = re.compile(r"[.!?;]+(?=\s)|[.!?;]+$|[\n\r]+")
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
# Denial targets are deliberately narrow: only unambiguously network-scoped words.
# Generic terms ("url", "server", "endpoint"), bare service names, dotted module
# paths ("os.path"), and filenames ("requirements.txt") are excluded so unrelated
# negations are not misread as denials. A missed denial is not a safety problem
# under this rule: it simply falls through to the generic external-egress review
# finding instead of the contradiction subtype.
_DENIAL_TARGET = r"(?:internet|networks?|remote|external|outbound)"
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
    severity: Severity


# Severity is per indicator family, because the families differ in how strongly the
# match implies an instruction aimed at the host model rather than a description of
# the tool's own behavior.
#
# CRITICAL families match a directive that has no legitimate reading in a tool
# description: overriding prior instructions, concealing activity from the user,
# acting covertly, impersonating a privileged role, or embedding a control token.
#
# HIGH families match wording that is frequently, but not exclusively, malicious:
#
# * `credential-handling instruction` matches a verb near a credential noun. A tool
#   that legitimately manages secrets describes itself that way ("Read credentials
#   from the configured system keychain entry"), so the match is evidence worth a
#   human decision rather than proof of poisoning.
# * `cross-call instruction` matches sequencing wording ("before any request"),
#   which is also how an ordinary tool documents a prerequisite.
#
# Reporting these at CRITICAL made honest credential, authentication, and workflow
# tools indistinguishable from poisoned ones. Detection is unchanged; only the
# severity assigned to an ambiguous family moved.
_INDICATOR_SEVERITIES: dict[str, Severity] = {
    "covert sensitive-data transfer": Severity.CRITICAL,
    "concealment instruction": Severity.CRITICAL,
    "hidden action": Severity.CRITICAL,
    "hidden-token marker": Severity.CRITICAL,
    "instruction override": Severity.CRITICAL,
    "privileged-role impersonation": Severity.CRITICAL,
    "credential-handling instruction": Severity.HIGH,
    "cross-call instruction": Severity.HIGH,
}


@dataclass(frozen=True)
class _DisclosureAssessment:
    disclosed: bool
    reason: str
    contradiction: bool = False


@dataclass(frozen=True)
class _NetworkDestinations:
    """Statically resolved destinations of a tool's reachable network egress.

    `unresolved` is True when any reachable egress call has a destination that
    cannot be read from a string literal (dynamic/computed URL), which must be
    flagged for review rather than trusted.
    """

    external: tuple[str, ...] = ()
    local: tuple[str, ...] = ()
    unresolved: bool = False


_LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "127.0.0.0/8",  # loopback
        "10.0.0.0/8",  # RFC1918
        "172.16.0.0/12",  # RFC1918
        "192.168.0.0/16",  # RFC1918
        "::1/128",  # IPv6 loopback
        "fc00::/7",  # IPv6 unique-local
    )
)


def _is_local_host(host: str) -> bool:
    """True only for the localhost name and genuine loopback/RFC1918/ULA IPs.

    Parses the host as an IP address so a hostname merely resembling a private range
    ("10.example.com", "127.0.0.1.evil.com") is treated as external, not dropped.
    Only loopback, RFC1918, and IPv6 unique-local addresses count as local; every
    other address — link-local (including 169.254.169.254 cloud metadata),
    benchmarking, test-net, reserved, and all globally routable hosts — is external
    and flagged, so local/loopback is the one exemption and nothing routable slips
    through it.
    """

    name = host.lower().strip(".")
    if name == "localhost" or name.endswith(".localhost"):
        return True
    candidate = name[1:-1] if name.startswith("[") and name.endswith("]") else name
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    # Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) so an external mapped address is not
    # read as private on CPython versions that classified the whole block private.
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return any(address in network for network in _LOCAL_NETWORKS)


def _poisoning_indicator(description: str) -> _DescriptionIndicator | None:
    normalized = " ".join(description.split())
    matches = [
        _DescriptionIndicator(
            label,
            match.group(0),
            _INDICATOR_SEVERITIES.get(label, Severity.CRITICAL),
        )
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
    # Report the strongest family a description matches, not the first pattern in
    # declaration order, so an unambiguous directive is never downgraded because it
    # also happens to mention a credential.
    return max(matches, key=lambda match: int(match.severity))


# Public registrable domains for each named service. A host match here NEVER clears
# a finding — every modeled external destination is flagged regardless. The match is
# used only to decide whether a reachable host is consistent with a service the
# description names: an inconsistency yields the destination-mismatch subtype, and a
# consistent host still yields the generic external-egress review finding. The list
# is kept to first-party API domains (user-content/redirect domains such as
# github.io and *.githubusercontent.com are omitted) so the mismatch subtype stays
# meaningful; it is not a trust or allow decision.
_SERVICE_DOMAINS: dict[str, frozenset[str]] = {
    "github": frozenset({"github.com"}),
    "gitlab": frozenset({"gitlab.com"}),
    "gmail": frozenset({"gmail.com", "google.com", "googleapis.com"}),
    "google": frozenset({"google.com", "googleapis.com", "gstatic.com"}),
    "slack": frozenset({"slack.com"}),
}

# Hosts that sit on a first-party registrable domain but serve arbitrary
# user-controlled endpoints (buckets, gists, deployed scripts, incoming webhooks).
# Because no external host is ever cleared, this list does not affect suppression;
# it only prevents such a host from being counted as "consistent" with a named
# service, so egress to it is reported as a destination mismatch rather than a plain
# review finding.
_UNTRUSTED_SERVICE_HOSTS = (
    "storage.googleapis.com",
    "firebasestorage.googleapis.com",
    "script.google.com",
    "sites.google.com",
    "docs.google.com",
    "drive.google.com",
    "chat.googleapis.com",
    "gist.github.com",
    "hooks.slack.com",
)


def _registrable_domain(host: str) -> str:
    """Approximate the registrable domain (eTLD+1) as the last two DNS labels."""

    labels = [label for label in host.lower().split(".") if label]
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _host_matches_service(host: str, service: str) -> bool:
    """True when a reachable host is consistent with a named service (registrable
    domain on the service list, excluding user-content/webhook hosts). This selects
    the destination-mismatch subtype only; it never clears an external egress
    finding."""

    host = host.lower().strip(".")
    if any(host == deny or host.endswith(f".{deny}") for deny in _UNTRUSTED_SERVICE_HOSTS):
        return False
    return _registrable_domain(host) in _SERVICE_DOMAINS.get(service, frozenset())


def _normalize_apostrophes(text: str) -> str:
    """Fold typographic apostrophes to ASCII so negation and denial matching is
    not defeated by a curly quote in "doesn't"/"won't"."""

    return text.replace("’", "'").replace("‘", "'").replace("ʼ", "'")


def _sentences(description: str) -> list[str]:
    return [
        " ".join(fragment.split())
        for fragment in _SENTENCE_SPLIT.split(_normalize_apostrophes(description))
        if fragment.strip()
    ]


def _assess_network_disclosure(
    description: str,
    destinations: _NetworkDestinations,
) -> _DisclosureAssessment:
    external = destinations.external

    # 0. Purely local/loopback egress is not external network access, so a "never
    # uses the network" denial about it is truthful rather than a contradiction.
    if not external and not destinations.unresolved:
        if destinations.local:
            return _DisclosureAssessment(
                True, "reachable network calls target only local or loopback hosts"
            )
        return _DisclosureAssessment(
            False, "reachable network egress has no statically resolved destination"
        )

    sentences = _sentences(description)

    # 1. Explicit denial of network access, scoped to a sentence -> contradiction.
    # Best-effort: a denial this misses still flags below rather than suppressing.
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

    # A service counts as a named destination only in a non-negated sentence, so a
    # denial ("never contacts Slack") can never double as a disclosure.
    described = sorted(
        service
        for service in KNOWN_DESTINATIONS
        if any(
            re.search(rf"\b{service}\b", sentence, re.I) and not _NEGATION.search(sentence)
            for sentence in sentences
        )
    )

    if external:
        # A resolved external host is never cleared, even when its registrable
        # domain matches a named service: GitHub, GitLab, and Google serve
        # attacker-controllable content (repos, gists, snippets, buckets, webhooks)
        # on the same hosts as their APIs, so a host match cannot prove the specific
        # destination is the disclosed one. The service comparison is used only to
        # choose the more informative subtype when a named service is contradicted.
        unmatched = [
            host
            for host in external
            if not any(_host_matches_service(host, service) for service in described)
        ]
        if described and unmatched:
            return _DisclosureAssessment(
                False,
                f"described destination {described!r} does not match "
                f"static host(s) {unmatched!r}",
            )
        return _DisclosureAssessment(
            False,
            f"reachable external host(s) {list(external)!r} are not verifiably "
            "disclosed",
        )

    # No external host resolved, but a dynamic/computed destination remains. It
    # cannot be verified, so it is flagged, never suppressed by prose.
    return _DisclosureAssessment(
        False,
        "the reachable network destination is not statically resolvable and is "
        "not disclosed",
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
        # A locally defined class shadows into the module alias table with an empty
        # target, so it must be recognized before the alias lookup below; otherwise
        # constructing it is misreported as a higher-order call through a variable.
        if (record.source_file, name) in project.classes:
            return _LocalCallResolution(
                reason=UnresolvedReason.UNSUPPORTED_INSTANCE_DISPATCH,
                candidate=name,
            )
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
            elif _callback_arguments(project, record, node):
                # A project-local function handed to a call the analyzer cannot
                # follow - `pool.submit(_worker, path)`, `sorted(items, key=_pick)`.
                # Whatever that callee does runs, but nothing here proves when. It
                # previously vanished with an empty ledger and a `complete` audit,
                # which denies a capability the tool has.
                add_unresolved(
                    record,
                    node,
                    UnresolvedReason.HIGHER_ORDER_CALL,
                    ", ".join(_callback_arguments(project, record, node)),
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


def _callback_arguments(
    project: ParsedProject,
    record: FunctionRecord,
    call: ast.Call,
) -> list[str]:
    """Names of project-local functions passed as arguments to `call`.

    Passing a function is not calling it, so no call edge is created, and the callee
    is never analyzed. Reporting nothing at all would state that a tool reading files
    inside its callback has no reachable capability.
    """

    names = []
    for argument in [*call.args, *[keyword.value for keyword in call.keywords]]:
        if not isinstance(argument, ast.Name):
            continue
        if (record.source_file, argument.id) in project.functions:
            names.append(argument.id)
    return names


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
    if name in CODE_EXECUTION_CALLS:
        return Capability.CODE_EXECUTION
    return None


def _network_method_kind(symbol: str) -> str:
    method = symbol.rsplit(".", 1)[-1].lower()
    if method in NETWORK_READ_METHODS:
        return "read"
    if method in NETWORK_WRITE_METHODS:
        return "write"
    return "unknown"


def _safe_target_description(node: ast.AST) -> str:
    """Short, bounded description of an assignment target for evidence."""

    rendered = _call_expression(node)
    return rendered[:80] if rendered else type(node).__name__


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


def _looks_like_path_expression(node: ast.AST, record: FunctionRecord) -> bool:
    """Structural test for an expression that yields a filesystem path.

    Evaluated in the callee's own scope, so a module-level root such as
    `ROOT = Path("/srv/docs")` counts: `return ROOT / value` is the ordinary way a
    path helper is written.
    """

    imports = record.imports
    if isinstance(node, ast.Name):
        return node.id in record.path_bindings
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _looks_like_path_expression(node.left, record)
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        return _looks_like_path_expression(node.value, record)
    if not isinstance(node, ast.Call):
        return False
    if _qualified_name(node.func, imports) in {"pathlib.Path", "os.fspath"}:
        return True
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in PATH_RETURNING_METHODS
        and _looks_like_path_expression(node.func.value, record)
    )


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
        if isinstance(value, ast.NamedExpr):
            return self._is_path_value(value.value, resolved_imports)
        # A container element is deliberately NOT a path. Whether `D[k]` holds one
        # is not knowable here, and every attempt to have it both ways produced a
        # verdict that changed with the spelling: treating it as a path invented
        # filesystem writes on in-memory caches, and gating that on method names
        # made `D[k].touch()` and `entry = D[k]; entry.touch()` disagree. A path
        # retrieved from a container by subscript is not tracked; that is a bounded
        # false negative, stated in docs/limitations.md, and it is preferred to an
        # unbounded false positive on ordinary code.
        if not isinstance(value, ast.Call):
            return False
        if _qualified_name(value.func, resolved_imports) == "pathlib.Path":
            return True
        if (
            isinstance(value.func, ast.Attribute)
            and value.func.attr in PATH_RETURNING_METHODS
            and self._is_path_value(value.func.value, resolved_imports)
        ):
            return True
        if self._returns_path(value):
            return True
        # A call that receives a path and returns something unmodeled may well
        # return that path: `_pick(Path(name)).write_text(body)` is an arbitrary
        # caller-controlled write. Treating the result as not-a-path made the sink
        # invisible, so the tool reported `Observed: none` under a `complete` audit -
        # an affirmative denial of a capability it has. Fail closed instead: if any
        # argument is a path, the result may be one.
        #
        # `str()` is excluded because it is documented to return a string, and
        # `str.replace` collides with `Path.replace`, which is a filesystem rename.
        # Without this, `str(ROOT / name).replace("a", "b")` - ordinary string
        # surgery - reported a filesystem write.
        if _qualified_name(value.func, resolved_imports) == "str":
            return False
        return any(
            self._is_path_value(argument, resolved_imports)
            for argument in value.args
            if not isinstance(argument, ast.Starred)
        ) or any(
            self._is_path_value(keyword.value, resolved_imports)
            for keyword in value.keywords
            if keyword.arg is not None
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

    def _returns_path(self, call: ast.Call) -> bool:
        """Whether a resolvable project-local callee returns a path.

        `def _resolve(name): return ROOT / name` then `_resolve(name).write_text(...)`
        is the ordinary way to write a path helper, and it constructs the path inside
        the callee, so there is no path argument to notice. Before 0.2.2 the sink was
        never registered and the tool reported `Observed: none` under a `complete`
        audit - an arbitrary caller-controlled write, denied outright.

        One level deep, over calls the analyzer already resolved, which is the
        same-file boundary the product already claims.
        """

        # Resolve the callee directly rather than reading the edge table: the
        # receiver call has not been traversed yet when its parent is classified.
        callee = self._direct_call_resolution(call).target
        if callee is None or callee is self.record:
            return False
        for node in ast.walk(callee.node):
            if not isinstance(node, (ast.Return, ast.Expr)):
                continue
            returned = node.value
            if returned is None:
                continue
            if isinstance(node, ast.Expr) and not isinstance(returned, ast.Yield):
                continue
            if isinstance(returned, ast.Yield):
                returned = returned.value
            if returned is None:
                continue
            if _looks_like_path_expression(returned, callee):
                return True
        return False

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
        # A generator expression is a comprehension. Visiting only the first
        # iterable, as releases before 0.2.2 did, made every call inside the
        # element expression invisible: `"".join(subprocess.check_output(cmd,
        # shell=True) for _ in ...)` reported `Side effects: 0`, `Observed: none`,
        # `complete`, exit 0 - an affirmative denial of a capability the tool has.
        self._visit_comprehension(node.generators, [node.elt])


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


def _network_destinations(
    project: ParsedProject,
    tool: ToolDefinition,
) -> _NetworkDestinations:
    """Classify the reachable network egress destinations of a tool.

    Every reachable egress call whose destination is not a resolvable string
    literal marks the result `unresolved`, so a dynamic or computed destination is
    flagged for review rather than trusted.
    """

    external: set[str] = set()
    local: set[str] = set()
    unresolved = False
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
            host = urlsplit(endpoint).hostname if endpoint is not None else None
            if not host:
                unresolved = True
                continue
            host = host.lower()
            (local if _is_local_host(host) else external).add(host)
    return _NetworkDestinations(
        external=tuple(sorted(external)),
        local=tuple(sorted(local)),
        unresolved=unresolved,
    )


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
                indicator.severity,
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
            _network_destinations(project, tool),
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
                title = "External network egress requires review"
                message = (
                    "A modeled reachable external network call was found. ScopeCheck "
                    "does not treat description prose or a matching service hostname "
                    "as proof of the intended destination."
                )
            findings.append(
                _finding(
                    "MSC102",
                    title,
                    Severity.HIGH,
                    tool,
                    message,
                    "Verify and approve the destination and data purpose; constrain "
                    "or remove network access if it is not intended.",
                    Evidence(
                        network_evidence.source_file,
                        network_evidence.line_number,
                        network_evidence.symbol,
                        f"{network_evidence.detail}; {disclosure_detail}",
                        network_evidence.path,
                    ),
                )
            )

    # Seed path tracking from every declared parameter and let the flow analysis
    # decide. `_sink_value` only reads path positions (the receiver, argument 0,
    # argument 1 of a two-path call, and the file/filename/path/src/dst keywords),
    # so a non-path parameter becomes a sink source only when it genuinely occupies
    # a path position. Parameter naming is a ranking hint, never the gate: a
    # traversal through `filepath`, `target`, or `name` is the same defect as one
    # through `path`.
    # MSC103 (filesystem scope) and MSC104 (dangerous filesystem default) are
    # withdrawn in 0.2.2. Both decided whether caller-controlled path access was
    # reported, and both got it wrong across four consecutive candidates in
    # alternating directions - and in the last one, still by parameter name, which
    # is the mechanism the project's own advisory is written about. A rule that
    # cannot decide containment reliably must not claim to: the filesystem
    # capability and its evidence path are still reported, and the reader is told
    # plainly that containment is not analyzed. See docs/limitations.md.
    records = reachable_functions(project, tool)

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

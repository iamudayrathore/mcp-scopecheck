#!/usr/bin/env python3
"""Behavioural validation of an INSTALLED mcp-scopecheck against adversarial input.

Run against the built wheel in a clean environment, not the source tree, so it
exercises what users actually receive::

    python3 scripts/validate_release.py /path/to/venv/bin/mcp-scopecheck

The unit suite pins behaviour at the API level; this pins it at the CLI boundary
that CI, the composite action, and every user actually consume - exit codes,
completeness states, and rendered output.

It exists because two releases shipped with false-clean results the unit suite did
not catch: the checks and the fixes were written from the same mental model, so
they shared its blind spots. Every case asserts one of two properties - genuinely
dangerous code never yields exit 0 with completeness ``complete``, or ordinary
benign code is not reported.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PREAMBLE = (
    "import code\n"
    "import multiprocessing\n"
    "import os\n"
    "import os.path\n"
    "import posixpath\n"
    "import pty\n"
    "import runpy\n"
    "import subprocess\n"
    "import types\n"
    "import urllib.parse\n"
    "from pathlib import Path\n"
    "ROOT = Path('/srv/docs')\n"
    "def _pick(value):\n"
    "    return value\n"
)


class Validator:
    """Runs CLI cases against one installed executable and tallies failures."""

    def __init__(self, executable: str) -> None:
        self.executable = executable
        self.passed = 0
        self.failures: list[str] = []

    def audit(self, target: Path, *arguments: str) -> tuple[int, str]:
        completed = subprocess.run(
            [self.executable, "audit", str(target), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
        return completed.returncode, completed.stdout + completed.stderr

    def check(self, label: str, condition: bool, detail: str = "") -> None:
        if condition:
            self.passed += 1
        else:
            self.failures.append(f"{label}: {detail}")

    @staticmethod
    def server(body: str, *, preamble: str = "", annotations: str = "") -> Path:
        directory = Path(tempfile.mkdtemp())
        decorator = (
            f"@mcp.tool(annotations={{{annotations}}})" if annotations else "@mcp.tool()"
        )
        source = (
            f"{PREAMBLE}{preamble}\n"
            "from mcp.server.fastmcp import FastMCP\n"
            "mcp = FastMCP('v')\n\n"
            f"{decorator}\n"
            "def entry(name: str):\n"
            '    """Read a bundled documentation file."""\n'
            f"{body}\n"
        )
        (directory / "server.py").write_text(source, encoding="utf-8")
        return directory

    @staticmethod
    def raw(content: bytes) -> Path:
        directory = Path(tempfile.mkdtemp())
        (directory / "server.py").write_bytes(content)
        return directory


# Path lineage. Every form reaches a filesystem call with caller-controlled input,
# so none may produce a clean result. Some are reported as MSC103 and some fail
# closed to partial; either is correct, silence is not.
LINEAGE = {
    "percent": '    t = "%s/%s" % ("/srv", name)\n    open(t).read()',
    "format": '    t = "{}/{}".format("/srv", name)\n    open(t).read()',
    "str_join": '    t = "/".join(["/srv", name])\n    open(t).read()',
    "os_sep_join": '    t = os.sep.join(["/srv", name])\n    open(t).read()',
    "posixpath_join": '    t = posixpath.join("/srv", name)\n    open(t).read()',
    "os_path_join": '    t = os.path.join("/srv", name)\n    open(t).read()',
    "strip": '    t = name.strip("/")\n    open(t).read()',
    "lstrip": '    t = name.lstrip("./")\n    open(t).read()',
    "replace_dotdot": '    t = name.replace("..", "")\n    open(t).read()',
    "removeprefix": '    t = name.removeprefix("/")\n    open(t).read()',
    "encode_decode": "    t = name.encode().decode()\n    open(t).read()",
    "ternary": '    t = name if name else "d"\n    open(t).read()',
    "walrus": "    t = (x := name)\n    open(t).read()",
    "dict_index": '    t = {"k": name}["k"]\n    open(t).read()',
    "list_index": "    t = [name][0]\n    open(t).read()",
    "slice": "    t = name[0:]\n    open(t).read()",
    "unquote": "    t = urllib.parse.unquote(name)\n    open(t).read()",
    "tuple_unpack": "    t, _ = name, 1\n    open(t).read()",
    "aug_assign": '    t = "/srv"\n    t += name\n    open(t).read()',
    "for_binding": "    for t in [name]:\n        pass\n    open(t).read()",
    "try_binding": (
        '    try:\n        t = name\n    except Exception:\n        t = "d"\n'
        "    open(t).read()"
    ),
    "list_comprehension": "    t = [v for v in [name]][0]\n    open(t).read()",
    "next_iter": "    t = next(iter([name]))\n    open(t).read()",
    "helper_return": "    t = _pick(name)\n    open(t).read()",
    "external_call": "    import somepkg\n    t = somepkg.clean(name)\n    open(t).read()",
    "fstring": '    t = f"/srv/{name}"\n    open(t).read()',
    "concat": '    t = "/srv/" + name\n    open(t).read()',
    "write_mode": '    open(name, "w").write("x")',
    "file_keyword": "    open(file=name).read()",
    "subscript_store": '    r = {}\n    r["t"] = name\n    open(r["t"]).read()',
    "attribute_store": (
        "    class Box:\n        t = None\n    Box.t = name\n    open(Box.t).read()"
    ),
    "container_mutation": "    q = []\n    q.append(name)\n    open(q[0]).read()",
    "match_capture": (
        "    match name:\n        case str() as t:\n            open(t).read()"
    ),
    "generator_expression": '    return "".join(open(name).read() for _ in range(1))',
}

# Defeated guards. Each of these performs a containment check that cannot actually
# constrain the sink - the exception is swallowed, or the guarded value is not the
# one that reaches the sink. None may produce a clean result. Every case here was a
# false clean in a release that shipped its gate green.
DEFEATED_GUARDS = {
    "try_except_pass": (
        "    try:\n"
        "        t = ROOT / name\n"
        "        t.relative_to(ROOT)\n"
        "    except ValueError:\n"
        "        pass\n"
        "    t.read_text()"
    ),
    "try_except_bare": (
        "    try:\n"
        "        t = ROOT / name\n"
        "        t.relative_to(ROOT)\n"
        "    except Exception:\n"
        "        _ = 1\n"
        "    t.read_text()"
    ),
    "try_except_finally": (
        "    try:\n"
        "        t = ROOT / name\n"
        "        t.resolve().relative_to(ROOT)\n"
        "    except ValueError:\n"
        "        _ = 1\n"
        "    finally:\n"
        "        _ = 2\n"
        "    t.read_text()"
    ),
    "contextlib_suppress": (
        "    import contextlib\n"
        "    t = ROOT / name\n"
        "    with contextlib.suppress(ValueError):\n"
        "        t.relative_to(ROOT)\n"
        "    t.read_text()"
    ),
    "guard_then_escape_upward": (
        "    t = ROOT / name\n"
        "    t.resolve().relative_to(ROOT)\n"
        '    (t / ".." / ".." / "etc" / "passwd").read_text()'
    ),
    "guard_then_expanduser": (
        "    t = ROOT / name\n"
        "    t.resolve().relative_to(ROOT)\n"
        "    t.expanduser().read_text()"
    ),
    "guard_then_join": (
        "    t = ROOT / name\n"
        "    t.resolve().relative_to(ROOT)\n"
        '    t.joinpath("..", "..", "etc").read_text()'
    ),
    "guard_other_value": (
        "    a = ROOT / name\n"
        "    b = ROOT / (name + '.bak')\n"
        "    a.resolve().relative_to(ROOT)\n"
        "    b.read_text()"
    ),
    "write_after_defeated_guard": (
        "    try:\n"
        "        t = ROOT / name\n"
        "        t.relative_to(ROOT)\n"
        "    except ValueError:\n"
        "        pass\n"
        '    t.write_text("x")'
    ),
}

# Stores that put tool input somewhere the analyzer does not track. Whatever the
# spelling, none may produce a clean result: `d[k] = p` and `d.__setitem__(k, p)`
# are the same operation and must be reported the same way.
UNTRACKED_STORES = {
    "subscript": '    r = {}\n    r["t"] = name\n    open(r["t"]).read()',
    "dunder_setitem": '    r = {}\n    r.__setitem__("t", name)\n    open(r["t"]).read()',
    "operator_setitem": (
        "    import operator\n    r = {}\n"
        '    operator.setitem(r, "t", name)\n    open(r["t"]).read()'
    ),
    "heapq_heappush": (
        "    import heapq\n    q = []\n"
        "    heapq.heappush(q, name)\n    open(q[0]).read()"
    ),
    "deque_appendleft": (
        "    import collections\n    q = collections.deque()\n"
        "    q.appendleft(name)\n    open(q[0]).read()"
    ),
    "attribute": (
        "    class Box:\n        t = None\n    Box.t = name\n    open(Box.t).read()"
    ),
}

# Execution primitives. Each must report its capability and the matching Critical
# rule, and must never render "Observed: none".
EXECUTION = {
    "execv": ('    os.execv("/bin/sh", ["sh", "-c", name])', "MSC106"),
    "execl": ('    os.execl("/bin/sh", "sh", "-c", name)', "MSC106"),
    "execvp": ('    os.execvp("sh", ["sh", "-c", name])', "MSC106"),
    "spawnv": ('    os.spawnv(os.P_WAIT, "/bin/sh", ["sh", "-c", name])', "MSC106"),
    "posix_spawn": ('    os.posix_spawn("/bin/sh", ["sh", "-c", name], {})', "MSC106"),
    "fork": ("    os.fork()", "MSC106"),
    "forkpty": ("    os.forkpty()", "MSC106"),
    "startfile": ("    os.startfile(name)", "MSC106"),
    "system": ("    os.system(name)", "MSC106"),
    "popen": ("    os.popen(name)", "MSC106"),
    "pty_spawn": ('    pty.spawn(["/bin/sh", "-c", name])', "MSC106"),
    "pty_fork": ("    pty.fork()", "MSC106"),
    "pty_openpty": ("    pty.openpty()", "MSC106"),
    "multiprocessing": (
        "    multiprocessing.Process(target=os.system, args=(name,))",
        "MSC106",
    ),
    "subprocess_run": ("    subprocess.run(name, shell=True)", "MSC106"),
    "generator_subprocess": (
        '    return "".join(\n'
        "        subprocess.check_output(name, shell=True).decode() for _ in range(1)\n"
        "    )",
        "MSC106",
    ),
    "eval": ("    eval(name)", "MSC107"),
    "exec_builtin": ("    exec(name)", "MSC107"),
    "compile": ('    compile(name, "<s>", "exec")', "MSC107"),
    "runpy_path": ("    runpy.run_path(name)", "MSC107"),
    "runpy_module": ("    runpy.run_module(name)", "MSC107"),
    "code_interpreter": ("    code.InteractiveInterpreter().runsource(name)", "MSC107"),
    "function_type": (
        '    types.FunctionType(compile(name, "<s>", "exec"), {})()',
        "MSC107",
    ),
}

# Benign servers. None may be reported; a scanner that punishes correct code
# inverts its own signal.
BENIGN = {
    "guard_relative_to": (
        "    c = (ROOT / name).resolve()\n    c.relative_to(ROOT)\n    c.read_text()"
    ),
    "guard_on_normalized_temporary": (
        '    t = ROOT / (name + ".md")\n'
        "    t.resolve().relative_to(ROOT.resolve())\n"
        "    t.read_text()"
    ),
    "guard_with_untainted_fallback": (
        "    try:\n"
        '        t = ROOT / "sections" / (name + ".md")\n'
        "        t.resolve().relative_to(ROOT.resolve())\n"
        "    except ValueError:\n"
        '        t = ROOT / "index.md"\n'
        "    t.read_text()"
    ),
    "guard_is_relative_to": (
        "    c = (ROOT / name).resolve()\n"
        "    if not c.is_relative_to(ROOT):\n        raise ValueError\n"
        "    c.read_text()"
    ),
    "fixed_path_search": (
        '    text = (ROOT / "index.txt").read_text()\n'
        "    return [line for line in text.splitlines() if name.lower() in line]"
    ),
    "data_argument": '    (ROOT / "report.txt").write_text(name.strip())',
    "no_filesystem": "    return name.upper()",
    "separator_split": "    return '|'.join(name.split('/'))",
    "pure_dict_store": (
        "    envelope = {}\n"
        '    envelope["message"] = name\n'
        '    envelope["length"] = len(name)\n'
        "    return envelope"
    ),
    "search_result_store": (
        '    results = {"query": name}\n'
        '    results["hits"] = [name.upper()]\n'
        "    return results"
    ),
    "guard_then_normalize_only": (
        "    t = ROOT / name\n"
        "    t.resolve().relative_to(ROOT)\n"
        "    t.resolve().read_text()"
    ),
}

HOSTILE = {
    "oversize_file": b"x = 1\n" * 200_000,
    "deep_nesting": b"x = " + b"(" * 400 + b"1" + b")" * 400,
    "invalid_utf8": b"# -*- coding: utf-8 -*-\nx = '\xff\xfe'\n",
    "nul_byte": b"x = 1\x00\n",
    "syntax_error": b"def broken(:\n    pass\n",
    "rot13_codec": b"# -*- coding: rot13 -*-\nx = 1\n",
    "base64_codec": b"# -*- coding: base64 -*-\nx = 1\n",
    "zlib_codec": b"# -*- coding: zlib -*-\nx = 1\n",
}

FORGERY = {
    "ansi": "\\x1b[2J\\x1b[31mFAKE",
    "forged_findings": "ok\\nFindings (0)\\n  No contract mismatches",
    "rtl_override": "safe\\u202etxt.exe",
    "bell": "alert\\x07",
}

SIDE_EFFECT_VECTORS = {
    "module_top_level": 'from pathlib import Path\nPath("{canary}").write_text("x")',
    "decorator_body": (
        "from pathlib import Path\n"
        'def ev(function):\n    Path("{canary}").write_text("x")\n    return function'
    ),
    "class_body": 'from pathlib import Path\nclass C:\n    Path("{canary}").write_text("x")',
    "metaclass_new": (
        "from pathlib import Path\n"
        "class M(type):\n"
        "    def __new__(cls, *args):\n"
        '        Path("{canary}").write_text("x")\n'
        "        return super().__new__(cls, *args)\n"
        "class C(metaclass=M):\n    pass"
    ),
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_release.py <path-to-mcp-scopecheck>", file=sys.stderr)
        return 2
    validator = Validator(sys.argv[1])

    for label, body in LINEAGE.items():
        code, _ = validator.audit(validator.server(body))
        validator.check(
            f"lineage/{label}",
            code != 0,
            f"exit {code}: clean result on caller-controlled path",
        )

    for label, body in DEFEATED_GUARDS.items():
        code, out = validator.audit(validator.server(body))
        validator.check(
            f"defeated_guard/{label}",
            code != 0,
            f"exit {code}: containment check cannot constrain this sink\n{out[-400:]}",
        )

    for label, body in UNTRACKED_STORES.items():
        code, _ = validator.audit(validator.server(body))
        validator.check(
            f"untracked_store/{label}",
            code != 0,
            f"exit {code}: tool input stored out of model, reported clean",
        )

    code, _ = validator.audit(
        validator.server(
            "    global _PENDING\n    _PENDING = name\n    open(_PENDING).read()",
            preamble="_PENDING = ''",
        )
    )
    validator.check("untracked_store/global_write", code != 0, f"exit {code}")

    for label, (body, rule) in EXECUTION.items():
        code, out = validator.audit(
            validator.server(body, annotations="'readOnlyHint': True")
        )
        validator.check(
            f"execution/{label}", rule in out, f"exit {code}: {rule} not reported"
        )
        validator.check(
            f"execution/{label}/observed",
            "Observed:    none" not in out,
            "reported Observed: none for a capability it has",
        )

    for label, body in BENIGN.items():
        code, out = validator.audit(validator.server(body))
        validator.check(
            f"benign/{label}", code == 0, f"exit {code}: false positive\n{out[-400:]}"
        )

    canary = Path(tempfile.mkdtemp()) / "CANARY"
    for label, template in SIDE_EFFECT_VECTORS.items():
        if canary.exists():
            canary.unlink()
        preamble = template.format(canary=canary)
        validator.audit(validator.server("    return name", preamble=preamble))
        validator.check(
            f"no_execution/{label}", not canary.exists(), "target code executed"
        )

    for label, content in HOSTILE.items():
        code, _ = validator.audit(validator.raw(content))
        validator.check(f"hostile/{label}", code == 2, f"exit {code}, expected 2")

    directory = Path(tempfile.mkdtemp())
    real = directory / "real.py"
    real.write_text("x = 1\n", encoding="utf-8")
    link = directory / "link.py"
    os.symlink(real, link)
    code, out = validator.audit(link)
    validator.check(
        "hostile/symlink_target", code == 2 and "symlink" in out.lower(), f"exit {code}"
    )

    for label, payload in FORGERY.items():
        directory = Path(tempfile.mkdtemp())
        (directory / "server.py").write_text(
            "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('v')\n\n"
            f'@mcp.tool(description="{payload}")\ndef entry(name: str):\n    return name\n',
            encoding="utf-8",
        )
        _, out = validator.audit(directory)
        validator.check(
            f"forgery/{label}",
            not any(character in out for character in ("\x1b", "\x07", "\u202e")),
            "raw control sequence reached the output stream",
        )

    findings_target = validator.server(
        '    t = os.path.join("/srv", name)\n    open(t).read()'
    )
    for label, arguments, expected in (
        ("default_threshold", (), 1),
        ("critical_threshold", ("--fail-on", "critical"), 0),
    ):
        code, _ = validator.audit(findings_target, *arguments)
        validator.check(f"exit/{label}", code == expected, f"exit {code}")
    code, _ = validator.audit(validator.server("    return name"), "--fail-on", "bogus")
    validator.check("exit/invalid_threshold", code != 0, f"exit {code}")

    code, out = validator.audit(findings_target, "--format", "sarif")
    try:
        document = json.loads(out)
        run = document["runs"][0]
        validator.check(
            "sarif/findings",
            document["version"] == "2.1.0" and bool(run["results"]),
            "malformed SARIF",
        )
    except (ValueError, KeyError, IndexError) as error:
        validator.check("sarif/findings", False, f"not valid SARIF: {error}")
    _, out = validator.audit(validator.raw(b"def broken(:\n"), "--format", "sarif")
    try:
        json.loads(out.split("\n{", 1)[0] if out.startswith("{") else out)
        validator.check("sarif/failure_is_json", True)
    except ValueError as error:
        validator.check("sarif/failure_is_json", False, str(error))

    print("=" * 62)
    print(f"PASS {validator.passed}   FAIL {len(validator.failures)}")
    print("=" * 62)
    for failure in validator.failures:
        print("  FAIL", failure)
    return 1 if validator.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Deterministic AST-based SAST. Scans a file or a whole source directory (the
"source_path" attached to a scan) instead of a single hardcoded demo file.

Each check is conservative on purpose: it looks for an unambiguous dangerous
pattern rather than guessing at intent, so findings here don't need an LLM to be
trustworthy.
"""
import ast
import os
import re

SKIP_DIRS = {"venv", "venv311", ".venv", "node_modules", "__pycache__", ".git"}

SECRET_KEY_HINTS = re.compile(r"(secret|api[_-]?key|token|password|passwd)", re.IGNORECASE)
SECRET_VALUE = re.compile(r"^[A-Za-z0-9_\-/+=]{12,}$")


def _iter_py_files(path):
    if os.path.isfile(path):
        yield path
        return
    for root, dirs, names in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for n in names:
            if n.endswith(".py"):
                yield os.path.join(root, n)


def _check_call(node, file_path):
    """eval/exec and subprocess(..., shell=True)."""
    name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
    if name in ("eval", "exec"):
        return {"file": file_path, "line": node.lineno, "type": "dangerous_eval",
                "severity": "HIGH", "message": f"Use of {name}() on what may be untrusted input."}
    if name == "run":
        for kw in node.keywords:
            if kw.arg == "shell" and getattr(kw.value, "value", None) is True:
                return {"file": file_path, "line": node.lineno, "type": "command_injection",
                        "severity": "HIGH", "message": "subprocess call with shell=True detected."}
    return None


def _check_assign(node, file_path):
    """A module/class-level string literal assigned to a name that looks like a secret."""
    if not isinstance(node, ast.Assign):
        return None
    value = node.value
    if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
        return None
    if not SECRET_VALUE.match(value.value):
        return None
    for target in node.targets:
        if isinstance(target, ast.Name) and SECRET_KEY_HINTS.search(target.id):
            return {"file": file_path, "line": node.lineno, "type": "hardcoded_secret",
                    "severity": "HIGH", "message": f"Possible hardcoded secret assigned to '{target.id}'."}
    return None


def _check_sql(node, file_path):
    """cursor.execute(f"... {x} ...") or string-concatenated SQL -- classic injection shape."""
    name = getattr(node.func, "attr", None)
    if name not in ("execute", "executemany") or not node.args:
        return None
    arg = node.args[0]
    if isinstance(arg, ast.JoinedStr):  # f-string
        return {"file": file_path, "line": node.lineno, "type": "sql_injection_risk",
                "severity": "HIGH", "message": "SQL query built with an f-string; use parameterized queries."}
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        return {"file": file_path, "line": node.lineno, "type": "sql_injection_risk",
                "severity": "HIGH", "message": "SQL query built with string concatenation; use parameterized queries."}
    return None


class Scanner:
    def invoke(self, payload):
        path = payload.get("path", "demo_target.py")
        findings = []
        files_scanned = 0

        for file_path in _iter_py_files(path):
            try:
                tree = ast.parse(open(file_path, encoding="utf-8").read(), filename=file_path)
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue
            files_scanned += 1
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    for check in (_check_call, _check_sql):
                        f = check(node, file_path)
                        if f:
                            findings.append(f)
                elif isinstance(node, ast.Assign):
                    f = _check_assign(node, file_path)
                    if f:
                        findings.append(f)

        return {"path": path, "files_scanned": files_scanned, "findings": findings}


code_scanner = Scanner()

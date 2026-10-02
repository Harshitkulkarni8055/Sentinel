"""Static route extraction for FastAPI/Flask-style decorators: maps a URL path
template to the file and line that handles it, so a runtime finding on that path
can be traced back to source. AST-based, no execution of target code.
"""
import ast
import os

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def _decorator_route(dec):
    """Return (method, path) for @app.get("/x"), @router.post("/x"), etc., or None."""
    if not isinstance(dec, ast.Call):
        return None
    func = dec.func
    if not isinstance(func, ast.Attribute) or func.attr.lower() not in HTTP_METHODS:
        return None
    if not dec.args:
        return None
    arg = dec.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return func.attr.upper(), arg.value
    return None


def _normalize(path):
    """FastAPI's {user_id} and Flask's <int:user_id> both become {id}-shaped for matching."""
    import re
    path = re.sub(r"<[^:>]+:([^>]+)>", r"{\1}", path)   # Flask typed converter
    path = re.sub(r"<([^>]+)>", r"{\1}", path)           # Flask plain
    return path


def extract_routes(path):
    """path: a .py file or a directory. Returns {normalized_path: [{method, file, line, function}]}."""
    routes = {}
    files = []
    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            if any(part.startswith(".") or part in ("venv", "venv311", "node_modules", "__pycache__")
                   for part in root.split(os.sep)):
                continue
            files.extend(os.path.join(root, n) for n in names if n.endswith(".py"))

    for file_path in files:
        try:
            tree = ast.parse(open(file_path, encoding="utf-8").read(), filename=file_path)
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                route = _decorator_route(dec)
                if not route:
                    continue
                method, raw_path = route
                norm = _normalize(raw_path)
                routes.setdefault(norm, []).append({
                    "method": method, "file": file_path, "line": node.lineno, "function": node.name,
                })
    return routes


def find_route(routes, url_path, method=None):
    """Look up a runtime-observed path (already {id}-templated the same way
    authorization_tester produces) against the extracted route map."""
    entries = routes.get(url_path)
    if not entries:
        return None
    if method:
        for e in entries:
            if e["method"] == method.upper():
                return e
    return entries[0]

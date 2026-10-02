import re
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup

TIMEOUT = 3.0
MAX_PAGES = 30

# Common API/auth paths that are rarely linked from HTML, so a plain crawl misses them.
# This is a generic discovery technique (used by every real DAST tool), not app-specific.
COMMON_PATHS = [
    "/login", "/signin", "/auth/login", "/api/login", "/api/auth",
    "/api/users", "/api/user", "/api/accounts", "/api/products", "/api/items",
    "/api/admin", "/admin", "/api/me", "/api/profile", "/api/search",
    "/health", "/api/health", "/api/status",
]


def _probe_common_paths(client, base, endpoints, seen):
    for path in COMMON_PATHS:
        try:
            r = client.get(base + path)
        except Exception:
            continue
        if r.status_code == 404:
            continue
        methods = ["GET"]
        if r.status_code == 405:
            # GET isn't allowed here; read the real methods off the Allow header
            # instead of guessing (common for POST-only login endpoints).
            allow = r.headers.get("allow", "")
            methods = [m.strip().upper() for m in allow.split(",") if m.strip()] or ["POST"]
        params = ["q"] if path == "/api/search" else []
        if "POST" in methods and path.endswith(("login", "signin")):
            params = params + ["username", "password"]
        _add_endpoint(endpoints, seen, path, methods, params)


def _probe_object_ids(client, base, endpoints, seen):
    """REST ID-guessing: for a discovered collection-style path (e.g. /api/users) with
    no ID segment yet, try appending a small id and see if the app resolves a single
    object. This is how authorization_tester finds endpoints worth IDOR-testing without
    hardcoding any path."""
    collection_like = [e for e in list(endpoints) if not re.search(r"\{.*\}|/\d+$", e["path"])
                        and e["path"].count("/") <= 2 and "GET" in e["methods"]]
    for ep in collection_like[:10]:
        path = ep["path"].rstrip("/")
        try:
            r = client.get(f"{base}{path}/1")
        except Exception:
            continue
        if r.status_code == 200:
            template = f"{path}/{{id}}"
            _add_endpoint(endpoints, seen, template, ["GET"], ["id"])


def _headers(resp):
    h = {k.lower(): v for k, v in resp.headers.items()}
    return {
        "content_security_policy": "content-security-policy" in h,
        "x_frame_options": "x-frame-options" in h,
        "x_content_type_options": "x-content-type-options" in h,
        "strict_transport_security": "strict-transport-security" in h,
        "access_control_allow_origin": "access-control-allow-origin" in h,
    }

def _add_endpoint(endpoints, seen, path, methods=None, parameters=None):
    methods = methods or ["GET"]
    parameters = parameters or []
    key = (path, tuple(sorted(methods)), tuple(sorted(parameters)))
    if key in seen:
        return
    seen.add(key)
    endpoints.append({
        "path": path,
        "methods": sorted(set(methods)),
        "parameters": sorted(set(parameters)),
    })

def web_recon(target: str):
    target = target.rstrip("/")
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    endpoints, seen = [], set()
    pages = []
    queue = [target]
    visited = set()
    security_headers = {}

    with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
        # OpenAPI first, if present.
        for spec_path in ("/openapi.json", "/swagger.json"):
            try:
                r = client.get(base + spec_path)
                if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
                    spec = r.json()
                    for path, methods in spec.get("paths", {}).items():
                        for method, op in methods.items():
                            if method.lower() not in {"get","post","put","patch","delete","options","head"}:
                                continue
                            params = []
                            for p in op.get("parameters", []) or []:
                                if isinstance(p, dict) and p.get("name"):
                                    params.append(p["name"])
                            for pname in (p.get("name") for p in (op.get("parameters", []) or []) if isinstance(p, dict)):
                                if pname:
                                    params.append(pname)
                            _add_endpoint(endpoints, seen, path, [method.upper()], params)
                    break
            except Exception:
                pass

        while queue and len(visited) < MAX_PAGES:
            url = queue.pop(0)
            if url in visited:
                continue
            if urlparse(url).netloc != parsed.netloc:
                continue
            visited.add(url)
            try:
                r = client.get(url)
            except Exception:
                continue
            pages.append(url)
            path = urlparse(str(r.url)).path or "/"
            security_headers[path] = _headers(r)
            ctype = r.headers.get("content-type", "")
            if "html" in ctype:
                soup = BeautifulSoup(r.text, "html.parser")
                _add_endpoint(endpoints, seen, path, ["GET"], [])
                for form in soup.find_all("form"):
                    action = urlparse(urljoin(str(r.url), form.get("action") or path))
                    fpath = action.path or "/"
                    method = (form.get("method") or "GET").upper()
                    params = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if name:
                            params.append(name)
                    _add_endpoint(endpoints, seen, fpath, [method], params)
                for a in soup.find_all("a", href=True):
                    nxt = urljoin(str(r.url), a["href"])
                    u = urlparse(nxt)
                    if u.netloc == parsed.netloc and u.scheme in {"http","https"}:
                        clean = f"{u.scheme}://{u.netloc}{u.path or '/'}"
                        if clean not in visited and clean not in queue:
                            queue.append(clean)
            else:
                _add_endpoint(endpoints, seen, path, ["GET"], [])

    with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
        _probe_common_paths(client, base, endpoints, seen)
        _probe_object_ids(client, base, endpoints, seen)

    return {
        "target": target,
        "pages_scanned": len(pages),
        "endpoints": endpoints,
        "security_headers": security_headers,
        "requests_made": len(pages),
    }

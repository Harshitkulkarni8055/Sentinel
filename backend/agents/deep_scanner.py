"""Phase 3 coverage: SQLi, cookie flags, open redirect, CORS, exposed files, and
login rate limiting. Bundled into one planner-selectable tool since none of these
checks depend on an authenticated session.
"""
import httpx
from urllib.parse import urljoin
from tools.vuln_probes import (
    sqli_probe, cookie_flags, open_redirect_probe, cors_probe,
    exposed_file_probe, login_rate_limit_probe,
)
from tools.sessions import find_login_spec

REDIRECT_PARAM_HINTS = ("url", "redirect", "next", "return", "dest", "continue")
MAX_SQLI_TARGETS = 6


def deep_scanner(state):
    print("\n=== DEEP VULNERABILITY SCANNER ===")
    base = state["target"].rstrip("/")
    recon = next((o.get("result", {}) for o in state["observations"] if o.get("type") == "web_recon"), {})
    endpoints = recon.get("endpoints", [])

    findings = []
    with httpx.Client(timeout=5.0, follow_redirects=False) as client:
        # SQLi: any GET endpoint with parameters, capped to stay fast and polite.
        sqli_targets = [(e["path"], p) for e in endpoints if "GET" in e.get("methods", [])
                         for p in e.get("parameters", [])][:MAX_SQLI_TARGETS]
        for path, param in sqli_targets:
            url = urljoin(base + "/", path.lstrip("/").split("{")[0] or "/")
            f = sqli_probe(client, url, param)
            if f:
                findings.append(f)

        # Cookies: whatever the root page and a login attempt set.
        try:
            root_resp = client.get(base + "/")
            findings.extend(cookie_flags(base + "/", root_resp))
        except httpx.HTTPError:
            pass

        # Open redirect: endpoints whose parameter names look like redirect targets.
        for ep in endpoints:
            for param in ep.get("parameters", []):
                if param.lower() in REDIRECT_PARAM_HINTS:
                    f = open_redirect_probe(client, base, ep["path"], param)
                    if f:
                        findings.append(f)

        # CORS.
        f = cors_probe(client, base)
        if f:
            findings.append(f)

        # Exposed sensitive files.
        findings.extend(exposed_file_probe(client, base))

        # Login rate limiting, if a login form was found.
        spec = find_login_spec(endpoints)
        if spec:
            f = login_rate_limit_probe(client, base, spec, "sentinel_probe_user")
            if f:
                findings.append(f)

    result = {"checks_run": ["sqli", "cookies", "open_redirect", "cors", "exposed_files", "rate_limit"],
              "potential_findings": findings}
    state["observations"].append({"type": "deep_scan", "result": result})
    print(f"Potential findings: {len(findings)}")
    return state

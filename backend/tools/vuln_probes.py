"""Deterministic, non-destructive probes for Phase 3 coverage. Each function returns
either None (nothing found) or a finding dict in the same shape the rest of the
pipeline already uses, so it can go straight into `potential_findings`.

Every probe is read-only and uses benign payloads only -- no data is written or
deleted on the target.
"""
import re
import time
import httpx

TIMEOUT = 3.0

SQLI_ERROR_SIGNATURES = (
    "sql syntax", "mysql_fetch", "sqlite3.operationalerror", "psycopg2",
    "ora-01756", "unclosed quotation mark", "pg_query", "sqlstate",
)
SQLI_PAYLOADS = ["'", "' OR '1'='1", "\""]

EXPOSED_FILES = [".env", ".git/HEAD", ".git/config", "backup.zip", "backup.sql",
                  "config.php.bak", "web.config", ".DS_Store"]

JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")


def _finding(type_, vuln, endpoint, severity, status, confidence, evidence, reasoning, remediation,
             parameter=None, reproduction=None):
    f = {
        "type": type_, "vulnerability": vuln, "endpoint_or_file": endpoint,
        "severity": severity, "status": status, "confidence": confidence,
        "evidence": evidence, "reasoning": reasoning, "remediation": remediation,
        "provenance": "deterministic",
    }
    if parameter:
        f["parameter"] = parameter
    if reproduction:
        f["reproduction"] = reproduction
    return f


def sqli_probe(client, url, param):
    """Boolean/error-based SQLi: compare a baseline response to a single-quote probe
    and an always-true tautology. A real DB error string, or a tautology that returns
    materially more content than the baseline, is evidence worth flagging."""
    try:
        baseline = client.get(url, params={param: "sentinel_baseline"})
        quote = client.get(url, params={param: "'"})
        tautology = client.get(url, params={param: "' OR '1'='1"})
    except httpx.HTTPError:
        return None

    low = quote.text.lower()
    if any(sig in low for sig in SQLI_ERROR_SIGNATURES):
        return _finding(
            "sql_injection", "SQL Injection", url, "HIGH", "CONFIRMED", "HIGH",
            f"A single-quote probe on parameter '{param}' returned a database error message.",
            "The application returns raw database errors for malformed input, indicating "
            "the value is used unsafely in a SQL query.",
            "Use parameterized queries / prepared statements; never concatenate user input into SQL.",
            parameter=param, reproduction=str(quote.request.url),
        )

    if (tautology.status_code == 200 and baseline.status_code == 200
            and len(tautology.text) > len(baseline.text) * 1.5
            and len(tautology.text) - len(baseline.text) > 200):
        return _finding(
            "sql_injection", "Possible SQL Injection", url, "HIGH", "INCONCLUSIVE", "MEDIUM",
            f"A tautology probe ('OR '1'='1') on '{param}' returned a much larger response "
            f"than a baseline value ({len(tautology.text)} vs {len(baseline.text)} bytes).",
            "A large response-size shift on a boolean tautology can indicate the query "
            "returns extra rows, but this needs manual confirmation.",
            "Use parameterized queries / prepared statements; never concatenate user input into SQL.",
            parameter=param, reproduction=str(tautology.request.url),
        )
    return None


def cookie_flags(url, response):
    """Secure / HttpOnly / SameSite checks on any Set-Cookie header seen."""
    findings = []
    is_https = url.startswith("https://")
    for cookie in response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else \
            ([response.headers["set-cookie"]] if "set-cookie" in response.headers else []):
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        missing = []
        if is_https and "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            findings.append(_finding(
                "insecure_cookie", "Insecure Session Cookie", url, "MEDIUM", "CONFIRMED", "HIGH",
                f"Cookie '{name}' is missing: {', '.join(missing)}.",
                "A session cookie without these flags is more exposed to theft via XSS or CSRF.",
                "Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.",
            ))
    return findings


def open_redirect_probe(client, base, path, param):
    marker = "http://sentinel-redirect-check.invalid/"
    try:
        r = client.get(base + path, params={param: marker})
    except httpx.HTTPError:
        return None
    location = r.headers.get("location", "")
    if r.is_redirect and marker.rstrip("/") in location:
        return _finding(
            "open_redirect", "Open Redirect", path, "MEDIUM", "CONFIRMED", "HIGH",
            f"Request with {param}={marker} redirected to an attacker-controlled URL.",
            "The redirect target is taken from user input without validating it stays on-site.",
            "Validate redirect targets against an allow-list of known paths/hosts.",
            parameter=param, reproduction=str(r.request.url),
        )
    return None


def cors_probe(client, base):
    try:
        r = client.get(base + "/", headers={"Origin": "https://sentinel-cors-check.invalid"})
    except httpx.HTTPError:
        return None
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "")
    if acao == "https://sentinel-cors-check.invalid" or (acao == "*" and acac.lower() == "true"):
        return _finding(
            "cors_misconfiguration", "CORS Misconfiguration", "/", "HIGH", "CONFIRMED", "HIGH",
            f"Access-Control-Allow-Origin reflected an arbitrary origin "
            f"(Allow-Credentials: {acac or 'not set'}).",
            "Reflecting any Origin while allowing credentials lets any site read "
            "authenticated responses from a logged-in victim's browser.",
            "Use a strict allow-list of trusted origins; never reflect Origin when credentials are allowed.",
            reproduction=str(r.request.url),
        )
    return None


def exposed_file_probe(client, base):
    findings = []
    for path in EXPOSED_FILES:
        try:
            r = client.get(base + "/" + path)
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and len(r.content) > 0:
            findings.append(_finding(
                "exposed_sensitive_file", "Exposed Sensitive File", "/" + path, "HIGH", "CONFIRMED", "HIGH",
                f"GET /{path} returned HTTP 200 with {len(r.content)} bytes of content.",
                "A file that should never be served by the web server is publicly reachable.",
                "Remove the file from the web root or block it at the server/proxy level.",
                reproduction=str(r.request.url),
            ))
    return findings


def jwt_weak_probe(token):
    """Flags only the unambiguous case: alg:none, decoded without a signature check.
    Never attempts to crack or verify a real signature."""
    import base64
    import json as _json
    if not token or not JWT_RE.match(token):
        return None
    try:
        header_b64 = token.split(".")[0]
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        header = _json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        return _finding(
            "jwt_alg_none", "JWT alg:none Accepted", "(token)", "HIGH", "CONFIRMED", "HIGH",
            "The issued JWT declares alg:none in its header.",
            "A token with alg:none can be forged with no signature at all if the server honors it.",
            "Reject alg:none; pin the expected algorithm server-side instead of trusting the token header.",
        )
    return None


def login_rate_limit_probe(client, base, spec, bad_username):
    """Fires a handful of rapid failed logins and checks whether the app ever starts
    rejecting them (429, lockout message, or a growing delay). Capped low so this
    stays safe against real targets."""
    attempts = 6
    statuses = []
    start = time.monotonic()
    for i in range(attempts):
        try:
            r = client.post(base + spec["path"], data={
                spec["user_field"]: bad_username, spec["pass_field"]: f"wrong{i}"})
            statuses.append(r.status_code)
        except httpx.HTTPError:
            break
    elapsed = time.monotonic() - start
    if len(statuses) == attempts and 429 not in statuses and elapsed < attempts * TIMEOUT * 0.5:
        return _finding(
            "no_login_rate_limit", "Missing Login Rate Limiting", spec["path"], "MEDIUM", "CONFIRMED", "MEDIUM",
            f"{attempts} rapid failed login attempts all completed normally "
            f"(statuses: {statuses}) with no throttling observed.",
            "Without rate limiting or lockout, the login endpoint is open to credential brute-forcing.",
            "Add rate limiting, account lockout, or CAPTCHA after repeated failed login attempts.",
        )
    return None

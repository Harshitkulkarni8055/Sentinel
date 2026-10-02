import re
from urllib.parse import urljoin

# Sessions opened by auth_agent stay alive in state["auth_context"]["sessions"]
# for the verifier node to replay reproduction requests; it closes them.

OBJECT_ID_PARAMS = {"id", "user_id", "userid", "uid", "account_id", "order_id"}
ADMIN_HINTS = ("admin", "manage", "internal", "staff")


def _object_endpoints(endpoints):
    """Endpoints that look like they address a specific object: a {id}-style path segment
    or a query/body parameter named like one."""
    out = []
    for ep in endpoints or []:
        path = ep.get("path", "")
        path_param = re.search(r"\{(\w*(id|uid)\w*)\}", path, re.IGNORECASE)
        query_param = next((p for p in ep.get("parameters", []) if p.lower() in OBJECT_ID_PARAMS), None)
        if path_param or query_param:
            out.append({"path": path, "methods": ep.get("methods", ["GET"]),
                        "path_param": path_param.group(1) if path_param else None,
                        "query_param": query_param})
    return out


def _admin_endpoints(endpoints):
    return [ep for ep in endpoints or [] if any(h in ep.get("path", "").lower() for h in ADMIN_HINTS)]


def _fill(base, path, path_param, value):
    filled = path.replace("{" + path_param + "}", str(value)) if path_param else path
    return urljoin(base.rstrip("/") + "/", filled.lstrip("/"))


def _request(client, base, ep, value):
    if ep["path_param"]:
        url = _fill(base, ep["path"], ep["path_param"], value)
        return client.get(url)
    url = _fill(base, ep["path"], None, None)
    return client.get(url, params={ep["query_param"]: value})


def authorization_tester(state):
    print("\n=== AUTHORIZATION / IDOR ENGINE ===")
    base = state["target"].rstrip("/")

    recon = next((o.get("result", {}) for o in state["observations"] if o.get("type") == "web_recon"), {})
    endpoints = recon.get("endpoints", [])
    object_eps = _object_endpoints(endpoints)
    admin_eps = _admin_endpoints(endpoints)

    auth_ctx = state.get("auth_context", {})
    sessions = auth_ctx.get("sessions", {})
    labels = list(sessions.keys())

    tests = []
    findings = []

    if len(labels) >= 2 and object_eps:
        label_a, label_b = labels[0], labels[1]
        client_a, info_a, _ = sessions[label_a]
        client_b, info_b, _ = sessions[label_b]
        id_a = info_a.get("user_id") or "1"
        id_b = info_b.get("user_id") or "2"

        for ep in object_eps[:5]:
            try:
                resp_cross = _request(client_a, base, ep, id_b)
            except Exception:
                continue
            tests.append({"endpoint": ep["path"], "as": label_a, "requested_id": id_b, "status": resp_cross.status_code})
            if resp_cross.status_code == 200 and id_b in resp_cross.text:
                findings.append({
                    "type": "idor",
                    "vulnerability": "Insecure Direct Object Reference (IDOR)",
                    "endpoint_or_file": ep["path"],
                    "parameter": ep["path_param"] or ep["query_param"],
                    "severity": "HIGH",
                    "status": "CONFIRMED",
                    "confidence": "HIGH",
                    "evidence": f"Authenticated identity '{label_a}' (id {id_a}) accessed object id {id_b} belonging to '{label_b}' with HTTP 200.",
                    "reasoning": "The endpoint authenticates the caller but does not enforce ownership of the requested object.",
                    "remediation": "Enforce server-side object-level authorization: verify the requested object belongs to the caller before returning it.",
                    "reproduction": str(resp_cross.request.url),
                })

    if labels and admin_eps:
        non_admin = next((l for l in labels if sessions[l][2].get("role") != "admin"), None)
        if non_admin:
            client, _info, _cred = sessions[non_admin]
            for ep in admin_eps[:3]:
                try:
                    url = urljoin(base + "/", ep["path"].lstrip("/"))
                    resp = client.get(url)
                except Exception:
                    continue
                tests.append({"endpoint": ep["path"], "as": non_admin, "status": resp.status_code})
                if resp.status_code == 200:
                    findings.append({
                        "type": "privilege_escalation",
                        "vulnerability": "Broken Access Control / Privilege Escalation",
                        "endpoint_or_file": ep["path"],
                        "severity": "HIGH",
                        "status": "CONFIRMED",
                        "confidence": "HIGH",
                        "evidence": f"Non-admin identity '{non_admin}' received HTTP 200 from {ep['path']}.",
                        "reasoning": "The endpoint checks authentication but does not enforce the required administrative role.",
                        "remediation": "Enforce server-side role/permission checks before administrative operations.",
                        "reproduction": str(resp.request.url),
                    })

    unique, seen = [], set()
    for f in findings:
        key = (f.get("type"), f.get("endpoint_or_file"))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    result = {"tests": tests, "potential_findings": unique, "status": "completed",
              "identities_available": labels, "object_endpoints_checked": len(object_eps),
              "admin_endpoints_checked": len(admin_eps)}
    state["observations"].append({"type": "authorization_test", "result": result})

    print(f"Identities available: {labels}")
    print(f"Authorization tests: {len(tests)}")
    print(f"Potential authorization findings: {len(unique)}")
    return state

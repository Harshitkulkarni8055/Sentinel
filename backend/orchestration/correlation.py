"""Joins runtime findings to the source code that handles them.

This is the "killer demo" feature from the original design doc: a runtime finding
like IDOR on /api/users/{id} doesn't just say "this URL misbehaves" -- it also says
which file and function handle that URL, and whether a static-analysis finding
sits in the same function.
"""
from tools.route_extractor import extract_routes


def _segments_match(discovered, route_key):
    """Structural match ignoring the actual path-param name: /api/users/{id} ==
    /api/users/{user_id}."""
    d = discovered.strip("/").split("/")
    r = route_key.strip("/").split("/")
    if len(d) != len(r):
        return False
    for ds, rs in zip(d, r):
        d_is_param = ds.startswith("{") and ds.endswith("}")
        r_is_param = rs.startswith("{") and rs.endswith("}")
        if d_is_param != r_is_param:
            return False
        if not d_is_param and ds != rs:
            return False
    return True


def _find_route(routes, discovered_path):
    if discovered_path in routes:
        return routes[discovered_path][0]
    for key, entries in routes.items():
        if _segments_match(discovered_path, key):
            return entries[0]
    return None


def _nearby_code_findings(code_findings, file_path, line, window=30):
    return [f for f in code_findings
            if f.get("file") == file_path and abs(f.get("line", -10_000) - line) <= window]


def correlation_engine(state):
    print("\n=== CORRELATION ENGINE ===")
    source_path = state.get("source_path") or "demo_target.py"
    routes = extract_routes(source_path)

    code_scan = next((o.get("result", {}) for o in state["observations"] if o.get("type") == "code_scan"), {})
    code_findings = code_scan.get("findings", [])

    changes = []
    for o in state.get("observations", []):
        if o.get("type") == "adaptive_dast":
            for f in (o.get("result", {}).get("potential_findings", []) or []):
                changes.append({"endpoint": f.get("endpoint_or_file"), "parameter": f.get("parameter"),
                                 "type": f.get("type")})

    correlated = 0
    for finding in state.get("findings", []):
        endpoint = finding.get("endpoint_or_file") or finding.get("endpoint") or ""
        if not endpoint.startswith("/") or not routes:
            continue
        route = _find_route(routes, endpoint)
        if not route:
            continue

        finding["source_location"] = {
            "file": route["file"], "line": route["line"], "function": route["function"],
        }
        supporting = _nearby_code_findings(code_findings, route["file"], route["line"])
        if supporting:
            finding["source_evidence"] = supporting
            if finding.get("confidence") != "HIGH":
                finding["confidence"] = "HIGH"
            finding["reasoning"] = (finding.get("reasoning", "") +
                f" Correlated with a static-analysis finding in the same handler "
                f"({route['file']}:{route['line']}).").strip()
        correlated += 1

    result = {"runtime_behavior_changes": changes, "routes_extracted": len(routes),
              "findings_correlated_to_source": correlated}
    state["observations"].append({"type": "correlation", "result": result})
    print(f"Runtime behavior changes: {len(changes)}")
    print(f"Routes extracted from source: {len(routes)}")
    print(f"Findings correlated to source: {correlated}")
    return state

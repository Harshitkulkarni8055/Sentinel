"""Checks any JWT issued during login for the unambiguous alg:none weakness.
Runs after `auth` so it has live session tokens/cookies to inspect.
"""
from tools.vuln_probes import jwt_weak_probe


def _candidate_tokens(sessions):
    tokens = []
    for client, _info, _cred in sessions.values():
        auth_header = client.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            tokens.append(auth_header.split(" ", 1)[1])
        for cookie_value in client.cookies.values():
            if cookie_value.count(".") == 2:
                tokens.append(cookie_value)
    return tokens


def jwt_tester(state):
    print("\n=== JWT ANALYZER ===")
    sessions = state.get("auth_context", {}).get("sessions", {})
    findings = []
    seen = set()
    for token in _candidate_tokens(sessions):
        if token in seen:
            continue
        seen.add(token)
        f = jwt_weak_probe(token)
        if f:
            findings.append(f)

    result = {"tokens_checked": len(seen), "potential_findings": findings}
    state["observations"].append({"type": "jwt_check", "result": result})
    print(f"Tokens checked: {len(seen)}; potential findings: {len(findings)}")
    return state

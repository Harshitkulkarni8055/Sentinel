from tools.sessions import credentials_from_env, find_login_spec, probe_login_candidates, open_sessions


def auth_agent(state):
    print("\n=== AUTHENTICATION ENGINE ===")
    base = state["target"].rstrip("/")

    recon = next((o.get("result", {}) for o in state["observations"] if o.get("type") == "web_recon"), {})
    endpoints = recon.get("endpoints", [])

    credentials = state.get("credentials") or credentials_from_env()
    spec = find_login_spec(endpoints)
    candidates = probe_login_candidates(base) if not spec else [spec["path"]]

    sessions = {}
    if spec and credentials:
        sessions = open_sessions(base, spec, credentials)

    identities = {
        label: {"role": cred.get("role", "user"), "user_id": info.get("user_id")}
        for label, (_client, info, cred) in sessions.items()
    }

    result = {
        "login_endpoint": spec["path"] if spec else None,
        "auth_endpoints": candidates,
        "endpoints_found": candidates,
        "authenticated": bool(sessions),
        "authenticated_session": bool(sessions),
        "identities": identities,
    }
    state["observations"].append({"type": "auth", "result": result})

    # Hand live sessions to later steps (authorization_tester, verifier) via auth_context.
    # Not serialized into the API response; findings only ever carry the result dict above.
    state["auth_context"] = {"base": base, "spec": spec, "sessions": sessions}

    print(f"Auth endpoints: {len(candidates)}")
    print(f"Authenticated identities: {list(identities.keys())}")

    # Sessions stay open in auth_context for authorization_tester to reuse;
    # it is responsible for closing them when done.
    return state

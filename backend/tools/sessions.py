"""Login discovery and authenticated HTTP sessions, shared by the auth, authorization and verifier steps."""
import os
import httpx

TIMEOUT = 3.0
LOGIN_CANDIDATES = ["/login", "/signin", "/auth/login", "/api/login", "/token"]
USER_HINTS = ("user", "email", "login", "name")
OK_STATUSES = (200, 201, 204, 302, 303)


def credentials_from_env():
    creds = []
    for suffix, label in (("", "A"), ("_2", "B"), ("_ADMIN", "admin")):
        user = os.getenv(f"SENTINEL_AUTH_USER{suffix}")
        password = os.getenv(f"SENTINEL_AUTH_PASS{suffix}")
        if user and password:
            creds.append({"label": label, "username": user, "password": password,
                          "role": "admin" if suffix == "_ADMIN" else "user"})
    return creds


def find_login_spec(recon_endpoints):
    """Pick a POST endpoint that takes a password-like field, from forms found during recon."""
    for ep in recon_endpoints or []:
        params = ep.get("parameters", [])
        pass_field = next((p for p in params if "pass" in p.lower()), None)
        if "POST" in ep.get("methods", []) and pass_field:
            user_field = next((p for p in params if any(h in p.lower() for h in USER_HINTS)), None)
            if user_field:
                return {"path": ep["path"], "user_field": user_field, "pass_field": pass_field}
    return None


def probe_login_candidates(base):
    """Fallback when recon found no login form: look for conventional paths that exist."""
    found = []
    with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as c:
        for path in LOGIN_CANDIDATES:
            try:
                if c.get(base + path).status_code != 404:
                    found.append(path)
            except httpx.HTTPError:
                continue
    return found


def login(base, spec, cred):
    """Return (client, info). client is None when login failed. info holds ids/tokens seen in the response."""
    client = httpx.Client(timeout=TIMEOUT, follow_redirects=True)
    try:
        r = client.post(base + spec["path"], data={
            spec["user_field"]: cred["username"], spec["pass_field"]: cred["password"]})
    except httpx.HTTPError:
        client.close()
        return None, {}

    info = {}
    try:
        body = r.json()
        if isinstance(body, dict):
            for key in ("user_id", "id", "userId", "uid"):
                if key in body:
                    info["user_id"] = str(body[key])
                    break
            token = body.get("token") or body.get("access_token")
            if isinstance(token, str):
                client.headers["Authorization"] = f"Bearer {token}"
                info["token"] = True
    except ValueError:
        pass

    if r.status_code in OK_STATUSES and (client.cookies or info.get("token")):
        return client, info

    client.close()
    return None, info


def open_sessions(base, spec, credentials):
    """Log in every credential. Returns {label: (client, info, cred)} for the ones that worked."""
    sessions = {}
    for cred in credentials[:3]:
        client, info = login(base, spec, cred)
        if client is not None:
            sessions[cred["label"]] = (client, info, cred)
    return sessions


def close_sessions(sessions):
    for client, _info, _cred in sessions.values():
        try:
            client.close()
        except httpx.HTTPError:
            pass

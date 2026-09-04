import os
import httpx

TIMEOUT = 1.5

def _login(base, username, password):
    client = httpx.Client(timeout=TIMEOUT, follow_redirects=True)
    try:
        response = client.post(
            f"{base}/login",
            data={"username": username, "password": password},
        )
        authenticated = response.status_code in (200, 302, 303) and bool(client.cookies)
        return client, authenticated
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError) as exc:
        print(f"[AUTHZ] Login failed for {username}: {type(exc).__name__}")
        client.close()
        return None, False

def _get(client, url):
    try:
        return client.get(url)
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError) as exc:
        print(f"[AUTHZ] Request failed: {url} ({type(exc).__name__})")
        return None

def authorization_tester(state):
    print("\n=== AUTHORIZATION / IDOR ENGINE ===")

    base = state["target"].rstrip("/")
    user1 = os.getenv("SENTINEL_AUTH_USER", "alice")
    pass1 = os.getenv("SENTINEL_AUTH_PASS", "alice123")
    user2 = os.getenv("SENTINEL_AUTH_USER_2", "bob")
    pass2 = os.getenv("SENTINEL_AUTH_PASS_2", "bob123")

    tests = []
    findings = []

    # Do not let an authorization timeout kill the entire Sentinel scan.
    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as probe:
            health = probe.get(f"{base}/")
            if health.status_code >= 500:
                raise RuntimeError(f"target returned HTTP {health.status_code}")
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError, RuntimeError) as exc:
        print(f"[AUTHZ] Target unavailable; skipping authorization safely: {type(exc).__name__}")
        state["observations"].append({
            "type": "authorization_test",
            "result": {
                "tests": [],
                "potential_findings": [],
                "status": "SKIPPED_TARGET_UNAVAILABLE",
                "error": type(exc).__name__,
            },
        })
        print("Authorization tests: 0")
        print("Potential authorization findings: 0")
        return state

    alice, alice_auth = _login(base, user1, pass1)
    bob, bob_auth = _login(base, user2, pass2)

    try:
        # Horizontal authorization: Alice -> Bob and Bob -> Alice.
        if alice_auth:
            own = _get(alice, f"{base}/api/users/1")
            other = _get(alice, f"{base}/api/users/2")
            if own is not None and other is not None:
                tests.append({
                    "user": user1,
                    "own_id": 1,
                    "other_id": 2,
                    "own_status": own.status_code,
                    "other_status": other.status_code,
                })
                if other.status_code == 200 and '"id":2' in other.text.replace(" ", ""):
                    findings.append({
                        "type": "idor",
                        "vulnerability": "Insecure Direct Object Reference (IDOR)",
                        "endpoint_or_file": "/api/users/{user_id}",
                        "parameter": "user_id",
                        "severity": "HIGH",
                        "status": "CONFIRMED",
                        "confidence": "HIGH",
                        "evidence": f"Authenticated user '{user1}' accessed another user's object ID 2 with HTTP 200.",
                        "reasoning": "The endpoint authenticates the caller but does not enforce ownership of the requested object.",
                        "remediation": "Enforce server-side object-level authorization for every user/object access.",
                    })

        if bob_auth:
            own = _get(bob, f"{base}/api/users/2")
            other = _get(bob, f"{base}/api/users/1")
            if own is not None and other is not None:
                tests.append({
                    "user": user2,
                    "own_id": 2,
                    "other_id": 1,
                    "own_status": own.status_code,
                    "other_status": other.status_code,
                })
                if other.status_code == 200 and '"id":1' in other.text.replace(" ", ""):
                    findings.append({
                        "type": "idor",
                        "vulnerability": "Insecure Direct Object Reference (IDOR)",
                        "endpoint_or_file": "/api/users/{user_id}",
                        "parameter": "user_id",
                        "severity": "HIGH",
                        "status": "CONFIRMED",
                        "confidence": "HIGH",
                        "evidence": f"Authenticated user '{user2}' accessed another user's object ID 1 with HTTP 200.",
                        "reasoning": "The endpoint authenticates the caller but does not enforce ownership of the requested object.",
                        "remediation": "Enforce server-side object-level authorization for every user/object access.",
                    })

        # Vertical authorization: ordinary authenticated user -> admin.
        if alice_auth:
            admin = _get(alice, f"{base}/api/admin")
            if admin is not None:
                tests.append({
                    "user": user1,
                    "endpoint": "/api/admin",
                    "status": admin.status_code,
                })
                if admin.status_code == 200:
                    findings.append({
                        "type": "privilege_escalation",
                        "vulnerability": "Broken Access Control / Privilege Escalation",
                        "endpoint_or_file": "/api/admin",
                        "severity": "HIGH",
                        "status": "CONFIRMED",
                        "confidence": "HIGH",
                        "evidence": f"Normal authenticated user '{user1}' received HTTP 200 from /api/admin.",
                        "reasoning": "The endpoint checks authentication but does not enforce the required administrative role.",
                        "remediation": "Enforce server-side role/permission checks before administrative operations.",
                    })
    finally:
        if alice:
            alice.close()
        if bob:
            bob.close()

    # Deduplicate by vulnerability + endpoint.
    unique = []
    seen = set()
    for f in findings:
        key = (f.get("type"), f.get("endpoint_or_file"))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    result = {
        "tests": tests,
        "potential_findings": unique,
        "status": "completed",
    }
    state["observations"].append({"type": "authorization_test", "result": result})

    print(f"Authorization tests: {len(tests)}")
    print(f"Potential authorization findings: {len(unique)}")
    return state

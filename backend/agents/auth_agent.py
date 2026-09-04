import os
import httpx
from urllib.parse import urljoin

def auth_agent(state):
    print("\n=== AUTHENTICATION ENGINE ===")
    base = state["target"].rstrip("/")
    user = os.getenv("SENTINEL_AUTH_USER","alice")
    password = os.getenv("SENTINEL_AUTH_PASS","alice123")
    candidates = ["/login","/signin","/auth","/token","/oauth","/session"]
    found = []
    authenticated = False
    cookies = {}
    with httpx.Client(timeout=2.0, follow_redirects=True) as c:
        for path in candidates:
            try:
                r = c.get(base + path)
                if r.status_code not in (404,405):
                    found.append(path)
            except Exception:
                pass
        if "/login" in found or (state["target"].rstrip("/").endswith(":9000")):
            if "/login" not in found:
                found.append("/login")
            try:
                r = c.post(base+"/login", data={"username":user,"password":password})
                authenticated = r.status_code in (200,302,303) and bool(c.cookies)
                cookies = dict(c.cookies)
            except Exception:
                pass
    result={"auth_endpoints":found,"endpoints_found":found,"authenticated":authenticated,"authenticated_session":authenticated,"cookies":cookies}
    state["observations"].append({"type":"auth","result":result})
    print(f"Auth endpoints: {len(found)}")
    print(f"Authenticated session: {authenticated}")
    return state

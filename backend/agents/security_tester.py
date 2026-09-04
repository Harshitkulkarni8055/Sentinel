import httpx
from urllib.parse import urljoin

TIMEOUT = 2.0
MAX_REQUESTS = 80

def _sample_url(base, path):
    return urljoin(base.rstrip("/") + "/", path.lstrip("/")).replace("{user_id}", "1")

def security_tester(state):
    print("\n=== SECURITY TEST ENGINE ===")
    recon = next((o.get("result",{}) for o in state["observations"] if o.get("type")=="web_recon"), {})
    endpoints = recon.get("endpoints", [])
    tests, potential, requests = [], [], 0

    with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as c:
        for ep in endpoints[:12]:
            path = ep["path"]
            url = _sample_url(state["target"], path)
            method = ep.get("methods",["GET"])[0]
            if method != "GET":
                continue
            try:
                r = c.get(url)
                requests += 1
            except Exception:
                continue
            h = {k.lower(): v for k,v in r.headers.items()}
            missing = [x for x in ["content-security-policy","x-frame-options","x-content-type-options"] if x not in h]
            tests.append({"endpoint":path,"method":"GET","status_code":r.status_code})
            if missing:
                potential.append({
                    "type":"missing_security_headers",
                    "vulnerability":"Missing Security Headers",
                    "endpoint_or_file":path,
                    "severity":"LOW",
                    "status":"CONFIRMED",
                    "confidence":"HIGH",
                    "evidence":", ".join(x.upper() for x in missing),
                    "reasoning":"The HTTP response is missing recommended browser security headers.",
                    "remediation":"Add Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options headers."
                })

            for param in ep.get("parameters",[])[:2]:
                marker = "SENTINEL_REFLECT_7F3A"
                try:
                    if method == "GET":
                        rr = c.get(url, params={param:marker})
                    else:
                        rr = c.post(url, data={param:marker})
                    requests += 1
                    if marker in rr.text:
                        potential.append({
                            "type":"reflected_input",
                            "vulnerability":"Reflected Input",
                            "endpoint_or_file":path,
                            "parameter":param,
                            "severity":"MEDIUM",
                            "status":"INCONCLUSIVE",
                            "confidence":"MEDIUM",
                            "evidence":f"Marker '{marker}' was reflected in the response.",
                            "reasoning":"User-controlled input is reflected; reflection alone does not prove executable XSS.",
                            "remediation":"Contextually encode output and validate/sanitize user-controlled input."
                        })
                except Exception:
                    pass
            if requests >= MAX_REQUESTS:
                break

    result = {"tests":tests,"requests_made":requests,"potential_findings":potential}
    state["observations"].append({"type":"security_test","result":result})
    state["security_tested"] = True
    print(f"Tests executed: {len(tests)}")
    print(f"HTTP requests: {requests}")
    print(f"Potential findings: {len(potential)}")
    return state

import httpx
from urllib.parse import urljoin

def adaptive_dast(state):
    print("\n=== ADAPTIVE DAST ENGINE ===")
    recon = next((o.get("result",{}) for o in state["observations"] if o.get("type")=="web_recon"), {})
    eps = [e for e in recon.get("endpoints",[]) if e.get("parameters")]
    eps = sorted(eps, key=lambda e: len(e.get("parameters",[])), reverse=True)[:8]
    probes = 0
    requests = 0
    findings = []
    with httpx.Client(timeout=1.5, follow_redirects=True) as c:
        for ep in eps:
            path = ep["path"].replace("{user_id}","1")
            url = urljoin(state["target"].rstrip("/")+"/", path.lstrip("/"))
            for p in ep.get("parameters",[])[:2]:
                marker = "SENTINEL_ADAPT_93B1"
                try:
                    r = c.get(url, params={p:marker})
                    requests += 1; probes += 1
                    if marker in r.text:
                        findings.append({
                            "type":"reflected_input",
                            "vulnerability":"Reflected Input",
                            "endpoint_or_file":ep["path"],
                            "parameter":p,
                            "severity":"MEDIUM",
                            "status":"INCONCLUSIVE",
                            "confidence":"MEDIUM",
                            "evidence":"Adaptive probe marker was reflected in the response.",
                            "reasoning":"Adaptive DAST confirmed controllable input reaches the response.",
                            "remediation":"Encode output and validate/sanitize user-controlled input."
                        })
                except Exception:
                    pass
    result={"prioritized_endpoints":len(eps),"probes":probes,"requests_made":requests,"potential_findings":findings}
    state["observations"].append({"type":"adaptive_dast","result":result})
    print(f"Prioritized endpoints: {len(eps)}")
    print(f"Adaptive probes: {probes}")
    print(f"HTTP probes: {requests}")
    print(f"Potential findings: {len(findings)}")
    return state

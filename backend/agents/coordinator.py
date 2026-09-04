from orchestration.state import SecurityState
from tools.web_recon import web_recon

def coordinator(state: SecurityState) -> SecurityState:
    print("\n=== PYTHON RECON ENGINE ===")
    result = web_recon(state["target"])
    state["iteration"] += 1
    state["observations"].append({"type":"web_recon","result":result})
    state["status"] = "recon_complete"
    print(f"Pages scanned: {result['pages_scanned']}")
    print(f"Endpoints discovered: {len(result['endpoints'])}")
    for e in result["endpoints"]:
        print(f"  {e['path']} {e['methods']} {e['parameters']}")
    return state

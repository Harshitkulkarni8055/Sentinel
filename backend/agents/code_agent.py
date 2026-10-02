from orchestration.state import SecurityState
from tools.code_scanner import code_scanner

def code_agent(state: SecurityState) -> SecurityState:
    print("\n=== STATIC SECURITY SCANNER ===")
    source_path = state.get("source_path") or "demo_target.py"
    result = code_scanner.invoke({"path": source_path})
    state["observations"].append({"type":"code_scan","result":result})
    print(f"Files scanned: {result.get('files_scanned')}, findings: {len(result.get('findings', []))}")
    return state

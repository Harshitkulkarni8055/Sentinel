from orchestration.state import SecurityState
from tools.code_scanner import code_scanner

def code_agent(state: SecurityState) -> SecurityState:
    print("\n=== STATIC SECURITY SCANNER ===")
    result = code_scanner.invoke({"path":"demo_target.py"})
    state["observations"].append({"type":"code_scan","result":result})
    print(result)
    return state

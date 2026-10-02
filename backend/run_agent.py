import os
import sys
from orchestration.graph import graph
from orchestration.state import new_state
from tools.sessions import credentials_from_env

TARGET = os.getenv("SENTINEL_TARGET", "http://127.0.0.1:9000")
# Local-only: point this at a source checkout to enable Phase 4 correlation
# (not exposed over the public API -- see orchestration/correlation.py).
SOURCE_PATH = sys.argv[1] if len(sys.argv) > 1 else os.getenv("SENTINEL_SOURCE_PATH", "demo_target.py")


def main():
    state = new_state(TARGET, credentials=credentials_from_env(), source_path=SOURCE_PATH)
    result = graph.invoke(state)
    findings = result.get("findings", [])
    print("\n" + "=" * 62 + "\n                    FINDINGS\n" + "=" * 62)
    for i, f in enumerate(findings, 1):
        print(f"\nFINDING {i}: {f.get('vulnerability')} [{f.get('severity')}]")
        print(f"  Type       : {f.get('type')}")
        print(f"  Location   : {f.get('endpoint_or_file') or f.get('endpoint')}")
        print(f"  Status     : {f.get('status')}")
        print(f"  Confidence : {f.get('confidence')}")
        print(f"  Evidence   : {f.get('evidence')}")
        print(f"  Reasoning  : {f.get('reasoning')}")
        print(f"  Remediation: {f.get('remediation')}")
        source = f.get("source_location")
        if source:
            print(f"  Source     : {source['file']}:{source['line']} ({source['function']})")
    print(f"\nTotal findings: {len(findings)}")
    print(f"Attack paths: {len(result.get('attack_paths', []))}")
    print("SENTINEL SCAN COMPLETE\n")


if __name__ == "__main__":
    main()

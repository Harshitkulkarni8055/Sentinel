from orchestration.graph import graph
TARGET="http://127.0.0.1:9000"

def main():
    state={"target":TARGET,"status":"starting","iteration":0,"observations":[],"hypotheses":[],"findings":[],"messages":[],"security_tested":False,"next_actions":[],"attack_paths":[],"reasoning_iterations":0}
    result=graph.invoke(state)
    findings=result.get("findings",[])
    print("\n"+"="*62+"\n                    FINDINGS\n"+"="*62)
    for i,f in enumerate(findings,1):
        print(f"\nFINDING {i}: {f.get('vulnerability')} [{f.get('severity')}]")
        print(f"  Type       : {f.get('type')}")
        print(f"  Location   : {f.get('endpoint_or_file') or f.get('endpoint')}")
        print(f"  Status     : {f.get('status')}")
        print(f"  Confidence : {f.get('confidence')}")
        print(f"  Evidence   : {f.get('evidence')}")
        print(f"  Reasoning  : {f.get('reasoning')}")
        print(f"  Remediation: {f.get('remediation')}")
    print(f"\nTotal findings: {len(findings)}")
    print(f"Attack paths: {len(result.get('attack_paths',[]))}")
    print("SENTINEL SCAN COMPLETE\n")
if __name__=="__main__": main()

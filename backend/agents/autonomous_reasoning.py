def autonomous_reasoning(state):
    print("\n=== AUTONOMOUS SECURITY REASONING ===")
    observations=state.get("observations",[])
    hypotheses=[]
    actions=[]
    paths=[]
    authz=next((o.get("result",{}) for o in observations if o.get("type")=="authorization_test"),{})
    sec=next((o.get("result",{}) for o in observations if o.get("type")=="security_test"),{})
    if authz.get("potential_findings"):
        hypotheses.append({"hypothesis":"Broken authorization exists","evidence_count":len(authz["potential_findings"]),"priority":"HIGH"})
        actions.append({"action":"validate cross-user object access","priority":"HIGH"})
        for f in authz["potential_findings"]:
            if f.get("type")=="idor":
                paths.append({"name":"Horizontal privilege escalation","steps":["Authenticate as Alice","Request Bob's object","Observe HTTP 200/object data"],"severity":"HIGH"})
            elif f.get("type")=="privilege_escalation":
                paths.append({"name":"Vertical privilege escalation","steps":["Authenticate as normal user","Request admin endpoint","Observe protected response"],"severity":"HIGH"})
    if sec.get("potential_findings"):
        hypotheses.append({"hypothesis":"Input/output security controls require validation","evidence_count":len(sec["potential_findings"]),"priority":"MEDIUM"})
        actions.append({"action":"correlate reflected input with response behavior","priority":"MEDIUM"})
    state["hypotheses"]=hypotheses
    state["next_actions"]=actions
    state["attack_paths"]=paths
    state["reasoning_iterations"]=1 if (hypotheses or actions or paths) else 0
    print(f"Hypotheses: {len(hypotheses)} | Next actions: {len(actions)} | Attack paths: {len(paths)}")
    state["observations"].append({"type":"reasoning","result":{"hypotheses":hypotheses,"next_actions":actions,"attack_paths":paths}})
    return state

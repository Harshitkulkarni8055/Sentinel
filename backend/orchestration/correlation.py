def correlation_engine(state):
    print("\n=== CORRELATION ENGINE ===")
    changes=[]
    for o in state.get("observations",[]):
        if o.get("type")=="adaptive_dast":
            for f in (o.get("result",{}).get("potential_findings",[]) or []):
                changes.append({"endpoint":f.get("endpoint_or_file"),"parameter":f.get("parameter"),"type":f.get("type")})
    result={"runtime_behavior_changes":changes}
    state["observations"].append({"type":"correlation","result":result})
    print(f"Runtime behavior changes: {len(changes)}")
    return state

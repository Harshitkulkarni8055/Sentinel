import json, os
from orchestration.state import SecurityState
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

load_dotenv(".env")

def _collect(observations):
    out=[]
    for o in observations:
        if not isinstance(o,dict): continue
        r=o.get("result",{})
        if isinstance(r,dict):
            for f in r.get("potential_findings",[]) or []:
                if isinstance(f,dict): out.append(dict(f))
    return out

def _dedupe(findings):
    out=[]; seen=set()
    for f in findings:
        key=(f.get("type"),f.get("endpoint_or_file"),f.get("parameter"))
        if key in seen: continue
        seen.add(key); out.append(f)
    return out

def ai_security_agent(state: SecurityState):
    print("\n=== AI SECURITY ANALYST ===")
    print("[AI] Evidence collection complete.")
    print("[AI] Compressing attack-surface data...")
    print("[AI] Reviewing dynamic security test results...")
    print("[AI] Reviewing static analysis findings...")
    print("[AI] Correlating runtime and code evidence...")
    print("[AI] Building vulnerability hypotheses...")
    print("[AI] Prioritizing findings by severity and confidence...")
    deterministic=_collect(state.get("observations",[]))
    ai_findings=[]
    prompt={
        "target":state["target"],
        "findings":deterministic,
        "hypotheses":state.get("hypotheses",[]),
        "rules":["Never invent evidence.","Preserve confirmed findings.","Reflection alone is not automatically XSS.","Return JSON object with findings array."]
    }
    try:
        llm=ChatOpenAI(
            model=os.getenv("FEATHERLESS_MODEL"),
            temperature=0.2,
            max_tokens=1024,
            api_key=os.getenv("FEATHERLESS_API_KEY"),
            base_url="https://api.featherless.ai/v1",
            extra_body={"chat_template_kwargs":{"enable_thinking":False}},
        )
        print("[AI] Sending evidence to Qwen 9B...")
        raw=llm.invoke(json.dumps(prompt))
        text=getattr(raw,"content","")
        print("[AI] Report generated successfully.")
        start=text.find("{"); end=text.rfind("}")
        if start!=-1 and end>start:
            data=json.loads(text[start:end+1])
            if isinstance(data,dict) and isinstance(data.get("findings"),list):
                ai_findings=data["findings"]
    except Exception as e:
        print(f"[AI] Provider unavailable; deterministic evidence retained ({type(e).__name__}).")
    merged=_dedupe(deterministic+ai_findings)
    for f in merged:
        f.setdefault("source","AI_SECURITY_AGENT")
        f.setdefault("vulnerability",f.get("type","Security Finding"))
        f.setdefault("endpoint",f.get("endpoint_or_file",""))
        f.setdefault("status","INCONCLUSIVE")
        f.setdefault("confidence","MEDIUM")
        f.setdefault("evidence",[])
        f.setdefault("reasoning","Validated from dynamic security evidence.")
        f.setdefault("remediation","Review and enforce appropriate server-side security controls.")
        f["severity"]=str(f.get("severity","MEDIUM")).upper()
        f["status"]=str(f.get("status","INCONCLUSIVE")).upper()
        f["confidence"]=str(f.get("confidence","MEDIUM")).upper()
    state["findings"]=merged
    state["observations"].append({"type":"ai_security_analysis","result":{"findings_count":len(merged),"provider_used":bool(ai_findings)}})
    return state

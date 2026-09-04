from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from orchestration.graph import graph
import json
import re
import uuid
from urllib.parse import urlparse
import httpx

app = FastAPI(title="Sentinel Security API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"status": "Sentinel is alive"}

@app.get("/api/users")
def users():
    return {"users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]}

@app.get("/api/products")
def products():
    return {"products": [{"id": 1, "name": "Laptop"}, {"id": 2, "name": "Phone"}]}

class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)

def validate_target(target: str) -> str:
    target = target.strip()
    parsed = urlparse(target)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid target. Use a complete HTTP or HTTPS URL.")

    # Reject malformed ports early.
    try:
        _ = parsed.port
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid target port.")

    # Authoritative reachability check. Any HTTP response means the target is alive;
    # 4xx/5xx are still legitimate applications to assess. Connection/DNS failures
    # are rejected so a dead/bad URL never enters the expensive agent pipeline.
    try:
        with httpx.Client(timeout=3.0, follow_redirects=True) as client:
            client.get(target)
    except httpx.InvalidURL:
        raise HTTPException(status_code=400, detail="Invalid target URL.")
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.NetworkError) as exc:
        raise HTTPException(status_code=400, detail=f"Target is unreachable: {exc.__class__.__name__}.")
    except Exception:
        # Treat unexpected network parsing/transport failures as an unreachable target.
        raise HTTPException(status_code=400, detail="Target could not be reached. Check the URL and try again.")

    return target

def _parse_ai_findings(raw_findings):
    for item in raw_findings or []:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source", "")).lower()
        if source not in {"ai_security_agent", "ai analyst", "ai_security"}:
            continue
        analysis = item.get("analysis") or item.get("result") or item.get("content") or ""
        if not isinstance(analysis, str):
            continue
        cleaned = re.sub(r"```(?:json)?", "", analysis, flags=re.IGNORECASE).replace("```", "").strip()
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end <= start:
            continue
        try:
            payload = json.loads(cleaned[start:end + 1])
        except Exception:
            continue
        findings = payload.get("findings", []) if isinstance(payload, dict) else []
        if not isinstance(findings, list):
            continue
        normalized = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            normalized.append({
                "vulnerability": f.get("vulnerability") or f.get("name") or f.get("title") or "Security Finding",
                "type": f.get("type", "security_finding"),
                "endpoint": f.get("endpoint") or f.get("endpoint_or_file") or f.get("file") or "",
                "endpoint_or_file": f.get("endpoint_or_file") or f.get("endpoint") or f.get("file") or "",
                "severity": str(f.get("severity", "MEDIUM")).upper(),
                "status": str(f.get("status", "INCONCLUSIVE")).upper(),
                "confidence": str(f.get("confidence", "LOW")).upper(),
                "evidence": f.get("evidence", ""),
                "reasoning": f.get("reasoning") or f.get("explanation") or "",
                "remediation": f.get("remediation", ""),
                "source": "AI_SECURITY_AGENT",
            })
        return normalized
    return []

def _extract_direct_structured_findings(raw_findings):
    result = []
    for item in raw_findings or []:
        if not isinstance(item, dict):
            continue
        if item.get("source") in {"ai_security_agent", "code_agent", "correlation_engine", "correlation"}:
            continue
        if not (item.get("severity") and (item.get("type") or item.get("vulnerability"))):
            continue
        result.append({
            **item,
            "vulnerability": item.get("vulnerability") or item.get("name") or item.get("type", "Security Finding"),
            "endpoint": item.get("endpoint") or item.get("endpoint_or_file") or item.get("file") or "",
            "severity": str(item.get("severity", "MEDIUM")).upper(),
            "status": str(item.get("status", "INCONCLUSIVE")).upper(),
            "confidence": str(item.get("confidence", "LOW")).upper(),
        })
    return result

def _severity_counts(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = str(f.get("severity", "medium")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts

def _extract_attack_surface(observations):
    endpoints = []
    pages_scanned = 0
    for obs in observations or []:
        if not isinstance(obs, dict):
            continue
        if obs.get("type") == "web_recon":
            result = obs.get("result", {})
            if isinstance(result, dict):
                pages_scanned = result.get("pages_scanned", pages_scanned)
                raw_eps = result.get("endpoints", [])
                if isinstance(raw_eps, list):
                    endpoints = raw_eps
    return {"pages_scanned": pages_scanned, "endpoints_discovered": len(endpoints), "endpoints": endpoints}

@app.post("/scan")
def scan(request: ScanRequest):
    target = validate_target(request.target)

    initial_state = {
        "target": target,
        "status": "starting",
        "iteration": 0,
        "observations": [],
        "hypotheses": [],
        "findings": [],
        "messages": [],
        "security_tested": False,
        "next_actions": [],
        "attack_paths": [],
        "reasoning_iterations": 0,
    }

    result = graph.invoke(initial_state)
    raw_findings = result.get("findings", [])
    findings = _parse_ai_findings(raw_findings)
    if not findings:
        findings = _extract_direct_structured_findings(raw_findings)

    counts = _severity_counts(findings)
    confirmed = sum(1 for f in findings if str(f.get("status", "")).upper() == "CONFIRMED")

    return {
        "scan_id": f"scan_{uuid.uuid4().hex[:10]}",
        "target": result.get("target", target),
        "status": "completed",
        "iterations": result.get("iteration", 0),
        "reasoning_iterations": result.get("reasoning_iterations", 0),
        "summary": {
            "total_findings": len(findings),
            **counts,
            "confirmed": confirmed,
            "risk_level": (
                "CRITICAL" if counts["critical"] else
                "HIGH" if counts["high"] else
                "MEDIUM" if counts["medium"] else
                "LOW" if counts["low"] else
                "SECURE"
            ),
        },
        "attack_surface": _extract_attack_surface(result.get("observations", [])),
        "hypotheses": result.get("hypotheses", []),
        "next_actions": result.get("next_actions", []),
        "attack_paths": result.get("attack_paths", []),
        "reasoning": {
            "iterations": result.get("reasoning_iterations", 0),
            "next_actions": result.get("next_actions", []),
            "attack_paths": result.get("attack_paths", []),
        },
        "findings": findings,
        "observations": result.get("observations", []),
    }

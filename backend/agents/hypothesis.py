from orchestration.state import SecurityState
from llm import llm


def hypothesis_agent(state: SecurityState) -> SecurityState:

    recon = next(
        (
            x["result"]
            for x in state["observations"]
            if x["type"] == "web_recon"
        ),
        {}
    )

    security = next(
        (
            x["result"]
            for x in state["observations"]
            if x["type"] == "security_test"
        ),
        {}
    )

    prompt = f"""
You are Sentinel's autonomous security reasoning agent.

Analyze the following authorized web application attack surface.

ATTACK SURFACE:
{recon.get("endpoints", [])}

SECURITY TEST RESULTS:
{security}

Identify the most important security hypotheses.

For each hypothesis provide:

Vulnerability:
Endpoint:
Reasoning:
Evidence:
Priority: LOW | MEDIUM | HIGH | CRITICAL

Rules:
- Never invent evidence.
- A missing security header is not automatically a serious vulnerability.
- Do not call something IDOR unless unauthorized object access is demonstrated.
- Distinguish suspicious behavior from confirmed vulnerabilities.
- Focus on the strongest evidence.
- Maximum 5 hypotheses.
- Maximum 400 words.
"""

    response = llm.invoke(prompt)

    state["hypotheses"].append({
        "source": "ai_security_reasoning",
        "analysis": response.content
    })

    print("\n=== AI SECURITY REASONING ===")
    print(response.content)

    return state
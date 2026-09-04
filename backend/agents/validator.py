from orchestration.state import SecurityState
from llm import llm


def validator_agent(
    state: SecurityState
) -> SecurityState:

    hypotheses = state["hypotheses"]

    observations = [
        x
        for x in state["observations"]
        if x["type"] == "security_test"
    ]

    prompt = f"""
You are Sentinel's final vulnerability validation agent.

HYPOTHESES:
{hypotheses}

SECURITY EVIDENCE:
{observations}

Validate every hypothesis conservatively.

Use exactly one status:

CONFIRMED
REJECTED
INCONCLUSIVE

Definitions:

CONFIRMED:
The evidence directly demonstrates security-relevant behavior.

REJECTED:
The evidence demonstrates that the suspected vulnerability
was not reproduced.

INCONCLUSIVE:
There is not enough evidence to determine whether the
vulnerability exists.

IMPORTANT:

If no vulnerability exists, DO NOT mark it CONFIRMED.

A statement such as "None identified" must be REJECTED,
not CONFIRMED.

Never invent evidence.

Return:

FINDING:
- Vulnerability:
- Endpoint:
- Status:
- Severity:
- Confidence:
- Evidence:
- Reasoning:
- Remediation:

Keep the report concise.
"""

    response = llm.invoke(prompt)

    state["findings"].append({
        "validation": response.content
    })

    print("\n=== AI VALIDATOR ===")
    print(response.content)

    return state
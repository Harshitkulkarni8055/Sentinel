"""Coordinator-style planner: picks the next investigation step from what has been
observed so far, instead of always running every tool in a fixed order.

Falls back to a safe deterministic order whenever the LLM is unavailable or returns
something unusable, so a flaky provider never breaks the scan.
"""
import json
from llm import llm

STEP_BUDGET = 8

# name -> (human description, hard prerequisite)
TOOL_MENU = {
    "security_test": ("probe discovered endpoints for missing security headers and reflected input", None),
    "adaptive_dast": ("prioritize parameterized endpoints and re-probe them", "security_test"),
    "deep_scan": ("probe for SQL injection, insecure cookies, open redirect, CORS "
                  "misconfiguration, exposed sensitive files, and login rate limiting", None),
    "auth": ("attempt to log in with the provided test credentials", None),
    "authorization": ("test IDOR and privilege escalation using authenticated sessions", "auth"),
    "jwt_check": ("inspect any issued JWT for the alg:none weakness", "auth"),
}

DEFAULT_ORDER = ["security_test", "adaptive_dast", "deep_scan", "auth", "authorization", "jwt_check"]


def _available(state):
    done = set(state.get("tools_done", []))
    out = []
    for name, (_desc, prereq) in TOOL_MENU.items():
        if name in done:
            continue
        if prereq and prereq not in done:
            continue
        out.append(name)
    return out


def _fallback_choice(available):
    for name in DEFAULT_ORDER:
        if name in available:
            return name
    return "finish"


def _llm_choice(state, available):
    recon = next((o.get("result", {}) for o in state["observations"] if o.get("type") == "web_recon"), {})
    summary = {
        "endpoints_discovered": len(recon.get("endpoints", [])),
        "has_parameters": any(e.get("parameters") for e in recon.get("endpoints", [])),
        "tools_already_run": state.get("tools_done", []),
        "findings_so_far": sum(
            len(o.get("result", {}).get("potential_findings", []) or [])
            for o in state["observations"] if isinstance(o.get("result"), dict)
        ),
    }
    menu_text = "\n".join(f"- {name}: {TOOL_MENU[name][0]}" for name in available)
    prompt = f"""You are Sentinel's security test planner for an authorized scan.

What has been observed so far:
{json.dumps(summary)}

Tools still available this turn:
{menu_text}

Reply with exactly one word: one of the tool names above, or "finish" if no more
investigation is worthwhile. No explanation."""

    try:
        response = llm.invoke(prompt)
        choice = (response.content or "").strip().lower().split()[0].strip('".')
    except Exception as exc:
        print(f"[PLANNER] LLM unavailable, using fallback order: {type(exc).__name__}")
        return _fallback_choice(available), "fallback"

    if choice in available:
        return choice, "llm"
    if choice == "finish":
        return "finish", "llm"
    return _fallback_choice(available), "fallback"


def planner(state):
    print("\n=== PLANNER ===")
    state["steps"] = state.get("steps", 0) + 1

    if state["steps"] > STEP_BUDGET:
        print(f"Step budget ({STEP_BUDGET}) reached; finishing investigation.")
        state["next_tool"] = "finish"
        return state

    available = _available(state)
    if not available:
        print("No further tools available; finishing investigation.")
        state["next_tool"] = "finish"
        return state

    choice, source = _llm_choice(state, available)
    state["next_tool"] = choice
    state.setdefault("trace", []).append({"step": state["steps"], "chose": choice, "source": source})
    print(f"Step {state['steps']}: chose '{choice}' (source: {source})")
    return state


def route(state):
    choice = state.get("next_tool", "finish")
    return choice if choice != "finish" else "finish"


def mark_done(tool_name):
    """Returns a thin wrapper node that runs `tool_fn` then records it as done, so the
    planner never re-selects a step that already ran."""
    def wrap(tool_fn):
        def node(state):
            state = tool_fn(state)
            state.setdefault("tools_done", []).append(tool_name)
            return state
        return node
    return wrap

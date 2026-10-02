from langgraph.graph import StateGraph, START, END
from orchestration.state import SecurityState
from agents.coordinator import coordinator
from agents.security_tester import security_tester
from agents.adaptive_dast import adaptive_dast
from agents.auth_agent import auth_agent
from agents.authorization_tester import authorization_tester
from agents.autonomous_reasoning import autonomous_reasoning
from agents.code_agent import code_agent
from agents.ai_security_agent import ai_security_agent
from agents.verifier import verifier
from agents.planner import planner, route, mark_done
from orchestration.correlation import correlation_engine

builder = StateGraph(SecurityState)
builder.add_node("recon", coordinator)
builder.add_node("planner", planner)
builder.add_node("security_test", mark_done("security_test")(security_tester))
builder.add_node("adaptive_dast", mark_done("adaptive_dast")(adaptive_dast))
builder.add_node("auth", mark_done("auth")(auth_agent))
builder.add_node("authorization", mark_done("authorization")(authorization_tester))
builder.add_node("reasoning", autonomous_reasoning)
builder.add_node("code_scan", code_agent)
builder.add_node("ai_security", ai_security_agent)
builder.add_node("verifier", verifier)
builder.add_node("correlation", correlation_engine)

builder.add_edge(START, "recon")
builder.add_edge("recon", "planner")

# The planner chooses the next tool from what has been observed so far, within a step
# budget (agents/planner.py). Each tool loops back to the planner; "finish" leaves the loop.
builder.add_conditional_edges("planner", route, {
    "security_test": "security_test",
    "adaptive_dast": "adaptive_dast",
    "auth": "auth",
    "authorization": "authorization",
    "finish": "reasoning",
})
builder.add_edge("security_test", "planner")
builder.add_edge("adaptive_dast", "planner")
builder.add_edge("auth", "planner")
builder.add_edge("authorization", "planner")

builder.add_edge("reasoning", "code_scan")
builder.add_edge("code_scan", "ai_security")
builder.add_edge("ai_security", "verifier")
builder.add_edge("verifier", "correlation")
builder.add_edge("correlation", END)
graph = builder.compile()

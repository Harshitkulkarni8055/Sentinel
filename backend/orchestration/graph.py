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
from orchestration.correlation import correlation_engine

builder=StateGraph(SecurityState)
builder.add_node("recon",coordinator)
builder.add_node("security_test",security_tester)
builder.add_node("adaptive_dast",adaptive_dast)
builder.add_node("auth",auth_agent)
builder.add_node("authorization",authorization_tester)
builder.add_node("reasoning",autonomous_reasoning)
builder.add_node("code_scan",code_agent)
builder.add_node("ai_security",ai_security_agent)
builder.add_node("correlation",correlation_engine)

builder.add_edge(START,"recon")
builder.add_edge("recon","security_test")
builder.add_edge("security_test","adaptive_dast")
builder.add_edge("adaptive_dast","auth")
builder.add_edge("auth","authorization")
builder.add_edge("authorization","reasoning")
builder.add_edge("reasoning","code_scan")
builder.add_edge("code_scan","ai_security")
builder.add_edge("ai_security","correlation")
builder.add_edge("correlation",END)
graph=builder.compile()

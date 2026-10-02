from typing import TypedDict
from langchain_core.messages import BaseMessage


class SecurityState(TypedDict):
    target: str
    status: str
    iteration: int
    observations: list
    hypotheses: list
    findings: list
    messages: list[BaseMessage]
    security_tested: bool
    next_actions: list
    attack_paths: list
    reasoning_iterations: int
    # v2 fields
    credentials: list      # [{"label","username","password","role"}]
    auth_context: dict     # discovered login spec + per-identity info
    source_path: str       # optional path to the target's source for static analysis
    tools_done: list
    steps: int
    next_tool: str
    trace: list            # planner decisions, returned to the client


def new_state(target: str, credentials: list | None = None, source_path: str = "") -> SecurityState:
    return {
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
        "credentials": credentials or [],
        "auth_context": {},
        "source_path": source_path,
        "tools_done": [],
        "steps": 0,
        "next_tool": "",
        "trace": [],
    }

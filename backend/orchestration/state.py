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

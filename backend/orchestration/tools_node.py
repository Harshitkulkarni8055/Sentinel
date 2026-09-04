from orchestration.state import SecurityState
from tools.http_recon import http_recon
from tools.http_request import http_request
from tools.endpoint_discovery import endpoint_discovery
from tools.security_http import security_http_request


TOOLS = {
    "http_recon": http_recon,
    "http_request": http_request,
    "endpoint_discovery": endpoint_discovery,
    "security_http_request": security_http_request,
}


def tool_node(state: SecurityState) -> SecurityState:
    messages = state["messages"]

    last_message = messages[-1]

    for tool_call in last_message.tool_calls:
        tool_name = tool_call["name"]
        tool_args = tool_call["args"]

        tool = TOOLS.get(tool_name)

        if tool is None:
            continue

        result = tool.invoke(tool_args)

        print("\n=== TOOL NODE ===")
        print("Tool:", tool_name)
        print("Result:", result)

        state["observations"].append({
            "type": tool_name,
            "result": result,
        })

        messages.append(
        {
            "role": "tool",
            "content": str(result),
            "tool_call_id": tool_call["id"],
            "name": tool_name,
        })

    return state
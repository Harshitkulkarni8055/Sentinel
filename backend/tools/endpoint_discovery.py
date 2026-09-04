import httpx
from langchain_core.tools import tool


@tool
def endpoint_discovery(base_url: str) -> dict:
    """Discover endpoints from an authorized web application."""

    base_url = base_url.rstrip("/")
    results = []

    try:
        response = httpx.get(
            f"{base_url}/openapi.json",
            timeout=5,
            follow_redirects=True
        )

        if response.status_code == 200:
            data = response.json()
            paths = list(data.get("paths", {}).keys())

            return {
                "base_url": base_url,
                "source": "/openapi.json",
                "discovered_endpoints": paths,
            }

    except Exception as e:
        return {
            "base_url": base_url,
            "error": str(e),
        }

    return {
        "base_url": base_url,
        "source": "/openapi.json",
        "discovered_endpoints": [],
        "message": "OpenAPI specification not available",
    }
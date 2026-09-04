import httpx
from langchain_core.tools import tool


@tool
def http_request(url: str) -> dict:
    """Send a GET request to an authorized test URL and return the response details."""

    try:
        response = httpx.get(
            url,
            timeout=10,
            follow_redirects=True
        )

        return {
            "url": str(response.url),
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:5000],
        }

    except Exception as e:
        return {
            "error": str(e)
        }
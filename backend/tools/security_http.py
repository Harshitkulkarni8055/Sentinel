import httpx
from langchain_core.tools import tool


@tool
def security_http_request(
    url: str,
    params: dict | None = None,
) -> dict:
    """Send a controlled HTTP GET request to an authorized target."""

    try:
        response = httpx.get(
            url,
            params=params,
            timeout=10,
            follow_redirects=True,
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
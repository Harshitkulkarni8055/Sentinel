import httpx
from langchain_core.tools import tool


@tool
def http_recon(url: str) -> dict:
    """Perform basic HTTP reconnaissance against a URL."""

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
            "content_length": len(response.content),
        }

    except Exception as e:
        return {
            "error": str(e)
        }
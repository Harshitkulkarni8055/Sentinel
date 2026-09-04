from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse

app = FastAPI(title="Sentinel Clean Target")


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)

    for key, value in SECURITY_HEADERS.items():
        response.headers[key] = value

    return response


@app.get("/")
def root():
    return {"status": "healthy", "application": "clean-target"}


@app.get("/api/products")
def products():
    return {
        "products": [
            {"id": 1, "name": "Laptop"},
            {"id": 2, "name": "Phone"},
        ]
    }


@app.get("/api/profile")
def profile():
    return {
        "user": "demo",
        "role": "user",
        "message": "Authenticated profile placeholder"
    }


@app.get("/api/search")
def search(q: str = ""):
    # Safely return user input as JSON.
    return JSONResponse({
        "query": q,
        "results": []
    })


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9100)
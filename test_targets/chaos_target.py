import uvicorn
import asyncio
from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse

app = FastAPI(title="Sentinel Chaos Target")


@app.get("/")
def root():
    return {
        "application": "chaos-target",
        "message": "This application intentionally produces unusual responses."
    }


@app.get("/ok")
def ok():
    return {"status": "normal"}


@app.get("/bad-request")
def bad_request():
    return JSONResponse(
        status_code=400,
        content={"error": "Bad request", "details": "Synthetic test error"}
    )


@app.get("/unauthorized")
def unauthorized():
    return JSONResponse(
        status_code=401,
        content={"error": "Authentication required"}
    )


@app.get("/forbidden")
def forbidden():
    return JSONResponse(
        status_code=403,
        content={"error": "Access denied"}
    )


@app.get("/not-found")
def not_found():
    return JSONResponse(
        status_code=404,
        content={"error": "Resource does not exist"}
    )


@app.post("/method-test")
def method_test():
    return {"message": "POST endpoint"}


@app.get("/server-error")
def server_error():
    return JSONResponse(
        status_code=500,
        content={"error": "Synthetic internal server error"}
    )


@app.get("/bad-gateway")
def bad_gateway():
    return JSONResponse(
        status_code=502,
        content={"error": "Synthetic bad gateway"}
    )


@app.get("/service-unavailable")
def unavailable():
    return JSONResponse(
        status_code=503,
        content={"error": "Synthetic service unavailable"}
    )


@app.get("/empty")
def empty():
    return Response(status_code=200)


@app.get("/text")
def text():
    return PlainTextResponse(
        "This is intentionally plain text rather than JSON."
    )


@app.get("/malformed-json")
async def malformed_json():
    # Deliberately invalid JSON-like content.
    return Response(
        content='{"status": "broken", "missing": ',
        media_type="application/json",
        status_code=200
    )


@app.get("/redirect")
def redirect():
    return RedirectResponse("/ok", status_code=302)


@app.get("/slow")
async def slow():
    await asyncio.sleep(4)
    return {"status": "slow-response"}


@app.get("/slow2")
async def slow2():
    await asyncio.sleep(8)
    return {"status": "very-slow-response"}


@app.get("/large")
def large():
    # Moderately large response for parser/resilience testing.
    data = "A" * 500_000

    return PlainTextResponse(data)


@app.get("/echo")
def echo(q: str = ""):
    return {
        "received": q
    }


@app.get("/unstable")
def unstable():
    return JSONResponse(
        status_code=500,
        content={
            "error": "Synthetic unstable endpoint",
            "retry": True
        }
    )


@app.get("/api/items/{item_id}")
def item(item_id: str):
    if item_id == "error":
        return JSONResponse(
            status_code=500,
            content={"error": "Synthetic item failure"}
        )

    return {
        "id": item_id,
        "name": "Test Item"
    }


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9200)
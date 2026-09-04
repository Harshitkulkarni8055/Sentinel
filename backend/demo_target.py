from fastapi import FastAPI, Form, Cookie
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

app = FastAPI(title="Sentinel Demo Vulnerable App")

USERS = {
    "alice": {"password": "alice123", "id": 1, "name": "Alice", "email": "alice@example.com", "role": "user"},
    "bob": {"password": "bob123", "id": 2, "name": "Bob", "email": "bob@example.com", "role": "user"},
    "admin": {"password": "admin123", "id": 99, "name": "Admin", "email": "admin@example.com", "role": "admin"},
}

SESSIONS = {}


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
      <body>
        <h1>Sentinel Demo Application</h1>
        <form method="post" action="/login">
          <input name="username" placeholder="username">
          <input name="password" type="password" placeholder="password">
          <button>Login</button>
        </form>
      </body>
    </html>
    """


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    user = USERS.get(username)

    if not user or user["password"] != password:
        return JSONResponse({"error": "invalid credentials"}, status_code=401)

    token = f"session-{username}"
    SESSIONS[token] = username

    response = JSONResponse({
        "message": "login successful",
        "user_id": user["id"],
        "role": user["role"],
    })
    response.set_cookie("session", token, httponly=True)
    return response


@app.get("/api/users")
def users():
    # Intentional information disclosure for the demo.
    return {
        "users": [
            {"id": u["id"], "name": u["name"]}
            for u in USERS.values()
            if u["id"] != 99
        ]
    }


@app.get("/api/users/{user_id}")
def get_user(user_id: int, session: str | None = Cookie(default=None)):
    # INTENTIONAL IDOR:
    # Authentication is checked, but ownership is NOT checked.
    username = SESSIONS.get(session)

    if not username:
        return JSONResponse({"error": "authentication required"}, status_code=401)

    for user in USERS.values():
        if user["id"] == user_id:
            return {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "owner": user["name"],
                "requested_by": username,
            }

    return JSONResponse({"error": "not found"}, status_code=404)


@app.get("/api/search")
def search(q: str = ""):
    # Intentional reflected-input behavior for Sentinel's benign marker test.
    return {
        "query": q,
        "results": [
            {"id": 1, "name": "Laptop"},
            {"id": 2, "name": "Phone"},
        ],
    }


@app.get("/api/admin")
def admin_panel(session: str | None = Cookie(default=None)):
    username = SESSIONS.get(session)

    if not username:
        return JSONResponse({"error": "authentication required"}, status_code=401)

    # Intentional vertical authorization flaw for the demo.
    return {
        "message": "admin panel",
        "requested_by": username,
        "secret": "DEMO-ADMIN-DATA",
    }


@app.get("/api/products")
def products():
    return {
        "products": [
            {"id": 1, "name": "Laptop"},
            {"id": 2, "name": "Phone"},
        ]
    }
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9000)
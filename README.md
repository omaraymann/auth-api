# Auth API

A small authenticated API built with **FastAPI** and **Supabase Auth** for the FlyRank Internship — Backend Track.

It does three things: registers users, logs them in, and refuses to answer certain routes unless the caller proves who they are.

The deliberate part is what it *doesn't* do. It never sees a password hash, never stores a credential, and never decides whether a password is correct. Supabase does all of that. This API's job is the part that actually belongs to a backend developer: **receive a token, verify it, and open or refuse the door.**

```
Client  --credentials-->  Supabase        "here is a signed token"
Client  --token-------->  this API        "is this token real? whose is it?"
this API --token------->  Supabase        "yes, it belongs to user e60ed290..."
```

## Run it

You need Python 3.10+ and a free [Supabase](https://supabase.com) project (no card).

```powershell
git clone https://github.com/omaraymann/auth-api.git
cd auth-api
copy .env.example .env      # macOS/Linux: cp .env.example .env
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

- API: **http://localhost:8000**
- Swagger docs: **http://localhost:8000/docs**

Fill in `.env` from your Supabase dashboard under **Project Settings → API**, and turn **Confirm email** *off* under **Authentication → Sign In / Providers → Email**. Without that, signup succeeds but returns no session, and the login that follows fails with "Email not confirmed" — a real security feature in production, an hour of confused debugging in development.

The server refuses to start if either variable is missing or still holds a placeholder, and makes one live call to Supabase on startup so that "connected" in the log means it.

## Configuration

All configuration is read from a `.env` file, which is **git-ignored and never committed**. `.env.example` is committed with placeholder values so you know what to supply.

| Variable | What it is | Where to find it |
|----------|------------|------------------|
| `SUPABASE_URL` | your project's URL | Project Settings → API → Project URL |
| `SUPABASE_KEY` | the **publishable** (anon) key | Project Settings → API |
| `PORT` | port uvicorn listens on | your choice, defaults to 8000 |

`SUPABASE_KEY` must be the publishable/anon key. Its sibling — the secret `service_role` key — bypasses every security rule and belongs nowhere near a client, a commit, or this file.

## Endpoints

| Method | Path | What it does | Auth | Status codes |
|--------|------|--------------|------|--------------|
| POST | `/auth/signup` | Register from `{"email", "password"}` | none | 201 · 400 bad or duplicate |
| POST | `/auth/login` | Exchange credentials for tokens | none | 200 · 400 missing field · 401 wrong credentials |
| POST | `/auth/logout` | Revoke the session's refresh token | **Bearer** | 204 · 401 |
| GET | `/public/info` | Open data, anyone may read | none | 200 |
| GET | `/protected/profile` | The caller's own id, email, created_at | **Bearer** | 200 · 401 |
| GET | `/protected/dashboard` | A second guarded route | **Bearer** | 200 · 401 |

Every error returns JSON in the shape `{"error": "..."}` — including the ones FastAPI generates itself, such as a 404 on an unknown path or a 400 for an unparseable body.

Protected routes expect the token from `/auth/login` in the standard header:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

## Example request

A verified call to a protected route, taken from a real run:

```
$ curl -i http://localhost:8000/protected/profile -H "Authorization: Bearer eyJhbGciOi..."
HTTP/1.1 200 OK
content-length: 120
content-type: application/json
date: Mon, 31 Aug 2026 02:11:11 GMT
server: uvicorn

{
  "id": "e60ed290-f1bd-46e9-a42f-f40309447812",
  "email": "new1@example.com",
  "created_at": "2026-08-30 21:02:25.774686+00:00"
}
```

Change a single character of that token and the same request returns `401 {"error": "Invalid or expired token"}`. The payload of a JWT is readable by anyone — it is only base64 — but it is signed, so altering it invalidates the signature.

## How it is put together

```
config.py     reads .env, refuses to start on a missing or placeholder value
auth.py       every line that talks to Supabase - the only module importing the SDK
main.py       routes, validation, status codes, and the reusable auth guard
.env          real secrets - git-ignored
.env.example  the same keys with placeholder values - committed
```

**`auth.py` is the only module that knows Supabase exists.** The routes in `main.py` call `sign_up()`, `sign_in()`, `get_user()` and `sign_out()`; they contain no SDK calls at all. This is the same wall `db.py` gave the task API, where the routes contained no SQL — swapping identity provider should touch one file.

`main.py` holds one dependency, `current_user`, which every protected route declares:

```python
@app.get("/protected/dashboard")
def dashboard(user=Depends(current_user)):
    return {"message": f"Welcome back, {user.email}."}
```

That is the entire route. No header parsing, no `try/except`, no 401 — by the time the body runs, the token has been verified and the user injected. Adding a protected route costs one parameter, and protection is visible in the signature rather than buried in a body where a reviewer might miss its absence.

## Design notes

### Why 401 and 400 are not interchangeable

A missing `password` field is a **malformed request** — 400. A *wrong* password is a perfectly well-formed request that failed authentication — 401. Both come back from Supabase as the same exception type, and deciding which is which is the API's job, not the SDK's.

### Why a failed login says so little

`/auth/login` returns `{"error": "Invalid login credentials"}` whether the password was wrong or the email was never registered. The two responses are byte-identical on purpose. If they differed, anyone could feed the endpoint a list of addresses and learn which ones have accounts here — user enumeration. Signup cannot hide this (it has to say the email is taken); login can, so it does.

### Why `get_user` requires a token

The Supabase SDK's `get_user()` can be called with no argument, in which case it falls back to whatever session the client object is holding. On a server that client is shared by every request, so that session belongs to **whoever logged in most recently** — not the caller. A guard written that way returns the wrong person's identity and never errors.

`auth.get_user(token)` therefore takes the token as a required argument with no default, so the unsafe call cannot be written.

### Why logging out doesn't fully log you out

`POST /auth/logout` revokes the **refresh** token. The **access** token keeps working until it expires, roughly an hour later — so immediately after a successful logout, the same token still opens `/protected/profile`.

That is not a bug to fix. This API holds no session table: it verifies a signature on each request, which is what makes it fast and horizontally scalable. The cost of never looking anything up is having nothing to delete — a correctly signed token stays correctly signed. The SDK's own documentation says as much: *"There is no way to revoke a user's access token jwt until it expires."*

The industry answer is short expiries, so the window between "logged out" and "genuinely locked out" stays small.

## Swagger UI

Every endpoint is documented and testable in the browser at `/docs`. Protected routes carry a padlock, and the **Authorize** button accepts a token once and reuses it across all of them:

![Swagger UI](screenshots/swagger.png)

The padlocks are not decoration — they exist because the routes depend on `HTTPBearer`, a declared OpenAPI security scheme. A hand-rolled header check works identically at runtime but leaves Swagger unaware that the route is guarded, and the lock never appears.

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from supabase import AuthApiError

import auth
import config


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Verify the Supabase configuration before the server accepts any request."""
    settings = auth.check_connection()
    print(f"Server running and connected to Supabase at {config.SUPABASE_URL}")

    # Signup and login both break in confusing ways when this is left on: signup
    # succeeds but returns no session, and the login that follows fails with
    # "Email not confirmed". Warn at startup rather than during Stage 1 debugging.
    if not settings.get("mailer_autoconfirm"):
        print(
            "WARNING: email confirmation is ON for this project. New users cannot log "
            "in until they confirm. Turn it off under Authentication -> Sign In / "
            "Providers -> Email for local development."
        )

    yield


app = FastAPI(
    title="Auth API",
    version="1.0",
    description="Sign up, log in, log out, and guard protected routes with Supabase-issued JWTs.",
    lifespan=lifespan,
)

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    """Render every HTTPException in this API's error shape.

    FastAPI's default is {"detail": ...}; everything else here returns
    {"error": ...}. Registered against Starlette's class rather than FastAPI's so
    that framework-raised errors, like a 404 for an unknown path, match too.
    """
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    """Answer 400 in this API's shape when the request body cannot be parsed.

    FastAPI rejects an absent or non-object body before the route runs, with its
    own 422 and a {"detail": [...]} list. The routes' own checks never get to see
    it. Since a missing body is missing input like any other, it is answered the
    same way: 400, {"error": ...}.
    """
    return JSONResponse(
        status_code=400,
        content={"error": "request body must be a JSON object with email and password"},
    )

def user_to_dict(user):
    """Convert Supabase's user object into the shape this API publishes.

    Supabase's user carries a great deal more than a client needs - app and user
    metadata, linked identities, confirmation timestamps. Deciding here, in one
    place, what a "user" looks like on the wire keeps that internal shape out of
    the API's contract. Same job row_to_task did for database rows in the task API.
    """
    return {
        "id": str(user.id),
        "email": user.email,
        "created_at": str(user.created_at),
    }


def session_to_dict(session):
    """Convert Supabase's session into the token payload this API hands to clients.

    Named to match the OAuth2 convention clients already expect, and deliberately
    narrow: the session object also carries a nested copy of the user, which login
    has no reason to publish.
    """
    return {
        "access_token": session.access_token,
        "refresh_token": session.refresh_token,
        "token_type": "bearer",
        "expires_in": session.expires_in,
    }



@app.post("/auth/signup", status_code=201)
def signup(body: dict):
    """Register an account from {"email": ..., "password": ...}.

    400 if either field is missing or empty, or if Supabase rejects the details
    (a duplicate email, or a password below the project's minimum length).
    """
    email = body.get("email")
    password = body.get("password")

    if not isinstance(email, str) or not email.strip():
        return JSONResponse(
            status_code=400,
            content={"error": "email is required and must be a non-empty string"},
        )
    # Not stripped: leading and trailing spaces are legitimate characters in a
    # password, and silently trimming them would lock the user out of their own
    # account at login.
    if not isinstance(password, str) or not password:
        return JSONResponse(
            status_code=400,
            content={"error": "password is required and must be a non-empty string"},
        )

    try:
        result = auth.sign_up(email.strip(), password)
    except AuthApiError as error:
        # Supabase answers 422 for a duplicate email. This API does not pass that
        # through: from a client's point of view it is a bad request like any other,
        # and Supabase's status codes are an implementation detail, not our contract.
        return JSONResponse(status_code=400, content={"error": error.message})

    return user_to_dict(result.user)


@app.post("/auth/login")
def login(body: dict):
    """Exchange {"email": ..., "password": ...} for tokens.

    400 if either field is missing or empty - the request itself is malformed.
    401 if the credentials are simply wrong - the request was fine, the answer is no.
    """
    email = body.get("email")
    password = body.get("password")

    if not isinstance(email, str) or not email.strip():
        return JSONResponse(
            status_code=400,
            content={"error": "email is required and must be a non-empty string"},
        )
    if not isinstance(password, str) or not password:
        return JSONResponse(
            status_code=400,
            content={"error": "password is required and must be a non-empty string"},
        )

    try:
        result = auth.sign_in(email.strip(), password)
    except AuthApiError:
        # Deliberately not echoing Supabase's message here. "Invalid login
        # credentials" is one answer for both a wrong password and an email that
        # was never registered - telling them apart would let an attacker discover
        # which accounts exist.
        return JSONResponse(
            status_code=401, content={"error": "Invalid login credentials"}
        )

    if result.session is None:
        # Supabase returns a user with no session when the account exists but its
        # email is unconfirmed. There is no token to hand back, so this is a 401
        # rather than a 200 with an empty body.
        return JSONResponse(
            status_code=401,
            content={"error": "Email not confirmed"},
        )

    return session_to_dict(result.session)


@app.get("/public/info")
def public_info():
    """Public data. No token required - this is the open lobby."""
    return {"message": "Welcome stranger! This info is public."}


def bearer_token(authorization):
    """Pull the token out of an "Authorization: Bearer <token>" header.

    Returns the token string, or None when the header is absent, uses a different
    scheme, or carries no token after the scheme. The caller decides what to do
    about that - this function only parses.

    The scheme is compared case-insensitively because RFC 7235 defines it that way:
    "bearer", "Bearer" and "BEARER" are all the same scheme to a compliant client.
    """
    if not authorization:
        return None

    parts = authorization.split()
    if len(parts) != 2:
        # Covers "Bearer" alone, a bare token with no scheme, and anything with
        # stray spaces in it.
        return None

    scheme, token = parts
    if scheme.lower() != "bearer" or not token:
        return None

    return token

def current_user(authorization: str | None = Header(default=None)):
    """Verify the caller's token and return their Supabase user.

    Used with Depends() on any protected route. Raises rather than returns,
    because a dependency's return value is injected into the route - handing back
    an error response would arrive in the route as if it were the user.
    """
    token = bearer_token(authorization)
    if token is None:
        raise HTTPException(status_code=401, detail="Access token required")

    try:
        user = auth.get_user(token)
    except AuthApiError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if user is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return user


def current_token(authorization: str | None = Header(default=None)):
    """Return the caller's raw token, for the one route that needs the string itself.

    Deliberately separate from current_user: that one answers "who is calling",
    this one answers "what did they present". Logout needs both, every other
    protected route needs only the first.
    """
    token = bearer_token(authorization)
    if token is None:
        raise HTTPException(status_code=401, detail="Access token required")

    return token


@app.get("/protected/profile")
def profile(user=Depends(current_user)):
    """The caller's own safe metadata: id, email, created_at."""
    return user_to_dict(user)


@app.get("/protected/dashboard")
def dashboard(user=Depends(current_user)):
    """A second protected route - same guard, no new auth code."""
    return {"message": f"Welcome back, {user.email}."}


@app.post("/auth/logout", status_code=204)
def logout(user=Depends(current_user), token=Depends(current_token)):
    """End the caller's session. 204 with no body.

    Two dependencies doing different jobs: current_user enforces that the token is
    genuine, which is what makes this a protected route, and current_token hands
    over the string Supabase needs in order to revoke it.

    Worth knowing what this achieves. The refresh token is revoked, so no further
    access tokens can be minted. The access token already in the caller's hands
    keeps working until its exp - a signed JWT cannot be recalled, which is the
    price of verifying signatures instead of consulting a session table.
    """
    auth.sign_out(token)
    return None

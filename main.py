from contextlib import asynccontextmanager

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
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


@app.get("/protected/profile")
def profile(authorization: str | None = Header(default=None)):
    """Private data. Requires "Authorization: Bearer <token>".

    Stage 2 only checks that a token was presented, not that it is real - a
    nonsense token still gets in. Stage 3 adds verification against Supabase.
    """
    token = bearer_token(authorization)
    if token is None:
        # One message for every way the header can be wrong. Saying which mistake
        # they made would help someone probing the API more than it helps a client.
        return JSONResponse(
            status_code=401, content={"error": "Access token required"}
        )

    return {"message": "You sent a token. It has not been verified yet."}

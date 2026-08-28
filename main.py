from contextlib import asynccontextmanager

from fastapi import FastAPI

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

import os

from dotenv import load_dotenv

# Pull .env into the process environment. The real values live in .env (git-ignored);
# .env.example documents the same keys with placeholder values.
load_dotenv()

PLACEHOLDER = "CHANGEME"


def _required(name):
    """Read a setting the app cannot run without.

    No default on purpose. A missing or unedited value stops the program here, with a
    message saying what to fix, instead of surfacing later as a confusing 401 from
    Supabase that looks like a bug in the auth code.
    """
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(
            f"{name} is not set. Copy .env.example to .env and fill in your Supabase values."
        )
    if PLACEHOLDER in value:
        raise RuntimeError(
            f"{name} still holds the {PLACEHOLDER} placeholder from .env.example. "
            "Replace it with the real value from Supabase: Project Settings -> API."
        )
    return value


SUPABASE_URL = _required("SUPABASE_URL")

# The publishable (anon) key only. Its sibling - the secret / service_role key -
# bypasses every security rule this project builds, and must never reach a client
# or a commit.
SUPABASE_KEY = _required("SUPABASE_KEY")

# Optional: uvicorn's default matches the Python lane's port anyway.
PORT = int(os.environ.get("PORT", 8000))

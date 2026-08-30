"""Every line that talks to Supabase. No other module imports the SDK.

Same rule db.py followed in the task API: one module owns the external system, and
the routes never see it. Swapping Supabase for another identity provider should
touch this file and nothing else.
"""

import httpx
from supabase import Client, create_client

import config

# One client for the whole process. create_client() builds an object and makes no
# network call, so this is cheap at import time and cannot fail on a cold start.
supabase: Client = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)


def check_connection(timeout=5.0):
    """Make one real call to Supabase, so startup can honestly claim to be connected.

    Because create_client() never contacts Supabase, a typo in SUPABASE_URL or a
    paused project would otherwise go unnoticed until the first login attempt - and
    would look like broken auth code rather than broken configuration. This asks the
    auth service for its public settings and lets any failure propagate, so the
    server refuses to start on a bad config instead of lying in its startup log.
    """
    response = httpx.get(
        f"{config.SUPABASE_URL}/auth/v1/settings",
        headers={"apikey": config.SUPABASE_KEY},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()

def sign_up(email, password):
    """Create a new account. Supabase hashes the password; we never store it.

    Returns an AuthResponse with .user and .session attributes - an object, not a
    dict, so read it as result.user. Raises AuthApiError if the email is already
    registered or the password fails the project's rules.
    """
    return supabase.auth.sign_up({"email": email, "password": password})


def sign_in(email, password):
    """Exchange credentials for tokens. Supabase does the checking; we never see the hash."""
    return supabase.auth.sign_in_with_password({"email": email, "password": password})

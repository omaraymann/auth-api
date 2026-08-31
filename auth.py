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


def get_user(token):
    """Ask Supabase whether a token is genuine, and who it belongs to.

    The token is a required argument and deliberately has no default. The SDK's
    get_user() accepts being called with nothing, in which case it falls back to
    whatever session this module-level client is holding - which is whoever logged
    in most recently, not whoever is making the current request. Requiring the
    token here makes that mistake impossible to write.

    Returns the Supabase user, or None if there is nothing to return. Raises
    AuthApiError when Supabase rejects the token as tampered with or expired.
    """
    response = supabase.auth.get_user(token)
    if response is None:
        return None
    return response.user

def sign_out(token):
    """Revoke the refresh tokens behind an access token.

    The token is passed explicitly. supabase.auth.sign_out() takes no token - it
    reads whatever session this shared client is holding, which on a server is
    whoever logged in most recently, and it suppresses the resulting error. It
    would return successfully having logged out the wrong person, or nobody.

    What this does and does not do: it revokes the refresh token, so no new access
    tokens can be minted. The access token already issued stays valid until its
    exp - a signed JWT cannot be recalled.
    """
    supabase.auth.admin.sign_out(token)

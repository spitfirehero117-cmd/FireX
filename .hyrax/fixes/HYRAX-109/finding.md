# Default admin credentials fall back to weak hardcoded values

**Tool:** `auth`
**Severity:** high
**Category:** security
**Location:** `app.py:65`

## What's wrong

`ADMIN_PASSWORD` defaults to the literal string `"change-me"` (app.py:73) and is used to bootstrap the initial `admin` account in `init_db()` (app.py:518-529) if `admin_users` is empty. `app.secret_key` similarly defaults to `"CHANGE-ME-BEFORE-DEPLOYING"` (app.py:65). If an operator deploys without setting `ADMIN_PASSWORD`/`SECRET_KEY` env vars, the app silently boots with a well-known admin password and a well-known Flask session-signing key.

A leaked/guessed `secret_key` lets an attacker forge Flask session cookies and set `admin_user_id`/`admin_role` directly, bypassing login entirely (Flask sessions are client-side signed, not server-verified beyond the signature). Combined with the printed bootstrap credentials (`print("Password: your existing ADMIN_PASSWORD")`), this is a realistic first-run misconfiguration path for a self-hosted tool.

## What changed

Fail startup (raise SystemExit) if `SECRET_KEY` or `ADMIN_PASSWORD` are unset/using the placeholder value in a non-debug/production context, rather than silently defaulting. Generate a random secret_key on first run and persist it (e.g., to a local file with restrictive permissions) instead of a static string literal.

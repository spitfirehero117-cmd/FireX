"""Shared pytest fixtures for the Flask app's test suite.

The application (``app.py``) is a single global Flask app object created at
import time, with its SQLite path resolved once from the ``DB_PATH``
environment variable. To get isolated, order-independent tests we:

  * Set ``DB_PATH`` (and other bootstrap env vars) *before* ``app`` is
    imported for the very first time, pointing at a fresh temp-directory
    database for the whole test session.
  * Re-run ``init_db()`` against a brand new temp file for every test via
    the ``app_module`` fixture, monkeypatching ``app.DB_PATH`` so each test
    is fully isolated (no leaking admin users, devices, audit rows, or
    lockout attempts between tests).
  * Reset the in-memory rate limiter between tests, since it's keyed by
    remote address and Flask's test client always uses the same address.

This repo snapshot ships without a ``templates/`` directory, so any route
that reaches ``render_template`` (including the 403/404/429/500 error
handlers) cannot be driven end-to-end here. Tests therefore favor:

  * Direct unit tests of pure helper functions.
  * Exercising the auth/role decorators and DB-backed helpers directly
    (``current_admin``, ``current_device``, ``admin_required`` and
    friends) inside a ``test_request_context``, which never touches Jinja.
  * HTTP-level tests only for endpoints whose *tested* branches redirect
    rather than render (e.g. unauthenticated access, PIN unlock/lock,
    device enrollment success/failure).
"""

import os
import sys
import time
import uuid
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# These must be set before `app` is first imported anywhere in the test
# session, since app.py reads them at module import time.
os.environ.setdefault(
    "DB_PATH", str(REPO_ROOT / f".pytest_bootstrap_{uuid.uuid4().hex}.db")
)
os.environ.setdefault("ADMIN_PASSWORD", "Bootstrap-Password-123")
os.environ.setdefault("WTF_CSRF_ENABLED", "0")

import app as app_module

app_module.app.config["WTF_CSRF_ENABLED"] = False
app_module.app.config["TESTING"] = True


@pytest.fixture()
def app(tmp_path, monkeypatch):
    """Point the app at a fresh, empty SQLite DB and initialize schema."""
    db_path = tmp_path / "test_crew.db"
    monkeypatch.setattr(app_module, "DB_PATH", db_path)
    app_module.init_db()
    app_module.limiter.reset()
    yield app_module.app


@pytest.fixture()
def client(app):
    with app.test_client() as c:
        yield c


def make_admin_user(
    username="admin1", role="admin", password="Password123", **overrides
):
    """Insert an admin_users row directly and return its id."""
    conn = app_module.db()
    now = int(time.time())
    fields = {
        "username": username,
        "display_name": overrides.pop("display_name", username.title()),
        "password_hash": generate_password_hash(password),
        "role": role,
        "enabled": overrides.pop("enabled", 1),
        "created_at": now,
        "must_change_password": overrides.pop("must_change_password", 0),
        "failed_logins": overrides.pop("failed_logins", 0),
        "locked_until": overrides.pop("locked_until", None),
    }
    fields.update(overrides)
    cur = conn.execute(
        """
        INSERT INTO admin_users(
            username, display_name, password_hash, role, enabled, created_at,
            must_change_password, failed_logins, locked_until
        ) VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (
            fields["username"],
            fields["display_name"],
            fields["password_hash"],
            fields["role"],
            fields["enabled"],
            fields["created_at"],
            fields["must_change_password"],
            fields["failed_logins"],
            fields["locked_until"],
        ),
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    return user_id


def make_device(name="test-device"):
    """Insert an approved_devices row directly and return its raw token."""
    token = uuid.uuid4().hex
    conn = app_module.db()
    now = int(time.time())
    conn.execute(
        """
        INSERT INTO approved_devices(name, token_hash, created_at, last_used_at, revoked)
        VALUES(?,?,?,?,0)
        """,
        (name, app_module.token_hash(token), now, now),
    )
    conn.commit()
    conn.close()
    return token


def make_profile(slug="crew-member", name="Crew Member", pin="1234", **overrides):
    """Insert a profiles row directly and return its slug."""
    conn = app_module.db()
    fields = {
        "role": overrides.pop("role", "Firefighter"),
        "department": overrides.pop("department", "Operations"),
        "location": overrides.pop("location", ""),
        "position": overrides.pop("position", ""),
        "crew_id": overrides.pop("crew_id", ""),
        "certifications": overrides.pop("certifications", ""),
        "emergency_contact": overrides.pop("emergency_contact", ""),
        "relationship": overrides.pop("relationship", ""),
        "emergency_phone": overrides.pop("emergency_phone", ""),
        "blood_type": overrides.pop("blood_type", "O+"),
        "allergies": overrides.pop("allergies", ""),
        "medications": overrides.pop("medications", ""),
        "medical_notes": overrides.pop("medical_notes", ""),
        "enabled": overrides.pop("enabled", 1),
    }
    conn.execute(
        """
        INSERT INTO profiles(
            slug, name, role, department, location, position, crew_id,
            certifications, emergency_contact, relationship, emergency_phone,
            blood_type, allergies, medications, medical_notes, pin_hash, enabled
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            slug,
            name,
            fields["role"],
            fields["department"],
            fields["location"],
            fields["position"],
            fields["crew_id"],
            fields["certifications"],
            fields["emergency_contact"],
            fields["relationship"],
            fields["emergency_phone"],
            fields["blood_type"],
            fields["allergies"],
            fields["medications"],
            fields["medical_notes"],
            generate_password_hash(pin),
            fields["enabled"],
        ),
    )
    conn.commit()
    conn.close()
    return slug


@pytest.fixture()
def device_cookie(app):
    """Create an approved device and return (name, cookie_kwargs)."""
    token = make_device()
    return token


@pytest.fixture()
def logged_in_client(app, device_cookie):
    """A test client with an approved device cookie and admin session set."""
    user_id = make_admin_user(username="admin1", role="admin", password="Password123")
    with app.test_client() as c:
        c.set_cookie(app_module.DEVICE_COOKIE_NAME, device_cookie)
        with c.session_transaction() as sess:
            sess["admin_user_id"] = user_id
            sess["admin_username"] = "admin1"
            sess["admin_role"] = "admin"
        yield c

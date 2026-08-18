"""Tests for the medical-PIN unlock flow (unlock_medical / lock_medical) and
the public Red Card PIN unlock (unlock_red_card_public), including:

  * successful unlock sets the one-view session flag
  * failed PIN does not set it
  * lockout after MAX_ATTEMPTS consecutive failures from the same IP
  * lock_medical clears the one-view flag

The GET /p/<slug> page itself calls render_template(), which this snapshot
can't do (no templates/ directory shipped) -- so these tests unlock via the
POST endpoints (which only flash+redirect, never render) and then verify the
resulting *session state* directly, which is exactly what the one-view PIN
semantics are implemented with.
"""

import time

from conftest import make_profile

import app as app_module


def test_unlock_medical_success_sets_one_view_flag(client):
    slug = make_profile(pin="4242")

    resp = client.post(f"/p/{slug}/unlock", data={"pin": "4242"})

    assert resp.status_code == 302
    assert resp.headers["Location"].endswith(f"/p/{slug}#medical")
    with client.session_transaction() as sess:
        assert sess.get(f"medical_once:{slug}") is True


def test_unlock_medical_wrong_pin_does_not_unlock(client):
    slug = make_profile(pin="4242")

    resp = client.post(f"/p/{slug}/unlock", data={"pin": "0000"})

    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert sess.get(f"medical_once:{slug}") is None


def test_unlock_medical_records_access_attempts(app, client):
    slug = make_profile(pin="4242")

    client.post(f"/p/{slug}/unlock", data={"pin": "wrong"})

    conn = app_module.db()
    rows = conn.execute(
        "SELECT success FROM access_attempts WHERE slug=?", (slug,)
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0]["success"] == 0


def test_unlock_medical_locks_out_after_max_attempts(app, client):
    slug = make_profile(pin="4242")

    for _ in range(app_module.MAX_ATTEMPTS):
        client.post(f"/p/{slug}/unlock", data={"pin": "wrong"})

    # One more attempt, even with the *correct* PIN, must be blocked by the
    # lockout rather than reaching the PIN check at all.
    resp = client.post(f"/p/{slug}/unlock", data={"pin": "4242"})
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert sess.get(f"medical_once:{slug}") is None


def test_unlock_medical_lockout_is_per_slug(app, client):
    """A lockout on one profile must not block PIN attempts on another."""
    slug_a = make_profile(slug="member-a", pin="1111")
    slug_b = make_profile(slug="member-b", pin="2222")

    for _ in range(app_module.MAX_ATTEMPTS):
        client.post(f"/p/{slug_a}/unlock", data={"pin": "wrong"})

    resp = client.post(f"/p/{slug_b}/unlock", data={"pin": "2222"})
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert sess.get(f"medical_once:{slug_b}") is True


def test_lock_medical_clears_one_view_flag(client):
    slug = make_profile(pin="4242")
    client.post(f"/p/{slug}/unlock", data={"pin": "4242"})
    with client.session_transaction() as sess:
        assert sess.get(f"medical_once:{slug}") is True

    resp = client.post(f"/p/{slug}/lock")
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert sess.get(f"medical_once:{slug}") is None


def test_is_locked_out_pure_function_all_failures(app):
    slug = make_profile(pin="4242")
    ip = "203.0.113.5"
    for _ in range(app_module.MAX_ATTEMPTS):
        app_module.log_attempt(slug, ip, False)

    assert app_module.is_locked_out(slug, ip) is True


def test_is_locked_out_pure_function_one_success_breaks_lockout(app):
    """If any of the most-recent MAX_ATTEMPTS attempts succeeded, not locked."""
    slug = make_profile(pin="4242")
    ip = "203.0.113.6"
    for _ in range(app_module.MAX_ATTEMPTS - 1):
        app_module.log_attempt(slug, ip, False)
    app_module.log_attempt(slug, ip, True)

    assert app_module.is_locked_out(slug, ip) is False


def test_is_locked_out_pure_function_below_threshold(app):
    slug = make_profile(pin="4242")
    ip = "203.0.113.7"
    for _ in range(app_module.MAX_ATTEMPTS - 1):
        app_module.log_attempt(slug, ip, False)

    assert app_module.is_locked_out(slug, ip) is False


def test_is_locked_out_ignores_old_attempts(app, monkeypatch):
    """Attempts older than LOCKOUT_SECONDS must not count toward lockout."""
    slug = make_profile(pin="4242")
    ip = "203.0.113.8"
    conn = app_module.db()
    old_ts = int(time.time()) - app_module.LOCKOUT_SECONDS - 10
    for _ in range(app_module.MAX_ATTEMPTS):
        conn.execute(
            "INSERT INTO access_attempts(slug,ip,success,created_at) VALUES(?,?,0,?)",
            (slug, ip, old_ts),
        )
    conn.commit()
    conn.close()

    assert app_module.is_locked_out(slug, ip) is False


def test_unlock_red_card_public_success_sets_view_token(app, client):
    slug = make_profile(pin="9999")
    # red_card_filename isn't part of the base INSERT columns; set it after.
    conn = app_module.db()
    conn.execute(
        "UPDATE profiles SET red_card_filename=? WHERE slug=?", ("card.png", slug)
    )
    conn.commit()
    conn.close()

    resp = client.post(f"/p/{slug}/red-card/unlock", data={"pin": "9999"})
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert sess.get(f"redcard_once:{slug}") is True
        assert sess.get(f"redcard_view:{slug}")


def test_unlock_red_card_public_without_file_on_record(app, client):
    slug = make_profile(pin="9999")  # no red_card_filename set

    resp = client.post(f"/p/{slug}/red-card/unlock", data={"pin": "9999"})
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert sess.get(f"redcard_once:{slug}") is None


def test_reset_medical_lockout_clears_attempts(app, logged_in_client):
    slug = make_profile(pin="4242")
    ip = "203.0.113.9"
    for _ in range(app_module.MAX_ATTEMPTS):
        app_module.log_attempt(slug, ip, False)
    assert app_module.is_locked_out(slug, ip) is True

    conn = app_module.db()
    profile_id = conn.execute(
        "SELECT id FROM profiles WHERE slug=?", (slug,)
    ).fetchone()["id"]
    conn.close()

    resp = logged_in_client.post(f"/admin/reset-lockout/{profile_id}")
    assert resp.status_code == 302
    assert app_module.is_locked_out(slug, ip) is False

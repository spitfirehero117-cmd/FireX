"""Tests for calculate_hours() (the financial/timesheet pure-function logic)
and device enrollment (code expiry / reuse), plus the admin login flow's
lockout behavior.

A note on the rejection-branch tests below: this repo snapshot ships
without a ``templates/`` directory, so the (pre-existing, out of scope for
this fix) branches of ``device_enroll``/``admin_login`` that re-render the
form on failure raise ``TemplateNotFound`` under ``TESTING=True`` rather
than returning a normal response. Those tests use ``pytest.raises`` to
acknowledge that and then assert on the *database-level* side effects
(the part that actually matters for regression protection here: was the
code marked used? was a device row inserted? was failed_logins bumped?).
"""

import time

import jinja2
import pytest
from conftest import TEST_ADMIN_PASSWORD, make_admin_user, make_device

import app as app_module


class TestCalculateHours:
    def test_simple_same_day_shift(self):
        assert app_module.calculate_hours("08:00", "17:00") == 9.0

    def test_overnight_shift_wraps_past_midnight(self):
        # 22:00 -> 06:00 is 8 hours, crossing midnight.
        assert app_module.calculate_hours("22:00", "06:00") == 8.0

    def test_zero_length_shift(self):
        assert app_module.calculate_hours("09:00", "09:00") == 0.0

    def test_rounds_to_two_decimal_places(self):
        # 08:00 -> 08:20 is 1/3 hour = 0.3333... -> rounds to 0.33
        assert app_module.calculate_hours("08:00", "08:20") == 0.33

    def test_one_minute_shift(self):
        assert app_module.calculate_hours("08:00", "08:01") == round(1 / 60, 2)

    def test_invalid_start_time_returns_zero(self):
        assert app_module.calculate_hours("not-a-time", "17:00") == 0.0

    def test_invalid_end_time_returns_zero(self):
        assert app_module.calculate_hours("08:00", "not-a-time") == 0.0

    def test_empty_strings_return_zero(self):
        assert app_module.calculate_hours("", "") == 0.0

    def test_full_24_hour_wrap(self):
        # start == end but treated as a full 24-hour shift when end < start
        # after the midnight-wrap adjustment: here end == start so no wrap
        # is applied and the result is 0, distinguishing it from a 24h shift.
        assert app_module.calculate_hours("00:00", "00:00") == 0.0


class TestRedCardStatus:
    def test_no_expiry_date_on_file(self):
        assert app_module.red_card_status(None) == "Not on file"
        assert app_module.red_card_status("") == "Not on file"

    def test_expired_date_in_past(self):
        assert app_module.red_card_status("2000-01-01") == "Expired"

    def test_expiring_soon_within_60_days(self):
        future = time.strftime("%Y-%m-%d", time.localtime(time.time() + 30 * 86400))
        assert app_module.red_card_status(future) == "Expiring Soon"

    def test_current_far_in_future(self):
        future = time.strftime("%Y-%m-%d", time.localtime(time.time() + 400 * 86400))
        assert app_module.red_card_status(future) == "Current"

    def test_malformed_date_returns_unknown(self):
        assert app_module.red_card_status("not-a-date") == "Unknown"


class TestDeviceEnrollment:
    def test_enroll_with_valid_code_sets_device_cookie(self, app, client):
        code = app_module.make_enrollment_code()
        conn = app_module.db()
        now = int(time.time())
        conn.execute(
            "INSERT INTO enrollment_codes(code_hash,created_at,expires_at,created_by_device_id) "
            "VALUES(?,?,?,NULL)",
            (
                app_module.token_hash(code),
                now,
                now + app_module.ENROLLMENT_CODE_SECONDS,
            ),
        )
        conn.commit()
        conn.close()

        resp = client.post(
            "/admin/device-enroll",
            data={"device_name": "Engine 1 Tablet", "code": code},
        )
        assert resp.status_code == 302
        assert "nfc_admin_device" in resp.headers.get("Set-Cookie", "")

        conn = app_module.db()
        row = conn.execute(
            "SELECT used_at FROM enrollment_codes WHERE code_hash=?",
            (app_module.token_hash(code),),
        ).fetchone()
        conn.close()
        assert row["used_at"] is not None

    def test_enroll_with_expired_code_is_rejected(self, app, client):
        code = app_module.make_enrollment_code()
        conn = app_module.db()
        now = int(time.time())
        conn.execute(
            "INSERT INTO enrollment_codes(code_hash,created_at,expires_at,created_by_device_id) "
            "VALUES(?,?,?,NULL)",
            (app_module.token_hash(code), now - 3600, now - 1),  # expired 1 second ago
        )
        conn.commit()
        conn.close()

        with pytest.raises(jinja2.TemplateNotFound):
            client.post(
                "/admin/device-enroll",
                data={"device_name": "Engine 1 Tablet", "code": code},
            )

        conn = app_module.db()
        devices = conn.execute("SELECT COUNT(*) AS c FROM approved_devices").fetchone()[
            "c"
        ]
        conn.close()
        assert devices == 0

    def test_enroll_with_already_used_code_is_rejected(self, app, client):
        code = app_module.make_enrollment_code()
        conn = app_module.db()
        now = int(time.time())
        conn.execute(
            "INSERT INTO enrollment_codes(code_hash,created_at,expires_at,used_at,created_by_device_id) "
            "VALUES(?,?,?,?,NULL)",
            (app_module.token_hash(code), now, now + 900, now),  # already used
        )
        conn.commit()
        conn.close()

        with pytest.raises(jinja2.TemplateNotFound):
            client.post(
                "/admin/device-enroll",
                data={"device_name": "Engine 1 Tablet", "code": code},
            )

        conn = app_module.db()
        devices = conn.execute("SELECT COUNT(*) AS c FROM approved_devices").fetchone()[
            "c"
        ]
        conn.close()
        assert devices == 0

    def test_enroll_with_unknown_code_is_rejected(self, app, client):
        with pytest.raises(jinja2.TemplateNotFound):
            client.post(
                "/admin/device-enroll",
                data={"device_name": "Engine 1 Tablet", "code": "0000-0000-0000"},
            )

        conn = app_module.db()
        devices = conn.execute("SELECT COUNT(*) AS c FROM approved_devices").fetchone()[
            "c"
        ]
        conn.close()
        assert devices == 0

    def test_enroll_reused_code_cannot_be_used_twice(self, app, client):
        """A valid code, once consumed, must not enroll a second device."""
        code = app_module.make_enrollment_code()
        conn = app_module.db()
        now = int(time.time())
        conn.execute(
            "INSERT INTO enrollment_codes(code_hash,created_at,expires_at,created_by_device_id) "
            "VALUES(?,?,?,NULL)",
            (
                app_module.token_hash(code),
                now,
                now + app_module.ENROLLMENT_CODE_SECONDS,
            ),
        )
        conn.commit()
        conn.close()

        first = client.post(
            "/admin/device-enroll", data={"device_name": "Device A", "code": code}
        )
        assert first.status_code == 302

        # New client (no device cookie yet) tries to reuse the same code.
        with app.test_client() as second_client, pytest.raises(jinja2.TemplateNotFound):
            second_client.post(
                "/admin/device-enroll", data={"device_name": "Device B", "code": code}
            )

        conn = app_module.db()
        devices = conn.execute("SELECT COUNT(*) AS c FROM approved_devices").fetchone()[
            "c"
        ]
        conn.close()
        assert devices == 1  # only Device A


class TestAdminLoginLockout:
    def test_login_success_sets_session(self, app, client):
        make_admin_user(username="loginuser")
        device_token = make_device()
        client.set_cookie(app_module.DEVICE_COOKIE_NAME, device_token)

        resp = client.post(
            "/admin/login",
            data={"username": "loginuser", "password": TEST_ADMIN_PASSWORD},
        )
        assert resp.status_code == 302
        with client.session_transaction() as sess:
            assert sess.get("admin_username") == "loginuser"

    def test_login_wrong_password_increments_failed_logins(self, app, client):
        device_token = make_device()
        client.set_cookie(app_module.DEVICE_COOKIE_NAME, device_token)
        make_admin_user(username="loginuser2")

        with pytest.raises(jinja2.TemplateNotFound):
            client.post(
                "/admin/login", data={"username": "loginuser2", "password": "wrong"}
            )

        conn = app_module.db()
        row = conn.execute(
            "SELECT failed_logins FROM admin_users WHERE username=?", ("loginuser2",)
        ).fetchone()
        conn.close()
        assert row["failed_logins"] == 1

    def test_login_locks_account_after_five_failures(self, app, client):
        device_token = make_device()
        client.set_cookie(app_module.DEVICE_COOKIE_NAME, device_token)
        make_admin_user(username="loginuser3")

        for _ in range(5):
            with pytest.raises(jinja2.TemplateNotFound):
                client.post(
                    "/admin/login", data={"username": "loginuser3", "password": "wrong"}
                )

        conn = app_module.db()
        row = conn.execute(
            "SELECT locked_until FROM admin_users WHERE username=?", ("loginuser3",)
        ).fetchone()
        conn.close()
        assert row["locked_until"] is not None and row["locked_until"] > int(
            time.time()
        )

        # Even the *correct* password must now be rejected while locked.
        with pytest.raises(jinja2.TemplateNotFound):
            client.post(
                "/admin/login",
                data={"username": "loginuser3", "password": TEST_ADMIN_PASSWORD},
            )
        with client.session_transaction() as sess:
            assert sess.get("admin_username") is None

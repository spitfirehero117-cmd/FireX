"""Tests for account-management business rules inside admin_account_edit()
that go beyond simple role-decorator gating:

  * A Chief may edit Chief/Officer/Engine Boss accounts, but Admin accounts
    are immutable to a Chief (abort 403), both when editing an existing
    Admin and when trying to *promote* someone to Admin.
  * The last enabled Admin account can't be demoted or disabled, even by
    another Admin, so the system is never left with zero enabled Admins.

The success path here redirects (no render_template), so it's safe to
drive through the real HTTP client. The 403 path (chief touching an admin
account) hits the pre-existing, out-of-scope missing-templates gap in this
snapshot (see tests/test_wildland.py docstring) so it's asserted the same
way: via pytest.raises(TemplateNotFound) plus a DB-state assertion that the
account was *not* modified.
"""

import jinja2
import pytest
from conftest import make_admin_user, make_device

import app as app_module


@pytest.fixture()
def chief_client(app):
    device_token = make_device()
    chief_id = make_admin_user(username="chief1", role="chief", password="Password123")
    with app.test_client() as c:
        c.set_cookie(app_module.DEVICE_COOKIE_NAME, device_token)
        with c.session_transaction() as sess:
            sess["admin_user_id"] = chief_id
            sess["admin_username"] = "chief1"
            sess["admin_role"] = "chief"
        yield c


def _account_row(username):
    conn = app_module.db()
    row = conn.execute(
        "SELECT * FROM admin_users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    return row


class TestChiefCannotTouchAdminAccounts:
    def test_chief_cannot_edit_an_existing_admin_account(self, app, chief_client):
        target_id = make_admin_user(username="admin-target", role="admin")

        with pytest.raises(jinja2.TemplateNotFound):
            chief_client.post(
                f"/admin/accounts/edit/{target_id}",
                data={
                    "username": "admin-target",
                    "display_name": "Renamed By Chief",
                    "role": "admin",
                    "enabled": "on",
                },
            )

        row = _account_row("admin-target")
        assert row["display_name"] != "Renamed By Chief"

    def test_chief_cannot_promote_an_officer_to_admin(self, app, chief_client):
        target_id = make_admin_user(username="officer-target", role="officer")

        with pytest.raises(jinja2.TemplateNotFound):
            chief_client.post(
                f"/admin/accounts/edit/{target_id}",
                data={
                    "username": "officer-target",
                    "display_name": "Officer Target",
                    "role": "admin",  # attempted privilege escalation
                    "enabled": "on",
                },
            )

        row = _account_row("officer-target")
        assert row["role"] == "officer"

    def test_chief_can_edit_an_officer_account(self, app, chief_client):
        target_id = make_admin_user(username="officer-target2", role="officer")

        resp = chief_client.post(
            f"/admin/accounts/edit/{target_id}",
            data={
                "username": "officer-target2",
                "display_name": "Updated Officer Name",
                "role": "officer",
                "enabled": "on",
            },
        )
        assert resp.status_code == 302

        row = _account_row("officer-target2")
        assert row["display_name"] == "Updated Officer Name"

    def test_chief_can_edit_another_chief_account(self, app, chief_client):
        target_id = make_admin_user(username="chief-target", role="chief")

        resp = chief_client.post(
            f"/admin/accounts/edit/{target_id}",
            data={
                "username": "chief-target",
                "display_name": "Updated Chief Name",
                "role": "chief",
                "enabled": "on",
            },
        )
        assert resp.status_code == 302

        row = _account_row("chief-target")
        assert row["display_name"] == "Updated Chief Name"


class TestLastAdminGuard:
    def test_cannot_demote_the_last_enabled_admin(self, app, chief_client):
        """Even though a Chief can't touch Admins at all, this guard also
        protects Admin-on-Admin edits; verify it holds with an Admin actor.
        """
        # init_db() always bootstraps one default "admin" account when the
        # table is empty (see app.py's init_db admin_count==0 branch); disable
        # it so our test's "sole-admin" really is the only enabled Admin.
        conn = app_module.db()
        conn.execute("UPDATE admin_users SET enabled=0 WHERE username='admin'")
        conn.commit()
        conn.close()

        # Replace the chief session with an Admin actor for this test.
        admin_id = make_admin_user(username="sole-admin", role="admin")
        with chief_client.session_transaction() as sess:
            sess["admin_user_id"] = admin_id
            sess["admin_username"] = "sole-admin"
            sess["admin_role"] = "admin"

        resp = chief_client.post(
            f"/admin/accounts/edit/{admin_id}",
            data={
                "username": "sole-admin",
                "display_name": "Sole Admin",
                "role": "officer",  # attempted demotion of the only admin
                "enabled": "on",
            },
        )
        assert resp.status_code == 302  # redirected back with a flash error

        row = _account_row("sole-admin")
        assert row["role"] == "admin"

    def test_can_demote_an_admin_when_another_admin_remains_enabled(
        self, app, chief_client
    ):
        admin_id = make_admin_user(username="admin-one", role="admin")
        make_admin_user(username="admin-two", role="admin")
        with chief_client.session_transaction() as sess:
            sess["admin_user_id"] = admin_id
            sess["admin_username"] = "admin-one"
            sess["admin_role"] = "admin"

        resp = chief_client.post(
            f"/admin/accounts/edit/{admin_id}",
            data={
                "username": "admin-one",
                "display_name": "Admin One",
                "role": "officer",
                "enabled": "on",
            },
        )
        assert resp.status_code == 302

        row = _account_row("admin-one")
        assert row["role"] == "officer"

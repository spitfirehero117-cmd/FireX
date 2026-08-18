"""Tests for the role-gating decorators: admin_required, tier1_required,
leadership_required, staff_required, oversight_required, wildland_required,
and the can_manage_deployment pure-function helper.

These call the decorators directly (wrapping a dummy view function) inside
a ``test_request_context`` so we exercise the real ``current_device()`` /
``current_admin()`` DB-backed lookups and the real ``role not in (...)``
checks, without needing the (missing in this snapshot) Jinja templates that
the error handlers render on ``abort()``.
"""

import pytest
import werkzeug.exceptions
from conftest import make_admin_user, make_device

import app as app_module

ALL_ROLES = ("admin", "chief", "officer", "engine_boss")

# For each decorator: which roles must pass (no exception) vs. get 403.
DECORATOR_ROLE_MATRIX = {
    "admin_required": {"allowed": ALL_ROLES, "forbidden": ()},
    "tier1_required": {
        "allowed": ("admin",),
        "forbidden": ("chief", "officer", "engine_boss"),
    },
    "leadership_required": {
        "allowed": ("admin", "chief"),
        "forbidden": ("officer", "engine_boss"),
    },
    "staff_required": {
        "allowed": ("admin", "chief", "officer"),
        "forbidden": ("engine_boss",),
    },
    "oversight_required": {
        "allowed": ("admin", "chief", "officer"),
        "forbidden": ("engine_boss",),
    },
    "wildland_required": {"allowed": ALL_ROLES, "forbidden": ()},
}


def _call_decorated(app, decorator_name, role, device_token, user_id):
    decorator = getattr(app_module, decorator_name)
    sentinel = object()

    def view():
        return sentinel

    wrapped = decorator(view)

    with app.test_request_context(
        "/protected",
        headers={"Cookie": f"{app_module.DEVICE_COOKIE_NAME}={device_token}"},
    ):
        from flask import session

        session["admin_user_id"] = user_id
        session["admin_username"] = f"user-{role}"
        session["admin_role"] = role
        return wrapped()


@pytest.mark.parametrize(
    "decorator_name,role",
    [
        (name, role)
        for name, spec in DECORATOR_ROLE_MATRIX.items()
        for role in spec["allowed"]
    ],
)
def test_decorator_allows_authorized_roles(app, decorator_name, role):
    device_token = make_device()
    user_id = make_admin_user(username=f"user-{decorator_name}-{role}", role=role)

    result = _call_decorated(app, decorator_name, role, device_token, user_id)
    assert result is not None  # the sentinel object the wrapped view returns


@pytest.mark.parametrize(
    "decorator_name,role",
    [
        (name, role)
        for name, spec in DECORATOR_ROLE_MATRIX.items()
        for role in spec["forbidden"]
    ],
)
def test_decorator_rejects_underprivileged_roles(app, decorator_name, role):
    device_token = make_device()
    user_id = make_admin_user(username=f"user-{decorator_name}-{role}", role=role)

    with pytest.raises(werkzeug.exceptions.Forbidden):
        _call_decorated(app, decorator_name, role, device_token, user_id)


def test_admin_required_without_device_redirects_to_enrollment(app):
    """No approved device cookie at all -> redirect, not a hard failure."""
    from flask import url_for

    sentinel = object()

    def view():
        return sentinel

    wrapped = app_module.admin_required(view)

    with app.test_request_context("/protected"):
        response = wrapped()
        assert response.status_code == 302
        assert response.headers["Location"] == url_for("device_enroll")


def test_admin_required_without_session_redirects_to_login(app):
    from flask import url_for

    device_token = make_device()
    sentinel = object()

    def view():
        return sentinel

    wrapped = app_module.admin_required(view)

    with app.test_request_context(
        "/protected",
        headers={"Cookie": f"{app_module.DEVICE_COOKIE_NAME}={device_token}"},
    ):
        response = wrapped()
        assert response.status_code == 302
        assert response.headers["Location"] == url_for("admin_login")


def test_admin_required_disabled_user_is_treated_as_logged_out(app):
    """current_admin() filters on enabled=1 -- a disabled account must not pass."""
    from flask import session, url_for

    device_token = make_device()
    user_id = make_admin_user(username="disabled-user", role="admin", enabled=0)
    sentinel = object()

    def view():
        return sentinel

    wrapped = app_module.admin_required(view)

    with app.test_request_context(
        "/protected",
        headers={"Cookie": f"{app_module.DEVICE_COOKIE_NAME}={device_token}"},
    ):
        session["admin_user_id"] = user_id
        session["admin_username"] = "disabled-user"
        session["admin_role"] = "admin"
        response = wrapped()
        assert response.status_code == 302
        assert response.headers["Location"] == url_for("admin_login")


class TestCanManageDeployment:
    """Pure-function unit tests for can_manage_deployment()."""

    @pytest.mark.parametrize("role", ["admin", "chief"])
    def test_admin_and_chief_can_manage_any_status(self, role):
        user = {"role": role}
        assert app_module.can_manage_deployment(user, {"status": "Active"}) is True
        assert app_module.can_manage_deployment(user, {"status": "Completed"}) is True

    @pytest.mark.parametrize("role", ["officer", "engine_boss"])
    def test_officer_and_engine_boss_only_manage_active(self, role):
        user = {"role": role}
        assert app_module.can_manage_deployment(user, {"status": "Active"}) is True
        assert app_module.can_manage_deployment(user, {"status": "Completed"}) is False

    def test_unknown_role_cannot_manage(self):
        user = {"role": "some_future_role"}
        assert app_module.can_manage_deployment(user, {"status": "Active"}) is False

    def test_no_user_cannot_manage(self):
        assert app_module.can_manage_deployment(None, {"status": "Active"}) is False

    def test_no_deployment_cannot_manage(self):
        assert app_module.can_manage_deployment({"role": "admin"}, None) is False


class TestPasswordPolicy:
    def test_too_short_rejected(self):
        assert app_module.password_policy_error("Ab1") is not None

    def test_missing_uppercase_rejected(self):
        assert app_module.password_policy_error("lowercase123") is not None

    def test_missing_lowercase_rejected(self):
        assert app_module.password_policy_error("UPPERCASE123") is not None

    def test_missing_digit_rejected(self):
        assert app_module.password_policy_error("NoDigitsHere") is not None

    def test_valid_password_accepted(self):
        assert app_module.password_policy_error("ValidPass123") is None

    def test_boundary_length_ten_is_accepted(self):
        # Exactly 10 chars, satisfies all other rules -- boundary check.
        pwd = "Abcdefgh1"
        assert len(pwd) == 9
        pwd10 = "Abcdefgh12"
        assert len(pwd10) == 10
        assert app_module.password_policy_error(pwd10) is None
        assert app_module.password_policy_error(pwd) is not None

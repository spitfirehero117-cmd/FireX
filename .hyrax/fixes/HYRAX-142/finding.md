# No test suite exists for a 3,482-line Flask app with auth, PIN unlock, and financial timesheet logic

**Tool:** `tests`
**Severity:** high
**Category:** correctness
**Location:** `app.py:1`

## What's wrong

The entire application (`app.py`, ~3,500 lines) implementing admin authentication, role-based access control (`admin_required`, `tier1_required`, `leadership_required`, `staff_required`), medical-PIN unlock (`unlock_medical`, `unlock_red_card_public`), device enrollment, and timesheet/hours calculation (`calculate_hours`) has zero automated tests. `self_test.py` is the only test-like artifact, and it only verifies that `init_db()` runs and `/healthz` returns 200 — it does not exercise any authentication, authorization, or business logic path.

This means role-boundary logic (e.g. `can_manage_deployment`, chief-vs-admin account restrictions in `admin_account_edit`) and the one-view-only medical PIN semantics have no regression protection. A behavior change (e.g. accidentally weakening a `role not in (...)` check) would ship silently.

## What changed

Add a `pytest` suite using Flask's `test_client()` (already demonstrated in `self_test.py`) covering: admin_required/staff/leadership/tier1 role gating (expect 403 for under-privileged roles), medical PIN unlock success/lockout/failure paths, device enrollment code expiry/reuse, and `calculate_hours`/`can_manage_deployment` as pure-function unit tests. Wire it into a `tests/` directory with `test_auth.py`, `test_wildland.py`, etc.

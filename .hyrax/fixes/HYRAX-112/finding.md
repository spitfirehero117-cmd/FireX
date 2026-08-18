# init_db() is a 280-line function mixing schema creation, migration, and admin bootstrap

**Tool:** `code-quality`
**Severity:** medium
**Category:** maintainability
**Location:** `app.py:262`

## What's wrong

`init_db()` (lines 262-541, ~280 lines) creates every table via `executescript`, runs multiple `ensure_column` migrations, calls `ensure_four_role_admin_schema` (an inline table-rename migration), seeds default qualification/certification option rows, updates feedback priority values, bootstraps the first admin account, and finally calls `ensure_bootstrap_code()`. It mixes at least four distinct concerns: schema DDL, ad-hoc column migrations, data seeding, and admin-account bootstrap.

This makes the function hard to reason about and risky to change — a change to admin bootstrap logic requires re-reading unrelated table DDL, and a mistake anywhere aborts the whole startup path since it all runs in one transaction scope with no per-step isolation.

## What changed

Split `init_db()` into focused steps: `create_schema(conn)` (executescript), `run_migrations(conn)` (the `ensure_column`/`ensure_four_role_admin_schema` calls), `seed_default_options(conn)`, and `bootstrap_admin_account(conn)`. Have `init_db()` become a thin orchestrator calling each in sequence. This isolates schema changes from bootstrap logic and makes each piece independently testable.

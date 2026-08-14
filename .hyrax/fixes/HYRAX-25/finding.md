# Manual backup path in backup_db.py calls create_backup without error handling

**Tool:** `resilience`
**Severity:** medium
**Category:** correctness
**Location:** `backup_db.py:59`

## What's wrong

The `backup_db.py` script's `__main__` block calls `create_backup("manual")` directly at line 59, bypassing the `safe_backup` wrapper in `server.py`. This is the manual backup path invoked via `BACKUP_DATABASE.bat`.

Because `create_backup` can raise `FileNotFoundError` (DB missing), `sqlite3.OperationalError` (DB locked or corrupt), or any filesystem exception, the bare call will propagate unhandled to the terminal. For a `.bat` script used by operators, an uncaught Python traceback is a confusing failure mode. The convention documented in the project principles is that `safe_backup` should be the guard layer.

Note: `safe_backup` lives in `server.py` and imports `app.logger`, so it cannot be directly reused from `backup_db.py`. The gap is that `backup_db.py` has no equivalent error-handling wrapper.

## What changed

Wrap the `__main__` call in a try/except to give the operator a clear failure message:

```python
if __name__ == "__main__":
    try:
        dest = create_backup("manual")
        print(f"Backup created: {dest}")
    except Exception as exc:
        print(f"Backup FAILED: {exc}")
        raise SystemExit(1)
```

This matches the spirit of `safe_backup` without importing the Flask app, and surfaces a clear non-zero exit code for the `.bat` wrapper to detect.

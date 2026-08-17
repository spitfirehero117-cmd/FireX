# SQLite connections not closed in `finally` block on backup error in `create_backup`

**Tool:** `harden`
**Severity:** medium
**Category:** security
**Location:** `backup_db.py:23`

## What's wrong

`create_backup` in `backup_db.py` opens two SQLite connections (`src` at line 23, `dst` at line 24) and then calls `src.backup(dst)`. If an exception is thrown during the backup (e.g. disk full, DB locked beyond timeout), neither connection is closed because no `try/finally` block wraps the operation. The `with dst:` context manager only handles COMMIT/ROLLBACK, not `close()`. Both `src` and `dst` should be closed in a `finally` clause, or the code should use context managers (`with sqlite3.connect(...) as src, sqlite3.connect(...) as dst:`) to guarantee cleanup.

## What changed

Wrap both connections in context managers that guarantee close-on-exit:
```python
def create_backup(label="auto"):
    if not DB.exists():
        raise FileNotFoundError(f"Database not found: {DB}")
    stamp = time.strftime("%Y%m%d_%H%M%S")
    dest = BACKUPS / f"crew_{stamp}_{label}.db"
    src = sqlite3.connect(DB, timeout=15)
    try:
        dst = sqlite3.connect(dest)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    prune_backups()
    return dest
```
Or use `contextlib.closing` to achieve the same effect.

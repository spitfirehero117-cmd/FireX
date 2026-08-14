# `recovery.py` executes database writes and prints at module scope instead of inside a guarded `main()`

**Tool:** `refactor`
**Severity:** medium
**Category:** maintainability
**Location:** `recovery.py:19`

## What's wrong

`recovery.py` mixes module-level setup code (DB existence check, `sqlite3.connect`, raw `conn.execute`, `conn.commit`, `conn.close`) with the two helper functions `h()` and `make_code()`. Every `import recovery` anywhere in the project would immediately execute the database write and the `print` output.

This is the classic "script with globals" antipattern: the logic is procedural code at module scope rather than inside a callable, making it:

- Impossible to unit-test `make_code()` or `h()` in isolation without triggering a DB write.
- Impossible to import the helpers from another module without side effects.
- Confusing to read (the function definitions are interspersed with top-level statements).

## What changed

Wrap the procedural body in a `main()` function and guard it with `if __name__ == "__main__"`:

```python
def sha256_hex(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()

def make_code() -> str:
    raw = secrets.token_hex(6).upper()
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}"

def main() -> None:
    db = Path(os.environ.get("DB_PATH") or (Path(__file__).resolve().parent / "crew.db"))
    if not db.exists():
        raise SystemExit(f"Database not found: {db}")
    conn = sqlite3.connect(db, timeout=15)
    now = int(time.time())
    code = make_code()
    conn.execute("""
        INSERT INTO enrollment_codes(
            code_hash, created_at, expires_at, used_at, created_by_device_id
        ) VALUES (?, ?, ?, NULL, NULL)
    """, (sha256_hex(code), now, now + 15 * 60))
    conn.commit()
    conn.close()
    print("")
    print("LOCAL ADMIN DEVICE RECOVERY")
    print("One-time enrollment code:", code)
    print("Expires in 15 minutes.")
    print("Use this only from a trusted device.")
    print("")

if __name__ == "__main__":
    main()
```

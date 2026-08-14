import hashlib
import os
import secrets
import sqlite3
import time
from pathlib import Path


def sha256_hex(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


def make_code() -> str:
    raw = secrets.token_hex(6).upper()
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}"


def main() -> None:
    db = Path(
        os.environ.get("DB_PATH") or (Path(__file__).resolve().parent / "crew.db")
    )
    if not db.exists():
        raise SystemExit(f"Database not found: {db}")
    conn = sqlite3.connect(db, timeout=15)
    now = int(time.time())
    code = make_code()
    conn.execute(
        """
INSERT INTO enrollment_codes(
    code_hash, created_at, expires_at, used_at, created_by_device_id
) VALUES (?, ?, ?, NULL, NULL)
""",
        (sha256_hex(code), now, now + 15 * 60),
    )
    conn.commit()
    conn.close()
    print()
    print("LOCAL ADMIN DEVICE RECOVERY")
    print("One-time enrollment code:", code)
    print("Expires in 15 minutes.")
    print("Use this only from a trusted device.")
    print()


if __name__ == "__main__":
    main()

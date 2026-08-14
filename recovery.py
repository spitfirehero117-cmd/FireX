
import sqlite3
import time
import secrets
import hashlib
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB = Path(os.environ.get("DB_PATH", BASE / "crew.db"))

def h(v):
    return hashlib.sha256(v.encode()).hexdigest()

def make_code():
    raw = secrets.token_hex(6).upper()
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}"

if not DB.exists():
    raise SystemExit(f"Database not found: {DB}")

conn = sqlite3.connect(DB, timeout=15)
now = int(time.time())
code = make_code()

conn.execute("""
INSERT INTO enrollment_codes(
    code_hash,created_at,expires_at,used_at,created_by_device_id
) VALUES(?,?,?,NULL,NULL)
""", (h(code), now, now + 15 * 60))
conn.commit()
conn.close()

print("")
print("LOCAL ADMIN DEVICE RECOVERY")
print("One-time enrollment code:", code)
print("Expires in 15 minutes.")
print("Use this only from a trusted device.")
print("")

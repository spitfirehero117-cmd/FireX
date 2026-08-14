import hashlib
import os
import secrets
import sqlite3
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB = Path(os.environ.get("DB_PATH", BASE / "crew.db"))

# Scrypt parameters: n=2^14 (16384), r=8, p=1 — standard interactive cost.
# dklen=32 gives a 256-bit derived key.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32


def h(v: str) -> str:
    """Hash a recovery code with scrypt (random salt, key-stretching).

    Returns a self-describing string:
        scrypt:<hex_salt>:<hex_hash>

    The verification side must parse this format and re-derive with the
    stored salt before comparing (use :func:`verify_code`).
    """
    salt = os.urandom(16)
    dk = hashlib.scrypt(
        v.encode(),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return f"scrypt:{salt.hex()}:{dk.hex()}"


def verify_code(submitted: str, stored_hash: str) -> bool:
    """Verify a submitted recovery code against a stored scrypt hash.

    Supports the ``scrypt:<hex_salt>:<hex_hash>`` format produced by
    :func:`h`.  Returns ``False`` for any malformed or legacy hash so
    that old unsalted SHA-256 hashes stored before this change are
    always rejected (they expired already, but this is a safety net).
    """
    try:
        scheme, salt_hex, hash_hex = stored_hash.split(":", 2)
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    dk = hashlib.scrypt(
        submitted.encode(),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return secrets.compare_digest(dk, expected)


def make_code():
    raw = secrets.token_hex(6).upper()
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}"


if not DB.exists():
    raise SystemExit(f"Database not found: {DB}")

conn = sqlite3.connect(DB, timeout=15)
now = int(time.time())
code = make_code()

conn.execute(
    """
INSERT INTO enrollment_codes(
    code_hash,created_at,expires_at,used_at,created_by_device_id
) VALUES(?,?,?,NULL,NULL)
""",
    (h(code), now, now + 15 * 60),
)
conn.commit()
conn.close()

print()
print("LOCAL ADMIN DEVICE RECOVERY")
print("One-time enrollment code:", code)
print("Expires in 15 minutes.")
print("Use this only from a trusted device.")
print()

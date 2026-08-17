# Recovery enrollment codes hashed with unsalted SHA-256 in `recovery.py`

**Tool:** `security`
**Severity:** medium
**Category:** security
**Location:** `recovery.py:13`

## What's wrong

The `h()` helper in `recovery.py` (line 13) hashes the raw recovery code string with a bare `SHA-256` using no salt:

```python
def h(v):
    return hashlib.sha256(v.encode()).hexdigest()
```

The recovery code format is `XXXX-YYYY-ZZZZ` where each segment is 4 uppercase hex characters (12 hex chars total from `secrets.token_hex(6).upper()`). The code space is 16¹² = ~2.8 trillion, which sounds large but is trivially brute-forceable offline given only a SHA-256 hash with no salt or stretching. An attacker who gains read access to the `enrollment_codes` table (e.g., via a backup) could recover the code with a GPU in seconds to minutes.

Recovery codes granting admin-device enrollment should be hashed with a password-hashing algorithm (`bcrypt`, `argon2id`, `scrypt`) or at minimum SHA-256 with a random salt stored alongside the hash.

## What changed

Replace bare `SHA-256` hashing with `bcrypt` or `hashlib.scrypt`:
```python
import bcrypt

def h(v):
    # bcrypt includes its own random salt
    return bcrypt.hashpw(v.encode(), bcrypt.gensalt()).decode()

# Verification at enrollment:
def verify_code(submitted, stored_hash):
    return bcrypt.checkpw(submitted.encode(), stored_hash.encode())
```
Alternatively use `hashlib.scrypt(v.encode(), salt=os.urandom(16), n=2**14, r=8, p=1)` and store the salt alongside the hash.

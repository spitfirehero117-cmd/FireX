# PIN brute-force lockout and rate limiting keyed on spoofable X-Forwarded-For header when not behind a trusted proxy

**Tool:** `security`
**Severity:** high
**Category:** security
**Location:** `app.py:169`

## What's wrong

`client_ip()` (app.py:169-173) always trusts the `X-Forwarded-For` header over `request.remote_addr`, and this value is used as the key for lockout tracking (`is_locked_out`/`log_attempt`, app.py:740-762) on the medical-PIN and Red-Card PIN brute-force protections, as well as `flask_limiter`'s `get_remote_address` key func for rate limiting.

However, `ProxyFix` (which correctly parses and trusts only the configured number of proxy hops for `X-Forwarded-For`) is only applied when `TRUST_PROXY=1` is set (app.py:76-77). `client_ip()` itself unconditionally reads `X-Forwarded-For` regardless of that setting. This means: (a) when not behind a proxy (the common case per domain.md — self-hosted, binds to 127.0.0.1 by default), any client can set an arbitrary `X-Forwarded-For` header on each request to reset their own lockout bucket, defeating the 5-attempt-per-5-minutes PIN brute-force protection on `/p/<slug>/unlock` and `/p/<slug>/red-card/unlock`, and bypassing IP-based Flask-Limiter throttling on login/enroll endpoints too. This directly undermines the `MAX_ATTEMPTS`/`LOCKOUT_SECONDS` brute-force defense on the 4-6 digit numeric PINs guarding medical data and Red Cards.

## What changed

Only trust `X-Forwarded-For` when `TRUST_PROXY=1` is set (mirroring the `ProxyFix` gate), falling back to `request.remote_addr` otherwise:
```python
def client_ip():
    if os.environ.get("TRUST_PROXY", "0") == "1":
        return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    return request.remote_addr or "unknown"
```
Alternatively, rely on `request.remote_addr` everywhere once `ProxyFix` is active (it rewrites `remote_addr` itself), and drop the manual header parsing entirely.

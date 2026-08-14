
import os
import tempfile
from pathlib import Path

# Uses the real configured DB only for read checks.
from app import app, init_db, system_health

print("NFC Crew System V6 self-test")
init_db()

health = system_health()
print("Database health:", health)
if not health["ok"]:
    raise SystemExit("FAILED: database health")

with app.test_client() as client:
    r = client.get("/healthz")
    print("/healthz:", r.status_code, r.json)
    if r.status_code != 200:
        raise SystemExit("FAILED: /healthz")

print("PASS: core startup/database/health checks")

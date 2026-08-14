
import os
import threading
import time
import traceback
from pathlib import Path

from waitress import serve

from app import app, init_db, audit_local, system_health, VERSION, cleanup_audit_log
from backup_db import create_backup

BASE = Path(__file__).resolve().parent
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8080"))
THREADS = int(os.environ.get("WAITRESS_THREADS", "8"))
BACKUP_INTERVAL_HOURS = int(os.environ.get("BACKUP_INTERVAL_HOURS", "24"))


def safe_backup(label):
    try:
        dest = create_backup(label)
        app.logger.info("Database backup created: %s", dest)
        try:
            audit_local("database_backup_created", f"file={dest.name}")
        except Exception:
            app.logger.exception("Could not write backup audit event")
    except Exception:
        app.logger.exception("Automatic database backup failed")


def backup_loop():
    while True:
        time.sleep(max(1, BACKUP_INTERVAL_HOURS) * 3600)
        safe_backup("auto")


def maintenance_loop():
    while True:
        time.sleep(24 * 3600)
        try:
            cleanup_audit_log(write_event=True)
        except Exception:
            app.logger.exception("Automatic audit cleanup failed")


def startup():
    init_db()

    health = system_health()
    if not health["ok"]:
        raise RuntimeError(f"Startup health check failed: {health}")

    # Backup on each clean server startup.
    safe_backup("startup")

    try:
        cleanup_audit_log(write_event=True)
    except Exception:
        app.logger.exception("Startup audit cleanup failed")

    thread = threading.Thread(
        target=backup_loop,
        name="database-backup",
        daemon=True
    )
    thread.start()

    maintenance = threading.Thread(
        target=maintenance_loop,
        name="audit-maintenance",
        daemon=True
    )
    maintenance.start()

    audit_local("server_started", f"NFC Crew System V{VERSION} started")


if __name__ == "__main__":
    try:
        startup()
        print(f"NFC Crew System V{VERSION} running on http://{HOST}:{PORT}")
        print("Health check:", f"http://{HOST}:{PORT}/healthz")
        print("Press Ctrl+C to stop.")
        serve(
            app,
            host=HOST,
            port=PORT,
            threads=THREADS,
            channel_timeout=60,
            clear_untrusted_proxy_headers=True
        )
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except Exception:
        app.logger.critical("Server startup/runtime failure\n%s", traceback.format_exc())
        print("SERVER FAILED TO START. Check logs\\app.log for details.")
        raise

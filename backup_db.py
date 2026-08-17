import os
import sqlite3
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB = Path(os.environ.get("DB_PATH", BASE / "crew.db"))
BACKUPS = BASE / "backups"
BACKUPS.mkdir(exist_ok=True)

RETENTION_DAYS = int(os.environ.get("BACKUP_RETENTION_DAYS", "30"))
MAX_BACKUPS = int(os.environ.get("MAX_BACKUPS", "60"))


def create_backup(label="auto"):
    if not DB.exists():
        raise FileNotFoundError(f"Database not found: {DB}")

    stamp = time.strftime("%Y%m%d_%H%M%S")
    dest = BACKUPS / f"crew_{stamp}_{label}.db"

    src = sqlite3.connect(DB, timeout=15)
    try:
        dst = sqlite3.connect(dest)
        try:
            with dst:
                src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()

    prune_backups()
    return dest


def prune_backups():
    now = time.time()
    files = sorted(
        BACKUPS.glob("crew_*.db"), key=lambda p: p.stat().st_mtime, reverse=True
    )

    for old in files[MAX_BACKUPS:]:
        old.unlink(missing_ok=True)

    cutoff = now - RETENTION_DAYS * 86400
    files = sorted(
        BACKUPS.glob("crew_*.db"), key=lambda p: p.stat().st_mtime, reverse=True
    )

    # Always preserve at least the newest 7 backups.
    for old in files[7:]:
        if old.stat().st_mtime < cutoff:
            old.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        dest = create_backup("manual")
        print(f"Backup created: {dest}")
    except Exception as exc:  # noqa: BLE001
        print(f"Backup FAILED: {exc}")
        raise SystemExit(1)

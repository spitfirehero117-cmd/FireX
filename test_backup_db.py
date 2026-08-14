"""Tests for prune_backups() in backup_db.py.

These tests cover:
- Count-cap (MAX_BACKUPS) phase
- Age-cap (RETENTION_DAYS) phase
- The "keep at least 7 newest" guard that overrides the age cap
- Within-limits no-op (files are younger than the retention window)
- age=0 with fewer than 7 files (keep-7 guard keeps all of them)
- age=0 with more than 7 files (keep-7 floor applies, exactly 7 survive)
"""

import os
import time
from pathlib import Path

import pytest

import backup_db

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _seed_backups(directory: Path, n: int, age_seconds: float = 0.0) -> list[Path]:
    """Create *n* synthetic backup files in *directory*.

    Files are named so that they sort newest-first by mtime when reversed.
    The ``age_seconds`` offset is applied uniformly so all files appear that
    old relative to ``time.time()``.  Returns the list of created paths,
    sorted newest-first (matching prune_backups internals).
    """
    now = time.time()
    paths = []
    for i in range(n):
        p = directory / f"crew_20240101_{i:06d}_auto.db"
        p.write_bytes(b"")
        # Spread files by 1 second each so mtime ordering is deterministic.
        mtime = now - age_seconds - i
        os.utime(p, (mtime, mtime))
        paths.append(p)
    # Return newest-first (matches prune_backups sort order).
    return sorted(paths, key=lambda p: p.stat().st_mtime, reverse=True)


# ---------------------------------------------------------------------------
# Parametrized main suite
#
# ``age_seconds`` controls how old the seeded files appear:
#   - For cases that should trigger the age cap, files are seeded
#     (retention_days + 1) * 86400 seconds old.
#   - For the "within limits, nothing deleted" case the files are seeded only
#     60 seconds old so they are well inside any plausible retention window.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "n_files, max_backups, retention_days, file_age_days, expected_remaining",
    [
        # Count cap fires: 10 files, cap=5, files are old → 5 survive.
        (10, 5, 30, 31, 5),
        # age=0 but fewer than 7 files → keep-7 guard keeps all 3.
        (3, 60, 0, 0, 3),
        # age=0 with 10 files → keep-7 floor applies, exactly 7 survive.
        (10, 60, 0, 0, 7),
        # Within all limits: 8 files, cap=60, retention=30 days,
        # files are only 1 day old → nothing deleted.
        (8, 60, 30, 1, 8),
        # Count cap exactly at boundary: n == max_backups → nothing deleted
        # (files are old enough that age cap would fire if >7 remain after
        # count cap — here n == max_backups so count cap is a no-op, and
        # files[7:] == [files[7]] would be pruned — but we cap at n=7 so
        # files[7:] is empty).
        (7, 7, 30, 31, 7),
        # Count cap: cap < 7; only count cap phase fires (age phase's files[7:]
        # is empty because only 3 survive), so keep-7 guard is vacuously safe.
        (10, 3, 30, 31, 3),
    ],
)
def test_prune_backups(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    n_files: int,
    max_backups: int,
    retention_days: int,
    file_age_days: int,
    expected_remaining: int,
) -> None:
    """prune_backups must leave exactly *expected_remaining* files."""
    age_seconds = file_age_days * 86400

    _seed_backups(tmp_path, n_files, age_seconds=age_seconds)

    monkeypatch.setattr(backup_db, "BACKUPS", tmp_path)
    monkeypatch.setattr(backup_db, "MAX_BACKUPS", max_backups)
    monkeypatch.setattr(backup_db, "RETENTION_DAYS", retention_days)

    backup_db.prune_backups()

    remaining = list(tmp_path.glob("crew_*.db"))
    assert len(remaining) == expected_remaining, (
        f"Expected {expected_remaining} backups to remain, "
        f"got {len(remaining)} "
        f"(n_files={n_files}, max_backups={max_backups}, "
        f"retention_days={retention_days}, file_age_days={file_age_days})"
    )


# ---------------------------------------------------------------------------
# Focused keep-7 guard tests
# ---------------------------------------------------------------------------


def test_keep7_guard_preserves_newest_seven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With retention_days=0, exactly the 7 newest files must survive."""
    _seed_backups(tmp_path, 15, age_seconds=1)

    monkeypatch.setattr(backup_db, "BACKUPS", tmp_path)
    monkeypatch.setattr(backup_db, "MAX_BACKUPS", 60)
    monkeypatch.setattr(backup_db, "RETENTION_DAYS", 0)

    backup_db.prune_backups()

    remaining = sorted(
        tmp_path.glob("crew_*.db"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    assert len(remaining) == 7


def test_keep7_guard_newest_files_are_retained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 7 files that survive must be the 7 with the most-recent mtime."""
    files = _seed_backups(tmp_path, 10, age_seconds=1)
    # files[0] is newest, files[9] is oldest.
    expected_survivors = {f.name for f in files[:7]}

    monkeypatch.setattr(backup_db, "BACKUPS", tmp_path)
    monkeypatch.setattr(backup_db, "MAX_BACKUPS", 60)
    monkeypatch.setattr(backup_db, "RETENTION_DAYS", 0)

    backup_db.prune_backups()

    survivors = {p.name for p in tmp_path.glob("crew_*.db")}
    assert survivors == expected_survivors


def test_keep7_guard_fewer_than_seven_files_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When there are fewer than 7 files, none should be deleted even at age=0."""
    _seed_backups(tmp_path, 5, age_seconds=1)

    monkeypatch.setattr(backup_db, "BACKUPS", tmp_path)
    monkeypatch.setattr(backup_db, "MAX_BACKUPS", 60)
    monkeypatch.setattr(backup_db, "RETENTION_DAYS", 0)

    backup_db.prune_backups()

    remaining = list(tmp_path.glob("crew_*.db"))
    assert len(remaining) == 5


# ---------------------------------------------------------------------------
# Count-cap and age-cap interaction
# ---------------------------------------------------------------------------


def test_count_cap_fires_before_age_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Count cap runs first; age cap re-lists so it sees only post-cap files."""
    # 10 old files; MAX_BACKUPS=5 keeps 5 newest; retention=0 would delete
    # them all, but keep-7 guard only applies if there are >7 left after count
    # cap — here only 5 remain, so the age loop's files[7:] is empty and
    # nothing more is deleted.
    _seed_backups(tmp_path, 10, age_seconds=1)

    monkeypatch.setattr(backup_db, "BACKUPS", tmp_path)
    monkeypatch.setattr(backup_db, "MAX_BACKUPS", 5)
    monkeypatch.setattr(backup_db, "RETENTION_DAYS", 0)

    backup_db.prune_backups()

    remaining = list(tmp_path.glob("crew_*.db"))
    assert len(remaining) == 5


def test_young_files_not_deleted_by_age_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Files newer than the retention cutoff must never be deleted."""
    # Create 10 files that are only 60 seconds old; retention = 30 days.
    _seed_backups(tmp_path, 10, age_seconds=60)

    monkeypatch.setattr(backup_db, "BACKUPS", tmp_path)
    monkeypatch.setattr(backup_db, "MAX_BACKUPS", 60)
    monkeypatch.setattr(backup_db, "RETENTION_DAYS", 30)

    backup_db.prune_backups()

    remaining = list(tmp_path.glob("crew_*.db"))
    assert len(remaining) == 10

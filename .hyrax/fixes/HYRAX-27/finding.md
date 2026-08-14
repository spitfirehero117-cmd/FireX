# prune_backups retention logic has no test coverage for the 'keep at least 7' guard

**Tool:** `tests`
**Severity:** medium
**Category:** correctness
**Location:** `backup_db.py:34`

## What's wrong

`prune_backups` in `backup_db.py` implements a three-phase retention policy:

1. Delete all backups beyond `MAX_BACKUPS` (count cap).
2. Re-list and delete files older than `RETENTION_DAYS` (age cap).
3. But always preserve the newest 7 (`files[7:]` guard).

The interaction between the count cap and the age cap is subtle: if `MAX_BACKUPS < 7`, the second sweep's `files[7:]` guard is never reached but there are already fewer than 7 files, so the guard is vacuously safe. Conversely, if the operator sets `BACKUP_RETENTION_DAYS=0`, every backup older than 0 seconds gets deleted except the 7 newest — which is probably correct but is not tested.

There is also a TOCTOU: the function lists files, deletes by count, then re-lists and deletes by age. Between the two `BACKUPS.glob()` calls another process could add or remove files. With no test exercising this boundary, a regression in the slice logic (off-by-one on `files[7:]`) would silently delete more backups than intended.

## What changed

Add `pytest`-parameterized tests for `prune_backups` using a temp directory:

```python
@pytest.mark.parametrize("n_files,max_backups,retention_days,expected_remaining", [
    (10, 5,  30, 5),   # count cap fires
    (3,  60,  0, 3),   # age=0 but keep-7 guard keeps all 3
    (10, 60,  0, 7),   # age=0, keep-7 floor applies
    (8,  60, 30, 8),   # within limits, nothing deleted
])
def test_prune_backups(tmp_path, monkeypatch, ...):
    ...
```

Patch `BACKUPS` in `backup_db` to `tmp_path` and seed synthetic `.db` files with controlled `mtime` values before calling `prune_backups()`.

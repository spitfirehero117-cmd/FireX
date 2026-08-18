# Raw sqlite3.IntegrityError text shown directly to admin users in flash messages

**Tool:** `error-ux`
**Severity:** medium
**Category:** maintainability
**Location:** `app.py:2915`

## What's wrong

In `admin_new()` (app.py:2915), `admin_edit()` (app.py:3011), and `batch_members()` (app.py:3155), `sqlite3.IntegrityError` is caught and its raw driver message is shown to the admin verbatim via `flash(str(exc), "error")` (or embedded in an f-string at 3158). SQLite's `IntegrityError` text for a UNIQUE-constraint violation looks like `UNIQUE constraint failed: profiles.slug` — this leaks the underlying table/column name and is not phrased as actionable guidance ("choose a different NFC tag ID/slug").

For a non-technical fire-crew admin filling out a member/apparatus form, seeing a raw SQL constraint name provides no clue about which form field to fix (the `slug` field, i.e. the NFC tag ID) or why the save failed, forcing them to guess or ask a developer.

## What changed

Catch `sqlite3.IntegrityError` specifically and translate to a friendly message before falling back to a generic one, e.g.:
```python
except sqlite3.IntegrityError as exc:
    if 'slug' in str(exc):
        flash('That NFC tag ID is already assigned to another member. Choose a different one.', 'error')
    else:
        flash('Could not save: a value conflicts with an existing record.', 'error')
except ValueError as exc:
    flash(str(exc), 'error')
```
Apply the same pattern at `admin_edit` (line 3011) and `batch_members` (line 3155/3158), where the raw exception is also flashed at 3158 (`f"Batch was not saved: {exc}"`).

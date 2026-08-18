# Admin can permanently erase the entire audit log with no tamper-evidence or backup

**Tool:** `compliance`
**Severity:** medium
**Category:** security
**Location:** `app.py:1569`

## What's wrong

`/admin/audit/clear` (guarded by `tier1_required`, i.e. the `admin` role) executes `DELETE FROM audit_log` — a full, irreversible wipe of the entire audit trail table (app.py:1574). The `audit_log` table is a normal mutable SQLite table with no append-only storage, no external log shipping, and no backup-before-clear step; the only trace left behind is the single `audit_log_cleared` row inserted immediately after the wipe, itself deletable by the next call to the same endpoint.

For an admin-tracking tool whose entire compliance value proposition is the audit trail (device enrollment, login attempts, medical PIN access, account changes), giving the top role the ability to fully erase history without any tamper-evidence (hash chain, WORM storage, or shipped copy) undermines investigations after an incident — including investigating that admin's own account. This is a real design tradeoff already present in the code (not accidental), but from a compliance/audit-trail standpoint a single `admin`-role click erasing all history with no independent copy is a genuine gap.

## What changed

Do not allow full deletion of audit_log via the app; instead implement retention-based `cleanup_audit_log` only (already exists) and remove/replace `clear_audit_log` with either a role-restricted export+archive step, or disable the hard delete and require an out-of-band DB operation for equivalent action. If the clear must stay, ship the deleted rows to an append-only location (file, syslog) before deleting, and audit the specific admin user id with a hash of the previous log tail to detect tampering.

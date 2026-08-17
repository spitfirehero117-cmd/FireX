# NTAG215 Crew System V7.5

## Dependencies

Dependency versions are managed with two files:

- `requirements.txt` — the human-edited source of truth. Version *ranges*
  live here (e.g. `Flask>=3.1,<4`). Edit this file when bumping a
  dependency.
- `requirements.lock.txt` — the generated, fully pinned lockfile with
  `--hash=sha256:...` entries for every package and its transitive
  dependencies. `START_SERVER.bat` and the upgrade steps below install
  from this file so every machine resolves to the exact same versions,
  not "whatever is newest on PyPI today."

To regenerate the lockfile after editing `requirements.txt` (requires
`pip-tools` or `uv`):

```
uv pip compile requirements.txt -o requirements.lock.txt --generate-hashes --python-platform windows
```

(or, with `pip-tools`: `pip-compile --generate-hashes -o requirements.lock.txt requirements.txt`)

Commit the regenerated `requirements.lock.txt` alongside the
`requirements.txt` change.

## V7.5 fixes
- Engine Boss accounts now land directly on Wildland after login and after a forced password change.
- Visiting `/admin` as an Engine Boss redirects to Wildland instead of showing Access Denied.
- Engine Bosses and Officers may manage any active Wildland deployment, regardless of who created it.
- Completed crew timesheet entries can be corrected while the deployment is active by any role allowed to manage that active deployment. Corrections still require a reason and remain audited.
- Completed deployments must be reopened before operational edits.

# NTAG215 Crew System V7.2

V6 focuses on reliability, presentation readiness, and consistent navigation.

## Navigation fix

V5 used different sidebar HTML on different admin pages, and the sidebar was hidden entirely on smaller browser widths.

V6 uses ONE shared admin navigation on every admin page:

- Members
- Add Member
- Approved Devices
- Audit Log
- System Status
- Logout

On smaller screens the navigation becomes a horizontal, scrollable top bar. It does not disappear.

## Reliability additions

- Waitress production WSGI server
- SQLite WAL mode
- SQLite 15-second busy timeout
- SQLite foreign keys enabled
- Startup database health check
- `/healthz` endpoint
- System Status admin page
- Database backup on every server start
- Automatic database backup every 24 hours
- Backup rotation:
  - default 30-day retention
  - default maximum 60 backups
  - always keeps at least the newest 7
- Rotating application log:
  - `logs/app.log`
  - 2 MB per file
  - 5 rotated files
- Friendly 404 / 429 / 500 error pages with request references
- Member create/update/delete audit events
- Optional Windows startup task that restarts after failures
- Self-test utility

## Upgrade from V5.5

1. Stop V5.5 with Ctrl+C.
2. Make a backup of your existing `crew.db`.
3. Extract V6 into a NEW folder.
4. Copy the working `crew.db` into the V6 folder beside `app.py`.
5. Copy custom uploaded logo files from the old:
   `static/uploads`
   into V6:
   `static/uploads`
6. Open Terminal in V6.
7. Run:

   `python -m pip install --require-hashes -r requirements.lock.txt`

8. Before starting the server, run:

   `python self_test.py`

   or double-click:

   `RUN_SELF_TEST.bat`

9. Start:

   `python server.py`

   or double-click:

   `START_SERVER.bat`

10. Open:
    `http://127.0.0.1:8080/admin`

## System Status

Admin > System Status shows:

- overall health
- database health
- WAL status
- server uptime
- member count
- approved-device count
- audit-event count
- database size
- latest backup status

Public health endpoint:

`http://127.0.0.1:8080/healthz`

## Automatic backups

A backup is made:
- whenever V6 starts cleanly
- every 24 hours while V6 remains running

Manual backup:
`BACKUP_DATABASE.bat`

Backups are stored in:
`backups`

Environment overrides:
- `BACKUP_INTERVAL_HOURS`
- `BACKUP_RETENTION_DAYS`
- `MAX_BACKUPS`

## Application logs

Server errors and reliability messages are written to:

`logs/app.log`

If a browser shows a Server Error page, the page includes a request reference and the terminal/log file should contain the corresponding problem.

## Optional Windows automatic startup/restart

After V6 is fully tested, run:

`INSTALL_WINDOWS_STARTUP_TASK.bat`

This creates a Windows Scheduled Task that:
- starts V6 at Windows startup
- starts it when Windows becomes available
- retries the task after failures

Run the installer from an Administrator terminal if Windows requires elevated permission.

To remove it:

`REMOVE_WINDOWS_STARTUP_TASK.bat`

Do NOT install the startup task until you have finished normal V6 testing.

## Before department presentation

Recommended test checklist:

1. Every admin tab remains visible while moving between pages.
2. Logout remains visible on every admin page.
3. Add/edit member.
4. Upload/change logo.
5. Public profile loads.
6. Correct medical PIN unlocks.
7. Wrong medical PIN is rejected and audited.
8. Medical Lock button works and audits.
9. Admin login success/failure audit.
10. Generate device authorization code.
11. Approve second browser/device.
12. Revoke second device.
13. Manual backup.
14. Restart server and verify startup backup.
15. Open System Status and confirm WAL + Healthy.
16. Open `/healthz` and confirm `"ok": true`.
17. Run `RUN_SELF_TEST.bat`.
18. Test a fake profile only before adding real medical information.

## Important

`crew.db` contains the profile/database information, but uploaded department logo images are separate files under `static/uploads`.

Keep a backup of both before major upgrades.


## V6.1 medical privacy change

Medical access is now **one-view only**.

After a correct medical PIN:
1. The medical information opens.
2. The unlock authorization is consumed immediately when that page loads.
3. Pressing Refresh locks the medical section again.
4. Closing and reopening the profile locks it again.
5. Navigating away and returning locks it again.

The explicit **Lock** button still works as an immediate manual lock.


## V6.2 — Two permission tiers

Tier 1 — Admin:
Full system control.

Tier 2 — Officer:
- Members
- Add Member
- View/edit profiles
- Edit public and medical profile information
- Change medical PIN
- Enable/disable profiles
- Upload/remove logos
- Reset medical lockout

Officers cannot:
- Delete members
- Manage Approved Devices
- Manage Administrators
- View Audit Log
- View System Status

Restrictions are enforced server-side.

### First V6.2 account
When upgrading an existing V6.1 database, V6.2 creates a Tier 1 account if none exist:

Username: `admin`
Password: your existing `ADMIN_PASSWORD`

You can set `ADMIN_USERNAME` before the first V6.2 start to choose a different first username.

The Administrators page is visible only to Tier 1.

Audit details now include the logged-in username.

V6.2 prevents the last enabled Tier 1 account from being disabled or demoted.


## V6.3 — Account security improvements

- New admin/officer accounts are forced to change their temporary password at first login.
- The first migrated Tier 1 account is also forced to change its password.
- Every signed-in Admin or Officer has a **Change Password** link.
- Password minimum:
  - 10 characters
  - uppercase
  - lowercase
  - number
- After 5 failed password attempts, that account is locked for 15 minutes.
- Successful login resets failed-login counters.
- Tier 1 can mark an account to require a password change at its next login.
- Password changes are audited as `admin_password_changed`.
- Account login failures and lockouts remain audited.


## V6.4 — Audit retention and reset

Default Audit Log retention is 90 days.

Automatic cleanup:
- runs when the server starts
- runs once every 24 hours
- removes entries older than the retention window
- writes `audit_log_cleanup` when old rows are removed

Tier 1 Admins also get a **Clear Audit Log** button.

Manual clear behavior:
- deletes all existing audit entries
- immediately writes one new `audit_log_cleared` event
- records the Tier 1 username who performed the clear
- requires confirmation in the browser

Tier 2 Officers cannot clear or view the Audit Log.

Retention can be changed with:
`AUDIT_RETENTION_DAYS`

Example for 180 days:
`AUDIT_RETENTION_DAYS=180`


## V6.5 — Internal pilot feedback

V6.5 adds a self-contained pilot feedback system. No email or external service is used.

Tier 1 Admin and Tier 2 Officer accounts can submit feedback with:
- category
- priority
- subject
- description

Tier 1 Admins additionally have a Feedback Inbox and can move reports through:
- New
- Reviewing
- Planned
- Fixed
- Closed

Feedback records the submitting username/display name and timestamps. Feedback is stored in crew.db, so it is included in the existing database backup process.

Audit events include `feedback_submitted` and `feedback_status_changed`. Tier 2 Officers cannot open the Feedback Inbox.


## V6.6 — Password visibility toggle

All password fields now include a clickable eye icon.

- Click the eye to show the password text.
- Click it again to hide the password.
- Works on login, forced password change, normal Change Password, and account password forms.
- The password remains masked by default.
- No password is stored or transmitted differently; this is only a display control in the browser.


## V6.7 — Three-level department access

Roles are now:

### Admin
Full system control.

### Chief
Chiefs can use all operational and management areas, including:
- Members / Add Member / edit / delete
- public and medical profile management
- Approved Devices
- Administrators
- Feedback and Feedback Inbox
- Audit Log
- System Status

Chief restrictions:
- cannot create an Admin account
- cannot promote a Chief or Officer to Admin
- cannot edit, disable, reset, or otherwise modify an existing Admin account
- cannot clear the Audit Log

### Officer
Officer profile permissions remain unchanged:
- view/add/edit member profiles
- public and medical fields
- medical PIN management
- enable/disable profiles
- logo management
- reset medical lockouts
- submit Feedback
- cannot delete members
- cannot manage Approved Devices or administrator accounts
- cannot manage Feedback Inbox

V6.7 additionally allows Officers to:
- view the Audit Log
- view System Status

Existing `admin` and `officer` accounts are preserved automatically during upgrade.
The database migration expands the account role schema to support `chief`.


## V6.8 — Feedback urgency colors

Feedback priorities are now:
- **Urgent** — red
- **Normal** — orange
- **Low** — yellow

The Feedback form shows the color key, and the Feedback Inbox displays the selected priority as a colored badge.

Existing feedback saved as `High` is automatically changed to `Urgent` during startup.


## V6.9 — Feedback status tracking and completed deletion

### Feedback status tracking
Every signed-in Admin, Chief, and Officer can now see **My Submitted Feedback** on the Feedback page.

Each submitted item displays:
- feedback number
- subject
- category
- priority color
- submission date/time
- current status: New, Reviewing, Planned, Fixed, or Closed
- original description

Officers can see the status of their own submissions without gaining access to the full Feedback Inbox.

Chiefs continue to have the full Feedback Inbox and can manage feedback status.

### Delete completed feedback
Only Admin accounts can permanently delete feedback.

Deletion rules:
- feedback must first be marked **Closed**
- Chiefs cannot delete feedback
- Officers cannot delete feedback
- a browser confirmation is required
- deletion creates a `feedback_deleted` Audit Log event containing the feedback ID, subject, and original submitter

This leaves an audit record even after the feedback item itself is removed.


## V6.10 — Revoked device cleanup

Admins and Chiefs can now permanently remove a device from the Approved Devices list after it has been revoked.

Rules:
- active/approved devices cannot be deleted directly
- the device must be revoked first
- Admins and Chiefs may delete revoked devices
- Officers cannot access device management
- deletion requires confirmation
- deletion writes `approved_device_deleted` to the Audit Log

Public member profiles do not require an approved-device cookie. Approved devices are only required for protected administrative access.


## V7.0 — Wildland Operations

V7.0 introduces the first Wildland deployment module.

### New permission tier
**Engine Boss** is the fourth account role.

Engine Boss accounts can:
- use Wildland
- start a deployment
- manage a deployment they lead
- add personnel by NFC tag or personnel lookup
- maintain crew accountability
- enter crew timesheets
- complete deployments
- submit and track feedback

Engine Boss accounts cannot:
- edit general member profiles
- view Audit Log or System Status
- manage approved devices
- manage administrator accounts
- manage the Feedback Inbox

Admins and Chiefs may override/manage all deployments.
Officers may start/manage deployments they personally lead.

### Wildland tab
The new Wildland workspace contains:
- active deployments
- apparatus / NFC tag records
- deployment history
- crew
- timesheets

### Apparatus NFC
Each apparatus has a permanent NFC URL:
`/e/<NFC-ID>`

Scanning it opens the apparatus page. Public users see basic apparatus/assignment status. An approved, signed-in operational user receives deployment controls.

### Personnel NFC crew building
On an active deployment, choose **Tap Personnel NFC Tag**. The system enters a temporary add mode. Tapping the person's normal profile tag (`/p/<slug>`) adds that person to the active deployment.

Personnel may also be added by lookup/search.

The system prevents:
- duplicate active assignment to the same deployment
- silent assignment to two active apparatus deployments

### Crew history
Removing someone from a deployment records the time they left instead of erasing their assignment history.

### Timesheets
Deployment leaders can:
- enter date/start/stop times
- automatically calculate hours
- handle overnight shifts
- categorize time as Regular, Travel, Standby, Rest, Training, or Other
- apply one time entry to the entire active crew

### Date of Birth
Member profiles now include Date of Birth.
DOB is:
- editable by authorized member-management roles
- not displayed on the public profile
- shown only inside the PIN-protected Medical & Emergency section

### Upgrade
Copy your existing `crew.db` and `static/uploads` into V7.0 before starting.
The database migration automatically adds the Engine Boss role, Wildland tables, and birthdate field.


## V7.1 — Live deployment timekeeping

- One-touch individual Clock In Now / Clock Out Now
- Clock In Entire Crew / Clock Out Entire Crew
- Server date/time captured automatically
- Duplicate open clock-ins prevented
- Chief/Admin Live Operations Board
- Live board refreshes every 20 seconds
- Browser-side elapsed timers update while viewing
- Chief/Admin timesheet correction with mandatory reason
- Corrections preserve the original start/stop values and correcting username
- Corrections generate `timesheet_corrected` Audit Log events


## V7.2 — Wildland and member records expansion

- Apparatus clock in/out and apparatus time history
- Combined Crew + Apparatus clock controls
- Optional odometer and engine-hour meter readings
- Chief/Admin live apparatus status
- Qualification and certification selectable lists with manual add retained
- Member Red Card upload (PDF/JPG/PNG), issue date, expiration date, and status
- Admin/Chief can reopen completed deployments with a required reason
- Original completion timestamp is preserved
- Access auditing for authenticated member profile, medical, Red Card, deployment, timesheet/live board, and apparatus opens
- Sensitive record contents are not copied into audit event details


## V7.5 additions
- Batch member add (up to 20 at a time).
- Private member document/certification library with issue/expiry dates, source, verification state, external system ID/link, and future-sync metadata.
- Public Red Card status plus one-view PIN unlock of the full uploaded Red Card.
- Apparatus NFC tag sends an authenticated user directly to its active deployment.
- Deployment-only CTR/SF-261, OF-288 and OF-286 document workspace. All application form fields are editable before preview.
- Preview before final save, versioned PDFs stored with the deployment, and audit events for generated/overridden forms.
- Generated PDFs are working department outputs and must be reviewed against the incident/agency's current official form and finance requirements before submission.

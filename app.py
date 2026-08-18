
import os
import sqlite3
import time
import uuid
import secrets
import hashlib
import logging
import json
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    abort, flash, make_response, jsonify, g, send_from_directory, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

VERSION = "7.5.1"
STARTED_AT = int(time.time())

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DB_PATH", APP_DIR / "crew.db"))
UPLOAD_DIR = APP_DIR / "static" / "uploads"
LOG_DIR = APP_DIR / "logs"
BACKUP_DIR = APP_DIR / "backups"
MEMBER_DOC_DIR = APP_DIR / "member_documents"
DEPLOYMENT_FORM_DIR = APP_DIR / "deployment_forms"

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
MAX_LOGO_BYTES = 2 * 1024 * 1024
DEVICE_COOKIE_NAME = "nfc_admin_device"
DEVICE_COOKIE_DAYS = 180
ENROLLMENT_CODE_SECONDS = 15 * 60
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
DB_TIMEOUT_SECONDS = 15
AUDIT_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "90"))
FEEDBACK_STATUSES = ("New", "Reviewing", "Planned", "Fixed", "Closed")
FEEDBACK_CATEGORIES = ("Bug", "Suggestion", "Usability", "NFC / Tag", "Profile", "Security", "Other")
FEEDBACK_PRIORITIES = ("Low", "Normal", "Urgent")
DEFAULT_QUALIFICATION_OPTIONS = (
    "FFT2", "FFT1", "Engine Boss", "Crew Boss", "Firing Boss",
    "Strike Team / Task Force Leader", "Sawyer A", "Sawyer B", "Sawyer C",
    "EMT", "Paramedic", "HazMat Operations", "Driver / Operator",
    "Pump Operator", "Instructor"
)
DEFAULT_CERTIFICATION_OPTIONS = (
    "S-130", "S-190", "L-180", "IS-100", "IS-200", "IS-700", "IS-800",
    "CPR / BLS", "Red Card", "Chainsaw / Sawyer", "Driver / Operator",
    "EMT", "Paramedic"
)

for folder in (UPLOAD_DIR, LOG_DIR, BACKUP_DIR, MEMBER_DOC_DIR, DEPLOYMENT_FORM_DIR):
    folder.mkdir(parents=True, exist_ok=True)

# Historical placeholder values that must never actually be used as live
# secrets/credentials. If an operator has explicitly set the env var to one
# of these (e.g. copy-pasted from documentation/.env.example) we fail
# startup instead of silently booting with a well-known value.
_PLACEHOLDER_SECRET_KEY = "CHANGE-ME-BEFORE-DEPLOYING"
_PLACEHOLDER_ADMIN_PASSWORD = "change-me"

SECRET_KEY_FILE = APP_DIR / ".secret_key"
ADMIN_BOOTSTRAP_CREDENTIALS_FILE = APP_DIR / ".admin_bootstrap_credentials"


def _load_or_create_secret_key():
    """Return a strong secret key for Flask session/CSRF signing.

    Preference order:
      1. An explicit ``SECRET_KEY`` env var (rejected if it is the known
         placeholder literal -- that indicates a copy-pasted default, not an
         intentional secret).
      2. A key persisted from a previous run, so restarts do not invalidate
         every existing session/CSRF token/device cookie.
      3. A freshly generated, cryptographically random key, persisted with
         restrictive file permissions for future runs.
    """
    env_value = os.environ.get("SECRET_KEY")
    if env_value:
        if env_value == _PLACEHOLDER_SECRET_KEY:
            raise SystemExit(
                "SECRET_KEY is set to the documented placeholder value "
                f"({_PLACEHOLDER_SECRET_KEY!r}). Set SECRET_KEY to a real, "
                "random secret before deploying."
            )
        return env_value

    if SECRET_KEY_FILE.exists():
        existing = SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
        if existing:
            return existing

    generated = secrets.token_hex(32)
    try:
        fd = os.open(SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(generated)
        os.chmod(SECRET_KEY_FILE, 0o600)
    except OSError:
        logging.getLogger(__name__).warning(
            "Could not persist generated SECRET_KEY to %s; a new key will "
            "be generated on every restart, invalidating existing sessions.",
            SECRET_KEY_FILE,
        )
    return generated


def _resolve_admin_bootstrap_password():
    """Return the password to use when bootstrapping the first admin user.

    If ``ADMIN_PASSWORD`` is unset or set to the documented placeholder, a
    strong random password is generated instead of falling back to a
    well-known literal. The generated value is surfaced to the operator
    once, at bootstrap time, via a local restrictive-permission file (see
    ``_write_bootstrap_credentials_file``) -- never via stdout or the
    application log, both of which are durable/persistent sinks here.
    """
    env_value = os.environ.get("ADMIN_PASSWORD")
    if env_value and env_value != _PLACEHOLDER_ADMIN_PASSWORD:
        return env_value, False
    return secrets.token_urlsafe(18), True


def _write_bootstrap_credentials_file(username, password):
    """Persist a one-time-generated admin bootstrap credential to disk.

    This intentionally never goes through ``print`` or ``app.logger`` --
    both stdout and the application log are captured by durable, persistent
    sinks in production deployments (process supervisor / container log
    drivers, and the rotating file handler configured on ``app.logger``),
    so writing a plaintext credential to either one leaves it sitting in
    long-lived logs. Instead it is written once to a local file with
    restrictive permissions, following the same pattern already used for
    the generated ``SECRET_KEY`` (see ``_load_or_create_secret_key``).
    The operator is expected to read this file once and delete it.
    """
    try:
        fd = os.open(
            ADMIN_BOOTSTRAP_CREDENTIALS_FILE,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(
                "One-time generated admin bootstrap credentials.\n"
                "Read this file, log in, change the password, then delete this file.\n\n"
                f"Username: {username}\n"
                f"Password: {password}\n"
            )
        os.chmod(ADMIN_BOOTSTRAP_CREDENTIALS_FILE, 0o600)
    except OSError:
        logging.getLogger(__name__).error(
            "Could not write admin bootstrap credentials file to %s. "
            "Set ADMIN_PASSWORD explicitly and re-run bootstrap instead.",
            ADMIN_BOOTSTRAP_CREDENTIALS_FILE,
        )
        raise SystemExit(
            f"Failed to persist generated admin bootstrap credentials to "
            f"{ADMIN_BOOTSTRAP_CREDENTIALS_FILE}. Refusing to print the "
            "password in clear text to stdout/logs; set ADMIN_PASSWORD to a "
            "real value via environment variable and restart."
        )


app = Flask(__name__)
app.secret_key = _load_or_create_secret_key()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"
app.config["PERMANENT_SESSION_LIFETIME"] = 8 * 60 * 60
app.config["WTF_CSRF_TIME_LIMIT"] = 60 * 60
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"

if os.environ.get("TRUST_PROXY", "0") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=[]
)

# Rotating application log: 2 MB x 5 files.
file_handler = RotatingFileHandler(
    LOG_DIR / "app.log",
    maxBytes=2 * 1024 * 1024,
    backupCount=5,
    encoding="utf-8"
)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter(
    "%(asctime)s %(levelname)s %(message)s"
))
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)


def db():
    conn = sqlite3.connect(
        DB_PATH,
        timeout=DB_TIMEOUT_SECONDS,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(f"PRAGMA busy_timeout={DB_TIMEOUT_SECONDS * 1000}")
    return conn


def configure_database(conn):
    # WAL improves read/write concurrency for this single-server SQLite workload.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(f"PRAGMA busy_timeout={DB_TIMEOUT_SECONDS * 1000}")


def ensure_column(conn, table, column, definition):
    cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def token_hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def human_time(ts):
    if not ts:
        return "Never"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def password_policy_error(password):
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if not any(c.isupper() for c in password):
        return "Password must include an uppercase letter."
    if not any(c.islower() for c in password):
        return "Password must include a lowercase letter."
    if not any(c.isdigit() for c in password):
        return "Password must include a number."
    return None


def human_uptime(seconds):
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


app.jinja_env.globals["human_time"] = human_time
app.jinja_env.globals["human_uptime"] = human_uptime
app.jinja_env.globals["APP_VERSION"] = VERSION


def client_ip():
    # Only trust the X-Forwarded-For header when TRUST_PROXY=1, which is the
    # same flag that gates ProxyFix above. Without a trusted proxy in front
    # of the app, this header is fully attacker-controlled and can be used
    # to reset per-IP PIN lockout counters / rate limits on every request.
    if os.environ.get("TRUST_PROXY", "0") == "1":
        return request.headers.get(
            "X-Forwarded-For",
            request.remote_addr or "unknown"
        ).split(",")[0].strip()
    return request.remote_addr or "unknown"


def audit(event_type, detail="", actor=None):
    conn = None
    try:
        username = actor if actor is not None else session.get("admin_username")
        prefix = f"user={username} " if username else ""
        conn = db()
        conn.execute(
            "INSERT INTO audit_log(event_type,detail,ip,created_at) VALUES(?,?,?,?)",
            (event_type, (prefix + (detail or ""))[:1000], client_ip(), int(time.time()))
        )
        conn.commit()
    except Exception:
        app.logger.exception("AUDIT LOG WRITE FAILED")
    finally:
        if conn is not None:
            conn.close()


def cleanup_audit_log(write_event=True):
    cutoff = int(time.time()) - AUDIT_RETENTION_DAYS * 86400
    conn = db()
    cur = conn.execute(
        "DELETE FROM audit_log WHERE created_at < ?",
        (cutoff,)
    )
    removed = cur.rowcount if cur.rowcount is not None else 0
    conn.commit()
    conn.close()

    if write_event and removed > 0:
        audit_local(
            "audit_log_cleanup",
            f"removed={removed} retention_days={AUDIT_RETENTION_DAYS}"
        )
    return removed


def audit_local(event_type, detail=""):
    conn = db()
    conn.execute(
        "INSERT INTO audit_log(event_type,detail,ip,created_at) VALUES(?,?,?,?)",
        (event_type, (detail or "")[:1000], "local-server", int(time.time()))
    )
    conn.commit()
    conn.close()



def ensure_four_role_admin_schema(conn):
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='admin_users'"
    ).fetchone()
    table_sql = (row["sql"] if row and row["sql"] else "").lower()
    if "'engine_boss'" in table_sql:
        return

    conn.execute("ALTER TABLE admin_users RENAME TO admin_users_pre_v7")
    conn.execute("""
        CREATE TABLE admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','chief','officer','engine_boss')),
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            last_login_at INTEGER,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            failed_logins INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER,
            password_changed_at INTEGER
        )
    """)
    conn.execute("""
        INSERT INTO admin_users(
            id,username,display_name,password_hash,role,enabled,created_at,last_login_at,
            must_change_password,failed_logins,locked_until,password_changed_at
        )
        SELECT
            id,username,display_name,password_hash,role,enabled,created_at,last_login_at,
            must_change_password,failed_logins,locked_until,password_changed_at
        FROM admin_users_pre_v7
    """)
    conn.execute("DROP TABLE admin_users_pre_v7")


def init_db():
    conn = db()
    configure_database(conn)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        role TEXT,
        department TEXT,
        location TEXT,
        position TEXT,
        crew_id TEXT,
        certifications TEXT,
        emergency_contact TEXT,
        relationship TEXT,
        emergency_phone TEXT,
        blood_type TEXT,
        allergies TEXT,
        medications TEXT,
        medical_notes TEXT,
        pin_hash TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS access_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT NOT NULL,
        ip TEXT,
        success INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS approved_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER,
        revoked INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS enrollment_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code_hash TEXT UNIQUE NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER,
        created_by_device_id INTEGER
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        detail TEXT,
        ip TEXT,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        submitted_by TEXT NOT NULL,
        submitted_by_display TEXT,
        role TEXT,
        category TEXT NOT NULL,
        priority TEXT NOT NULL DEFAULT 'Normal',
        subject TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'New',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        updated_by TEXT
    );

    CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','chief','officer','engine_boss')),
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        last_login_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS apparatus (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        unit_code TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        apparatus_type TEXT,
        department TEXT,
        nfc_slug TEXT UNIQUE NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS deployments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        apparatus_id INTEGER NOT NULL,
        incident_name TEXT NOT NULL,
        incident_number TEXT,
        location TEXT,
        leader_user_id INTEGER,
        leader_name TEXT NOT NULL,
        started_at INTEGER NOT NULL,
        ended_at INTEGER,
        status TEXT NOT NULL DEFAULT 'Active',
        created_by TEXT,
        FOREIGN KEY(apparatus_id) REFERENCES apparatus(id)
    );

    CREATE TABLE IF NOT EXISTS deployment_crew (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        deployment_id INTEGER NOT NULL,
        profile_id INTEGER NOT NULL,
        deployment_role TEXT,
        joined_at INTEGER NOT NULL,
        left_at INTEGER,
        added_method TEXT NOT NULL DEFAULT 'Search',
        added_by TEXT,
        FOREIGN KEY(deployment_id) REFERENCES deployments(id),
        FOREIGN KEY(profile_id) REFERENCES profiles(id)
    );

    CREATE TABLE IF NOT EXISTS timesheets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        deployment_id INTEGER NOT NULL,
        profile_id INTEGER NOT NULL,
        work_date TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        hours REAL NOT NULL DEFAULT 0,
        category TEXT NOT NULL DEFAULT 'Regular',
        notes TEXT,
        created_by TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY(deployment_id) REFERENCES deployments(id),
        FOREIGN KEY(profile_id) REFERENCES profiles(id)
    );

    CREATE TABLE IF NOT EXISTS apparatus_timesheets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        deployment_id INTEGER NOT NULL,
        apparatus_id INTEGER NOT NULL,
        work_date TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL DEFAULT '',
        hours REAL NOT NULL DEFAULT 0,
        clocked_in_at INTEGER,
        clocked_out_at INTEGER,
        start_odometer REAL,
        end_odometer REAL,
        start_engine_hours REAL,
        end_engine_hours REAL,
        notes TEXT,
        created_by TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS qualification_options (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS certification_options (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS member_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        profile_id INTEGER NOT NULL,
        document_type TEXT NOT NULL,
        title TEXT NOT NULL,
        issue_date TEXT,
        expiry_date TEXT,
        notes TEXT,
        filename TEXT,
        source TEXT,
        external_system TEXT,
        external_record_id TEXT,
        verification_status TEXT NOT NULL DEFAULT 'Department Record',
        last_sync_at INTEGER,
        external_link TEXT,
        created_by TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS deployment_forms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        deployment_id INTEGER NOT NULL,
        form_type TEXT NOT NULL,
        subject_profile_id INTEGER,
        version INTEGER NOT NULL DEFAULT 1,
        field_data TEXT NOT NULL,
        pdf_filename TEXT,
        status TEXT NOT NULL DEFAULT 'Draft',
        created_by TEXT,
        created_at INTEGER NOT NULL,
        updated_by TEXT,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY(deployment_id) REFERENCES deployments(id) ON DELETE CASCADE,
        FOREIGN KEY(subject_profile_id) REFERENCES profiles(id)
    );
    """)

    for col, definition in [
        ("department_details", "TEXT"),
        ("qualifications", "TEXT"),
        ("training", "TEXT"),
        ("public_notes", "TEXT"),
        ("logo_filename", "TEXT"),
        ("birthdate", "TEXT")
    ]:
        ensure_column(conn, "profiles", col, definition)

    for col, definition in [
        ("must_change_password", "INTEGER NOT NULL DEFAULT 0"),
        ("failed_logins", "INTEGER NOT NULL DEFAULT 0"),
        ("locked_until", "INTEGER"),
        ("password_changed_at", "INTEGER")
    ]:
        ensure_column(conn, "admin_users", col, definition)

    ensure_four_role_admin_schema(conn)
    ensure_column(conn, "profiles", "red_card_filename", "TEXT")
    ensure_column(conn, "profiles", "red_card_issue_date", "TEXT")
    ensure_column(conn, "profiles", "red_card_expiry_date", "TEXT")
    ensure_column(conn, "apparatus", "current_odometer", "REAL")
    ensure_column(conn, "apparatus", "current_engine_hours", "REAL")
    ensure_column(conn, "deployments", "reopened_at", "INTEGER")
    ensure_column(conn, "deployments", "reopened_by", "TEXT")
    ensure_column(conn, "deployments", "reopen_reason", "TEXT")
    ensure_column(conn, "deployments", "original_ended_at", "INTEGER")
    ensure_column(conn, "timesheets", "clocked_in_at", "INTEGER")
    ensure_column(conn, "timesheets", "clocked_out_at", "INTEGER")
    ensure_column(conn, "timesheets", "corrected_from_start", "TEXT")
    ensure_column(conn, "timesheets", "corrected_from_end", "TEXT")
    ensure_column(conn, "timesheets", "correction_reason", "TEXT")
    ensure_column(conn, "timesheets", "corrected_by", "TEXT")
    conn.execute("UPDATE feedback SET priority='Urgent' WHERE priority='High'")
    for name in DEFAULT_QUALIFICATION_OPTIONS:
        conn.execute("INSERT OR IGNORE INTO qualification_options(name) VALUES(?)", (name,))
    for name in DEFAULT_CERTIFICATION_OPTIONS:
        conn.execute("INSERT OR IGNORE INTO certification_options(name) VALUES(?)", (name,))

    conn.commit()

    admin_count = conn.execute("SELECT COUNT(*) AS c FROM admin_users").fetchone()["c"]
    if admin_count == 0:
        bootstrap_username = os.environ.get("ADMIN_USERNAME", "admin").strip() or "admin"
        bootstrap_password, generated = _resolve_admin_bootstrap_password()
        conn.execute("""
            INSERT INTO admin_users(
                username,display_name,password_hash,role,enabled,created_at,must_change_password
            ) VALUES(?,?,?,?,1,?,1)
        """, (
            bootstrap_username,
            "System Administrator",
            generate_password_hash(bootstrap_password),
            "admin",
            int(time.time())
        ))
        conn.commit()
        print("")
        print("=" * 64)
        print("V6.2 ADMIN ACCOUNT CREATED")
        print("Username:", bootstrap_username)
        if generated:
            # Never print/log the generated credential in clear text -- both
            # stdout and app.logger are captured by durable, persistent sinks
            # in this deployment (process supervisor / container log drivers,
            # and the RotatingFileHandler configured on app.logger above).
            # Instead, write it once to a local, restrictively-permissioned
            # file the operator must read and then delete, mirroring how
            # SECRET_KEY_FILE is handled.
            _write_bootstrap_credentials_file(bootstrap_username, bootstrap_password)
            print(f"Password: see {ADMIN_BOOTSTRAP_CREDENTIALS_FILE}")
            print("(generated -- ADMIN_PASSWORD was not set to a real value)")
            print("Read that file now, then delete it -- it will not be shown again.")
        else:
            print("Password: your existing ADMIN_PASSWORD")
        print("Role: Admin")
        print("This password must be changed at first login.")
        print("=" * 64)
        print("")

    conn.close()
    ensure_bootstrap_code()


def make_enrollment_code():
    raw = secrets.token_hex(6).upper()
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}"


def ensure_bootstrap_code():
    conn = db()
    active = conn.execute(
        "SELECT COUNT(*) AS c FROM approved_devices WHERE revoked=0"
    ).fetchone()["c"]

    if active == 0:
        now = int(time.time())
        pending = conn.execute("""
            SELECT id FROM enrollment_codes
            WHERE used_at IS NULL AND expires_at > ?
            LIMIT 1
        """, (now,)).fetchone()

        if not pending:
            code = make_enrollment_code()
            conn.execute("""
                INSERT INTO enrollment_codes(
                    code_hash,created_at,expires_at,created_by_device_id
                ) VALUES(?,?,?,NULL)
            """, (
                token_hash(code),
                now,
                now + ENROLLMENT_CODE_SECONDS
            ))
            conn.commit()
            print("")
            print("=" * 64)
            print("FIRST ADMIN DEVICE ENROLLMENT")
            print("One-time enrollment code:", code)
            print("Expires in 15 minutes.")
            print("Open: http://127.0.0.1:8080/admin/device-enroll")
            print("=" * 64)
            print("")
    conn.close()


def current_device():
    token = request.cookies.get(DEVICE_COOKIE_NAME)
    if not token:
        return None

    conn = db()
    row = conn.execute("""
        SELECT * FROM approved_devices
        WHERE token_hash=? AND revoked=0
    """, (token_hash(token),)).fetchone()

    if row:
        now = int(time.time())
        conn.execute(
            "UPDATE approved_devices SET last_used_at=? WHERE id=?",
            (now, row["id"])
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM approved_devices WHERE id=?",
            (row["id"],)
        ).fetchone()
    conn.close()
    return row


def device_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_device():
            return redirect(url_for("device_enroll"))
        return fn(*args, **kwargs)
    return wrapped


def current_admin():
    admin_id = session.get("admin_user_id")
    if not admin_id:
        return None
    conn = db()
    row = conn.execute(
        "SELECT * FROM admin_users WHERE id=? AND enabled=1",
        (admin_id,)
    ).fetchone()
    conn.close()
    return row


def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_device():
            return redirect(url_for("device_enroll"))
        user = current_admin()
        if not user:
            session.clear()
            return redirect(url_for("admin_login"))
        if user["must_change_password"] and request.endpoint != "change_own_password":
            return redirect(url_for("change_own_password"))
        return fn(*args, **kwargs)
    return wrapped


def tier1_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_device():
            return redirect(url_for("device_enroll"))
        user = current_admin()
        if not user:
            session.clear()
            return redirect(url_for("admin_login"))
        if user["must_change_password"] and request.endpoint != "change_own_password":
            return redirect(url_for("change_own_password"))
        if user["role"] != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapped


def leadership_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_device():
            return redirect(url_for("device_enroll"))
        user = current_admin()
        if not user:
            session.clear()
            return redirect(url_for("admin_login"))
        if user["must_change_password"] and request.endpoint != "change_own_password":
            return redirect(url_for("change_own_password"))
        if user["role"] not in ("admin", "chief"):
            abort(403)
        return fn(*args, **kwargs)
    return wrapped


def staff_required(fn):
    """Admin, Chief, and Officer: normal member/profile management."""
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_device():
            return redirect(url_for("device_enroll"))
        user = current_admin()
        if not user:
            session.clear()
            return redirect(url_for("admin_login"))
        if user["must_change_password"] and request.endpoint != "change_own_password":
            return redirect(url_for("change_own_password"))
        if user["role"] not in ("admin", "chief", "officer"):
            abort(403)
        return fn(*args, **kwargs)
    return wrapped


def oversight_required(fn):
    """Admin, Chief, and Officer may view Audit Log and System Status."""
    return staff_required(fn)


def wildland_required(fn):
    """All four signed-in roles may use the Wildland workspace."""
    return admin_required(fn)


def can_manage_deployment(user, deployment):
    """Return whether the signed-in user may manage this deployment.

    Admin and Chief retain management access for active or historical
    deployments. Officer and Engine Boss may manage any ACTIVE Wildland
    deployment regardless of who originally created or leads it. Completed
    deployments must be reopened before operational edits are allowed.
    """
    if not user or not deployment:
        return False
    if user["role"] in ("admin", "chief"):
        return True
    if user["role"] in ("officer", "engine_boss"):
        return deployment["status"] == "Active"
    return False


def profile_or_404(slug):
    conn = db()
    p = conn.execute(
        "SELECT * FROM profiles WHERE slug=? AND enabled=1",
        (slug,)
    ).fetchone()
    conn.close()
    if not p:
        abort(404)
    return p


def is_locked_out(slug, ip):
    cutoff = int(time.time()) - LOCKOUT_SECONDS
    conn = db()
    attempts = conn.execute("""
        SELECT success FROM access_attempts
        WHERE slug=? AND ip=? AND created_at>=?
        ORDER BY created_at DESC LIMIT ?
    """, (slug, ip, cutoff, MAX_ATTEMPTS)).fetchall()
    conn.close()
    return (
        len(attempts) >= MAX_ATTEMPTS
        and all(a["success"] == 0 for a in attempts)
    )


def log_attempt(slug, ip, success):
    conn = db()
    conn.execute("""
        INSERT INTO access_attempts(slug,ip,success,created_at)
        VALUES(?,?,?,?)
    """, (slug, ip, 1 if success else 0, int(time.time())))
    conn.commit()
    conn.close()


def allowed_logo(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def save_logo(file_storage):
    if not file_storage or not file_storage.filename:
        return None

    original = secure_filename(file_storage.filename)
    if not allowed_logo(original):
        raise ValueError("Logo must be PNG, JPG, JPEG, or WEBP.")

    ext = original.rsplit(".", 1)[1].lower()
    unique = f"{uuid.uuid4().hex}.{ext}"
    full = UPLOAD_DIR / unique
    file_storage.save(full)

    if full.stat().st_size > MAX_LOGO_BYTES:
        full.unlink(missing_ok=True)
        raise ValueError("Logo must be 2 MB or smaller.")

    return unique


def fv(form, key):
    return form.get(key, "").strip()


def system_health():
    result = {
        "ok": True,
        "database": "ok",
        "database_check": "ok",
        "backup": "unknown",
        "version": VERSION
    }
    try:
        conn = db()
        conn.execute("SELECT 1").fetchone()
        quick = conn.execute("PRAGMA quick_check").fetchone()[0]
        conn.close()
        if quick != "ok":
            result["ok"] = False
            result["database_check"] = quick
    except Exception as exc:
        result["ok"] = False
        result["database"] = f"error: {type(exc).__name__}"

    backups = sorted(
        BACKUP_DIR.glob("crew_*.db"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    if backups:
        age_hours = (time.time() - backups[0].stat().st_mtime) / 3600
        result["backup"] = "ok" if age_hours <= 48 else "stale"
        result["last_backup"] = int(backups[0].stat().st_mtime)
    else:
        result["backup"] = "missing"
        result["last_backup"] = None

    return result


@app.before_request
def request_id():
    g.request_id = uuid.uuid4().hex[:12]


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()"
    )
    response.headers["X-Request-ID"] = getattr(g, "request_id", "unknown")
    if request.is_secure:
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains"
        )
    return response


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    return render_template(
        "csrf_error.html",
        reason=error.description
    ), 400


@app.errorhandler(403)
def forbidden(error):
    return render_template(
        "error.html",
        title="Access denied",
        message="Your account does not have permission to open this administration page.",
        request_id=getattr(g, "request_id", "")
    ), 403


@app.errorhandler(404)
def not_found(error):
    return render_template(
        "error.html",
        title="Page not found",
        message="The page or profile could not be found.",
        request_id=getattr(g, "request_id", "")
    ), 404


@app.errorhandler(429)
def rate_limited(error):
    return render_template(
        "error.html",
        title="Too many attempts",
        message="Too many requests were made in a short period. Wait a few minutes and try again.",
        request_id=getattr(g, "request_id", "")
    ), 429


@app.errorhandler(500)
def internal_error(error):
    app.logger.exception(
        "Unhandled server error request_id=%s path=%s",
        getattr(g, "request_id", "unknown"),
        request.path
    )
    return render_template(
        "error.html",
        title="Server error",
        message="The server had a problem processing this request. No changes should be assumed saved.",
        request_id=getattr(g, "request_id", "")
    ), 500


@app.route("/healthz")
def healthz():
    health = system_health()
    return jsonify(health), 200 if health["ok"] else 503


@app.route("/")
def home():
    return redirect(url_for("admin"))


# -------------------------
# Public member profiles
# -------------------------

@app.route("/p/<slug>")
def profile(slug):
    # Wildland NFC add mode: an authenticated Engine Boss/Officer/Chief/Admin
    # can tap a member's normal NFC tag and have that member added to the
    # deployment currently waiting for a tag.
    pending_deployment = session.get("wildland_add_deployment_id")
    if pending_deployment and current_device() and current_admin():
        return redirect(url_for(
            "wildland_add_by_tag",
            deployment_id=pending_deployment,
            slug=slug
        ))

    p = profile_or_404(slug)

    # Medical access is intentionally one-view only.
    # A successful PIN sets this flag, and the very next profile GET consumes it.
    # Refreshing/reopening the page therefore shows the medical section locked again.
    unlocked = bool(session.pop(f"medical_once:{slug}", False))
    red_card_unlocked = bool(session.pop(f"redcard_once:{slug}", False))
    if red_card_unlocked:
        # Keep a per-view token for the inline image/PDF and the Open Full Red Card
        # button. A normal refresh/reopen clears it, preserving one-view behavior.
        red_card_view_token = session.get(f"redcard_view:{slug}")
    else:
        session.pop(f"redcard_view:{slug}", None)
        red_card_view_token = None

    certs = [
        x.strip()
        for x in (p["certifications"] or "").replace("\n", ",").split(",")
        if x.strip()
    ]
    quals = [
        x.strip() for x in (p["qualifications"] or "").splitlines()
        if x.strip()
    ]
    training = [
        x.strip() for x in (p["training"] or "").splitlines()
        if x.strip()
    ]

    return render_template(
        "profile.html",
        p=p,
        certs=certs,
        quals=quals,
        training=training,
        unlocked=unlocked,
        red_card_unlocked=red_card_unlocked,
        red_card_view_token=red_card_view_token,
        red_card_status_value=red_card_status(p["red_card_expiry_date"]) if p["red_card_filename"] else "Not on file",
        red_card_is_image=bool(p["red_card_filename"] and Path(p["red_card_filename"]).suffix.lower() in (".png", ".jpg", ".jpeg")),
        red_card_is_pdf=bool(p["red_card_filename"] and Path(p["red_card_filename"]).suffix.lower() == ".pdf")
    )

@app.post("/p/<slug>/unlock")
@limiter.limit("12 per 15 minutes")
def unlock_medical(slug):
    p = profile_or_404(slug)
    ip = client_ip()

    if is_locked_out(slug, ip):
        audit("medical_unlock_locked_out", f"profile={slug}")
        flash(
            "Too many failed attempts. Try again in 5 minutes.",
            "error"
        )
        return redirect(url_for("profile", slug=slug) + "#medical")

    pin = request.form.get("pin", "")
    ok = check_password_hash(p["pin_hash"], pin)
    log_attempt(slug, ip, ok)

    if ok:
        audit("medical_unlock_success", f"profile={slug}")
        audit("member_medical_opened", f"profile={slug}")
        session[f"medical_once:{slug}"] = True
        return redirect(url_for("profile", slug=slug) + "#medical")

    audit("medical_unlock_failure", f"profile={slug}")
    flash("Incorrect PIN.", "error")
    return redirect(url_for("profile", slug=slug) + "#medical")


@app.post("/p/<slug>/lock")
def lock_medical(slug):
    # Clear both the V6.1 one-view key and any older persistent V6 key.
    session.pop(f"medical_once:{slug}", None)
    session.pop(f"medical:{slug}", None)
    audit("medical_section_locked", f"profile={slug}")
    return redirect(url_for("profile", slug=slug) + "#medical")

# -------------------------
# Approved device enrollment
# -------------------------

@app.route("/admin/device-enroll", methods=["GET", "POST"])
@limiter.limit("10 per 15 minutes", methods=["POST"])
def device_enroll():
    if current_device():
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        name = request.form.get("device_name", "").strip()
        code = request.form.get("code", "").strip().upper()

        if not name:
            flash("Enter a name for this device.", "error")
            return render_template("device_enroll.html")

        now = int(time.time())
        conn = db()
        row = conn.execute("""
            SELECT * FROM enrollment_codes
            WHERE code_hash=? AND used_at IS NULL AND expires_at>=?
            ORDER BY id DESC LIMIT 1
        """, (token_hash(code), now)).fetchone()

        if not row:
            conn.close()
            audit("device_enrollment_failure", f"device={name}")
            flash(
                "That enrollment code is invalid, already used, or expired.",
                "error"
            )
            return render_template("device_enroll.html")

        device_token = secrets.token_urlsafe(48)
        conn.execute("""
            INSERT INTO approved_devices(
                name,token_hash,created_at,last_used_at,revoked
            ) VALUES(?,?,?,?,0)
        """, (
            name,
            token_hash(device_token),
            now,
            now
        ))
        conn.execute(
            "UPDATE enrollment_codes SET used_at=? WHERE id=?",
            (now, row["id"])
        )
        conn.commit()
        conn.close()

        audit("device_enrolled", f"device={name}")
        session.clear()

        response = make_response(redirect(url_for("admin_login")))
        response.set_cookie(
            DEVICE_COOKIE_NAME,
            device_token,
            max_age=DEVICE_COOKIE_DAYS * 86400,
            httponly=True,
            samesite="Strict",
            secure=COOKIE_SECURE
        )
        return response

    return render_template("device_enroll.html")


# -------------------------
# Admin auth
# -------------------------

@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("12 per 15 minutes", methods=["POST"])
@device_required
def admin_login():
    device = current_device()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        now = int(time.time())

        conn = db()
        user = conn.execute(
            "SELECT * FROM admin_users WHERE username=?",
            (username,)
        ).fetchone()

        if user and user["locked_until"] and user["locked_until"] > now:
            conn.close()
            audit(
                "admin_login_locked_out",
                f'attempted_username={username}',
                actor=username
            )
            flash("This account is temporarily locked. Try again later.", "error")
            return render_template("login.html", device=device)

        valid = (
            user
            and user["enabled"]
            and check_password_hash(user["password_hash"], password)
        )

        if valid:
            conn.execute("""
                UPDATE admin_users
                SET last_login_at=?, failed_logins=0, locked_until=NULL
                WHERE id=?
            """, (now, user["id"]))
            conn.commit()
            conn.close()

            session.clear()
            session["admin_user_id"] = user["id"]
            session["admin_username"] = user["username"]
            session["admin_role"] = user["role"]
            session.permanent = True

            audit(
                "admin_login_success",
                f'device={device["name"] if device else "unknown"} role={user["role"]}',
                actor=user["username"]
            )

            if user["must_change_password"]:
                return redirect(url_for("change_own_password"))

            if user["role"] == "engine_boss":
                return redirect(url_for("wildland"))
            return redirect(url_for("admin"))

        if user:
            failures = (user["failed_logins"] or 0) + 1
            locked_until = now + 15 * 60 if failures >= 5 else None
            conn.execute("""
                UPDATE admin_users
                SET failed_logins=?, locked_until=?
                WHERE id=?
            """, (failures, locked_until, user["id"]))
            conn.commit()

        conn.close()
        audit(
            "admin_login_failure",
            f'device={device["name"] if device else "unknown"} attempted_username={username}',
            actor=username or "unknown"
        )
        flash("Incorrect username or password.", "error")

    return render_template("login.html", device=device)


@app.post("/admin/logout")
@device_required
def admin_logout():
    device = current_device()
    username = session.get("admin_username", "unknown")
    audit("admin_logout", f'device={device["name"] if device else "unknown"}', actor=username)
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/change-password", methods=["GET", "POST"])
@admin_required
def change_own_password():
    user = current_admin()

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not check_password_hash(user["password_hash"], current_password):
            flash("Current password is incorrect.", "error")
            return render_template(
                "change_password.html",
                admin_user=user,
                active_page=""
            )

        if new_password != confirm_password:
            flash("New passwords do not match.", "error")
            return render_template(
                "change_password.html",
                admin_user=user,
                active_page=""
            )

        error = password_policy_error(new_password)
        if error:
            flash(error, "error")
            return render_template(
                "change_password.html",
                admin_user=user,
                active_page=""
            )

        conn = db()
        conn.execute("""
            UPDATE admin_users
            SET password_hash=?, must_change_password=0, password_changed_at=?,
                failed_logins=0, locked_until=NULL
            WHERE id=?
        """, (
            generate_password_hash(new_password),
            int(time.time()),
            user["id"]
        ))
        conn.commit()
        conn.close()

        audit("admin_password_changed", f"account={user['username']}")
        flash("Password changed successfully.", "success")
        if user["role"] == "engine_boss":
            return redirect(url_for("wildland"))
        return redirect(url_for("admin"))

    return render_template(
        "change_password.html",
        admin_user=user,
        active_page=""
    )


# -------------------------
# Admin pages
# -------------------------

@app.route("/admin")
@admin_required
def admin():
    user = current_admin()
    if user["role"] == "engine_boss":
        return redirect(url_for("wildland"))
    if user["role"] not in ("admin", "chief", "officer"):
        abort(403)
    conn = db()
    profiles = conn.execute("""
        SELECT p.*,
               (SELECT COUNT(*) FROM member_documents md WHERE md.profile_id=p.id) AS document_count,
               (SELECT MIN(expiry_date) FROM member_documents md
                WHERE md.profile_id=p.id AND COALESCE(expiry_date,'')<>'') AS next_document_expiry
        FROM profiles p
        ORDER BY p.name
    """).fetchall()
    conn.close()
    return render_template(
        "admin.html",
        profiles=profiles,
        admin_user=current_admin(),
        active_page="members"
    )


@app.route("/admin/devices")
@leadership_required
def approved_devices():
    conn = db()
    devices = conn.execute("""
        SELECT * FROM approved_devices
        ORDER BY revoked ASC,last_used_at DESC
    """).fetchall()
    conn.close()
    return render_template(
        "devices.html",
        devices=devices,
        current=current_device(),
        generated_code=None,
        admin_user=current_admin(),
        active_page="devices"
    )


@app.post("/admin/devices/generate-code")
@leadership_required
def generate_device_code():
    current = current_device()
    now = int(time.time())
    code = make_enrollment_code()

    conn = db()
    conn.execute(
        "DELETE FROM enrollment_codes WHERE used_at IS NULL AND expires_at<?",
        (now,)
    )
    conn.execute("""
        INSERT INTO enrollment_codes(
            code_hash,created_at,expires_at,created_by_device_id
        ) VALUES(?,?,?,?)
    """, (
        token_hash(code),
        now,
        now + ENROLLMENT_CODE_SECONDS,
        current["id"]
    ))
    conn.commit()
    devices = conn.execute("""
        SELECT * FROM approved_devices
        ORDER BY revoked ASC,last_used_at DESC
    """).fetchall()
    conn.close()

    audit(
        "enrollment_code_generated",
        f'created_by={current["name"]}'
    )

    return render_template(
        "devices.html",
        devices=devices,
        current=current,
        generated_code=code,
        admin_user=current_admin(),
        active_page="devices"
    )


@app.post("/admin/devices/revoke/<int:device_id>")
@leadership_required
def revoke_device(device_id):
    current = current_device()

    if current["id"] == device_id:
        flash(
            "You cannot revoke the device you are currently using. Approve another device first.",
            "error"
        )
        return redirect(url_for("approved_devices"))

    conn = db()
    target = conn.execute(
        "SELECT name FROM approved_devices WHERE id=?",
        (device_id,)
    ).fetchone()
    conn.execute(
        "UPDATE approved_devices SET revoked=1 WHERE id=?",
        (device_id,)
    )
    conn.commit()
    conn.close()

    audit(
        "device_revoked",
        f'device={target["name"] if target else device_id}'
    )
    flash("Device revoked.", "success")
    return redirect(url_for("approved_devices"))



@app.post("/admin/devices/delete/<int:device_id>")
@leadership_required
def delete_revoked_device(device_id):
    conn = db()
    device = conn.execute(
        "SELECT * FROM approved_devices WHERE id=?",
        (device_id,)
    ).fetchone()

    if not device:
        conn.close()
        abort(404)

    if not device["revoked_at"]:
        conn.close()
        flash("A device must be revoked before it can be deleted.", "error")
        return redirect(url_for("approved_devices"))

    username = session.get("admin_username", "unknown")
    device_name = device["name"] if "name" in device.keys() else f"device-{device_id}"

    conn.execute("DELETE FROM approved_devices WHERE id=?", (device_id,))
    conn.commit()
    conn.close()

    audit(
        "approved_device_deleted",
        f'device_id={device_id} name="{device_name}"',
        actor=username
    )
    flash("Revoked device deleted.", "success")
    return redirect(url_for("approved_devices"))


@app.post("/admin/audit/test")
@leadership_required
def audit_test():
    audit("audit_test", "Manual audit logging test")
    flash("Audit test event written.", "success")
    return redirect(url_for("audit_logs"))


@app.route("/admin/feedback", methods=["GET", "POST"])
@admin_required
def feedback_submit():
    user = current_admin()
    if request.method == "POST":
        category = request.form.get("category", "").strip()
        priority = request.form.get("priority", "Normal").strip()
        subject = request.form.get("subject", "").strip()
        description = request.form.get("description", "").strip()

        if category not in FEEDBACK_CATEGORIES:
            flash("Please choose a valid feedback category.", "error")
        elif priority not in FEEDBACK_PRIORITIES:
            flash("Please choose a valid priority.", "error")
        elif not subject:
            flash("Subject is required.", "error")
        elif not description:
            flash("Description is required.", "error")
        elif len(subject) > 160:
            flash("Subject must be 160 characters or fewer.", "error")
        elif len(description) > 5000:
            flash("Description must be 5000 characters or fewer.", "error")
        else:
            now = int(time.time())
            conn = db()
            cur = conn.execute(
                """INSERT INTO feedback(
                    submitted_by, submitted_by_display, role, category, priority,
                    subject, description, status, created_at, updated_at, updated_by
                ) VALUES(?,?,?,?,?,?,?,'New',?,?,?)""",
                (user["username"], user["display_name"], user["role"], category,
                 priority, subject, description, now, now, user["username"])
            )
            feedback_id = cur.lastrowid
            conn.commit()
            conn.close()
            audit(
                "feedback_submitted",
                f"feedback_id={feedback_id} category={category} priority={priority}",
                actor=user["username"]
            )
            flash("Feedback submitted. Thank you.", "success")
            return redirect(url_for("feedback_submit"))

    conn = db()
    my_feedback = conn.execute(
        """SELECT * FROM feedback
           WHERE submitted_by=?
           ORDER BY created_at DESC""",
        (user["username"],)
    ).fetchall()
    conn.close()

    return render_template(
        "feedback_submit.html",
        categories=FEEDBACK_CATEGORIES,
        priorities=FEEDBACK_PRIORITIES,
        my_feedback=my_feedback,
        admin_user=user,
        active_page="feedback"
    )


@app.get("/admin/feedback/inbox")
@leadership_required
def feedback_inbox():
    conn = db()
    items = conn.execute(
        """SELECT * FROM feedback
           ORDER BY CASE status
             WHEN 'New' THEN 0
             WHEN 'Reviewing' THEN 1
             WHEN 'Planned' THEN 2
             WHEN 'Fixed' THEN 3
             WHEN 'Closed' THEN 4
             ELSE 5 END, created_at DESC"""
    ).fetchall()
    conn.close()
    return render_template(
        "feedback_inbox.html",
        items=items,
        statuses=FEEDBACK_STATUSES,
        admin_user=current_admin(),
        active_page="feedback_inbox"
    )


@app.post("/admin/feedback/<int:feedback_id>/status")
@leadership_required
def feedback_status(feedback_id):
    new_status = request.form.get("status", "").strip()
    if new_status not in FEEDBACK_STATUSES:
        abort(400)

    conn = db()
    item = conn.execute("SELECT * FROM feedback WHERE id=?", (feedback_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)

    username = session.get("admin_username", "unknown")
    old_status = item["status"]
    now = int(time.time())
    conn.execute(
        "UPDATE feedback SET status=?, updated_at=?, updated_by=? WHERE id=?",
        (new_status, now, username, feedback_id)
    )
    conn.commit()
    conn.close()
    audit(
        "feedback_status_changed",
        f"feedback_id={feedback_id} {old_status}->{new_status}",
        actor=username
    )
    flash(f"Feedback #{feedback_id} marked {new_status}.", "success")
    return redirect(url_for("feedback_inbox"))



@app.post("/admin/feedback/<int:feedback_id>/delete")
@tier1_required
def feedback_delete(feedback_id):
    conn = db()
    item = conn.execute(
        "SELECT * FROM feedback WHERE id=?",
        (feedback_id,)
    ).fetchone()

    if not item:
        conn.close()
        abort(404)

    if item["status"] != "Closed":
        conn.close()
        flash("Feedback must be marked Closed before it can be deleted.", "error")
        return redirect(url_for("feedback_inbox"))

    username = session.get("admin_username", "unknown")
    audit_detail = (
        f'feedback_id={feedback_id} '
        f'subject="{item["subject"]}" '
        f'submitted_by={item["submitted_by"]}'
    )

    conn.execute("DELETE FROM feedback WHERE id=?", (feedback_id,))
    conn.commit()
    conn.close()

    audit(
        "feedback_deleted",
        audit_detail,
        actor=username
    )
    flash(f"Feedback #{feedback_id} deleted.", "success")
    return redirect(url_for("feedback_inbox"))


@app.post("/admin/audit/clear")
@tier1_required
def clear_audit_log():
    username = session.get("admin_username", "unknown")
    conn = db()
    conn.execute("DELETE FROM audit_log")
    conn.commit()
    conn.close()

    audit(
        "audit_log_cleared",
        "All previous audit events cleared by Tier 1",
        actor=username
    )
    flash("Audit Log cleared.", "success")
    return redirect(url_for("audit_logs"))


@app.route("/admin/audit")
@oversight_required
def audit_logs():
    conn = db()
    rows = conn.execute("""
        SELECT * FROM audit_log
        ORDER BY created_at DESC LIMIT 500
    """).fetchall()
    conn.close()
    return render_template(
        "audit.html",
        rows=rows,
        admin_user=current_admin(),
        active_page="audit"
    )


@app.route("/admin/system")
@oversight_required
def system_status():
    health = system_health()

    conn = db()
    db_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    member_count = conn.execute(
        "SELECT COUNT(*) AS c FROM profiles"
    ).fetchone()["c"]
    active_devices = conn.execute("""
        SELECT COUNT(*) AS c FROM approved_devices WHERE revoked=0
    """).fetchone()["c"]
    audit_count = conn.execute(
        "SELECT COUNT(*) AS c FROM audit_log"
    ).fetchone()["c"]
    journal_mode = conn.execute(
        "PRAGMA journal_mode"
    ).fetchone()[0]
    conn.close()

    backups = sorted(
        BACKUP_DIR.glob("crew_*.db"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    last_backup = backups[0] if backups else None

    return render_template(
        "system.html",
        health=health,
        db_size=db_size,
        member_count=member_count,
        active_devices=active_devices,
        audit_count=audit_count,
        journal_mode=journal_mode,
        uptime=int(time.time()) - STARTED_AT,
        last_backup=last_backup,
        audit_retention_days=AUDIT_RETENTION_DAYS,
        admin_user=current_admin(),
        active_page="system"
    )





@app.post("/admin/member/<int:profile_id>/red-card")
@staff_required
def upload_red_card(profile_id):
    conn = db()
    p = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not p:
        conn.close(); abort(404)
    file = request.files.get("red_card")
    filename = p["red_card_filename"]
    if file and file.filename:
        safe = secure_filename(file.filename)
        ext = Path(safe).suffix.lower()
        if ext not in (".pdf", ".png", ".jpg", ".jpeg"):
            conn.close()
            flash("Red Card must be PDF, PNG, JPG, or JPEG.", "error")
            return redirect(url_for("admin_edit", profile_id=profile_id))
        filename = f"redcard_{profile_id}_{int(time.time())}{ext}"
        file.save(UPLOAD_DIR / filename)
    conn.execute("""UPDATE profiles SET red_card_filename=?,red_card_issue_date=?,red_card_expiry_date=? WHERE id=?""",
                 (filename, fv(request.form,"red_card_issue_date"), fv(request.form,"red_card_expiry_date"), profile_id))
    conn.commit(); conn.close()
    audit("red_card_updated", f"profile_id={profile_id}")
    flash("Red Card information saved.", "success")
    return redirect(url_for("admin_edit", profile_id=profile_id))


@app.route("/admin/member/<int:profile_id>/red-card/view")
@staff_required
def view_red_card(profile_id):
    conn=db(); p=conn.execute("SELECT * FROM profiles WHERE id=?",(profile_id,)).fetchone(); conn.close()
    if not p or not p["red_card_filename"]: abort(404)
    audit("red_card_opened", f"profile_id={profile_id}")
    return send_from_directory(str(UPLOAD_DIR), p["red_card_filename"], as_attachment=False)


# -------------------------
# Wildland operations
# -------------------------

def deployment_or_404(deployment_id):
    conn = db()
    row = conn.execute("""
        SELECT d.*, a.unit_code, a.name AS apparatus_name,
               a.apparatus_type, a.nfc_slug
        FROM deployments d
        JOIN apparatus a ON a.id=d.apparatus_id
        WHERE d.id=?
    """, (deployment_id,)).fetchone()
    conn.close()
    if not row:
        abort(404)
    return row


@app.route("/admin/wildland")
@wildland_required
def wildland():
    user = current_admin()
    conn = db()
    apparatus_rows = conn.execute(
        "SELECT * FROM apparatus WHERE enabled=1 ORDER BY unit_code"
    ).fetchall()
    active = conn.execute("""
        SELECT d.*, a.unit_code, a.name AS apparatus_name
        FROM deployments d
        JOIN apparatus a ON a.id=d.apparatus_id
        WHERE d.status='Active'
        ORDER BY d.started_at DESC
    """).fetchall()
    history = conn.execute("""
        SELECT d.*, a.unit_code, a.name AS apparatus_name
        FROM deployments d
        JOIN apparatus a ON a.id=d.apparatus_id
        WHERE d.status!='Active'
        ORDER BY COALESCE(d.ended_at,d.started_at) DESC
        LIMIT 25
    """).fetchall()
    conn.close()
    return render_template(
        "wildland.html",
        apparatus=apparatus_rows,
        active=active,
        history=history,
        admin_user=user,
        active_page="wildland"
    )


@app.route("/admin/wildland/apparatus/new", methods=["GET", "POST"])
@leadership_required
def apparatus_new():
    if request.method == "POST":
        f = request.form
        unit_code = fv(f, "unit_code")
        name = fv(f, "name")
        nfc_slug = fv(f, "nfc_slug") or unit_code
        if not unit_code or not name:
            flash("Unit code and apparatus name are required.", "error")
        else:
            conn = db()
            try:
                conn.execute("""
                    INSERT INTO apparatus(
                        unit_code,name,apparatus_type,department,nfc_slug,enabled,created_at
                    ) VALUES(?,?,?,?,?,?,?)
                """, (
                    unit_code, name, fv(f, "apparatus_type"), fv(f, "department"),
                    nfc_slug, 1 if f.get("enabled") else 0, int(time.time())
                ))
                conn.commit()
                audit("apparatus_created", f"unit={unit_code} nfc={nfc_slug}")
                return redirect(url_for("wildland"))
            except sqlite3.IntegrityError:
                flash("That unit code or NFC ID is already in use.", "error")
            finally:
                conn.close()
    return render_template(
        "apparatus_edit.html",
        apparatus=None,
        admin_user=current_admin(),
        active_page="wildland"
    )


@app.route("/admin/wildland/apparatus/<int:apparatus_id>/edit", methods=["GET", "POST"])
@leadership_required
def apparatus_edit(apparatus_id):
    conn = db()
    row = conn.execute("SELECT * FROM apparatus WHERE id=?", (apparatus_id,)).fetchone()
    if not row:
        conn.close()
        abort(404)

    if request.method == "POST":
        f = request.form
        try:
            conn.execute("""
                UPDATE apparatus
                SET unit_code=?,name=?,apparatus_type=?,department=?,nfc_slug=?,enabled=?
                WHERE id=?
            """, (
                fv(f, "unit_code"), fv(f, "name"), fv(f, "apparatus_type"),
                fv(f, "department"), fv(f, "nfc_slug"),
                1 if f.get("enabled") else 0, apparatus_id
            ))
            conn.commit()
            conn.close()
            audit("apparatus_updated", f"apparatus_id={apparatus_id}")
            return redirect(url_for("wildland"))
        except sqlite3.IntegrityError:
            flash("That unit code or NFC ID is already in use.", "error")

    conn.close()
    return render_template(
        "apparatus_edit.html",
        apparatus=row,
        admin_user=current_admin(),
        active_page="wildland"
    )


@app.route("/admin/wildland/apparatus/<int:apparatus_id>")
@wildland_required
def apparatus_profile(apparatus_id):
    conn = db()
    apparatus = conn.execute("SELECT * FROM apparatus WHERE id=?", (apparatus_id,)).fetchone()
    if not apparatus:
        conn.close(); abort(404)
    active = conn.execute("""
        SELECT * FROM deployments WHERE apparatus_id=? AND status='Active'
        ORDER BY started_at DESC LIMIT 1
    """, (apparatus_id,)).fetchone()
    history = conn.execute("""
        SELECT * FROM deployments WHERE apparatus_id=?
        ORDER BY started_at DESC LIMIT 50
    """, (apparatus_id,)).fetchall()
    usage = conn.execute("""
        SELECT at.*, d.incident_name, d.incident_number
        FROM apparatus_timesheets at
        JOIN deployments d ON d.id=at.deployment_id
        WHERE at.apparatus_id=?
        ORDER BY at.work_date DESC, at.id DESC LIMIT 50
    """, (apparatus_id,)).fetchall()
    conn.close()
    audit("apparatus_opened", f"apparatus_id={apparatus_id} view=profile")
    return render_template("apparatus_profile.html", apparatus=apparatus, active=active, history=history,
                           usage=usage, admin_user=current_admin(), active_page="wildland")


@app.post("/admin/wildland/deployment/<int:deployment_id>/apparatus/readings")
@wildland_required
def apparatus_update_readings(deployment_id):
    deployment = deployment_or_404(deployment_id)
    user = current_admin()
    if deployment["status"] != "Active" or not can_manage_deployment(user, deployment):
        abort(403)
    odo = request.form.get("odometer", "").strip()
    eng = request.form.get("engine_hours", "").strip()
    try:
        odo_val = float(odo) if odo else None
        eng_val = float(eng) if eng else None
    except ValueError:
        flash("Odometer and engine hours must be numbers.", "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))
    if odo_val is None and eng_val is None:
        flash("Enter an odometer or engine-hours value.", "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))
    conn = db()
    if odo_val is not None:
        conn.execute("UPDATE apparatus SET current_odometer=? WHERE id=?", (odo_val, deployment["apparatus_id"]))
    if eng_val is not None:
        conn.execute("UPDATE apparatus SET current_engine_hours=? WHERE id=?", (eng_val, deployment["apparatus_id"]))
    conn.commit(); conn.close()
    audit("apparatus_readings_updated", f"deployment_id={deployment_id} apparatus_id={deployment['apparatus_id']}")
    flash("Apparatus readings updated.", "success")
    return redirect(url_for("deployment_detail", deployment_id=deployment_id))


@app.route("/e/<nfc_slug>")
def apparatus_tag(nfc_slug):
    conn = db()
    a = conn.execute(
        "SELECT * FROM apparatus WHERE nfc_slug=? AND enabled=1",
        (nfc_slug,)
    ).fetchone()
    if not a:
        conn.close()
        abort(404)
    active = conn.execute("""
        SELECT * FROM deployments
        WHERE apparatus_id=? AND status='Active'
        ORDER BY started_at DESC LIMIT 1
    """, (a["id"],)).fetchone()
    conn.close()

    signed_in = bool(current_device() and current_admin())
    if signed_in:
        audit("apparatus_opened", f"apparatus_id={a['id']}")
        if active:
            return redirect(url_for("deployment_detail", deployment_id=active["id"]))
    return render_template(
        "apparatus_public.html",
        apparatus=a,
        deployment=active,
        signed_in=signed_in,
        admin_user=current_admin() if signed_in else None
    )


@app.route("/admin/wildland/start/<int:apparatus_id>", methods=["GET", "POST"])
@wildland_required
def deployment_start(apparatus_id):
    user = current_admin()
    conn = db()
    apparatus = conn.execute(
        "SELECT * FROM apparatus WHERE id=? AND enabled=1",
        (apparatus_id,)
    ).fetchone()
    if not apparatus:
        conn.close()
        abort(404)

    existing = conn.execute(
        "SELECT id FROM deployments WHERE apparatus_id=? AND status='Active' LIMIT 1",
        (apparatus_id,)
    ).fetchone()
    if existing:
        conn.close()
        return redirect(url_for("deployment_detail", deployment_id=existing["id"]))

    if request.method == "POST":
        incident_name = fv(request.form, "incident_name")
        if not incident_name:
            conn.close()
            flash("Incident name is required.", "error")
        else:
            now = int(time.time())
            cur = conn.execute("""
                INSERT INTO deployments(
                    apparatus_id,incident_name,incident_number,location,
                    leader_user_id,leader_name,started_at,status,created_by
                ) VALUES(?,?,?,?,?,?,?,'Active',?)
            """, (
                apparatus_id, incident_name, fv(request.form, "incident_number"),
                fv(request.form, "location"), user["id"], user["display_name"],
                now, user["username"]
            ))
            deployment_id = cur.lastrowid
            conn.commit()
            conn.close()
            audit(
                "deployment_started",
                f"deployment_id={deployment_id} unit={apparatus['unit_code']} incident={incident_name}"
            )
            return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    if conn:
        try:
            conn.close()
        except Exception:
            pass
    return render_template(
        "deployment_start.html",
        apparatus=apparatus,
        admin_user=user,
        active_page="wildland"
    )


@app.route("/admin/wildland/deployment/<int:deployment_id>")
@wildland_required
def deployment_detail(deployment_id):
    deployment = deployment_or_404(deployment_id)
    audit("deployment_opened", f"deployment_id={deployment_id}")
    user = current_admin()
    conn = db()
    crew = conn.execute("""
        SELECT dc.*, p.name, p.slug, p.position, p.crew_id
        FROM deployment_crew dc
        JOIN profiles p ON p.id=dc.profile_id
        WHERE dc.deployment_id=?
        ORDER BY CASE WHEN dc.left_at IS NULL THEN 0 ELSE 1 END, dc.joined_at
    """, (deployment_id,)).fetchall()
    profiles = conn.execute("""
        SELECT id,name,slug,position,crew_id
        FROM profiles
        WHERE enabled=1
        ORDER BY name
    """).fetchall()
    timesheets = conn.execute("""
        SELECT t.*, p.name
        FROM timesheets t
        JOIN profiles p ON p.id=t.profile_id
        WHERE t.deployment_id=?
        ORDER BY p.name COLLATE NOCASE, t.work_date ASC, t.start_time ASC, t.id ASC
    """, (deployment_id,)).fetchall()
    timesheet_groups = []
    groups = {}
    for row in timesheets:
        name = row["name"]
        if name not in groups:
            groups[name] = {"name": name, "entries": [], "total_hours": 0.0}
            timesheet_groups.append(groups[name])
        groups[name]["entries"].append(row)
        if row["clocked_out_at"] is not None or row["end_time"]:
            groups[name]["total_hours"] += float(row["hours"] or 0)
    apparatus_times = conn.execute("SELECT * FROM apparatus_timesheets WHERE deployment_id=? ORDER BY work_date ASC,id ASC", (deployment_id,)).fetchall()
    current_apparatus_clock = open_apparatus_timesheet_for(conn, deployment_id)
    apparatus_record = conn.execute("SELECT * FROM apparatus WHERE id=?", (deployment["apparatus_id"],)).fetchone()
    conn.close()
    return render_template(
        "deployment_detail.html",
        deployment=deployment,
        crew=crew,
        profiles=profiles,
        timesheets=timesheets, timesheet_groups=timesheet_groups, apparatus_times=apparatus_times,
        current_apparatus_clock=current_apparatus_clock, apparatus_record=apparatus_record,
        can_manage=can_manage_deployment(user, deployment),
        admin_user=user,
        active_page="wildland"
    )


@app.post("/admin/wildland/deployment/<int:deployment_id>/tap-mode")
@wildland_required
def wildland_tap_mode(deployment_id):
    deployment = deployment_or_404(deployment_id)
    user = current_admin()
    if not can_manage_deployment(user, deployment):
        abort(403)
    if deployment["status"] != "Active":
        flash("This deployment is no longer active.", "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))
    session["wildland_add_deployment_id"] = deployment_id
    flash("Tap the crew member's normal NFC tag now. Their profile tag will add them to this deployment.", "success")
    return redirect(url_for("wildland_tap_wait", deployment_id=deployment_id))


@app.route("/admin/wildland/deployment/<int:deployment_id>/tap-wait")
@wildland_required
def wildland_tap_wait(deployment_id):
    deployment = deployment_or_404(deployment_id)
    if session.get("wildland_add_deployment_id") != deployment_id:
        session["wildland_add_deployment_id"] = deployment_id
    return render_template(
        "tap_wait.html",
        deployment=deployment,
        admin_user=current_admin(),
        active_page="wildland"
    )


@app.post("/admin/wildland/deployment/<int:deployment_id>/tap-cancel")
@wildland_required
def wildland_tap_cancel(deployment_id):
    session.pop("wildland_add_deployment_id", None)
    return redirect(url_for("deployment_detail", deployment_id=deployment_id))


@app.route("/admin/wildland/deployment/<int:deployment_id>/scan/<slug>")
@wildland_required
def wildland_add_by_tag(deployment_id, slug):
    deployment = deployment_or_404(deployment_id)
    user = current_admin()
    session.pop("wildland_add_deployment_id", None)
    if not can_manage_deployment(user, deployment):
        abort(403)
    if deployment["status"] != "Active":
        flash("This deployment is no longer active.", "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    conn = db()
    p = conn.execute(
        "SELECT * FROM profiles WHERE slug=? AND enabled=1",
        (slug,)
    ).fetchone()
    if not p:
        conn.close()
        abort(404)

    existing = conn.execute("""
        SELECT id FROM deployment_crew
        WHERE deployment_id=? AND profile_id=? AND left_at IS NULL
    """, (deployment_id, p["id"])).fetchone()
    if existing:
        conn.close()
        flash(f'{p["name"]} is already assigned to this deployment.', "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    other = conn.execute("""
        SELECT dc.id, d.id AS deployment_id, a.unit_code
        FROM deployment_crew dc
        JOIN deployments d ON d.id=dc.deployment_id
        JOIN apparatus a ON a.id=d.apparatus_id
        WHERE dc.profile_id=? AND dc.left_at IS NULL
          AND d.status='Active' AND d.id<>?
        LIMIT 1
    """, (p["id"], deployment_id)).fetchone()
    if other:
        conn.close()
        flash(
            f'{p["name"]} is already active on {other["unit_code"]}. Remove/transfer them there first.',
            "error"
        )
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    conn.execute("""
        INSERT INTO deployment_crew(
            deployment_id,profile_id,deployment_role,joined_at,added_method,added_by
        ) VALUES(?,?,?,?,?,?)
    """, (
        deployment_id, p["id"], p["position"] or "Crew Member",
        int(time.time()), "NFC", user["username"]
    ))
    conn.commit()
    conn.close()
    audit(
        "deployment_crew_added",
        f"deployment_id={deployment_id} profile={slug} method=NFC"
    )
    flash(f'{p["name"]} added by NFC tag.', "success")
    return redirect(url_for("deployment_detail", deployment_id=deployment_id))


@app.post("/admin/wildland/deployment/<int:deployment_id>/crew/add")
@wildland_required
def deployment_crew_add(deployment_id):
    deployment = deployment_or_404(deployment_id)
    user = current_admin()
    if not can_manage_deployment(user, deployment):
        abort(403)
    if deployment["status"] != "Active":
        abort(403)

    try:
        profile_id = int(request.form.get("profile_id", "0"))
    except ValueError:
        profile_id = 0
    role = fv(request.form, "deployment_role") or "Crew Member"

    conn = db()
    p = conn.execute(
        "SELECT * FROM profiles WHERE id=? AND enabled=1",
        (profile_id,)
    ).fetchone()
    if not p:
        conn.close()
        flash("Choose a valid member.", "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    existing = conn.execute("""
        SELECT id FROM deployment_crew
        WHERE deployment_id=? AND profile_id=? AND left_at IS NULL
    """, (deployment_id, profile_id)).fetchone()
    if existing:
        conn.close()
        flash(f'{p["name"]} is already assigned to this deployment.', "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    other = conn.execute("""
        SELECT a.unit_code
        FROM deployment_crew dc
        JOIN deployments d ON d.id=dc.deployment_id
        JOIN apparatus a ON a.id=d.apparatus_id
        WHERE dc.profile_id=? AND dc.left_at IS NULL
          AND d.status='Active' AND d.id<>?
        LIMIT 1
    """, (profile_id, deployment_id)).fetchone()
    if other:
        conn.close()
        flash(
            f'{p["name"]} is already assigned to {other["unit_code"]}.',
            "error"
        )
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    conn.execute("""
        INSERT INTO deployment_crew(
            deployment_id,profile_id,deployment_role,joined_at,added_method,added_by
        ) VALUES(?,?,?,?,?,?)
    """, (
        deployment_id, profile_id, role, int(time.time()),
        "Search", user["username"]
    ))
    conn.commit()
    conn.close()
    audit(
        "deployment_crew_added",
        f"deployment_id={deployment_id} profile_id={profile_id} method=Search"
    )
    flash(f'{p["name"]} added to the deployment.', "success")
    return redirect(url_for("deployment_detail", deployment_id=deployment_id))


@app.post("/admin/wildland/deployment/<int:deployment_id>/crew/<int:crew_id>/leave")
@wildland_required
def deployment_crew_leave(deployment_id, crew_id):
    deployment = deployment_or_404(deployment_id)
    user = current_admin()
    if not can_manage_deployment(user, deployment):
        abort(403)

    conn = db()
    row = conn.execute("""
        SELECT dc.*, p.name
        FROM deployment_crew dc JOIN profiles p ON p.id=dc.profile_id
        WHERE dc.id=? AND dc.deployment_id=?
    """, (crew_id, deployment_id)).fetchone()
    if not row:
        conn.close()
        abort(404)
    if row["left_at"] is None:
        conn.execute(
            "UPDATE deployment_crew SET left_at=? WHERE id=?",
            (int(time.time()), crew_id)
        )
        conn.commit()
    conn.close()
    audit(
        "deployment_crew_removed",
        f"deployment_id={deployment_id} profile_id={row['profile_id']}"
    )
    flash(f'{row["name"]} marked as left the deployment.', "success")
    return redirect(url_for("deployment_detail", deployment_id=deployment_id))


def red_card_status(expiry_date):
    if not expiry_date:
        return "Not on file"
    try:
        exp_ts = int(time.mktime(time.strptime(expiry_date, "%Y-%m-%d")))
        days = int((exp_ts - time.time()) / 86400)
        if days < 0:
            return "Expired"
        if days <= 60:
            return "Expiring Soon"
        return "Current"
    except Exception:
        return "Unknown"


def open_apparatus_timesheet_for(conn, deployment_id):
    return conn.execute("""
        SELECT * FROM apparatus_timesheets
        WHERE deployment_id=? AND clocked_in_at IS NOT NULL AND clocked_out_at IS NULL
        ORDER BY id DESC LIMIT 1
    """, (deployment_id,)).fetchone()


def current_local_date_time():
    now = time.localtime()
    return (
        time.strftime("%Y-%m-%d", now),
        time.strftime("%H:%M", now),
        int(time.time())
    )


def open_timesheet_for(conn, deployment_id, profile_id):
    return conn.execute("""
        SELECT * FROM timesheets
        WHERE deployment_id=? AND profile_id=?
          AND clocked_in_at IS NOT NULL
          AND clocked_out_at IS NULL
        ORDER BY id DESC LIMIT 1
    """, (deployment_id, profile_id)).fetchone()


app.jinja_env.globals["red_card_status"] = red_card_status


def calculate_hours(start_time, end_time):
    try:
        sh, sm = [int(x) for x in start_time.split(":")]
        eh, em = [int(x) for x in end_time.split(":")]
        start_minutes = sh * 60 + sm
        end_minutes = eh * 60 + em
        if end_minutes < start_minutes:
            end_minutes += 24 * 60
        return round((end_minutes - start_minutes) / 60.0, 2)
    except Exception:
        return 0.0


@app.post("/admin/wildland/deployment/<int:deployment_id>/timesheet/add")
@wildland_required
def timesheet_add(deployment_id):
    deployment = deployment_or_404(deployment_id)
    user = current_admin()
    if not can_manage_deployment(user, deployment):
        abort(403)

    work_date = fv(request.form, "work_date")
    start_time = fv(request.form, "start_time")
    end_time = fv(request.form, "end_time")
    category = fv(request.form, "category") or "Regular"
    notes = fv(request.form, "notes")
    apply_all = bool(request.form.get("apply_all"))
    hours = calculate_hours(start_time, end_time)

    if not work_date or not start_time or not end_time or hours <= 0:
        flash("Enter a valid date, start time, and stop time.", "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    conn = db()
    if apply_all:
        rows = conn.execute("""
            SELECT profile_id FROM deployment_crew
            WHERE deployment_id=? AND left_at IS NULL
        """, (deployment_id,)).fetchall()
        profile_ids = [r["profile_id"] for r in rows]
    else:
        try:
            profile_ids = [int(request.form.get("profile_id", "0"))]
        except ValueError:
            profile_ids = []

    if not profile_ids:
        conn.close()
        flash("No active crew member was selected.", "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    now = int(time.time())
    for profile_id in profile_ids:
        conn.execute("""
            INSERT INTO timesheets(
                deployment_id,profile_id,work_date,start_time,end_time,hours,
                category,notes,created_by,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """, (
            deployment_id, profile_id, work_date, start_time, end_time, hours,
            category, notes, user["username"], now, now
        ))
    conn.commit()
    conn.close()
    audit(
        "timesheet_added",
        f"deployment_id={deployment_id} entries={len(profile_ids)} date={work_date} hours={hours}"
    )
    flash(f"Timesheet entry saved for {len(profile_ids)} crew member(s).", "success")
    return redirect(url_for("deployment_detail", deployment_id=deployment_id))



@app.post("/admin/wildland/deployment/<int:deployment_id>/clock/<int:profile_id>/in")
@wildland_required
def timesheet_clock_in(deployment_id, profile_id):
    deployment = deployment_or_404(deployment_id)
    user = current_admin()
    if not can_manage_deployment(user, deployment) or deployment["status"] != "Active":
        abort(403)

    conn = db()
    member = conn.execute("""
        SELECT p.* FROM profiles p
        JOIN deployment_crew dc ON dc.profile_id=p.id
        WHERE p.id=? AND dc.deployment_id=? AND dc.left_at IS NULL
        LIMIT 1
    """, (profile_id, deployment_id)).fetchone()
    if not member:
        conn.close()
        flash("That member is not active on this deployment.", "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    if open_timesheet_for(conn, deployment_id, profile_id):
        conn.close()
        flash(f'{member["name"]} is already clocked in.', "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    work_date, start_time, stamp = current_local_date_time()
    conn.execute("""
        INSERT INTO timesheets(
            deployment_id,profile_id,work_date,start_time,end_time,hours,
            category,notes,created_by,created_at,updated_at,clocked_in_at,clocked_out_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)
    """, (
        deployment_id, profile_id, work_date, start_time, "", 0.0,
        "Regular", "", user["username"], stamp, stamp, stamp
    ))
    conn.commit()
    conn.close()
    audit("timesheet_clock_in",
          f"deployment_id={deployment_id} profile_id={profile_id} at={work_date} {start_time}")
    flash(f'{member["name"]} clocked in at {start_time}.', "success")
    return redirect(url_for("deployment_detail", deployment_id=deployment_id))


@app.post("/admin/wildland/deployment/<int:deployment_id>/clock/<int:profile_id>/out")
@wildland_required
def timesheet_clock_out(deployment_id, profile_id):
    deployment = deployment_or_404(deployment_id)
    user = current_admin()
    if not can_manage_deployment(user, deployment):
        abort(403)

    conn = db()
    member = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    row = open_timesheet_for(conn, deployment_id, profile_id)
    if not row:
        conn.close()
        flash("That member is not currently clocked in.", "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    _, end_time, stamp = current_local_date_time()
    hours = calculate_hours(row["start_time"], end_time)
    conn.execute("""
        UPDATE timesheets
        SET end_time=?,hours=?,clocked_out_at=?,updated_at=?
        WHERE id=?
    """, (end_time, hours, stamp, stamp, row["id"]))
    conn.commit()
    conn.close()
    audit("timesheet_clock_out",
          f"deployment_id={deployment_id} profile_id={profile_id} hours={hours}")
    flash(f'{member["name"] if member else "Member"} clocked out at {end_time}.', "success")
    return redirect(url_for("deployment_detail", deployment_id=deployment_id))


@app.post("/admin/wildland/deployment/<int:deployment_id>/clock-all/in")
@wildland_required
def timesheet_clock_all_in(deployment_id):
    deployment = deployment_or_404(deployment_id)
    user = current_admin()
    if not can_manage_deployment(user, deployment) or deployment["status"] != "Active":
        abort(403)

    work_date, start_time, stamp = current_local_date_time()
    conn = db()
    crew = conn.execute("""
        SELECT profile_id FROM deployment_crew
        WHERE deployment_id=? AND left_at IS NULL
    """, (deployment_id,)).fetchall()

    added = 0
    for row in crew:
        profile_id = row["profile_id"]
        if open_timesheet_for(conn, deployment_id, profile_id):
            continue
        conn.execute("""
            INSERT INTO timesheets(
                deployment_id,profile_id,work_date,start_time,end_time,hours,
                category,notes,created_by,created_at,updated_at,clocked_in_at,clocked_out_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)
        """, (
            deployment_id, profile_id, work_date, start_time, "", 0.0,
            "Regular", "", user["username"], stamp, stamp, stamp
        ))
        added += 1

    conn.commit()
    conn.close()
    audit("timesheet_clock_all_in",
          f"deployment_id={deployment_id} count={added} at={work_date} {start_time}")
    if added == 0:
        flash("No crew members were clocked in because all active crew are already clocked in.", "info")
    else:
        flash(f"Clocked in {added} crew member(s) at {start_time}.", "success")
    return redirect(url_for("deployment_detail", deployment_id=deployment_id))


@app.post("/admin/wildland/deployment/<int:deployment_id>/clock-all/out")
@wildland_required
def timesheet_clock_all_out(deployment_id):
    deployment = deployment_or_404(deployment_id)
    user = current_admin()
    if not can_manage_deployment(user, deployment):
        abort(403)

    _, end_time, stamp = current_local_date_time()
    conn = db()
    rows = conn.execute("""
        SELECT * FROM timesheets
        WHERE deployment_id=? AND clocked_in_at IS NOT NULL AND clocked_out_at IS NULL
    """, (deployment_id,)).fetchall()

    count = 0
    for row in rows:
        hours = calculate_hours(row["start_time"], end_time)
        conn.execute("""
            UPDATE timesheets
            SET end_time=?,hours=?,clocked_out_at=?,updated_at=?
            WHERE id=?
        """, (end_time, hours, stamp, stamp, row["id"]))
        count += 1

    conn.commit()
    conn.close()
    audit("timesheet_clock_all_out",
          f"deployment_id={deployment_id} count={count} at={end_time}")
    flash(f"Clocked out {count} crew member(s) at {end_time}.", "success")
    return redirect(url_for("deployment_detail", deployment_id=deployment_id))


@app.post("/admin/wildland/deployment/<int:deployment_id>/timesheet/<int:timesheet_id>/correct")
@wildland_required
def timesheet_correct(deployment_id, timesheet_id):
    deployment = deployment_or_404(deployment_id)
    user = current_admin()

    # Corrections are operational edits. They are allowed only while the
    # deployment is active. Completed deployments must be reopened first.
    if deployment["status"] != "Active" or not can_manage_deployment(user, deployment):
        flash("Reopen this deployment before correcting a timesheet.", "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    conn = db()
    row = conn.execute(
        "SELECT * FROM timesheets WHERE id=? AND deployment_id=?",
        (timesheet_id, deployment_id)
    ).fetchone()
    if not row:
        conn.close()
        abort(404)

    new_start = fv(request.form, "start_time")
    new_end = fv(request.form, "end_time")
    reason = fv(request.form, "reason")
    if not new_start or not new_end or not reason:
        conn.close()
        flash("Start time, stop time, and correction reason are required.", "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    new_hours = calculate_hours(new_start, new_end)
    if new_hours <= 0:
        conn.close()
        flash("Enter a valid corrected time range.", "error")
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    conn.execute("""
        UPDATE timesheets
        SET corrected_from_start=?, corrected_from_end=?,
            start_time=?, end_time=?, hours=?,
            correction_reason=?, corrected_by=?, updated_at=?
        WHERE id=?
    """, (
        row["start_time"], row["end_time"], new_start, new_end, new_hours,
        reason, user["username"], int(time.time()), timesheet_id
    ))
    conn.commit()
    conn.close()

    audit("timesheet_corrected",
          f"deployment_id={deployment_id} timesheet_id={timesheet_id} "
          f"from={row['start_time']}-{row['end_time']} to={new_start}-{new_end} reason={reason}")
    flash("Timesheet corrected and audit record created.", "success")
    return redirect(url_for("deployment_detail", deployment_id=deployment_id))


@app.route("/admin/wildland/live")
@leadership_required
def wildland_live():
    audit("timesheet_opened", "scope=wildland_live_board")
    conn = db()
    active = conn.execute("""
        SELECT d.*, a.unit_code, a.name AS apparatus_name,
               COUNT(DISTINCT dc.profile_id) AS crew_count
        FROM deployments d
        JOIN apparatus a ON a.id=d.apparatus_id
        LEFT JOIN deployment_crew dc
          ON dc.deployment_id=d.id AND dc.left_at IS NULL
        WHERE d.status='Active'
        GROUP BY d.id
        ORDER BY d.started_at DESC
    """).fetchall()

    apparatus_live_rows = conn.execute("""
        SELECT at.deployment_id,at.start_time,at.work_date,at.clocked_in_at,a.unit_code
        FROM apparatus_timesheets at
        JOIN deployments d ON d.id=at.deployment_id
        JOIN apparatus a ON a.id=d.apparatus_id
        WHERE d.status='Active' AND at.clocked_in_at IS NOT NULL AND at.clocked_out_at IS NULL
    """).fetchall()

    live_rows = conn.execute("""
        SELECT t.deployment_id,t.profile_id,t.start_time,t.work_date,t.clocked_in_at,
               p.name,a.unit_code
        FROM timesheets t
        JOIN profiles p ON p.id=t.profile_id
        JOIN deployments d ON d.id=t.deployment_id
        JOIN apparatus a ON a.id=d.apparatus_id
        WHERE d.status='Active'
          AND t.clocked_in_at IS NOT NULL
          AND t.clocked_out_at IS NULL
        ORDER BY a.unit_code,p.name
    """).fetchall()
    conn.close()

    by_dep = {}
    for r in live_rows:
        by_dep.setdefault(r["deployment_id"], []).append(r)

    return render_template(
        "wildland_live.html",
        active=active,
        live_by_dep=by_dep,
        apparatus_live={r["deployment_id"]: r for r in apparatus_live_rows},
        now_ts=int(time.time()),
        admin_user=current_admin(),
        active_page="wildland"
    )


@app.post("/admin/wildland/deployment/<int:deployment_id>/apparatus/clock-in")
@wildland_required
def apparatus_clock_in(deployment_id):
    deployment=deployment_or_404(deployment_id); user=current_admin()
    if not can_manage_deployment(user,deployment) or deployment["status"] != "Active": abort(403)
    conn=db()
    if open_apparatus_timesheet_for(conn,deployment_id):
        conn.close(); flash("Apparatus is already clocked in.","error"); return redirect(url_for("deployment_detail",deployment_id=deployment_id))
    work_date,start_time,stamp=current_local_date_time()
    conn.execute("""INSERT INTO apparatus_timesheets(deployment_id,apparatus_id,work_date,start_time,end_time,hours,clocked_in_at,clocked_out_at,start_odometer,start_engine_hours,created_by,created_at,updated_at) VALUES(?,?,?,?,?,0,?,NULL,?,?,?,?,?)""",
        (deployment_id,deployment["apparatus_id"],work_date,start_time,"",stamp,request.form.get("start_odometer") or None,request.form.get("start_engine_hours") or None,user["username"],stamp,stamp))
    start_odo = request.form.get("start_odometer") or None
    start_eng = request.form.get("start_engine_hours") or None
    if start_odo is not None:
        conn.execute("UPDATE apparatus SET current_odometer=? WHERE id=?", (start_odo, deployment["apparatus_id"]))
    if start_eng is not None:
        conn.execute("UPDATE apparatus SET current_engine_hours=? WHERE id=?", (start_eng, deployment["apparatus_id"]))
    conn.commit(); conn.close(); audit("apparatus_clock_in",f"deployment_id={deployment_id} at={start_time}")
    flash(f"Apparatus clock started at {start_time}.","success"); return redirect(url_for("deployment_detail",deployment_id=deployment_id))

@app.post("/admin/wildland/deployment/<int:deployment_id>/apparatus/clock-out")
@wildland_required
def apparatus_clock_out(deployment_id):
    deployment=deployment_or_404(deployment_id); user=current_admin()
    if not can_manage_deployment(user,deployment): abort(403)
    conn=db(); row=open_apparatus_timesheet_for(conn,deployment_id)
    if not row:
        conn.close(); flash("Apparatus is not currently clocked in.","error"); return redirect(url_for("deployment_detail",deployment_id=deployment_id))
    _,end_time,stamp=current_local_date_time(); hours=calculate_hours(row["start_time"],end_time)
    conn.execute("UPDATE apparatus_timesheets SET end_time=?,hours=?,clocked_out_at=?,updated_at=?,end_odometer=?,end_engine_hours=? WHERE id=?",
        (end_time,hours,stamp,stamp,request.form.get("end_odometer") or None,request.form.get("end_engine_hours") or None,row["id"]))
    end_odo = request.form.get("end_odometer") or None
    end_eng = request.form.get("end_engine_hours") or None
    if end_odo is not None:
        conn.execute("UPDATE apparatus SET current_odometer=? WHERE id=?", (end_odo, deployment["apparatus_id"]))
    if end_eng is not None:
        conn.execute("UPDATE apparatus SET current_engine_hours=? WHERE id=?", (end_eng, deployment["apparatus_id"]))
    conn.commit(); conn.close(); audit("apparatus_clock_out",f"deployment_id={deployment_id} hours={hours}")
    flash(f"Apparatus clock stopped at {end_time}.","success"); return redirect(url_for("deployment_detail",deployment_id=deployment_id))

@app.post("/admin/wildland/deployment/<int:deployment_id>/clock-combined/in")
@wildland_required
def combined_clock_in(deployment_id):
    deployment=deployment_or_404(deployment_id); user=current_admin()
    if not can_manage_deployment(user,deployment) or deployment["status"] != "Active": abort(403)
    work_date,start_time,stamp=current_local_date_time(); conn=db(); apparatus_started=False
    if not open_apparatus_timesheet_for(conn,deployment_id):
        conn.execute("""INSERT INTO apparatus_timesheets(deployment_id,apparatus_id,work_date,start_time,end_time,hours,clocked_in_at,created_by,created_at,updated_at) VALUES(?,?,?,?,?,0,?,?,?,?)""",
            (deployment_id,deployment["apparatus_id"],work_date,start_time,"",stamp,user["username"],stamp,stamp)); apparatus_started=True
    crew=conn.execute("SELECT profile_id FROM deployment_crew WHERE deployment_id=? AND left_at IS NULL",(deployment_id,)).fetchall(); added=0
    for r in crew:
        if open_timesheet_for(conn,deployment_id,r["profile_id"]): continue
        conn.execute("""INSERT INTO timesheets(deployment_id,profile_id,work_date,start_time,end_time,hours,category,notes,created_by,created_at,updated_at,clocked_in_at,clocked_out_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
            (deployment_id,r["profile_id"],work_date,start_time,"",0.0,"Regular","",user["username"],stamp,stamp,stamp)); added+=1
    conn.commit(); conn.close(); audit("combined_clock_in",f"deployment_id={deployment_id} crew={added} apparatus_started={int(apparatus_started)} at={start_time}")
    if added == 0 and not apparatus_started:
        flash("No new clocks were started because the crew and apparatus are already clocked in.", "info")
    elif added == 0:
        flash(f"Apparatus clock started at {start_time}; no crew clocks were added because all active crew were already clocked in.", "success")
    else:
        prefix = "Apparatus and " if apparatus_started else "Apparatus already active; "
        flash(f"{prefix}{added} crew member(s) clocked in at {start_time}.", "success")
    return redirect(url_for("deployment_detail",deployment_id=deployment_id))

@app.post("/admin/wildland/deployment/<int:deployment_id>/clock-combined/out")
@wildland_required
def combined_clock_out(deployment_id):
    deployment=deployment_or_404(deployment_id); user=current_admin()
    if not can_manage_deployment(user,deployment): abort(403)
    _,end_time,stamp=current_local_date_time(); conn=db(); arow=open_apparatus_timesheet_for(conn,deployment_id)
    if arow:
        conn.execute("UPDATE apparatus_timesheets SET end_time=?,hours=?,clocked_out_at=?,updated_at=? WHERE id=?",(end_time,calculate_hours(arow["start_time"],end_time),stamp,stamp,arow["id"]))
    rows=conn.execute("SELECT * FROM timesheets WHERE deployment_id=? AND clocked_in_at IS NOT NULL AND clocked_out_at IS NULL",(deployment_id,)).fetchall(); count=0
    for row in rows:
        conn.execute("UPDATE timesheets SET end_time=?,hours=?,clocked_out_at=?,updated_at=? WHERE id=?",(end_time,calculate_hours(row["start_time"],end_time),stamp,stamp,row["id"])); count+=1
    conn.commit(); conn.close(); audit("combined_clock_out",f"deployment_id={deployment_id} crew={count} at={end_time}")
    flash(f"Apparatus and {count} crew member(s) clocked out at {end_time}.","success"); return redirect(url_for("deployment_detail",deployment_id=deployment_id))

@app.post("/admin/wildland/deployment/<int:deployment_id>/reopen")
@wildland_required
def deployment_reopen(deployment_id):
    deployment=deployment_or_404(deployment_id)
    if deployment["status"] == "Active": return redirect(url_for("deployment_detail",deployment_id=deployment_id))
    reason=fv(request.form,"reason")
    if not reason:
        flash("A reason is required to reopen a deployment.","error"); return redirect(url_for("deployment_detail",deployment_id=deployment_id))
    user=current_admin(); now=int(time.time()); conn=db()
    conn.execute("""UPDATE deployments SET status='Active',original_ended_at=COALESCE(original_ended_at,ended_at),ended_at=NULL,reopened_at=?,reopened_by=?,reopen_reason=? WHERE id=?""",(now,user["username"],reason,deployment_id))
    conn.commit(); conn.close(); audit("deployment_reopened",f"deployment_id={deployment_id} reason={reason}")
    flash("Deployment reopened for correction.","success"); return redirect(url_for("deployment_detail",deployment_id=deployment_id))


@app.post("/admin/wildland/deployment/<int:deployment_id>/end")
@wildland_required
def deployment_end(deployment_id):
    deployment = deployment_or_404(deployment_id)
    user = current_admin()
    if not can_manage_deployment(user, deployment):
        abort(403)
    if deployment["status"] != "Active":
        return redirect(url_for("deployment_detail", deployment_id=deployment_id))

    now = int(time.time())
    conn = db()
    conn.execute(
        "UPDATE deployments SET status='Completed',ended_at=? WHERE id=?",
        (now, deployment_id)
    )
    conn.execute("""
        UPDATE deployment_crew SET left_at=?
        WHERE deployment_id=? AND left_at IS NULL
    """, (now, deployment_id))
    conn.commit()
    conn.close()
    session.pop("wildland_add_deployment_id", None)
    audit("deployment_ended", f"deployment_id={deployment_id}")
    flash("Deployment completed and moved to history.", "success")
    return redirect(url_for("deployment_detail", deployment_id=deployment_id))



@app.route("/admin/accounts")
@leadership_required
def admin_accounts():
    conn = db()
    users = conn.execute("""
        SELECT * FROM admin_users
        ORDER BY CASE role WHEN 'admin' THEN 0 WHEN 'chief' THEN 1 WHEN 'officer' THEN 2 ELSE 3 END, display_name
    """).fetchall()
    conn.close()
    return render_template(
        "accounts.html",
        users=users,
        admin_user=current_admin(),
        active_page="accounts"
    )


@app.route("/admin/accounts/new", methods=["GET", "POST"])
@leadership_required
def admin_account_new():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        display_name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "officer")
        actor = current_admin()

        if role not in ("admin", "chief", "officer", "engine_boss"):
            role = "officer"
        if actor["role"] == "chief" and role == "admin":
            abort(403)

        if not username or not display_name or not password:
            flash("Username, display name, and password are required.", "error")
        elif password_policy_error(password):
            flash(password_policy_error(password), "error")
        else:
            conn = db()
            try:
                conn.execute("""
                    INSERT INTO admin_users(
                        username,display_name,password_hash,role,enabled,created_at,must_change_password
                    ) VALUES(?,?,?,?,1,?,1)
                """, (
                    username, display_name, generate_password_hash(password),
                    role, int(time.time())
                ))
                conn.commit()
                audit("admin_account_created", f"account={username} role={role}")
                return redirect(url_for("admin_accounts"))
            except sqlite3.IntegrityError:
                flash("That username is already in use.", "error")
            finally:
                conn.close()

    return render_template(
        "account_edit.html",
        user=None,
        admin_user=current_admin(),
        active_page="accounts"
    )


@app.route("/admin/accounts/edit/<int:user_id>", methods=["GET", "POST"])
@leadership_required
def admin_account_edit(user_id):
    conn = db()
    user = conn.execute("SELECT * FROM admin_users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        abort(404)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        display_name = request.form.get("display_name", "").strip()
        role = request.form.get("role", "officer")
        enabled = 1 if request.form.get("enabled") else 0
        password = request.form.get("password", "")
        must_change_password = 1 if request.form.get("must_change_password") else 0

        if role not in ("admin", "chief", "officer", "engine_boss"):
            role = "officer"

        actor = current_admin()
        if actor["role"] == "chief":
            # Chiefs can manage Chief and Officer accounts, but Admin accounts are immutable to them.
            if user["role"] == "admin" or role == "admin":
                conn.close()
                abort(403)

        if password:
            error = password_policy_error(password)
            if error:
                conn.close()
                flash(error, "error")
                return redirect(url_for("admin_account_edit", user_id=user_id))

        enabled_admins = conn.execute("""
            SELECT COUNT(*) AS c FROM admin_users
            WHERE role='admin' AND enabled=1
        """).fetchone()["c"]

        if user["role"] == "admin" and user["enabled"] and enabled_admins <= 1 and (role != "admin" or not enabled):
            conn.close()
            flash("At least one enabled Admin must remain.", "error")
            return redirect(url_for("admin_account_edit", user_id=user_id))

        try:
            if password:
                conn.execute("""
                    UPDATE admin_users
                    SET username=?,display_name=?,role=?,enabled=?,password_hash=?,
                        must_change_password=?,password_changed_at=?
                    WHERE id=?
                """, (
                    username,display_name,role,enabled,
                    generate_password_hash(password),
                    must_change_password,
                    int(time.time()),
                    user_id
                ))
            else:
                conn.execute("""
                    UPDATE admin_users
                    SET username=?,display_name=?,role=?,enabled=?,must_change_password=?
                    WHERE id=?
                """, (
                    username,display_name,role,enabled,must_change_password,user_id
                ))
            conn.commit()
            audit("admin_account_updated", f"account={username} role={role} enabled={enabled}")

            if session.get("admin_user_id") == user_id:
                session["admin_username"] = username
                session["admin_role"] = role

            conn.close()
            return redirect(url_for("admin_accounts"))
        except sqlite3.IntegrityError:
            flash("That username is already in use.", "error")

    conn.close()
    return render_template(
        "account_edit.html",
        user=user,
        admin_user=current_admin(),
        active_page="accounts"
    )


@app.route("/admin/new", methods=["GET", "POST"])
@staff_required
def admin_new():
    if request.method == "POST":
        f = request.form
        selected_quals = [x.strip() for x in request.form.getlist("qualification_option") if x.strip()]
        manual_quals = [x.strip() for x in fv(f, "qualifications").replace("\n", ",").split(",") if x.strip()]
        merged_qualifications = "\n".join(dict.fromkeys(selected_quals + manual_quals))
        selected_certs = [x.strip() for x in request.form.getlist("certification_option") if x.strip()]
        manual_certs = [x.strip() for x in fv(f, "certifications").replace("\n", ",").split(",") if x.strip()]
        merged_certifications = ", ".join(dict.fromkeys(selected_certs + manual_certs))
        conn = db()
        try:
            logo = save_logo(request.files.get("logo"))
            conn.execute("""
                INSERT INTO profiles(
                    slug,name,role,department,department_details,
                    location,position,crew_id,certifications,
                    qualifications,training,public_notes,logo_filename,
                    emergency_contact,relationship,emergency_phone,
                    birthdate,blood_type,allergies,medications,medical_notes,
                    pin_hash,enabled
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                fv(f, "slug"),
                fv(f, "name"),
                fv(f, "role"),
                fv(f, "department"),
                fv(f, "department_details"),
                fv(f, "location"),
                fv(f, "position"),
                fv(f, "crew_id"),
                merged_certifications,
                merged_qualifications,
                fv(f, "training"),
                fv(f, "public_notes"),
                logo,
                fv(f, "emergency_contact"),
                fv(f, "relationship"),
                fv(f, "emergency_phone"),
                fv(f, "birthdate"),
                fv(f, "blood_type"),
                fv(f, "allergies"),
                fv(f, "medications"),
                fv(f, "medical_notes"),
                generate_password_hash(fv(f, "pin")),
                1 if f.get("enabled") else 0
            ))
            conn.commit()
            audit("member_created", f'slug={fv(f, "slug")}')
            return redirect(url_for("admin"))
        except (sqlite3.IntegrityError, ValueError) as exc:
            flash(str(exc), "error")
        finally:
            conn.close()

    conn = db()
    qualification_options = conn.execute("SELECT name FROM qualification_options WHERE enabled=1 ORDER BY name").fetchall()
    certification_options = conn.execute("SELECT name FROM certification_options WHERE enabled=1 ORDER BY name").fetchall()
    conn.close()
    return render_template(
        "edit.html", p=None, qualification_options=qualification_options,
        certification_options=certification_options, admin_user=current_admin(), active_page="add"
    )


@app.route("/admin/edit/<int:profile_id>", methods=["GET", "POST"])
@staff_required
def admin_edit(profile_id):
    conn = db()
    p = conn.execute(
        "SELECT * FROM profiles WHERE id=?",
        (profile_id,)
    ).fetchone()

    if not p:
        conn.close()
        abort(404)

    audit("member_profile_opened", f"profile_id={profile_id}")

    if request.method == "POST":
        f = request.form
        selected_quals = [x.strip() for x in request.form.getlist("qualification_option") if x.strip()]
        manual_quals = [x.strip() for x in fv(f, "qualifications").replace("\n", ",").split(",") if x.strip()]
        merged_qualifications = "\n".join(dict.fromkeys(selected_quals + manual_quals))
        selected_certs = [x.strip() for x in request.form.getlist("certification_option") if x.strip()]
        manual_certs = [x.strip() for x in fv(f, "certifications").replace("\n", ",").split(",") if x.strip()]
        merged_certifications = ", ".join(dict.fromkeys(selected_certs + manual_certs))
        try:
            logo = save_logo(request.files.get("logo")) or p["logo_filename"]
            vals = [
                fv(f, "slug"),
                fv(f, "name"),
                fv(f, "role"),
                fv(f, "department"),
                fv(f, "department_details"),
                fv(f, "location"),
                fv(f, "position"),
                fv(f, "crew_id"),
                merged_certifications,
                merged_qualifications,
                fv(f, "training"),
                fv(f, "public_notes"),
                logo,
                fv(f, "emergency_contact"),
                fv(f, "relationship"),
                fv(f, "emergency_phone"),
                fv(f, "birthdate"),
                fv(f, "blood_type"),
                fv(f, "allergies"),
                fv(f, "medications"),
                fv(f, "medical_notes"),
                1 if f.get("enabled") else 0
            ]

            pin = fv(f, "pin")
            if pin:
                conn.execute("""
                    UPDATE profiles SET
                    slug=?,name=?,role=?,department=?,department_details=?,
                    location=?,position=?,crew_id=?,certifications=?,
                    qualifications=?,training=?,public_notes=?,
                    logo_filename=?,emergency_contact=?,relationship=?,
                    emergency_phone=?,birthdate=?,blood_type=?,allergies=?,
                    medications=?,medical_notes=?,enabled=?,pin_hash=?
                    WHERE id=?
                """, vals + [
                    generate_password_hash(pin),
                    profile_id
                ])
            else:
                conn.execute("""
                    UPDATE profiles SET
                    slug=?,name=?,role=?,department=?,department_details=?,
                    location=?,position=?,crew_id=?,certifications=?,
                    qualifications=?,training=?,public_notes=?,
                    logo_filename=?,emergency_contact=?,relationship=?,
                    emergency_phone=?,birthdate=?,blood_type=?,allergies=?,
                    medications=?,medical_notes=?,enabled=?
                    WHERE id=?
                """, vals + [profile_id])

            conn.commit()
            audit("member_updated", f'profile_id={profile_id}')
            conn.close()
            return redirect(url_for("admin"))
        except (sqlite3.IntegrityError, ValueError) as exc:
            flash(str(exc), "error")

    conn.close()
    conn2 = db()
    qualification_options = conn2.execute("SELECT name FROM qualification_options WHERE enabled=1 ORDER BY name").fetchall()
    certification_options = conn2.execute("SELECT name FROM certification_options WHERE enabled=1 ORDER BY name").fetchall()
    known_quals = {r["name"] for r in qualification_options}
    known_certs = {r["name"] for r in certification_options}
    custom_qualifications = ", ".join([x.strip() for x in (p["qualifications"] or "").replace("\n", ",").split(",") if x.strip() and x.strip() not in known_quals])
    custom_certifications = ", ".join([x.strip() for x in (p["certifications"] or "").replace("\n", ",").split(",") if x.strip() and x.strip() not in known_certs])
    conn2.close()
    return render_template(
        "edit.html", p=p, qualification_options=qualification_options,
        certification_options=certification_options, custom_qualifications=custom_qualifications,
        custom_certifications=custom_certifications, admin_user=current_admin(), active_page="members"
    )


@app.post("/admin/remove-logo/<int:profile_id>")
@staff_required
def remove_logo(profile_id):
    conn = db()
    p = conn.execute(
        "SELECT * FROM profiles WHERE id=?",
        (profile_id,)
    ).fetchone()

    if not p:
        conn.close()
        abort(404)

    conn.execute(
        "UPDATE profiles SET logo_filename=NULL WHERE id=?",
        (profile_id,)
    )
    conn.commit()
    conn.close()
    audit("member_logo_removed", f"profile_id={profile_id}")
    return redirect(url_for("admin_edit", profile_id=profile_id))


@app.post("/admin/reset-lockout/<int:profile_id>")
@staff_required
def reset_medical_lockout(profile_id):
    conn = db()
    p = conn.execute(
        "SELECT * FROM profiles WHERE id=?",
        (profile_id,)
    ).fetchone()

    if not p:
        conn.close()
        abort(404)

    conn.execute(
        "DELETE FROM access_attempts WHERE slug=?",
        (p["slug"],)
    )
    conn.commit()
    conn.close()

    audit("medical_lockout_reset", f'profile={p["slug"]}')
    flash(
        f'Medical PIN lockout cleared for {p["name"]}.',
        "success"
    )
    return redirect(url_for("admin"))


@app.post("/admin/delete/<int:profile_id>")
@leadership_required
def admin_delete(profile_id):
    conn = db()
    p = conn.execute(
        "SELECT slug,name FROM profiles WHERE id=?",
        (profile_id,)
    ).fetchone()
    conn.execute(
        "DELETE FROM profiles WHERE id=?",
        (profile_id,)
    )
    conn.commit()
    conn.close()

    if p:
        audit(
            "member_deleted",
            f'profile={p["slug"]} name={p["name"]}'
        )
    return redirect(url_for("admin"))


# -------------------------
# V7.4 batch members, member documents, public Red Card, deployment forms
# -------------------------

DOCUMENT_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}


def _safe_external_link(value):
    value = (value or "").strip()
    if not value:
        return ""
    if not (value.startswith("https://") or value.startswith("http://")):
        raise ValueError("External link must start with http:// or https://")
    return value


@app.route("/admin/members/batch", methods=["GET", "POST"])
@staff_required
def batch_members():
    if request.method == "POST":
        rows = []
        for i in range(1, 21):
            name = fv(request.form, f"name_{i}")
            slug = fv(request.form, f"slug_{i}")
            if not name and not slug:
                continue
            rows.append((i, name, slug))
        if not rows:
            flash("Enter at least one member.", "error")
            return redirect(url_for("batch_members"))
        conn = db()
        created = 0
        try:
            for i, name, slug in rows:
                if not name or not slug:
                    raise ValueError(f"Row {i}: Name and NFC slug are required.")
                pin = fv(request.form, f"pin_{i}")
                if not pin:
                    raise ValueError(f"Row {i}: Medical PIN is required.")
                certs = fv(request.form, f"certifications_{i}")
                quals = fv(request.form, f"qualifications_{i}").replace(",", "\n")
                conn.execute("""
                    INSERT INTO profiles(slug,name,role,department,location,position,crew_id,
                        certifications,qualifications,birthdate,pin_hash,enabled)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,1)
                """, (slug, name, fv(request.form, f"role_{i}"), fv(request.form, f"department_{i}"),
                      fv(request.form, f"location_{i}"), fv(request.form, f"position_{i}"),
                      fv(request.form, f"crew_id_{i}"), certs, quals,
                      fv(request.form, f"birthdate_{i}"), generate_password_hash(pin)))
                created += 1
            conn.commit()
        except (sqlite3.IntegrityError, ValueError) as exc:
            conn.rollback()
            conn.close()
            flash(f"Batch was not saved: {exc}", "error")
            return redirect(url_for("batch_members"))
        conn.close()
        audit("member_batch_created", f"count={created}")
        flash(f"Created {created} member(s).", "success")
        return redirect(url_for("admin"))
    return render_template("batch_members.html", admin_user=current_admin(), active_page="batch")


@app.route("/admin/member/<int:profile_id>/documents")
@staff_required
def member_documents(profile_id):
    conn = db()
    p = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not p:
        conn.close(); abort(404)
    docs = conn.execute("SELECT * FROM member_documents WHERE profile_id=? ORDER BY COALESCE(expiry_date,'9999') ASC, title", (profile_id,)).fetchall()
    conn.close()
    return render_template("member_documents.html", p=p, docs=docs, admin_user=current_admin(), active_page="members")


@app.post("/admin/member/<int:profile_id>/documents/add")
@staff_required
def member_document_add(profile_id):
    conn = db(); p = conn.execute("SELECT id FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not p: conn.close(); abort(404)
    title = fv(request.form, "title")
    doc_type = fv(request.form, "document_type") or "Other"
    if not title:
        conn.close(); flash("Document title is required.", "error"); return redirect(url_for("member_documents", profile_id=profile_id))
    filename = None
    upload = request.files.get("document")
    if upload and upload.filename:
        safe = secure_filename(upload.filename)
        ext = Path(safe).suffix.lower()
        if ext not in DOCUMENT_EXTENSIONS:
            conn.close(); flash("Document must be PDF, PNG, JPG, or JPEG.", "error"); return redirect(url_for("member_documents", profile_id=profile_id))
        filename = f"member_{profile_id}_{uuid.uuid4().hex}{ext}"
        upload.save(MEMBER_DOC_DIR / filename)
    try:
        external_link = _safe_external_link(fv(request.form, "external_link"))
    except ValueError as exc:
        conn.close(); flash(str(exc), "error"); return redirect(url_for("member_documents", profile_id=profile_id))
    now=int(time.time()); user=current_admin()
    cur=conn.execute("""INSERT INTO member_documents(profile_id,document_type,title,issue_date,expiry_date,notes,filename,
        source,external_system,external_record_id,verification_status,last_sync_at,external_link,created_by,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
        profile_id, doc_type, title, fv(request.form,"issue_date"), fv(request.form,"expiry_date"), fv(request.form,"notes"), filename,
        fv(request.form,"source") or "Department", fv(request.form,"external_system"), fv(request.form,"external_record_id"),
        fv(request.form,"verification_status") or "Department Record", None, external_link, user["username"], now, now))
    doc_id=cur.lastrowid; conn.commit(); conn.close()
    audit("member_document_uploaded", f"profile_id={profile_id} document_id={doc_id} type={doc_type}")
    flash("Document saved.", "success")
    return redirect(url_for("member_documents", profile_id=profile_id))


@app.route("/admin/member/<int:profile_id>/documents/<int:document_id>/view")
@staff_required
def member_document_view(profile_id, document_id):
    conn=db(); d=conn.execute("SELECT * FROM member_documents WHERE id=? AND profile_id=?",(document_id,profile_id)).fetchone(); conn.close()
    if not d or not d["filename"]: abort(404)
    audit("member_document_opened", f"profile_id={profile_id} document_id={document_id}")
    return send_from_directory(str(MEMBER_DOC_DIR), d["filename"], as_attachment=False)


@app.post("/admin/member/<int:profile_id>/documents/<int:document_id>/delete")
@staff_required
def member_document_delete(profile_id, document_id):
    conn=db(); d=conn.execute("SELECT * FROM member_documents WHERE id=? AND profile_id=?",(document_id,profile_id)).fetchone()
    if not d: conn.close(); abort(404)
    conn.execute("DELETE FROM member_documents WHERE id=?",(document_id,)); conn.commit(); conn.close()
    if d["filename"]: (MEMBER_DOC_DIR/d["filename"]).unlink(missing_ok=True)
    audit("member_document_deleted", f"profile_id={profile_id} document_id={document_id}")
    flash("Document deleted.", "success")
    return redirect(url_for("member_documents", profile_id=profile_id))


@app.post("/p/<slug>/red-card/unlock")
@limiter.limit("12 per 15 minutes")
def unlock_red_card_public(slug):
    p=profile_or_404(slug); ip=client_ip()
    if not p["red_card_filename"]:
        flash("No Red Card is on file.", "error"); return redirect(url_for("profile", slug=slug)+"#red-card")
    if is_locked_out(slug, ip):
        audit("red_card_unlock_locked_out", f"profile={slug}")
        flash("Too many failed attempts. Try again in 5 minutes.", "error")
        return redirect(url_for("profile", slug=slug)+"#red-card")
    ok=check_password_hash(p["pin_hash"], request.form.get("pin", "")); log_attempt(slug,ip,ok)
    if ok:
        session[f"redcard_once:{slug}"]=True
        # Create the protected view token before redirecting. This avoids the
        # browser subresource race that could make the image/PDF request arrive
        # before the temporary permission cookie existed.
        session[f"redcard_view:{slug}"] = secrets.token_urlsafe(24)
        audit("red_card_opened", f"profile={slug} access=public_pin")
    else:
        audit("red_card_unlock_failure", f"profile={slug}"); flash("Incorrect PIN.", "error")
    return redirect(url_for("profile", slug=slug)+"#red-card")


@app.route("/p/<slug>/red-card/file")
def public_red_card_file(slug):
    p = profile_or_404(slug)
    if not p["red_card_filename"]:
        abort(404)

    # Staff who are already authenticated on an approved device may view the
    # Red Card normally. Public-profile viewers must present the per-view token
    # created by a successful PIN unlock for this member.
    user = current_admin() if current_device() else None
    staff_ok = bool(user and user["role"] in ("admin", "chief", "officer"))
    supplied = request.args.get("view", "")
    expected = session.get(f"redcard_view:{slug}", "")
    public_ok = bool(supplied and expected and secrets.compare_digest(supplied, expected))
    if not (staff_ok or public_ok):
        abort(403)

    response = send_from_directory(str(UPLOAD_DIR), p["red_card_filename"], as_attachment=False)
    # The global security header is DENY. Permit the protected PDF to render
    # inside the same-origin <object> on the member profile only.
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


FORM_SCHEMAS = {
    "CTR": [
        ("incident_name","Incident Name"),("incident_number","Incident Order Number"),("fire_code","Fire Code"),
        ("resource_order","Resource Order Number"),("crew_name","Crew / Resource Name"),("supervisor","Supervisor"),
        ("unit_code","Apparatus / Unit"),("location","Location"),("reporting_period","Reporting Period"),
        ("crew_time","Crew Time Entries"),("positions","Positions / Roles"),("remarks","Remarks"),
        ("prepared_by","Prepared By"),("approved_by","Approved By")],
    "OF288": [
        ("hired_at","1. Hired At"),("employee_id","2. Employee Common Identifier"),("employment_type","3. Type of Employment"),
        ("hiring_unit","4. Hiring Unit Name"),("employee_name","5. Name"),("hiring_phone","6. Hiring Unit Phone"),
        ("hiring_fax","7. Hiring Unit Fax"),("incident_name","8. Incident Name"),("incident_order","9. Incident Order Number"),
        ("fire_code","10. Fire Code"),("resource_request","11. Resource Request Number"),("position_code","12. Position Code"),
        ("ad_class","13. AD Class"),("ad_rate","14. AD Rate"),("accounting_code","15. Home/Hiring Unit Accounting Code"),
        ("year","Year"),("time_entries","Time Entries"),("total_hours","17. Total Hours"),("commissary_travel","18. Commissary and Travel"),
        ("remarks","19. Remarks"),("employee_signature","20. Employee Signature / Name"),("time_officer_signature","21. Time Officer Signature / Name")],
    "OF286": [
        ("contractor","1. Contractor Name and Address"),("ein_ssn","EIN/SSN"),("incident_name","2. Incident or Project Name"),
        ("agreement_number","3. Agreement Number"),("agreement_beg","Agreement Begin Date"),("agreement_end","Agreement End Date"),
        ("equipment","5. Equipment"),("point_of_hire","6. Point of Hire"),("date_hire","7. Date of Hire"),("time_hire","8. Time of Hire"),
        ("admin_office","9. Administrative Office for Payment"),("operator_furnished","Operator Furnished By"),("resource_order","12. Resource Order Number"),
        ("use_entries","14. Units Worked / Rate / Amount"),("special_rates","15. Special Rates / Amount"),("total_earned","16. Total Amount Earned"),
        ("guarantee","17. Guarantee"),("amount_due","18. Amount"),("charge_code","19. Charge Code"),("object_code","20. Object Code"),
        ("release_date","21. Release Date"),("release_time","21. Release Time"),("remarks","22. Remarks"),("damage","Damage Status"),
        ("gross","23. Gross Amount Due"),("deductions","24. Deductions"),("total_due","25. Total Amount Due"),("net_due","28. Net Amount Due"),
        ("contractor_name","34. Contractor / Representative Name"),("government_name","35. Government Representative Name")]
}


def _deployment_form_defaults(deployment, form_type, profile_id=None):
    conn=db()
    crew=conn.execute("""SELECT dc.deployment_role,p.* FROM deployment_crew dc JOIN profiles p ON p.id=dc.profile_id
        WHERE dc.deployment_id=? ORDER BY dc.joined_at""",(deployment["id"],)).fetchall()
    times=conn.execute("SELECT t.*,p.name FROM timesheets t JOIN profiles p ON p.id=t.profile_id WHERE t.deployment_id=? ORDER BY t.work_date,t.start_time",(deployment["id"],)).fetchall()
    atimes=conn.execute("SELECT * FROM apparatus_timesheets WHERE deployment_id=? ORDER BY work_date,start_time",(deployment["id"],)).fetchall()
    subject=None
    if profile_id: subject=conn.execute("SELECT * FROM profiles WHERE id=?",(profile_id,)).fetchone()
    conn.close()
    crew_names=", ".join([c["name"] for c in crew])
    roles=", ".join([f'{c["name"]}: {c["deployment_role"] or c["position"] or "Crew"}' for c in crew])
    crew_time="; ".join([f'{t["name"]} {t["work_date"]} {t["start_time"]}-{t["end_time"]} ({t["hours"]:.2f}h)' for t in times])
    def _apparatus_usage_line(t):
        extras=[]
        if t["start_odometer"] is not None and t["end_odometer"] is not None:
            extras.append(f'{float(t["end_odometer"])-float(t["start_odometer"]):.1f} mi')
        if t["start_engine_hours"] is not None and t["end_engine_hours"] is not None:
            extras.append(f'{float(t["end_engine_hours"])-float(t["start_engine_hours"]):.1f} engine hr')
        suffix = f"; {'; '.join(extras)}" if extras else ""
        return f'{t["work_date"]} {t["start_time"]}-{t["end_time"] or "Live"} ({t["hours"]:.2f}h){suffix}'
    app_time="; ".join([_apparatus_usage_line(t) for t in atimes])
    total_subject=sum(float(t["hours"] or 0) for t in times if not subject or t["profile_id"]==subject["id"])
    now=datetime.now()
    base={"incident_name":deployment["incident_name"] or "","incident_number":deployment["incident_number"] or "",
          "incident_order":deployment["incident_number"] or "","location":deployment["location"] or "","unit_code":deployment["unit_code"] or "",
          "crew_name":crew_names,"supervisor":deployment["leader_name"] or "","positions":roles,"crew_time":crew_time,"time_entries":crew_time,
          "use_entries":app_time,"equipment":f'{deployment["unit_code"]} - {deployment["apparatus_name"]}',"employee_name":subject["name"] if subject else "",
          "employee_id":subject["crew_id"] if subject else "","position_code":subject["position"] if subject else "",
          "hiring_unit":subject["department"] if subject else "","contractor":deployment["apparatus_name"] or "","resource_order":deployment["unit_code"] or "",
          "resource_request":deployment["unit_code"] or "","year":str(now.year),"total_hours":f"{total_subject:.2f}","total_earned":"",
          "reporting_period":", ".join(sorted(set(t["work_date"] for t in times))),"prepared_by":current_admin()["display_name"],
          "remarks":"Generated from deployment data. Review all fields before finalizing."}
    return {key: base.get(key, "") for key,_ in FORM_SCHEMAS[form_type]}


def _next_form_version(conn, deployment_id, form_type, profile_id):
    row=conn.execute("SELECT MAX(version) AS v FROM deployment_forms WHERE deployment_id=? AND form_type=? AND COALESCE(subject_profile_id,0)=COALESCE(?,0)",
                     (deployment_id,form_type,profile_id)).fetchone()
    return int(row["v"] or 0)+1


def _write_form_pdf(path, form_type, deployment, fields):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
    c=canvas.Canvas(str(path), pagesize=letter)
    width,height=letter
    c.setFont("Helvetica-Bold",15); c.drawString(0.55*inch,height-0.6*inch,f"{form_type} — Deployment Form")
    c.setFont("Helvetica",8); c.drawRightString(width-0.55*inch,height-0.6*inch,f"Deployment #{deployment['id']}")
    c.setFont("Helvetica-Bold",9); c.drawString(0.55*inch,height-0.85*inch,"REVIEW BEFORE SUBMISSION — generated from department deployment data")
    y=height-1.15*inch
    for key,label in FORM_SCHEMAS[form_type]:
        val=str(fields.get(key,"") or "")
        c.setFont("Helvetica-Bold",8); c.drawString(0.55*inch,y,label)
        y-=11
        c.setFont("Helvetica",8)
        # simple wrapped text
        words=val.split(); line=""; lines=[]
        for w in words:
            test=(line+" "+w).strip()
            if c.stringWidth(test,"Helvetica",8) < width-1.2*inch:
                line=test
            else:
                if line: lines.append(line)
                line=w
        if line: lines.append(line)
        if not lines: lines=[""]
        for ln in lines[:4]:
            c.drawString(0.65*inch,y,ln); y-=10
        c.line(0.55*inch,y+5,width-0.55*inch,y+5); y-=8
        if y < 0.7*inch:
            c.showPage(); y=height-0.65*inch
    c.save()


@app.route("/admin/wildland/deployment/<int:deployment_id>/forms")
@wildland_required
def deployment_forms(deployment_id):
    deployment=deployment_or_404(deployment_id); user=current_admin()
    conn=db(); forms=conn.execute("""SELECT f.*,p.name AS subject_name FROM deployment_forms f LEFT JOIN profiles p ON p.id=f.subject_profile_id
        WHERE f.deployment_id=? ORDER BY f.form_type,f.created_at DESC""",(deployment_id,)).fetchall()
    crew=conn.execute("""SELECT DISTINCT p.id,p.name FROM deployment_crew dc JOIN profiles p ON p.id=dc.profile_id WHERE dc.deployment_id=? ORDER BY p.name""",(deployment_id,)).fetchall(); conn.close()
    return render_template("deployment_forms.html",deployment=deployment,forms=forms,crew=crew,can_manage=can_manage_deployment(user,deployment),admin_user=user,active_page="wildland")


@app.route("/admin/wildland/deployment/<int:deployment_id>/forms/new/<form_type>", methods=["GET","POST"])
@wildland_required
def deployment_form_new(deployment_id, form_type):
    form_type=form_type.upper()
    if form_type not in FORM_SCHEMAS: abort(404)
    deployment=deployment_or_404(deployment_id); user=current_admin()
    if not can_manage_deployment(user,deployment): abort(403)
    profile_id=request.values.get("profile_id", type=int)
    if form_type=="OF288" and not profile_id:
        flash("Choose a member for the OF-288.","error"); return redirect(url_for("deployment_forms",deployment_id=deployment_id))
    fields=_deployment_form_defaults(deployment,form_type,profile_id)
    return render_template("deployment_form_editor.html",deployment=deployment,form_type=form_type,schema=FORM_SCHEMAS[form_type],fields=fields,profile_id=profile_id,admin_user=user,active_page="wildland")


@app.post("/admin/wildland/deployment/<int:deployment_id>/forms/preview/<form_type>")
@wildland_required
def deployment_form_preview(deployment_id, form_type):
    form_type=form_type.upper(); deployment=deployment_or_404(deployment_id); user=current_admin()
    if form_type not in FORM_SCHEMAS or not can_manage_deployment(user,deployment): abort(403)
    fields={key:request.form.get(key,"") for key,_ in FORM_SCHEMAS[form_type]}
    return render_template("deployment_form_preview.html",deployment=deployment,form_type=form_type,schema=FORM_SCHEMAS[form_type],fields=fields,profile_id=request.form.get("profile_id",""),admin_user=user,active_page="wildland")


@app.post("/admin/wildland/deployment/<int:deployment_id>/forms/save/<form_type>")
@wildland_required
def deployment_form_save(deployment_id, form_type):
    form_type=form_type.upper(); deployment=deployment_or_404(deployment_id); user=current_admin()
    if form_type not in FORM_SCHEMAS or not can_manage_deployment(user,deployment): abort(403)
    profile_id=request.form.get("profile_id",type=int)
    fields={key:request.form.get(key,"") for key,_ in FORM_SCHEMAS[form_type]}
    defaults=_deployment_form_defaults(deployment,form_type,profile_id)
    overridden=[key for key in fields if str(fields.get(key,"")) != str(defaults.get(key,""))]
    conn=db(); version=_next_form_version(conn,deployment_id,form_type,profile_id); now=int(time.time())
    cur=conn.execute("""INSERT INTO deployment_forms(deployment_id,form_type,subject_profile_id,version,field_data,status,created_by,created_at,updated_by,updated_at)
        VALUES(?,?,?,?,?,'Final',?,?,?,?)""",(deployment_id,form_type,profile_id,version,json.dumps(fields),user["username"],now,user["username"],now))
    form_id=cur.lastrowid
    filename=f"deployment_{deployment_id}_{form_type.lower()}_{form_id}_v{version}.pdf"
    path=DEPLOYMENT_FORM_DIR/filename
    _write_form_pdf(path,form_type,deployment,fields)
    conn.execute("UPDATE deployment_forms SET pdf_filename=? WHERE id=?",(filename,form_id)); conn.commit(); conn.close()
    audit("deployment_form_generated",f"deployment_id={deployment_id} form_id={form_id} type={form_type} version={version}")
    if overridden:
        audit("deployment_form_overridden",f"deployment_id={deployment_id} form_id={form_id} fields={','.join(overridden)}")
    flash(f"{form_type} version {version} saved with this deployment.","success")
    return redirect(url_for("deployment_forms",deployment_id=deployment_id))


@app.route("/admin/wildland/deployment/<int:deployment_id>/forms/<int:form_id>/view")
@wildland_required
def deployment_form_view(deployment_id, form_id):
    conn=db(); f=conn.execute("SELECT * FROM deployment_forms WHERE id=? AND deployment_id=?",(form_id,deployment_id)).fetchone(); conn.close()
    if not f or not f["pdf_filename"]: abort(404)
    audit("deployment_form_opened",f"deployment_id={deployment_id} form_id={form_id}")
    return send_from_directory(str(DEPLOYMENT_FORM_DIR),f["pdf_filename"],as_attachment=False)

@app.route("/admin/member/<int:profile_id>/documents/<int:document_id>/edit", methods=["GET", "POST"])
@staff_required
def member_document_edit(profile_id, document_id):
    conn = db()
    p = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    d = conn.execute("SELECT * FROM member_documents WHERE id=? AND profile_id=?", (document_id, profile_id)).fetchone()
    if not p or not d:
        conn.close(); abort(404)
    if request.method == "POST":
        try:
            external_link = _safe_external_link(fv(request.form, "external_link"))
        except ValueError as exc:
            conn.close(); flash(str(exc), "error"); return redirect(url_for("member_document_edit", profile_id=profile_id, document_id=document_id))
        filename = d["filename"]
        upload = request.files.get("document")
        if upload and upload.filename:
            safe = secure_filename(upload.filename); ext = Path(safe).suffix.lower()
            if ext not in DOCUMENT_EXTENSIONS:
                conn.close(); flash("Document must be PDF, PNG, JPG, or JPEG.", "error"); return redirect(url_for("member_document_edit", profile_id=profile_id, document_id=document_id))
            new_filename = f"member_{profile_id}_{uuid.uuid4().hex}{ext}"
            upload.save(MEMBER_DOC_DIR / new_filename)
            if filename: (MEMBER_DOC_DIR / filename).unlink(missing_ok=True)
            filename = new_filename
        now=int(time.time()); user=current_admin()
        conn.execute("""UPDATE member_documents SET document_type=?,title=?,issue_date=?,expiry_date=?,notes=?,filename=?,source=?,external_system=?,external_record_id=?,verification_status=?,external_link=?,updated_at=? WHERE id=?""",
                     (fv(request.form,"document_type") or "Other", fv(request.form,"title"), fv(request.form,"issue_date"), fv(request.form,"expiry_date"), fv(request.form,"notes"), filename,
                      fv(request.form,"source"), fv(request.form,"external_system"), fv(request.form,"external_record_id"), fv(request.form,"verification_status") or "Department Record", external_link, now, document_id))
        conn.commit(); conn.close()
        audit("member_document_updated", f"profile_id={profile_id} document_id={document_id}")
        flash("Document updated.", "success")
        return redirect(url_for("member_documents", profile_id=profile_id))
    conn.close()
    return render_template("member_document_edit.html", p=p, d=d, admin_user=current_admin(), active_page="members")

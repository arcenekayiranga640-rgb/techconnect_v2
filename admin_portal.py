"""
TechConnect admin portal
========================
A self-contained Flask blueprint mounted at /admin.

It deliberately does NOT import app.py (that would create a circular import when
app.py is run as a script).  app.py wires it up with:

    import admin_portal
    admin_portal.init_app(app, db=get_db_connection, mailer=send_email_safe, mail_ready=lambda: ...)

Contents
  1. constants & small helpers (time, formatting)
  2. schema + migrations           -> ensure_schema()
  3. settings + audit log
  4. security (password, lockout, CSRF, session idle-timeout)
  5. domain logic: subscriptions, unlock/TNX ledger, retention alerts, metrics
  6. routes (dashboard, revenue, unlocks, clients, technicians, verifications,
             transactions, subscriptions, retention, settings, export)
  7. background scheduler for retention reminders
"""
import csv
import hmac
import io
import math
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlencode, urlparse

from flask import (Blueprint, Response, abort, current_app, flash, jsonify,
                   redirect, render_template, request, session, url_for)
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

# ══════════════════════════════════════════════════════════════════════════════
# 1. CONSTANTS & HELPERS
# ══════════════════════════════════════════════════════════════════════════════
PLANS = {
    "1-month": {"label": "1-Month", "price": 3000, "days": 30},
    "3-month": {"label": "3-Month", "price": 7000, "days": 90},
}
PLAN_LABELS = {**{k: v["label"] for k, v in PLANS.items()}, "trial": "7-Day Trial"}
TRIAL_DAYS = 7
UNLOCK_PRICE = 200
UNLOCK_HOURS = 24
# The ONE support address for the whole site (footer, policies, e-mails).  It lives here so that
# app.py and this module share a single value without a circular import.
SUPPORT_EMAIL = "techconnectsupport13@gmail.com"
PAYMENT_METHODS = ("cash", "momo", "bank", "complimentary", "other")
ALERT_STAGES = ("7-day", "3-day", "1-day")
STAGE_LABEL = {"7-day": "7-Day", "3-day": "3-Day", "1-day": "1-Day"}
STAGE_RANK = {"7-day": 1, "3-day": 2, "1-day": 3}
MAX_ALERT_ATTEMPTS = 3
PER_PAGE = 25

DEFAULT_ADMIN_PASSWORD = "TechConnect@Admin2026"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or DEFAULT_ADMIN_PASSWORD
ADMIN_IDLE_TIMEOUT = 60 * 60          # sign out after 60 min of inactivity
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW = 15 * 60                # 5 failures / 15 min / IP -> locked out
CAT_OFFSET = timedelta(hours=2)       # Rwanda time (UTC+2); the DB stores UTC
DB_FMT = "%Y-%m-%d %H:%M:%S"

_deps = {"db": None, "mailer": None, "mail_ready": lambda: False, "mail_problem": lambda: None}


def utcnow():
    """Naive UTC 'now' (SQLite's datetime('now') is UTC too)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_db(dt):
    return dt.strftime(DB_FMT)


def from_db(s):
    if not s:
        return None
    try:
        return datetime.strptime(str(s)[:19], DB_FMT)
    except ValueError:
        return None


def fmt_dt(s):
    """UTC db string -> 'YYYY-MM-DD HH:MM' in Rwanda time."""
    dt = from_db(s)
    return (dt + CAT_OFFSET).strftime("%Y-%m-%d %H:%M") if dt else "—"


def fmt_date(s):
    dt = from_db(s)
    return (dt + CAT_OFFSET).strftime("%Y-%m-%d") if dt else "—"


def fmt_rwf(v):
    try:
        return f"{int(v or 0):,}"
    except (TypeError, ValueError):
        return "0"


def days_left(expires, now=None):
    """Whole days remaining, rounded UP (so '<24h left' == 1). None if no/expired date."""
    exp = from_db(expires) if not isinstance(expires, datetime) else expires
    if not exp:
        return None
    now = now or utcnow()
    secs = (exp - now).total_seconds()
    return math.ceil(secs / 86400) if secs > 0 else 0


def remaining_label(expires, now=None):
    exp = from_db(expires)
    if not exp:
        return "—"
    d = days_left(exp, now)
    if d == 0:
        return "Expired"
    return f"{d} day" + ("" if d == 1 else "s")


def stage_for(d):
    """Reminder bucket for a whole-days-remaining value."""
    if d is None or d < 1:
        return None
    if d <= 1:
        return "1-day"
    if d <= 3:
        return "3-day"
    if d <= 7:
        return "7-day"
    return None


def normalize_phone(raw):
    """-> canonical Rwandan mobile '07XXXXXXXX' or None if invalid."""
    digits = re.sub(r"\D", "", raw or "")
    if digits.startswith("250") and len(digits) == 12:
        digits = "0" + digits[3:]
    elif len(digits) == 9 and digits[0] == "7":
        digits = "0" + digits
    return digits if re.fullmatch(r"07\d{8}", digits) else None


def normalize_tnx(raw):
    """Upper-case alphanumerics only, so 'tx-123 456' and 'TX123456' are the same code."""
    return re.sub(r"[^A-Z0-9]", "", (raw or "").upper())


def get_db():
    return _deps["db"]()


def client_ip():
    return request.remote_addr or "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# 2. SCHEMA + MIGRATIONS
# ══════════════════════════════════════════════════════════════════════════════
def ensure_schema(conn):
    """Idempotent: create admin tables, add technician columns, backfill. Safe to call every start."""
    for col, defn in [
        ("subscription_plan", "TEXT DEFAULT NULL"),
        ("subscription_expires", "TEXT DEFAULT NULL"),
        ("is_suspended", "INTEGER DEFAULT 0"),
        ("suspended_reason", "TEXT DEFAULT NULL"),
        ("suspended_at", "TEXT DEFAULT NULL"),
    ]:
        try:
            conn.execute(f"ALTER TABLE technicians ADD COLUMN {col} {defn}")
        except sqlite3.OperationalError:
            pass  # column already exists

    conn.executescript("""
    CREATE TABLE IF NOT EXISTS subscription_payments (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        technician_id   INTEGER,
        technician_name TEXT NOT NULL,
        plan            TEXT NOT NULL,
        amount          INTEGER NOT NULL DEFAULT 0,
        method          TEXT NOT NULL DEFAULT 'cash',
        reference       TEXT DEFAULT '',
        note            TEXT DEFAULT '',
        period_start    TEXT,
        period_end      TEXT,
        granted_by      TEXT DEFAULT 'admin',
        created_at      TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_subpay_created ON subscription_payments(created_at);

    CREATE TABLE IF NOT EXISTS unlock_ledger (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        client_phone    TEXT NOT NULL,
        tnx_code        TEXT NOT NULL,
        technician_id   INTEGER,
        technician_name TEXT,
        amount          INTEGER NOT NULL DEFAULT 200,
        status          TEXT NOT NULL DEFAULT 'valid',
        ip              TEXT,
        created_at      TEXT DEFAULT (datetime('now')),
        expires_at      TEXT,
        voided_at       TEXT,
        void_reason     TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS ux_unlock_tnx ON unlock_ledger(tnx_code);
    CREATE INDEX IF NOT EXISTS idx_unlock_phone ON unlock_ledger(client_phone);
    CREATE INDEX IF NOT EXISTS idx_unlock_created ON unlock_ledger(created_at);

    CREATE TABLE IF NOT EXISTS tnx_reuse_attempts (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        tnx_code           TEXT NOT NULL,
        client_phone       TEXT,
        ip                 TEXT,
        original_unlock_id INTEGER,
        attempted_at       TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS retention_alerts (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        technician_id   INTEGER NOT NULL,
        stage           TEXT NOT NULL,
        expiry_snapshot TEXT NOT NULL,
        to_email        TEXT,
        days_left       INTEGER,
        status          TEXT NOT NULL DEFAULT 'pending',
        attempts        INTEGER NOT NULL DEFAULT 1,
        error           TEXT,
        created_at      TEXT DEFAULT (datetime('now')),
        sent_at         TEXT,
        UNIQUE (technician_id, stage, expiry_snapshot)
    );

    CREATE TABLE IF NOT EXISTS admin_audit_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        action      TEXT NOT NULL,
        target_type TEXT,
        target_id   TEXT,
        detail      TEXT,
        ip          TEXT,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS app_settings (
        key   TEXT PRIMARY KEY,
        value TEXT
    );
    """)

    # Every technician who has never had a plan gets the promised 7-day trial,
    # counted from their sign-up date.  (A revoked plan has expires set, so it is left alone.)
    conn.execute("""
        UPDATE technicians
           SET subscription_plan = 'trial',
               subscription_expires = datetime(COALESCE(created_at, datetime('now')), '+7 days')
         WHERE subscription_plan IS NULL AND subscription_expires IS NULL
    """)

    # One-time import of the legacy payment_claims table into the new ledger.
    # INSERT OR IGNORE + the UNIQUE index means a code used twice in the old data is only kept once.
    done = conn.execute("SELECT value FROM app_settings WHERE key='unlock_backfill_done'").fetchone()
    if not done:
        has_old = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='payment_claims'").fetchone()
        if has_old:
            conn.execute("""
                INSERT OR IGNORE INTO unlock_ledger
                    (client_phone, tnx_code, technician_name, amount, status, ip, created_at, expires_at)
                SELECT phone,
                       UPPER(REPLACE(REPLACE(TRIM(code), ' ', ''), '-', '')),
                       'All technicians (24h pass)', ?, 'valid', ip, claimed_at,
                       datetime(claimed_at, '+24 hours')
                  FROM payment_claims
                 WHERE TRIM(COALESCE(code, '')) != ''
            """, (UNLOCK_PRICE,))
        conn.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('unlock_backfill_done', '1')")
    conn.commit()


# ══════════════════════════════════════════════════════════════════════════════
# 3. SETTINGS + AUDIT LOG
# ══════════════════════════════════════════════════════════════════════════════
SETTING_DEFAULTS = {
    "retention_enabled": "1",
    "enforce_expiry": "0",
    "site_url": os.environ.get("SITE_URL", "https://techconnect-v2.onrender.com"),
}


def get_setting(conn, key, default=None):
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    if row is not None and row[0] is not None:
        return row[0]
    return SETTING_DEFAULTS.get(key, default)


def set_setting(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)", (key, str(value)))


def audit(conn, action, target_type=None, target_id=None, detail="", ip=None):
    try:
        ip = ip or (client_ip() if request else None)
    except RuntimeError:           # outside a request (scheduler)
        ip = ip or "system"
    conn.execute(
        "INSERT INTO admin_audit_log (action, target_type, target_id, detail, ip) VALUES (?,?,?,?,?)",
        (action, target_type, None if target_id is None else str(target_id), (detail or "")[:500], ip))


# ══════════════════════════════════════════════════════════════════════════════
# 4. SECURITY
# ══════════════════════════════════════════════════════════════════════════════
_FAILS = {}                 # ip -> [timestamps of recent failed logins] (per-process)
_FAILS_LOCK = threading.Lock()


def _recent_fails(ip):
    cutoff = time.time() - LOGIN_WINDOW
    with _FAILS_LOCK:
        _FAILS[ip] = [t for t in _FAILS.get(ip, []) if t > cutoff]
        return list(_FAILS[ip])


def lockout_minutes(ip):
    fails = _recent_fails(ip)
    if len(fails) < LOGIN_MAX_FAILS:
        return 0
    return max(1, math.ceil((min(fails) + LOGIN_WINDOW - time.time()) / 60))


def register_failed_login(ip):
    with _FAILS_LOCK:
        _FAILS.setdefault(ip, []).append(time.time())


def clear_failed_logins(ip):
    with _FAILS_LOCK:
        _FAILS.pop(ip, None)


def using_default_password(conn):
    """True while the admin is still on the built-in default password."""
    return not get_setting(conn, "admin_password_hash") and ADMIN_PASSWORD == DEFAULT_ADMIN_PASSWORD


def verify_admin_password(candidate):
    conn = get_db()
    try:
        stored = get_setting(conn, "admin_password_hash")
    finally:
        conn.close()
    if stored:
        return check_password_hash(stored, candidate or "")
    return hmac.compare_digest((candidate or "").encode(), ADMIN_PASSWORD.encode())


def strong_password(pw):
    return (len(pw) >= 10 and re.search(r"[A-Z]", pw) and re.search(r"[a-z]", pw)
            and re.search(r"\d", pw) and re.search(r"[^A-Za-z0-9]", pw))


def is_admin():
    if session.get("is_admin") is not True:
        return False
    return (time.time() - session.get("admin_seen", 0)) < ADMIN_IDLE_TIMEOUT


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def csrf_ok():
    sent = request.form.get("csrf_token", "")
    real = session.get("csrf", "")
    return bool(real) and hmac.compare_digest(sent.encode(), real.encode())


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_admin():
            session.pop("is_admin", None)
            return redirect(url_for("admin.login"))
        session["admin_seen"] = time.time()
        return view(*args, **kwargs)
    return wrapped


def admin_post(view):
    """admin_required + a valid CSRF token (for every state-changing request)."""
    @wraps(view)
    @admin_required
    def wrapped(*args, **kwargs):
        if not csrf_ok():
            flash("Your session token expired. Please repeat the action.", "error")
            return redirect(safe_next(request.form.get("next")) or url_for("admin.dashboard"))
        return view(*args, **kwargs)
    return wrapped


def safe_next(target):
    """Only allow redirects back to /admin/... paths (no open redirect)."""
    if not target:
        return None
    p = urlparse(target)
    if p.scheme or p.netloc or not p.path.startswith("/admin"):
        return None
    return target


def back(default_endpoint="admin.dashboard"):
    return redirect(safe_next(request.form.get("next")) or url_for(default_endpoint))


# ══════════════════════════════════════════════════════════════════════════════
# 5. DOMAIN LOGIC
# ══════════════════════════════════════════════════════════════════════════════
ACTIVE_SQL = "COALESCE(is_suspended,0) = 0 AND subscription_expires IS NOT NULL AND subscription_expires > datetime('now')"


# ── 5a. Subscriptions (manual override) ─────────────────────────────────────
def apply_subscription_action(conn, tech_id, action, plan=None, days=None, method="cash",
                              reference="", note="", amount=None, record_payment=True):
    """Grant / extend / revoke a technician's subscription.  -> (ok: bool, message: str)"""
    tech = conn.execute(
        "SELECT id, full_name, subscription_plan, subscription_expires FROM technicians WHERE id = ?",
        (tech_id,)).fetchone()
    if not tech:
        return False, "Technician not found."
    now = utcnow()
    current_exp = from_db(tech["subscription_expires"])
    method = method if method in PAYMENT_METHODS else "other"
    reference = (reference or "").strip()[:60]
    note = (note or "").strip()[:200]

    if action == "revoke":
        conn.execute("UPDATE technicians SET subscription_plan = NULL, subscription_expires = ? WHERE id = ?",
                     (to_db(now), tech_id))
        return True, f"Subscription revoked for {tech['full_name']}."

    if action == "grant":
        if plan not in PLANS:
            return False, "Choose a valid plan (1-Month or 3-Month)."
        new_exp = now + timedelta(days=PLANS[plan]["days"])
        paid = PLANS[plan]["price"] if (record_payment and method != "complimentary") else 0
        pay_plan, start = plan, now
    elif action == "extend":
        try:
            n = int(days)
        except (TypeError, ValueError):
            return False, "Enter the number of days to add."
        if not 1 <= n <= 365:
            return False, "Extension must be between 1 and 365 days."
        if not tech["subscription_plan"]:
            return False, "This technician has no plan to extend. Use Grant instead."
        start = current_exp if (current_exp and current_exp > now) else now
        new_exp = start + timedelta(days=n)
        plan = pay_plan = tech["subscription_plan"]
        try:
            paid = int(amount or 0) if (record_payment and method != "complimentary") else 0
        except (TypeError, ValueError):
            return False, "Amount must be a whole number."
        if paid < 0 or paid > 1_000_000:
            return False, "Amount is out of range."
    else:
        return False, "Unknown action."

    conn.execute("UPDATE technicians SET subscription_plan = ?, subscription_expires = ? WHERE id = ?",
                 (plan, to_db(new_exp), tech_id))
    conn.execute(
        """INSERT INTO subscription_payments
               (technician_id, technician_name, plan, amount, method, reference, note,
                period_start, period_end, granted_by)
           VALUES (?,?,?,?,?,?,?,?,?, 'admin')""",
        (tech_id, tech["full_name"], pay_plan, paid, method, reference, note, to_db(start), to_db(new_exp)))
    verb = "granted" if action == "grant" else "extended"
    return True, (f"{PLAN_LABELS.get(plan, plan)} {verb} for {tech['full_name']} — "
                  f"now valid until {fmt_date(to_db(new_exp))}.")


# ── 5b. Unlock / TNX anti-reuse ledger ──────────────────────────────────────
def claim_unlock(conn, phone, tnx, technician_id=None, ip=None):
    """Atomically record an unlock.  The UNIQUE index on tnx_code is the real guard:
    two simultaneous requests with the same code cannot both succeed.
    -> {'ok': True, 'id', 'expires_at'}  or  {'ok': False, 'reason': 'reused'|'invalid', 'original': row}"""
    phone_n, tnx_n = normalize_phone(phone), normalize_tnx(tnx)
    if not phone_n:
        return {"ok": False, "reason": "invalid_phone"}
    if not 6 <= len(tnx_n) <= 32:
        return {"ok": False, "reason": "invalid_tnx"}
    tech_name = None
    if technician_id:
        row = conn.execute("SELECT full_name FROM technicians WHERE id = ?", (technician_id,)).fetchone()
        if row:
            tech_name = row["full_name"]
        else:
            technician_id = None
    now = utcnow()
    expires = now + timedelta(hours=UNLOCK_HOURS)
    try:
        cur = conn.execute(
            """INSERT INTO unlock_ledger
                   (client_phone, tnx_code, technician_id, technician_name, amount, status, ip, created_at, expires_at)
               VALUES (?,?,?,?,?, 'valid', ?,?,?)""",
            (phone_n, tnx_n, technician_id, tech_name or "All technicians (24h pass)",
             UNLOCK_PRICE, ip, to_db(now), to_db(expires)))
        conn.commit()
        return {"ok": True, "id": cur.lastrowid, "expires_at": expires, "phone": phone_n, "tnx": tnx_n}
    except sqlite3.IntegrityError:
        conn.rollback()
        orig = conn.execute("SELECT id FROM unlock_ledger WHERE tnx_code = ?", (tnx_n,)).fetchone()
        conn.execute(
            "INSERT INTO tnx_reuse_attempts (tnx_code, client_phone, ip, original_unlock_id) VALUES (?,?,?,?)",
            (tnx_n, phone_n, ip, orig["id"] if orig else None))
        conn.commit()
        return {"ok": False, "reason": "reused", "original": orig}


def unlock_is_valid(conn, unlock_id):
    """True while the ledger row exists, is not voided and has not expired."""
    row = conn.execute("SELECT status, expires_at FROM unlock_ledger WHERE id = ?", (unlock_id,)).fetchone()
    if not row or row["status"] != "valid":
        return False
    exp = from_db(row["expires_at"])
    return bool(exp and exp > utcnow())


# ── 5c. Retention reminders ─────────────────────────────────────────────────
def build_reminder_email(name, stage, expires, plan, site_url):
    d = {"7-day": "7 days", "3-day": "3 days", "1-day": "1 day"}[stage]
    when = {"7-day": "in 7 days", "3-day": "in 3 days", "1-day": "tomorrow"}[stage]
    subject = f"Your TechConnect subscription expires {when}"
    link = f"{site_url.rstrip('/')}/select-plan"
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;color:#0f172a;">
      <div style="background:#0F172A;padding:20px 26px;border-radius:12px 12px 0 0;">
        <h2 style="color:#fff;margin:0;font-size:1.15rem;">TechConnect</h2>
      </div>
      <div style="background:#f8fafc;padding:26px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
        <p style="margin:0 0 12px;">Hello <strong>{escape(name)}</strong>,</p>
        <p style="margin:0 0 12px;color:#475569;line-height:1.6;">
          Your <strong>{escape(PLAN_LABELS.get(plan, plan or 'TechConnect'))}</strong> plan expires in
          <strong>{d}</strong>, on <strong>{fmt_date(expires)}</strong>.
          After that your profile will stop appearing to clients searching for technicians.</p>
        <p style="margin:22px 0;"><a href="{escape(link)}"
           style="background:#2563EB;color:#fff;text-decoration:none;padding:12px 24px;border-radius:8px;font-weight:700;display:inline-block;">
           Renew my plan</a></p>
        <p style="margin:0 0 8px;color:#94a3b8;font-size:0.82rem;">1-Month: 3,000 RWF &nbsp;·&nbsp; 3-Month: 7,000 RWF.
           Already renewed? You can ignore this message.</p>
        <p style="margin:0;color:#94a3b8;font-size:0.82rem;">Questions? Write to
           <a href="mailto:{SUPPORT_EMAIL}" style="color:#2563EB;">{SUPPORT_EMAIL}</a>.</p>
      </div>
      <p style="text-align:center;color:#94a3b8;font-size:0.75rem;margin-top:14px;">The Tech Connection · Kigali, Rwanda</p>
    </div>"""
    return subject, html


def _claim_alert(conn, tech_id, stage, expiry, email, d, now):
    """Reserve (technician, stage, expiry) so only ONE process ever sends it.  -> row id or None."""
    cur = conn.execute(
        """INSERT OR IGNORE INTO retention_alerts
               (technician_id, stage, expiry_snapshot, to_email, days_left, status, attempts, created_at)
           VALUES (?,?,?,?,?, 'pending', 1, ?)""",
        (tech_id, stage, expiry, email, d, to_db(now)))
    conn.commit()
    if cur.rowcount == 1:
        return cur.lastrowid
    row = conn.execute(
        "SELECT id, status, attempts, created_at FROM retention_alerts WHERE technician_id=? AND stage=? AND expiry_snapshot=?",
        (tech_id, stage, expiry)).fetchone()
    if not row:
        return None
    retry = False
    if row["status"] == "failed" and row["attempts"] < MAX_ALERT_ATTEMPTS:
        retry = True
    elif row["status"] == "pending":                      # a crashed worker left it half-done
        created = from_db(row["created_at"])
        retry = bool(created and (now - created) > timedelta(minutes=30)) and row["attempts"] < MAX_ALERT_ATTEMPTS
    if not retry:
        return None
    cur = conn.execute(
        "UPDATE retention_alerts SET status='pending', attempts=attempts+1, created_at=? "
        "WHERE id=? AND status=? AND attempts=?", (to_db(now), row["id"], row["status"], row["attempts"]))
    conn.commit()
    return row["id"] if cur.rowcount == 1 else None


def run_retention_check(force=False, now=None):
    """Find technicians entering the 7/3/1-day windows and email each stage once.
    Safe to run from several workers at once (see _claim_alert).  -> summary dict."""
    now = now or utcnow()
    summary = {"checked": 0, "sent": 0, "failed": 0, "skipped": 0, "ran_at": to_db(now), "note": ""}
    conn = get_db()
    try:
        if not force and get_setting(conn, "retention_enabled", "1") != "1":
            summary["note"] = "Automation is switched off."
            return summary
        if not _deps["mail_ready"]():
            summary["note"] = "Email is not configured on this server, so no reminders were sent."
            return summary
        site_url = get_setting(conn, "site_url")
        horizon = to_db(now + timedelta(days=7))
        rows = conn.execute(
            """SELECT id, full_name, email, subscription_plan, subscription_expires
                 FROM technicians
                WHERE COALESCE(is_suspended,0) = 0
                  AND subscription_expires IS NOT NULL
                  AND subscription_expires > ? AND subscription_expires <= ?
                  AND COALESCE(email,'') != ''""", (to_db(now), horizon)).fetchall()
        for t in rows:
            summary["checked"] += 1
            d = days_left(t["subscription_expires"], now)
            stage = stage_for(d)
            if not stage:
                continue
            alert_id = _claim_alert(conn, t["id"], stage, t["subscription_expires"], t["email"], d, now)
            if alert_id is None:
                summary["skipped"] += 1          # already sent (or being sent) for this expiry
                continue
            subject, html = build_reminder_email(t["full_name"], stage, t["subscription_expires"],
                                                 t["subscription_plan"], site_url)
            ok, err = _deps["mailer"](t["email"], subject, html)
            if ok:
                conn.execute("UPDATE retention_alerts SET status='sent', sent_at=?, error=NULL WHERE id=?",
                             (to_db(utcnow()), alert_id))
                summary["sent"] += 1
            else:
                conn.execute("UPDATE retention_alerts SET status='failed', error=? WHERE id=?",
                             ((err or "unknown error")[:300], alert_id))
                summary["failed"] += 1
            conn.commit()
        set_setting(conn, "retention_last_run",
                    f"{summary['ran_at']}|{summary['checked']}|{summary['sent']}|{summary['failed']}")
        conn.commit()
    finally:
        conn.close()
    return summary


# ── 5d. Metrics ─────────────────────────────────────────────────────────────
def _one(conn, sql, params=()):
    row = conn.execute(sql, params).fetchone()
    return (row[0] or 0) if row else 0


def compute_metrics(conn):
    m = {}
    m["technicians_total"] = _one(conn, "SELECT COUNT(*) FROM technicians")
    for key, plan in (("active_1m", "1-month"), ("active_3m", "3-month"), ("active_trial", "trial")):
        m[key] = _one(conn, f"SELECT COUNT(*) FROM technicians WHERE subscription_plan = ? AND {ACTIVE_SQL}", (plan,))
    m["expired"] = _one(conn, """SELECT COUNT(*) FROM technicians WHERE subscription_plan IS NOT NULL
                                  AND subscription_expires <= datetime('now') AND COALESCE(is_suspended,0)=0""")
    m["no_plan"] = _one(conn, "SELECT COUNT(*) FROM technicians WHERE subscription_plan IS NULL AND COALESCE(is_suspended,0)=0")
    m["suspended"] = _one(conn, "SELECT COUNT(*) FROM technicians WHERE COALESCE(is_suspended,0)=1")
    m["pending_verifications"] = _one(conn, """SELECT COUNT(*) FROM technicians
        WHERE COALESCE(verification_status,'Pending Review') != 'Verified' AND COALESCE(is_suspended,0)=0""")
    m["expiring_7d"] = _one(conn, f"SELECT COUNT(*) FROM technicians WHERE {ACTIVE_SQL} AND subscription_expires <= datetime('now','+7 days')")

    m["unlocks"] = _one(conn, "SELECT COUNT(*) FROM unlock_ledger WHERE status = 'valid'")
    m["unlock_revenue"] = _one(conn, "SELECT SUM(amount) FROM unlock_ledger WHERE status = 'valid'")
    m["unlocks_voided"] = _one(conn, "SELECT COUNT(*) FROM unlock_ledger WHERE status = 'voided'")
    m["reuse_blocked"] = _one(conn, "SELECT COUNT(*) FROM tnx_reuse_attempts")
    m["unlock_clients"] = _one(conn, "SELECT COUNT(DISTINCT client_phone) FROM unlock_ledger")

    for key, plan in (("1m", "1-month"), ("3m", "3-month")):
        m[f"sales_{key}"] = _one(conn, "SELECT COUNT(*) FROM subscription_payments WHERE plan=? AND amount>0", (plan,))
        m[f"rev_{key}"] = _one(conn, "SELECT SUM(amount) FROM subscription_payments WHERE plan=?", (plan,))
    m["sub_revenue"] = _one(conn, "SELECT SUM(amount) FROM subscription_payments")
    m["rev_other"] = m["sub_revenue"] - m["rev_1m"] - m["rev_3m"]
    m["total_revenue"] = m["unlock_revenue"] + m["sub_revenue"]

    active_paid = m["active_1m"] + m["active_3m"]
    lapsed = _one(conn, """SELECT COUNT(*) FROM technicians WHERE subscription_plan IN ('1-month','3-month')
        AND subscription_expires <= datetime('now') AND subscription_expires > datetime('now','-30 days')
        AND COALESCE(is_suspended,0)=0""")
    m["churned_30d"] = lapsed
    m["churn_rate"] = round(100.0 * lapsed / (active_paid + lapsed), 1) if (active_paid + lapsed) else 0.0
    return m


def last_months(n=12):
    now = utcnow()
    y, mo, out = now.year, now.month, []
    for _ in range(n):
        out.append(f"{y:04d}-{mo:02d}")
        mo -= 1
        if mo == 0:
            y, mo = y - 1, 12
    return out[::-1]


def monthly_series(conn, months=12):
    """Per-month counts/revenue for the revenue charts and the revenue page table."""
    labels = last_months(months)
    since = labels[0] + "-01"
    idx = {m: i for i, m in enumerate(labels)}
    z = lambda: [0] * len(labels)
    s = {"labels": labels, "unlock_count": z(), "unlock_rev": z(), "rev_1m": z(), "rev_3m": z(),
         "sales_1m": z(), "sales_3m": z(), "rev_other": z(), "registrations": z()}
    for r in conn.execute("""SELECT strftime('%Y-%m', created_at) mo, COUNT(*) c, COALESCE(SUM(amount),0) a
                               FROM unlock_ledger WHERE status='valid' AND created_at >= ? GROUP BY mo""", (since,)):
        if r["mo"] in idx:
            s["unlock_count"][idx[r["mo"]]], s["unlock_rev"][idx[r["mo"]]] = r["c"], r["a"]
    for r in conn.execute("""SELECT strftime('%Y-%m', created_at) mo, plan, COUNT(*) c, COALESCE(SUM(amount),0) a
                               FROM subscription_payments WHERE created_at >= ? GROUP BY mo, plan""", (since,)):
        if r["mo"] not in idx:
            continue
        i = idx[r["mo"]]
        if r["plan"] == "1-month":
            s["rev_1m"][i] += r["a"]; s["sales_1m"][i] += r["c"] if r["a"] > 0 else 0
        elif r["plan"] == "3-month":
            s["rev_3m"][i] += r["a"]; s["sales_3m"][i] += r["c"] if r["a"] > 0 else 0
        else:
            s["rev_other"][i] += r["a"]
    for r in conn.execute("""SELECT strftime('%Y-%m', created_at) mo, COUNT(*) c FROM technicians
                              WHERE created_at >= ? GROUP BY mo""", (since,)):
        if r["mo"] in idx:
            s["registrations"][idx[r["mo"]]] = r["c"]
    s["total"] = [s["unlock_rev"][i] + s["rev_1m"][i] + s["rev_3m"][i] + s["rev_other"][i] for i in range(len(labels))]
    return s


def decorate_technician(row, now=None):
    """Add display fields (subscription state, days left, ...) to a technicians row."""
    now = now or utcnow()
    t = dict(row)
    exp = from_db(t.get("subscription_expires"))
    t["days_left"] = days_left(exp, now) if exp else None
    plan = t.get("subscription_plan")
    t["plan_label"] = PLAN_LABELS.get(plan, "None") if plan else "None"
    if t.get("is_suspended"):
        t["sub_state"] = "suspended"
    elif not plan:
        t["sub_state"] = "none"
    elif exp and exp > now:
        t["sub_state"] = "active"
    else:
        t["sub_state"] = "expired"
    t["verified"] = (t.get("verification_status") == "Verified")
    return t


# ── helpers shared by routes ───────────────────────────────────────────────
def paginate(total, page, per_page=PER_PAGE):
    pages = max(1, math.ceil(total / per_page))
    page = min(max(page or 1, 1), pages)
    return {"page": page, "pages": pages, "total": total, "per_page": per_page,
            "offset": (page - 1) * per_page, "has_prev": page > 1, "has_next": page < pages}


def like_escape(s):
    return "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


# ══════════════════════════════════════════════════════════════════════════════
# 6. ROUTES
# ══════════════════════════════════════════════════════════════════════════════
bp = Blueprint("admin", __name__, url_prefix="/admin")

NAV = [
    ("Overview", [("Dashboard", "admin.dashboard", "bar-chart"), ("Revenue", "admin.revenue", "wallet"),
                  ("Unlocks", "admin.unlocks", "lock-open")]),
    ("Users", [("Technicians", "admin.technicians", "wrench"), ("Clients", "admin.clients", "user"),
               ("Verifications", "admin.verifications", "check-circle")]),
    ("Finance", [("Transactions", "admin.transactions", "receipt"), ("Subscriptions", "admin.subscriptions", "calendar"),
                 ("Retention Alerts", "admin.retention_alerts", "bell")]),
    ("System", [("Settings", "admin.settings", "settings"), ("Export Data", "admin.export", "download")]),
]


@bp.app_template_filter("rwf")
def _f_rwf(v):
    return fmt_rwf(v)


@bp.app_template_filter("cat_dt")
def _f_dt(v):
    return fmt_dt(v)


@bp.app_template_filter("cat_date")
def _f_date(v):
    return fmt_date(v)


@bp.context_processor
def _inject():
    counts = {}
    if is_admin():
        conn = get_db()
        try:
            counts["verifications"] = _one(conn, """SELECT COUNT(*) FROM technicians
                WHERE COALESCE(verification_status,'Pending Review') = 'Pending Review' AND COALESCE(is_suspended,0)=0""")
            counts["retention_alerts"] = _one(conn, f"SELECT COUNT(*) FROM technicians WHERE {ACTIVE_SQL} AND subscription_expires <= datetime('now','+7 days')")
        finally:
            conn.close()

    def qs(**changes):
        """Current query string with some values replaced (used by pagers and filter tabs)."""
        d = request.args.to_dict()
        d.update(changes)
        return urlencode({k: v for k, v in d.items() if v not in (None, "")})

    return {"qs": qs, "csrf_token": csrf_token, "NAV": NAV, "nav_counts": counts, "PLANS": PLANS, "PLAN_LABELS": PLAN_LABELS,
            "UNLOCK_PRICE": UNLOCK_PRICE, "STAGE_LABEL": STAGE_LABEL, "PAYMENT_METHODS": PAYMENT_METHODS,
            "admin_path": request.path}


@bp.after_request
def _headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


# ── auth ────────────────────────────────────────────────────────────────────
@bp.route("/login", methods=["GET", "POST"])
def login():
    if is_admin():
        return redirect(url_for("admin.dashboard"))
    if request.method == "POST":
        ip = client_ip()
        wait = lockout_minutes(ip)
        if wait:
            flash(f"Too many failed attempts. Try again in {wait} minute{'s' if wait != 1 else ''}.", "error")
            return render_template("admin/login.html"), 429
        if not csrf_ok():
            flash("Your session expired. Please try again.", "error")
            return render_template("admin/login.html"), 400
        if verify_admin_password(request.form.get("password", "")):
            clear_failed_logins(ip)
            session["is_admin"] = True
            session["admin_seen"] = time.time()
            session["csrf"] = secrets.token_hex(16)          # fresh token on privilege change
            conn = get_db()
            try:
                audit(conn, "login", detail="admin signed in")
                conn.commit()
            finally:
                conn.close()
            return redirect(url_for("admin.dashboard"))
        register_failed_login(ip)
        conn = get_db()
        try:
            audit(conn, "login_failed", detail="wrong password")
            conn.commit()
        finally:
            conn.close()
        left = LOGIN_MAX_FAILS - len(_recent_fails(ip))
        flash("Incorrect password." + (f" {left} attempt{'s' if left != 1 else ''} left." if left > 0 else ""), "error")
        return render_template("admin/login.html"), 401
    return render_template("admin/login.html")


@bp.route("/logout")
def logout():
    for k in ("is_admin", "admin_seen", "csrf"):
        session.pop(k, None)
    return redirect(url_for("admin.login"))


# ── dashboard ───────────────────────────────────────────────────────────────
def _recent_transactions(conn, limit=8):
    return conn.execute("""
        SELECT 'unlock' AS type, created_at, client_phone AS party, tnx_code AS reference,
               COALESCE(technician_name, 'All technicians (24h pass)') AS detail, amount,
               CASE WHEN status='voided' THEN 'voided' ELSE 'valid' END AS status
          FROM unlock_ledger
        UNION ALL
        SELECT 'subscription', created_at, technician_name, COALESCE(reference,''),
               plan || ' · ' || method, amount, 'recorded' FROM subscription_payments
        ORDER BY created_at DESC LIMIT ?""", (limit,)).fetchall()


@bp.route("/", strict_slashes=False)
@admin_required
def dashboard():
    conn = get_db()
    try:
        m = compute_metrics(conn)
        series = monthly_series(conn)
        trades = [(r["skill_category"] or "Other", r["c"]) for r in conn.execute(
            "SELECT skill_category, COUNT(*) c FROM technicians WHERE COALESCE(is_suspended,0)=0 "
            "GROUP BY skill_category ORDER BY c DESC")]
        recent = _recent_transactions(conn)
        expiring = [decorate_technician(r) for r in conn.execute(
            f"SELECT * FROM technicians WHERE {ACTIVE_SQL} AND subscription_expires <= datetime('now','+7 days') "
            "ORDER BY subscription_expires ASC LIMIT 6")]
        warn_default_pw = using_default_password(conn)
        last_run = get_setting(conn, "retention_last_run")
    finally:
        conn.close()
    return render_template("admin/dashboard.html", m=m, series=series, trades=trades, recent=recent,
                           expiring=expiring, warn_default_pw=warn_default_pw,
                           secret_from_env=bool(os.environ.get("SECRET_KEY")), last_run=last_run)


# ── revenue ─────────────────────────────────────────────────────────────────
@bp.route("/revenue")
@admin_required
def revenue():
    conn = get_db()
    try:
        m = compute_metrics(conn)
        series = monthly_series(conn)
    finally:
        conn.close()
    cur, prev = series["total"][-1], series["total"][-2] if len(series["total"]) > 1 else 0
    growth = round(100.0 * (cur - prev) / prev, 1) if prev else None
    rows = list(reversed(range(len(series["labels"]))))
    return render_template("admin/revenue.html", m=m, series=series, growth=growth, rows=rows, cur=cur, prev=prev)


# ── unlocks (chronological ledger) ──────────────────────────────────────────
def _unlock_filters(args):
    where, params = ["1=1"], []
    q = (args.get("q") or "").strip()
    if q:
        where.append("(client_phone LIKE ? ESCAPE '\\' OR tnx_code LIKE ? ESCAPE '\\' OR technician_name LIKE ? ESCAPE '\\')")
        params += [like_escape(q), like_escape(normalize_tnx(q) or q), like_escape(q)]
    status = args.get("status", "all")
    if status == "valid":
        where.append("status = 'valid'")
    elif status == "voided":
        where.append("status = 'voided'")
    elif status == "active":
        where.append("status = 'valid' AND expires_at > datetime('now')")
    for key, op in (("from", ">="), ("to", "<")):
        v = (args.get(key) or "").strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
            if key == "to":
                v = (datetime.strptime(v, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
            where.append(f"created_at {op} ?")
            params.append(v)
    return " AND ".join(where), params


@bp.route("/unlocks")
@admin_required
def unlocks():
    where, params = _unlock_filters(request.args)
    conn = get_db()
    try:
        total = _one(conn, f"SELECT COUNT(*) FROM unlock_ledger WHERE {where}", params)
        pg = paginate(total, request.args.get("page", 1, type=int))
        rows = conn.execute(f"SELECT * FROM unlock_ledger WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                            params + [pg["per_page"], pg["offset"]]).fetchall()
        m = compute_metrics(conn)
        today = _one(conn, "SELECT COUNT(*) FROM unlock_ledger WHERE status='valid' AND created_at >= date('now')")
        month = _one(conn, "SELECT COUNT(*) FROM unlock_ledger WHERE status='valid' AND created_at >= date('now','start of month')")
    finally:
        conn.close()
    now = utcnow()
    rows = [dict(r, live=(r["status"] == "valid" and (from_db(r["expires_at"]) or now) > now)) for r in rows]
    return render_template("admin/unlocks.html", rows=rows, pg=pg, m=m, today=today, month=month, args=request.args)


@bp.route("/unlocks/<int:uid>/void", methods=["POST"])
@admin_post
def unlock_void(uid):
    action = request.form.get("action")
    reason = (request.form.get("reason") or "").strip()[:200]
    conn = get_db()
    try:
        row = conn.execute("SELECT id, tnx_code, status FROM unlock_ledger WHERE id = ?", (uid,)).fetchone()
        if not row:
            flash("Unlock record not found.", "error")
        elif action == "void":
            if not reason:
                flash("Please give a reason for voiding this payment.", "error")
            else:
                conn.execute("UPDATE unlock_ledger SET status='voided', voided_at=?, void_reason=? WHERE id=?",
                             (to_db(utcnow()), reason, uid))
                audit(conn, "unlock_void", "unlock", uid, f"TNX {row['tnx_code']}: {reason}")
                conn.commit()
                flash("Payment voided. The client's access ends immediately and the TNX code stays permanently locked.", "success")
        elif action == "restore":
            conn.execute("UPDATE unlock_ledger SET status='valid', voided_at=NULL, void_reason=NULL WHERE id=?", (uid,))
            audit(conn, "unlock_restore", "unlock", uid, f"TNX {row['tnx_code']}")
            conn.commit()
            flash("Payment restored.", "success")
    finally:
        conn.close()
    return back("admin.unlocks")


# ── clients + TNX audit ─────────────────────────────────────────────────────
@bp.route("/clients")
@admin_required
def clients():
    q = (request.args.get("q") or "").strip()
    where, params = "1=1", []
    if q:
        where, params = "client_phone LIKE ? ESCAPE '\\'", [like_escape(re.sub(r"\D", "", q) or q)]
    conn = get_db()
    try:
        total = _one(conn, f"SELECT COUNT(DISTINCT client_phone) FROM unlock_ledger WHERE {where}", params)
        pg = paginate(total, request.args.get("page", 1, type=int))
        groups = conn.execute(f"""
            SELECT client_phone, COUNT(*) n, SUM(CASE WHEN status='valid' THEN amount ELSE 0 END) paid,
                   SUM(CASE WHEN status='voided' THEN 1 ELSE 0 END) voided,
                   MIN(created_at) first_at, MAX(created_at) last_at
              FROM unlock_ledger WHERE {where} GROUP BY client_phone ORDER BY last_at DESC LIMIT ? OFFSET ?""",
            params + [pg["per_page"], pg["offset"]]).fetchall()
        recs = {}
        if groups:
            ph = [g["client_phone"] for g in groups]
            for r in conn.execute(f"SELECT * FROM unlock_ledger WHERE client_phone IN ({','.join('?' * len(ph))}) ORDER BY id DESC", ph):
                recs.setdefault(r["client_phone"], []).append(r)
        attempts = conn.execute("""
            SELECT a.*, u.client_phone AS owner_phone FROM tnx_reuse_attempts a
              LEFT JOIN unlock_ledger u ON u.id = a.original_unlock_id ORDER BY a.id DESC LIMIT 15""").fetchall()
        m = compute_metrics(conn)
        lookup = None
        tnx_q = normalize_tnx(request.args.get("tnx", ""))
        if tnx_q:
            lookup = {"code": tnx_q, "row": conn.execute("SELECT * FROM unlock_ledger WHERE tnx_code = ?", (tnx_q,)).fetchone()}
    finally:
        conn.close()
    return render_template("admin/clients.html", groups=groups, recs=recs, attempts=attempts, pg=pg, m=m,
                           lookup=lookup, args=request.args)


@bp.route("/clients/<phone>")
@admin_required
def client_detail(phone):
    phone = re.sub(r"\D", "", phone)
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM unlock_ledger WHERE client_phone = ? ORDER BY id DESC", (phone,)).fetchall()
        attempts = conn.execute("SELECT * FROM tnx_reuse_attempts WHERE client_phone = ? ORDER BY id DESC LIMIT 25", (phone,)).fetchall()
    finally:
        conn.close()
    if not rows and not attempts:
        abort(404)
    now = utcnow()
    rows = [dict(r, live=(r["status"] == "valid" and (from_db(r["expires_at"]) or now) > now)) for r in rows]
    paid = sum(r["amount"] for r in rows if r["status"] == "valid")
    return render_template("admin/client_detail.html", phone=phone, rows=rows, attempts=attempts, paid=paid)


# ── technicians (directory + override / verify / suspend actions) ───────────
def _tech_where(args):
    where, params = ["1=1"], []
    q = (args.get("q") or "").strip()
    if q:
        where.append("(full_name LIKE ? ESCAPE '\\' OR phone LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' OR whatsapp LIKE ? ESCAPE '\\')")
        params += [like_escape(q)] * 4
    status = args.get("status", "all")
    clauses = {
        "active": ACTIVE_SQL,
        "trial": f"subscription_plan = 'trial' AND {ACTIVE_SQL}",
        "1-month": f"subscription_plan = '1-month' AND {ACTIVE_SQL}",
        "3-month": f"subscription_plan = '3-month' AND {ACTIVE_SQL}",
        "expired": "subscription_plan IS NOT NULL AND subscription_expires <= datetime('now') AND COALESCE(is_suspended,0)=0",
        "none": "subscription_plan IS NULL AND COALESCE(is_suspended,0)=0",
        "suspended": "COALESCE(is_suspended,0) = 1",
        "verified": "verification_status = 'Verified'",
        "unverified": "COALESCE(verification_status,'Pending Review') != 'Verified'",
    }
    if status in clauses:
        where.append(clauses[status])
    return " AND ".join(where), params, status


def _tech_tab_counts(conn):
    r = conn.execute(f"""SELECT COUNT(*) AS total,
        SUM(CASE WHEN {ACTIVE_SQL} THEN 1 ELSE 0 END) AS active,
        SUM(CASE WHEN subscription_plan='trial' AND {ACTIVE_SQL} THEN 1 ELSE 0 END) AS trial,
        SUM(CASE WHEN subscription_plan IS NOT NULL AND subscription_expires <= datetime('now') AND COALESCE(is_suspended,0)=0 THEN 1 ELSE 0 END) AS expired,
        SUM(CASE WHEN COALESCE(verification_status,'Pending Review') != 'Verified' THEN 1 ELSE 0 END) AS unverified,
        SUM(CASE WHEN COALESCE(is_suspended,0)=1 THEN 1 ELSE 0 END) AS suspended
        FROM technicians""").fetchone()
    return {k: (r[k] or 0) for k in r.keys()}


@bp.route("/technicians")
@admin_required
def technicians():
    where, params, status = _tech_where(request.args)
    conn = get_db()
    try:
        total = _one(conn, f"SELECT COUNT(*) FROM technicians WHERE {where}", params)
        pg = paginate(total, request.args.get("page", 1, type=int))
        rows = [decorate_technician(r) for r in conn.execute(
            f"SELECT * FROM technicians WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [pg["per_page"], pg["offset"]])]
        counts = _tech_tab_counts(conn)
    finally:
        conn.close()
    return render_template("admin/technicians.html", rows=rows, pg=pg, counts=counts, status=status, args=request.args)


@bp.route("/technicians/<int:tid>/subscription", methods=["POST"])
@admin_post
def tech_subscription(tid):
    f = request.form
    conn = get_db()
    try:
        ok, msg = apply_subscription_action(
            conn, tid, f.get("action"), plan=f.get("plan"), days=f.get("days"), method=f.get("method", "cash"),
            reference=f.get("reference"), note=f.get("note"), amount=f.get("amount"),
            record_payment=(f.get("record_payment") == "1"))
        if ok:
            audit(conn, f"subscription_{f.get('action')}", "technician", tid,
                  f"{msg} [method={f.get('method')}, ref={(f.get('reference') or '')[:40]}]")
            conn.commit()
        else:
            conn.rollback()
    finally:
        conn.close()
    flash(msg, "success" if ok else "error")
    return back("admin.technicians")


@bp.route("/technicians/<int:tid>/verify", methods=["POST"])
@admin_post
def tech_verify(tid):
    action = request.form.get("action")
    new = {"verify": "Verified", "unverify": "Pending Review", "reject": "Rejected"}.get(action)
    conn = get_db()
    try:
        t = conn.execute("SELECT full_name FROM technicians WHERE id = ?", (tid,)).fetchone()
        if not t or not new:
            flash("Technician not found.", "error")
        else:
            conn.execute("UPDATE technicians SET verification_status = ? WHERE id = ?", (new, tid))
            audit(conn, f"verification_{action}", "technician", tid, f"{t['full_name']} -> {new}")
            conn.commit()
            flash(f"{t['full_name']} marked as {new}.", "success")
    finally:
        conn.close()
    return back("admin.technicians")


@bp.route("/technicians/<int:tid>/suspend", methods=["POST"])
@admin_post
def tech_suspend(tid):
    action = request.form.get("action")
    reason = (request.form.get("reason") or "").strip()[:200]
    conn = get_db()
    try:
        t = conn.execute("SELECT full_name FROM technicians WHERE id = ?", (tid,)).fetchone()
        if not t:
            flash("Technician not found.", "error")
        elif action == "suspend":
            if not reason:
                flash("Please give a reason before suspending an account.", "error")
            else:
                conn.execute("UPDATE technicians SET is_suspended=1, suspended_reason=?, suspended_at=? WHERE id=?",
                             (reason, to_db(utcnow()), tid))
                audit(conn, "suspend", "technician", tid, f"{t['full_name']}: {reason}")
                conn.commit()
                flash(f"{t['full_name']} is suspended: hidden from search and signed out.", "success")
        elif action == "unsuspend":
            conn.execute("UPDATE technicians SET is_suspended=0, suspended_reason=NULL, suspended_at=NULL WHERE id=?", (tid,))
            audit(conn, "unsuspend", "technician", tid, t["full_name"])
            conn.commit()
            flash(f"{t['full_name']} is active again.", "success")
    finally:
        conn.close()
    return back("admin.technicians")


# ── verifications queue ─────────────────────────────────────────────────────
@bp.route("/verifications")
@admin_required
def verifications():
    tab = request.args.get("tab", "pending")
    clause = {"pending": "COALESCE(verification_status,'Pending Review') = 'Pending Review'",
              "rejected": "verification_status = 'Rejected'",
              "verified": "verification_status = 'Verified'"}.get(tab)
    if clause is None:
        tab, clause = "pending", "COALESCE(verification_status,'Pending Review') = 'Pending Review'"
    conn = get_db()
    try:
        total = _one(conn, f"SELECT COUNT(*) FROM technicians WHERE {clause}")
        pg = paginate(total, request.args.get("page", 1, type=int), 15)
        rows = [decorate_technician(r) for r in conn.execute(
            f"SELECT * FROM technicians WHERE {clause} ORDER BY id DESC LIMIT ? OFFSET ?", (pg["per_page"], pg["offset"]))]
        tabs = {k: _one(conn, f"SELECT COUNT(*) FROM technicians WHERE {c}") for k, c in (
            ("pending", "COALESCE(verification_status,'Pending Review') = 'Pending Review'"),
            ("rejected", "verification_status = 'Rejected'"), ("verified", "verification_status = 'Verified'"))}
    finally:
        conn.close()
    return render_template("admin/verifications.html", rows=rows, pg=pg, tab=tab, tabs=tabs, args=request.args)


# ── transactions (combined financial ledger) ────────────────────────────────
TX_CTE = """WITH tx AS (
    SELECT 'unlock' AS type, created_at, client_phone AS party, tnx_code AS reference,
           COALESCE(technician_name, 'All technicians (24h pass)') AS detail, amount, status FROM unlock_ledger
    UNION ALL
    SELECT 'subscription', created_at, technician_name, COALESCE(reference,''),
           CASE plan WHEN 'trial' THEN '7-Day Trial' WHEN '1-month' THEN '1-Month plan' WHEN '3-month' THEN '3-Month plan' ELSE plan END
             || ' · ' || method, amount, 'recorded' FROM subscription_payments)"""


def _tx_filters(args):
    where, params = ["1=1"], []
    t = args.get("type", "all")
    if t in ("unlock", "subscription"):
        where.append("type = ?"); params.append(t)
    q = (args.get("q") or "").strip()
    if q:
        where.append("(party LIKE ? ESCAPE '\\' OR reference LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\')")
        params += [like_escape(q), like_escape(normalize_tnx(q) or q), like_escape(q)]
    for key, op in (("from", ">="), ("to", "<")):
        v = (args.get(key) or "").strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
            if key == "to":
                v = (datetime.strptime(v, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
            where.append(f"created_at {op} ?"); params.append(v)
    return " AND ".join(where), params, t


@bp.route("/transactions")
@admin_required
def transactions():
    where, params, ttype = _tx_filters(request.args)
    conn = get_db()
    try:
        agg = conn.execute(f"{TX_CTE} SELECT COUNT(*) c, COALESCE(SUM(CASE WHEN status!='voided' THEN amount ELSE 0 END),0) s FROM tx WHERE {where}", params).fetchone()
        pg = paginate(agg["c"], request.args.get("page", 1, type=int))
        rows = conn.execute(f"{TX_CTE} SELECT * FROM tx WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                            params + [pg["per_page"], pg["offset"]]).fetchall()
        m = compute_metrics(conn)
    finally:
        conn.close()
    return render_template("admin/transactions.html", rows=rows, pg=pg, total_amount=agg["s"], ttype=ttype, m=m, args=request.args)


# ── subscriptions overview ──────────────────────────────────────────────────
@bp.route("/subscriptions")
@admin_required
def subscriptions():
    state = request.args.get("state", "active")
    plan = request.args.get("plan", "all")
    where, params = ["1=1"], []
    if state == "active":
        where.append(ACTIVE_SQL)
    elif state == "expiring":
        where.append(f"{ACTIVE_SQL} AND subscription_expires <= datetime('now','+7 days')")
    elif state == "expired":
        where.append("subscription_plan IS NOT NULL AND subscription_expires <= datetime('now') AND COALESCE(is_suspended,0)=0")
    elif state == "none":
        where.append("subscription_plan IS NULL AND COALESCE(is_suspended,0)=0")
    else:
        state = "all"
    if plan in ("trial", "1-month", "3-month"):
        where.append("subscription_plan = ?"); params.append(plan)
    else:
        plan = "all"
    w = " AND ".join(where)
    conn = get_db()
    try:
        total = _one(conn, f"SELECT COUNT(*) FROM technicians WHERE {w}", params)
        pg = paginate(total, request.args.get("page", 1, type=int))
        rows = [decorate_technician(r) for r in conn.execute(
            f"SELECT * FROM technicians WHERE {w} ORDER BY subscription_expires ASC LIMIT ? OFFSET ?",
            params + [pg["per_page"], pg["offset"]])]
        m = compute_metrics(conn)
        payments = conn.execute("SELECT * FROM subscription_payments ORDER BY id DESC LIMIT 12").fetchall()
    finally:
        conn.close()
    return render_template("admin/subscriptions.html", rows=rows, pg=pg, m=m, state=state, plan=plan, payments=payments, args=request.args)


# ── retention alert desk ────────────────────────────────────────────────────
@bp.route("/retention-alerts")
@admin_required
def retention_alerts():
    win = request.args.get("window", "14")
    cond = ("subscription_expires IS NOT NULL AND COALESCE(is_suspended,0)=0 "
            "AND subscription_expires > datetime('now','-7 days')")
    params = []
    if win in ("7", "14", "30"):
        cond += " AND subscription_expires <= datetime('now', ?)"
        params.append(f"+{int(win)} days")
    else:
        win = "all"
    conn = get_db()
    try:
        techs = conn.execute(f"SELECT * FROM technicians WHERE {cond} ORDER BY subscription_expires ASC LIMIT 300", params).fetchall()
        sent_by = {}
        if techs:
            ids = [t["id"] for t in techs]
            for a in conn.execute(f"""SELECT technician_id, expiry_snapshot, stage, status FROM retention_alerts
                                       WHERE technician_id IN ({','.join('?' * len(ids))})""", ids):
                sent_by.setdefault((a["technician_id"], a["expiry_snapshot"]), []).append(a)
        now = utcnow()
        rows = []
        for t in techs:
            d = decorate_technician(t, now)
            alerts = sent_by.get((t["id"], t["subscription_expires"]), [])
            sent = [a["stage"] for a in alerts if a["status"] == "sent"]
            d["stage_sent"] = max(sent, key=lambda s: STAGE_RANK[s]) if sent else None
            d["stages_sent"] = sorted(sent, key=lambda s: STAGE_RANK[s])
            d["has_failed"] = any(a["status"] == "failed" for a in alerts)
            d["due_stage"] = stage_for(d["days_left"]) if d["sub_state"] == "active" else None
            rows.append(d)
        log = conn.execute("""SELECT r.*, t.full_name, t.phone FROM retention_alerts r
                                LEFT JOIN technicians t ON t.id = r.technician_id ORDER BY r.id DESC LIMIT 25""").fetchall()
        win_counts = {k: _one(conn, f"SELECT COUNT(*) FROM technicians WHERE {ACTIVE_SQL} AND subscription_expires <= datetime('now','+{k} days')") for k in (7, 3, 1)}
        sent30 = _one(conn, "SELECT COUNT(*) FROM retention_alerts WHERE status='sent' AND sent_at >= datetime('now','-30 days')")
        failed = _one(conn, "SELECT COUNT(*) FROM retention_alerts WHERE status='failed'")
        enabled = get_setting(conn, "retention_enabled", "1") == "1"
        last_run = get_setting(conn, "retention_last_run")
    finally:
        conn.close()
    lr = None
    if last_run:
        p = last_run.split("|")
        if len(p) == 4:
            lr = {"at": p[0], "checked": p[1], "sent": p[2], "failed": p[3]}
    return render_template("admin/retention.html", rows=rows, log=log, win=win, win_counts=win_counts, sent30=sent30,
                           failed=failed, enabled=enabled, last_run=lr, mail_ready=_deps["mail_ready"](),
                           mail_problem=_deps["mail_problem"]())


@bp.route("/retention-alerts/run", methods=["POST"])
@admin_post
def retention_run():
    """Manual run.  Sends happen in a background thread so the request can't hit the worker timeout."""
    conn = get_db()
    try:
        audit(conn, "retention_run", detail="manual check started")
        conn.commit()
    finally:
        conn.close()
    threading.Thread(target=lambda: run_retention_check(force=True), daemon=True).start()
    flash("Reminder check started in the background. Refresh in a few seconds to see the result.", "success")
    return back("admin.retention_alerts")


# ── settings ────────────────────────────────────────────────────────────────
def _password_source(conn):
    if get_setting(conn, "admin_password_hash"):
        return "Changed in this portal (stored hashed)"
    return "ADMIN_PASSWORD environment variable" if os.environ.get("ADMIN_PASSWORD") else "Built-in default (unsafe)"


@bp.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    if request.method == "POST":
        if not csrf_ok():
            flash("Your session token expired. Please try again.", "error")
            return redirect(url_for("admin.settings"))
        site_url = (request.form.get("site_url") or "").strip().rstrip("/")
        if site_url and not re.fullmatch(r"https?://[^\s/]+(/[^\s]*)?", site_url):
            flash("Site URL must start with http:// or https://", "error")
            return redirect(url_for("admin.settings"))
        conn = get_db()
        try:
            set_setting(conn, "retention_enabled", "1" if request.form.get("retention_enabled") else "0")
            set_setting(conn, "enforce_expiry", "1" if request.form.get("enforce_expiry") else "0")
            if site_url:
                set_setting(conn, "site_url", site_url)
            audit(conn, "settings_update", detail=f"retention={'on' if request.form.get('retention_enabled') else 'off'}, "
                                                  f"enforce_expiry={'on' if request.form.get('enforce_expiry') else 'off'}")
            conn.commit()
        finally:
            conn.close()
        flash("Settings saved.", "success")
        return redirect(url_for("admin.settings"))
    conn = get_db()
    try:
        cfg = {k: get_setting(conn, k) for k in ("retention_enabled", "enforce_expiry", "site_url")}
        audit_rows = conn.execute("SELECT * FROM admin_audit_log ORDER BY id DESC LIMIT 40").fetchall()
        info = {"technicians": _one(conn, "SELECT COUNT(*) FROM technicians"),
                "unlocks": _one(conn, "SELECT COUNT(*) FROM unlock_ledger"),
                "sub_payments": _one(conn, "SELECT COUNT(*) FROM subscription_payments"),
                "audit_entries": _one(conn, "SELECT COUNT(*) FROM admin_audit_log"),
                "password_source": _password_source(conn),
                "default_pw": using_default_password(conn)}
        db_file = next((r[2] for r in conn.execute("PRAGMA database_list") if r[1] == "main"), "")
        info["db_size_kb"] = round(os.path.getsize(db_file) / 1024, 1) if db_file and os.path.exists(db_file) else 0
    finally:
        conn.close()
    info["mail_ready"] = _deps["mail_ready"]()
    info["mail_problem"] = _deps["mail_problem"]()
    info["secret_from_env"] = bool(os.environ.get("SECRET_KEY"))
    return render_template("admin/settings.html", cfg=cfg, audit_rows=audit_rows, info=info)


@bp.route("/settings/password", methods=["POST"])
@admin_post
def settings_password():
    f = request.form
    if not verify_admin_password(f.get("current_password", "")):
        register_failed_login(client_ip())
        flash("Current password is incorrect.", "error")
    elif f.get("new_password") != f.get("confirm_password"):
        flash("New passwords do not match.", "error")
    elif not strong_password(f.get("new_password", "")):
        flash("New password needs 10+ characters with upper-case, lower-case, a number and a symbol.", "error")
    else:
        conn = get_db()
        try:
            set_setting(conn, "admin_password_hash", generate_password_hash(f["new_password"]))
            audit(conn, "password_change", detail="admin password changed")
            conn.commit()
        finally:
            conn.close()
        flash("Password changed. Use it next time you sign in.", "success")
    return redirect(url_for("admin.settings"))


@bp.route("/settings/test-email", methods=["POST"])
@admin_post
def settings_test_email():
    to = (request.form.get("to") or "").strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", to):
        flash("Enter a valid email address.", "error")
    elif not _deps["mail_ready"]():
        flash(f"Email is not configured on this server: {_deps['mail_problem']() or 'unknown reason'}.", "error")
    else:
        ok, err = _deps["mailer"](to, "TechConnect test email", "<p>This is a test email from the TechConnect admin portal.</p>")
        flash(f"Test email sent to {to}." if ok else f"Could not send: {err}", "success" if ok else "error")
    return redirect(url_for("admin.settings"))


# ── CSV export ──────────────────────────────────────────────────────────────
def _csv_safe(v):
    """Neutralise spreadsheet formula injection (cells starting = + - @ are treated as formulas)."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def _export_defs():
    d = fmt_dt
    return {
        "technicians": ("technicians", "All technician accounts (no passwords)",
            "SELECT * FROM technicians ORDER BY id",
            ["ID", "Full name", "Email", "Phone", "WhatsApp", "Trade", "Qualification", "Field of study", "Certificate no.",
             "Province", "District", "Sector", "Verification", "Plan", "Plan expires (CAT)", "Suspended", "Suspension reason", "Registered (CAT)"],
            lambda r: [r["id"], r["full_name"], r["email"], r["phone"], r["whatsapp"], r["skill_category"], r["qualification_type"],
                       r["degree"], r["certificate_number"], r["province"], r["district"], r["sector"], r["verification_status"],
                       PLAN_LABELS.get(r["subscription_plan"], ""), d(r["subscription_expires"]) if r["subscription_expires"] else "",
                       "yes" if r["is_suspended"] else "no", r["suspended_reason"] or "", d(r["created_at"])]),
        "subscriptions": ("subscriptions-active", "Technicians with an active plan",
            f"SELECT * FROM technicians WHERE {ACTIVE_SQL} ORDER BY subscription_expires",
            ["ID", "Full name", "Phone", "Email", "Plan", "Price (RWF)", "Expires (CAT)", "Days left"],
            lambda r: [r["id"], r["full_name"], r["phone"], r["email"], PLAN_LABELS.get(r["subscription_plan"], ""),
                       PLANS.get(r["subscription_plan"], {}).get("price", 0), d(r["subscription_expires"]), days_left(r["subscription_expires"])]),
        "subscription-payments": ("subscription-payments", "Subscription revenue ledger",
            "SELECT * FROM subscription_payments ORDER BY id",
            ["ID", "Technician ID", "Technician", "Plan", "Amount (RWF)", "Method", "Reference", "Note", "Period start (CAT)", "Period end (CAT)", "Recorded (CAT)"],
            lambda r: [r["id"], r["technician_id"], r["technician_name"], PLAN_LABELS.get(r["plan"], r["plan"]), r["amount"], r["method"],
                       r["reference"], r["note"], d(r["period_start"]), d(r["period_end"]), d(r["created_at"])]),
        "unlock-ledger": ("client-unlock-ledger", "Client unlocks with TNX audit trail",
            "SELECT * FROM unlock_ledger ORDER BY id",
            ["ID", "Client phone", "TNX / MoMo reference", "Technician unlocked", "Amount (RWF)", "Status", "Unlocked (CAT)", "Access ends (CAT)", "Void reason", "IP"],
            lambda r: [r["id"], r["client_phone"], r["tnx_code"], r["technician_name"], r["amount"], r["status"],
                       d(r["created_at"]), d(r["expires_at"]), r["void_reason"] or "", r["ip"] or ""]),
        "transactions": ("financial-ledger", "Combined financial ledger (unlocks + subscriptions)",
            f"{TX_CTE} SELECT * FROM tx ORDER BY created_at",
            ["Date (CAT)", "Type", "Party", "Reference", "Detail", "Amount (RWF)", "Status"],
            lambda r: [d(r["created_at"]), r["type"], r["party"], r["reference"], r["detail"], r["amount"], r["status"]]),
        "retention-alerts": ("retention-email-log", "Reminder emails sent / failed",
            "SELECT r.*, t.full_name FROM retention_alerts r LEFT JOIN technicians t ON t.id = r.technician_id ORDER BY r.id",
            ["ID", "Technician", "Email", "Stage", "Expiry (CAT)", "Status", "Attempts", "Error", "Sent (CAT)"],
            lambda r: [r["id"], r["full_name"] or "(deleted)", r["to_email"], STAGE_LABEL.get(r["stage"], r["stage"]), d(r["expiry_snapshot"]),
                       r["status"], r["attempts"], r["error"] or "", d(r["sent_at"]) if r["sent_at"] else ""]),
    }


@bp.route("/export")
@admin_required
def export():
    conn = get_db()
    try:
        counts = {
            "technicians": _one(conn, "SELECT COUNT(*) FROM technicians"),
            "subscriptions": _one(conn, f"SELECT COUNT(*) FROM technicians WHERE {ACTIVE_SQL}"),
            "subscription-payments": _one(conn, "SELECT COUNT(*) FROM subscription_payments"),
            "unlock-ledger": _one(conn, "SELECT COUNT(*) FROM unlock_ledger"),
            "transactions": _one(conn, "SELECT (SELECT COUNT(*) FROM unlock_ledger) + (SELECT COUNT(*) FROM subscription_payments)"),
            "retention-alerts": _one(conn, "SELECT COUNT(*) FROM retention_alerts"),
        }
    finally:
        conn.close()
    items = [(k, v[1], counts[k]) for k, v in _export_defs().items()]
    return render_template("admin/export.html", items=items)


@bp.route("/export/<kind>.csv")
@admin_required
def export_csv(kind):
    defs = _export_defs()
    if kind not in defs:
        abort(404)
    fname, _desc, sql, headers, row_fn = defs[kind]
    conn = get_db()
    try:
        rows = conn.execute(sql).fetchall()
        audit(conn, "export", "csv", kind, f"{len(rows)} rows")
        conn.commit()
    finally:
        conn.close()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(headers)
    for r in rows:
        w.writerow([_csv_safe(v) if v is not None else "" for v in row_fn(r)])
    stamp = (utcnow() + CAT_OFFSET).strftime("%Y%m%d-%H%M")
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="techconnect-{fname}-{stamp}.csv"'})


# ══════════════════════════════════════════════════════════════════════════════
# 7. WIRING + BACKGROUND SCHEDULER
# ══════════════════════════════════════════════════════════════════════════════
_SCHEDULER = {"started": False}


def _scheduler_loop(first_delay, interval):
    time.sleep(first_delay)
    while True:
        try:
            run_retention_check()
        except Exception as exc:                      # never let the thread die
            print(f"[RETENTION] check failed: {exc}", flush=True)
        time.sleep(interval)


def start_scheduler(first_delay=45, interval=3600):
    """Hourly reminder check (plus one shortly after start-up, which also catches a
    wake-up from Render's free-tier sleep).  Duplicate threads in other workers are harmless:
    _claim_alert guarantees each reminder is sent once."""
    if _SCHEDULER["started"] or os.environ.get("TC_DISABLE_SCHEDULER") == "1":
        return False
    _SCHEDULER["started"] = True
    threading.Thread(target=_scheduler_loop, args=(first_delay, interval), daemon=True, name="tc-retention").start()
    return True


def init_app(app, db, mailer, mail_ready, mail_problem=None):
    _deps.update({"db": db, "mailer": mailer, "mail_ready": mail_ready, "mail_problem": mail_problem or (lambda: None)})
    conn = db()
    try:
        ensure_schema(conn)
    finally:
        conn.close()
    app.register_blueprint(bp)
    start_scheduler()

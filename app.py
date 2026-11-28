"""
TechConnect - Technician Registration Prototype (v2)
--------------------------------------------------
What's new in this version:
- Technicians set a password at sign-up and can log in later to
  edit or delete their own profile.
- Location uses Rwanda's REAL administrative structure:
  Province -> District -> Sector, all cascading dropdowns
  (choosing a province fills the district list, choosing a
  district fills the sector list). Data comes from
  rwanda_locations.json (5 provinces, 30 districts, 416 sectors).
- Technicians can upload a profile photo and a certificate file
  (PDF or image) as proof of qualification.
- Uploaded certificates are automatically scanned (OCR) to check the
  document looks like the right qualification type/level, and that
  its visible text mentions the field of study they typed. This does
  NOT confirm the certificate is genuine (that still needs a human to
  check against real RTB/university records) - it only catches
  obvious mismatches, like uploading the wrong document.

REQUIRES Tesseract OCR to be installed separately on the computer
running this app - see README.md for Windows install steps. If it's
not installed, the document check is silently skipped (registration
still works, just without the automatic check).

Still a LEARNING PROTOTYPE:
- No payments yet.
- Uploaded files are stored in static/uploads/ on this same computer.
  In a real deployed version, these would need to go to proper
  cloud storage instead.

Run it with:
    python app.py
Then open http://127.0.0.1:5000 in your browser.
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import threading
import os
import secrets
from datetime import datetime, timedelta
import json
import uuid
import re
import calendar
import hmac
import logging
import smtplib
import ssl
import sys
import urllib.error
import urllib.request
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
import shutil
import time as _time

# OCR support: reads text out of uploaded certificate images/PDFs so we can
# automatically check the document looks like the right type (degree vs
# certificate) and that its visible text matches the field of study the
# technician typed in. If these libraries or the Tesseract program aren't
# installed, OCR checks are skipped gracefully (the rest of the app still works).
try:
    import pytesseract
    from PIL import Image
    from pdf2image import convert_from_path
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

# QR code scanning for NESA/RTB certificate verification
try:
    from pyzbar.pyzbar import decode as decode_qr
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

# Live portal verification (requests + BeautifulSoup)
try:
    import requests
    from bs4 import BeautifulSoup
    PORTAL_AVAILABLE = True
except ImportError:
    PORTAL_AVAILABLE = False

import admin_portal   # admin console (blueprint) - see admin_portal.py

app = Flask(__name__)

# ── Support address + e-mail (SMTP) configuration ─────────────────────────────
# ONE support address for the whole site (footer, policy pages, e-mails, messages).
# It is defined in admin_portal so both modules share it without a circular import.
SUPPORT_EMAIL = admin_portal.SUPPORT_EMAIL
IS_PRODUCTION = bool(os.environ.get("RENDER"))          # Render sets this variable automatically

# All SMTP settings come from environment variables (set them in Render > Environment):
#   MAIL_SERVER (smtp.gmail.com)  MAIL_PORT (587)  MAIL_USE_TLS (true)  MAIL_USE_SSL (false; true automatically on 465)
#   MAIL_USERNAME (the support Gmail)  MAIL_PASSWORD (a 16-character Google *App Password*)
#   MAIL_DEFAULT_SENDER (the support Gmail)
def _env_bool(name, default):
    raw = os.environ.get(name)
    return default if raw is None or not raw.strip() else raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name, default):
    try:
        return int((os.environ.get(name) or "").strip() or default)
    except ValueError:
        return default


mail_log = logging.getLogger("techconnect.mail")
if not mail_log.handlers:
    _h = logging.StreamHandler(sys.stderr)
    _h.setFormatter(logging.Formatter("%(asctime)s [MAIL %(levelname)s] %(message)s"))
    mail_log.addHandler(_h)
mail_log.setLevel(logging.INFO)
mail_log.propagate = False

_mail_port = _env_int("MAIL_PORT", 587)
_mail_ssl = _env_bool("MAIL_USE_SSL", _mail_port == 465)          # port 465 = implicit SSL
_sender_name, _sender_addr = parseaddr(os.environ.get("MAIL_DEFAULT_SENDER", ""))
app.config.update(
    MAIL_SERVER=(os.environ.get("MAIL_SERVER") or "").strip() or "smtp.gmail.com",
    MAIL_PORT=_mail_port,
    MAIL_USE_SSL=_mail_ssl,
    MAIL_USE_TLS=False if _mail_ssl else _env_bool("MAIL_USE_TLS", True),
    MAIL_USERNAME=(os.environ.get("MAIL_USERNAME") or "").strip() or SUPPORT_EMAIL,
    # Google shows App Passwords in four groups separated by spaces; the spaces are not part of the password.
    MAIL_PASSWORD=(os.environ.get("MAIL_PASSWORD") or "").replace(" ", ""),
    MAIL_DEFAULT_SENDER=(_sender_name or "TechConnect Support", _sender_addr or SUPPORT_EMAIL),
    # OPTIONAL: send over HTTPS (port 443) instead of SMTP.  Needed on Render's FREE plan, which blocks SMTP ports.
    BREVO_API_KEY=(os.environ.get("BREVO_API_KEY") or "").strip(),
    BREVO_API_URL=(os.environ.get("BREVO_API_URL") or "").strip() or "https://api.brevo.com/v3/smtp/email",
)
MAIL_TIMEOUT = 20      # seconds for every SMTP network step


def mail_problem():
    """None when e-mail can be sent, otherwise a short, human-readable reason (for logs and the admin console)."""
    if app.config["BREVO_API_KEY"]:
        return None                          # HTTPS API configured: no SMTP credentials needed
    if not app.config["MAIL_USERNAME"]:
        return "MAIL_USERNAME is not set"
    if not app.config["MAIL_PASSWORD"]:
        return ("MAIL_PASSWORD is not set. Gmail needs a 16-character Google App Password "
                "(Google Account > Security > 2-Step Verification > App passwords)")
    return None


def _mask_email(addr):
    name, _, domain = (addr or "").partition("@")
    return f"{name[:1]}***@{domain}" if domain else "***"


class MailApiError(Exception):
    """The HTTPS e-mail API answered with an error status."""
    def __init__(self, status, detail):
        super().__init__(f"HTTP {status}: {detail}")
        self.status, self.detail = status, detail


_RENDER_SMTP_HINT = (" IMPORTANT: Render's FREE web services block outbound SMTP (ports 25, 465 and 587), so a timeout here is "
                     "most likely that block. Fix: upgrade the service to a paid instance, or set BREVO_API_KEY to send over HTTPS "
                     "(see EMAIL_SETUP.md)")


def _looks_like_blocked_smtp(exc):
    """Timeouts / 'network unreachable' are what Render's free-plan SMTP block looks like (a plain 'connection
    refused' is not: that means wrong host or port)."""
    if not IS_PRODUCTION:
        return False
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return "timed out" in str(exc).lower()
    return isinstance(exc, TimeoutError) or getattr(exc, "errno", None) in (101, 110, 113)


def describe_mail_error(exc):
    """Turn an smtplib/socket/ssl/HTTP exception into a clear, actionable sentence for the logs."""
    host, port = app.config["MAIL_SERVER"], app.config["MAIL_PORT"]
    if isinstance(exc, MailApiError):
        if exc.status in (401, 403):
            return f"the e-mail API REJECTED THE API KEY (HTTP {exc.status}). Check BREVO_API_KEY. Server said: {exc.detail}"
        if exc.status == 400 and "sender" in exc.detail.lower():
            return (f"the e-mail API refused the sender address {app.config['MAIL_DEFAULT_SENDER'][1]}: it must be added and "
                    f"verified under Senders in the Brevo dashboard. Server said: {exc.detail}")
        return f"the e-mail API returned an error (HTTP {exc.status}): {exc.detail}"
    if isinstance(exc, urllib.error.URLError):
        return f"could not reach the e-mail API at {app.config['BREVO_API_URL']} ({exc.reason}). Check the internet connection / BREVO_API_URL"
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return ("the mail server REJECTED THE LOGIN. Gmail needs a 16-character Google App Password in MAIL_PASSWORD "
                "(not the normal account password), 2-Step Verification must be on, and MAIL_USERNAME must be that account. "
                f"Server said: {exc.smtp_code} {exc.smtp_error!r}")
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return f"the server does not support what was requested (check MAIL_USE_TLS / MAIL_PORT): {exc}"
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return f"the sender address was refused ({exc.sender}): MAIL_DEFAULT_SENDER must be the logged-in Gmail account or one of its aliases"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "the recipient address was refused by the mail server"
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return (f"the mail server closed the connection unexpectedly ({exc})."
                + (_RENDER_SMTP_HINT if _looks_like_blocked_smtp(exc) else ""))
    if isinstance(exc, ssl.SSLError):
        return f"TLS/SSL problem talking to {host}:{port}. Use port 587 with MAIL_USE_TLS=true, or port 465 with MAIL_USE_SSL=true ({exc})"
    if isinstance(exc, (TimeoutError, OSError)):
        return (f"could not reach {host}:{port} ({exc.__class__.__name__}: {exc}). Check MAIL_SERVER / MAIL_PORT and that outbound SMTP is allowed."
                + (_RENDER_SMTP_HINT if _looks_like_blocked_smtp(exc) else ""))
    if isinstance(exc, smtplib.SMTPException):
        return f"SMTP error: {exc}"
    return f"{exc.__class__.__name__}: {exc}"


def _smtp_send(to, subject, html, text=None):
    """Send one message through the configured SMTP server using only the standard library."""
    cfg = app.config
    name, addr = cfg["MAIL_DEFAULT_SENDER"]
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((name, addr))
    msg["To"] = to
    msg.set_content(text or re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip())
    msg.add_alternative(html, subtype="html")
    ctx = ssl.create_default_context()
    if cfg["MAIL_USE_SSL"]:
        server = smtplib.SMTP_SSL(cfg["MAIL_SERVER"], cfg["MAIL_PORT"], timeout=MAIL_TIMEOUT, context=ctx)
    else:
        server = smtplib.SMTP(cfg["MAIL_SERVER"], cfg["MAIL_PORT"], timeout=MAIL_TIMEOUT)
    try:
        server.ehlo()
        if cfg["MAIL_USE_TLS"] and not cfg["MAIL_USE_SSL"]:
            server.starttls(context=ctx)
            server.ehlo()
        if cfg["MAIL_USERNAME"] and cfg["MAIL_PASSWORD"]:
            server.login(cfg["MAIL_USERNAME"], cfg["MAIL_PASSWORD"])
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass


def _api_send(to, subject, html, text=None):
    """Send one message through the Brevo transactional-email HTTPS API (standard library only)."""
    name, addr = app.config["MAIL_DEFAULT_SENDER"]
    payload = {"sender": {"name": name, "email": addr}, "to": [{"email": to}], "subject": subject, "htmlContent": html,
               "textContent": text or re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()}
    req = urllib.request.Request(app.config["BREVO_API_URL"], data=json.dumps(payload).encode("utf-8"), method="POST",
                                 headers={"api-key": app.config["BREVO_API_KEY"], "content-type": "application/json",
                                          "accept": "application/json", "user-agent": "TechConnect/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=MAIL_TIMEOUT) as resp:
            resp.read()
    except urllib.error.HTTPError as http_err:
        raise MailApiError(http_err.code, http_err.read().decode("utf-8", "replace")[:300]) from None


def _deliver(to, subject, html, text=None):
    """Send and LOG the real outcome.  -> (ok, message).  Never raises."""
    problem = mail_problem()
    if problem:
        mail_log.error("not sending %r to %s: %s", subject, _mask_email(to), problem)
        return False, problem
    try:
        (_api_send if app.config["BREVO_API_KEY"] else _smtp_send)(to, subject, html, text)
    except Exception as exc:
        reason = describe_mail_error(exc)
        mail_log.error("FAILED to send %r to %s: %s", subject, _mask_email(to), reason)
        return False, reason
    mail_log.info("sent %r to %s", subject, _mask_email(to))
    return True, None


def send_email_async(to, subject, html, text=None):
    """Fire-and-forget: returns immediately so a slow mail server can never hold up (or time out) a web request.
    The outcome, including any error, is written to the log by _deliver()."""
    threading.Thread(target=_deliver, args=(to, subject, html, text), daemon=True, name="tc-mail").start()


def send_email_safe(to, subject, html, timeout=25):
    """Send and WAIT (used by the admin 'send test email' and reminder jobs).  -> (ok, error_message)"""
    result = {}
    th = threading.Thread(target=lambda: result.update(zip(("ok", "err"), _deliver(to, subject, html))), daemon=True, name="tc-mail")
    th.start()
    th.join(timeout)
    if th.is_alive():
        return False, f"The mail server did not answer within {timeout}s"
    return result.get("ok", False), result.get("err")


def _log_mail_status():
    problem = mail_problem()
    if problem:
        mail_log.error("NOT READY: %s. Password-reset codes and reminder e-mails cannot be sent until this is fixed.", problem)
    elif app.config["BREVO_API_KEY"]:
        mail_log.info("ready: sending over the Brevo HTTPS API (works on Render's free plan); sender %s", app.config["MAIL_DEFAULT_SENDER"][1])
    else:
        c = app.config
        mail_log.info("ready: %s:%s via %s as %s (sender %s)", c["MAIL_SERVER"], c["MAIL_PORT"],
                      "SSL" if c["MAIL_USE_SSL"] else ("STARTTLS" if c["MAIL_USE_TLS"] else "plain SMTP"),
                      c["MAIL_USERNAME"], c["MAIL_DEFAULT_SENDER"][1])


_log_mail_status()
# ─────────────────────────────────────────────────────────────────────────────

def _load_secret_key():
    """Session-signing key.  Order: SECRET_KEY env var -> a key file created once and reused
    (so all Gunicorn workers and restarts agree) -> random per-process as a last resort.
    Never hard-code this: whoever knows it can forge a session cookie, including an admin one."""
    env = os.environ.get("SECRET_KEY")
    if env:
        return env, "environment"
    here = os.path.dirname(os.path.abspath(__file__))
    for folder in (os.path.expanduser("~"), here):
        path = os.path.join(folder, ".techconnect_secret_key")
        try:
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(secrets.token_hex(32))
            except FileExistsError:
                pass                                   # another worker created it first
            for _ in range(20):                        # ...wait until it has been written
                with open(path) as fh:
                    key = fh.read().strip()
                if len(key) >= 32:
                    return key, "file"
                _time.sleep(0.05)
        except OSError:
            continue
    return secrets.token_hex(32), "random (per process)"


app.secret_key, SECRET_KEY_SOURCE = _load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),   # HTTPS-only cookie on Render
)
if os.environ.get("RENDER"):
    # Render terminates TLS in front of us: trust exactly one proxy hop for client IP / scheme.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "techconnect.db")
LOCATIONS_PATH = os.path.join(BASE_DIR, "rwanda_locations.json")

UPLOAD_PHOTO_DIR = os.path.join(BASE_DIR, "static", "uploads", "photos")
UPLOAD_CERT_DIR = os.path.join(BASE_DIR, "private_uploads", "certificates")      # NOT under /static
_LEGACY_CERT_DIR = os.path.join(BASE_DIR, "static", "uploads", "certificates")
os.makedirs(UPLOAD_PHOTO_DIR, exist_ok=True)
os.makedirs(UPLOAD_CERT_DIR, exist_ok=True)


def _migrate_legacy_certificates():
    """One-time move of certificates that were saved under /static (publicly downloadable) to the private folder."""
    if not os.path.isdir(_LEGACY_CERT_DIR):
        return
    for name in os.listdir(_LEGACY_CERT_DIR):
        src, dst = os.path.join(_LEGACY_CERT_DIR, name), os.path.join(UPLOAD_CERT_DIR, name)
        if not os.path.isfile(src) or name.startswith("."):
            continue
        if os.path.exists(dst):            # never leave a public copy behind: keep both, under a new name
            stem, ext = os.path.splitext(name)
            n = 1
            while os.path.exists(dst):
                dst = os.path.join(UPLOAD_CERT_DIR, f"{stem}.legacy{n}{ext}")
                n += 1
        try:
            shutil.move(src, dst)
        except OSError as exc:
            print(f"[CERT MIGRATION] could not move {name}: {exc}", flush=True)


_migrate_legacy_certificates()

ALLOWED_PHOTO_EXT = {"png", "jpg", "jpeg", "webp"}
ALLOWED_CERT_EXT = {"pdf", "png", "jpg", "jpeg"}
MAX_UPLOAD_MB = 5
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024  # 5 MB per request

# ── Language / Translation system ─────────────────────────────────────────────
TRANSLATIONS = {
    "en": {
        "nav_home":"Home","nav_find":"Find a Technician","nav_signup":"Sign up as Technician",
        "nav_login":"Log In","nav_profile":"My Profile","nav_logout":"Log Out","nav_plans":"Plans & Pricing",
        "hero_title":"Find the Right Technician.<br>Solve Anything.",
        "hero_subtitle":"Connecting Rwanda's skilled technical graduates with clients who need their expertise — wherever they are.",
        "problem_label":"THE PROBLEM","problem_title":"Skilled graduates without work. Clients without help.",
        "problem_p1":"Every year, thousands of young Rwandans graduate from TVET colleges and universities with real technical skills — in electricity, plumbing, land surveying, carpentry, ICT and more. Yet many spend months or years without finding stable employment, while their skills go unused.",
        "problem_p2":"At the same time, homeowners, businesses and communities across Rwanda struggle to find a trusted, qualified technician when something needs fixing. There is no easy way to know who is nearby, who is verified, or who to call.",
        "problem_p3":"TechConnect was built to close this gap — giving graduates visibility, and giving clients a fast, reliable way to find the right person near them.",
        "vision_label":"LONG TERM VISION","vision_title":"Rwanda's most trusted technical jobs platform.",
        "vision_intro":"Our vision is a Rwanda where no qualified technician goes jobless simply because no one knows they exist.",
        "vision_1_title":"Empower graduates","vision_1_body":"Give every TVET and university technical graduate a verified professional profile that clients can find and trust.",
        "vision_2_title":"Local matching","vision_2_body":"Connect clients with the nearest available technician, by province, district, and sector across all of Rwanda.",
        "vision_3_title":"Verified quality","vision_3_body":"Every profile is backed by a real certificate or diploma, checked and verified before going live.",
        "vision_4_title":"National impact","vision_4_body":"Reduce youth unemployment in the technical sector while improving access to skilled services for all Rwandans.",
        "how_label":"HOW IT WORKS","how_title":"Simple. Fast. Trusted.",
        "step1_title":"Technician signs up","step1_body":"A graduate creates a profile with their qualification, trade, location, contact details, and uploads their certificate for verification.",
        "step2_title":"Client searches","step2_body":"Anyone who needs a technician opens TechConnect, selects a trade, and searches by district to find someone qualified nearby.",
        "step3_title":"They connect","step3_body":"The client sees the technician's full profile — name, qualification, location, phone and WhatsApp — and contacts them directly.",
        "counter_text":"verified technicians have joined TechConnect","welcome_back":"Welcome back",
        "find_title":"Find a Technician","find_hint":"Filter by trade and location to find the right person near you.",
        "access_active":"Full access active — all contacts visible. Expires in:","access_locked":"Contact details are hidden. Pay 200 RWF to unlock all contacts for 24 hours.",
        "unlock_btn":"Unlock Now — 200 RWF","trade_label":"Trade / Skill Category","all_trades":"All trades",
        "filter_location":"▼ Filter by location (optional)","hide_location":"▲ Hide location filters",
        "province_label":"Province","all_provinces":"All provinces","district_label":"District",
        "all_districts":"All districts","select_province":"Select province first",
        "sector_label":"Sector","all_sectors":"All sectors","select_district":"Select district first",
        "search_btn":"Search","clear_btn":"Clear","showing_all":"Showing all technicians","showing":"Showing:","found":"found",
        "qualification_label":"Qualification:","degree_in":"Degree in","certificate_in":"Certificate in",
        "unlock_contact":"Pay 200 RWF to unlock","no_technicians":"No technicians found.",
        "try_removing":"Try removing some filters, or","signup_first":"be the first to sign up here",
        "verified":"Verified","pending":"Pending Review",
        "pay_title":"Unlock All Technician Contacts",
        "pay_intro":"Pay <strong>{price} RWF</strong> to get <strong>{hours}-hour access</strong> to all technician contacts on TechConnect.",
        "pay_step1":"Step 1 — Send {price} RWF to:","mtn_title":"MTN MoMo Pay",
        "mtn_body":"Dial <code>*182*8*1*1578942*200#</code> on your phone to pay via MTN Mobile Money.",
        "airtel_title":"Airtel Money","airtel_body":"Dial <code>*185*9*1*{number}*{price}#</code> or send <strong>{price} RWF</strong> to <strong>{number}</strong> via Airtel Money app.",
        "bank_title":"Internet Banking","bank_body":"Transfer {price} RWF to mobile number <strong>{number}</strong> via your bank's mobile money transfer.",
        "sms_hint":"After paying you will receive a confirmation SMS with a transaction code. Keep that code — you will need it in Step 2.",
        "pay_step2":"Step 2 — Enter your payment confirmation:",
        "phone_label":"Your Phone Number (the one you paid from) *","phone_placeholder":"e.g. 0788123456",
        "code_label":"Confirmation Code from your payment SMS *","code_placeholder":"e.g. TXN123456789",
        "code_hint":"This is the reference/transaction ID in the SMS you received after paying.",
        "confirm_btn":"Confirm Payment & Unlock Access","access_hint":"Once confirmed, your access lasts <strong>{hours} hours</strong> in this browser.",
        "register_title":"Technician Sign-Up","register_hint":"Fill in your details so clients near you can find and contact you.",
        "fullname_label":"Full Name *","qual_type_label":"Qualification Type *","qual_degree":"Degree / Advanced Diploma (L6+)","qual_cert":"Professional Certificate","qual_diploma":"Advanced TVET Certificate V (L5)",
        "degree_level_label":"Degree Level *","field_label":"Field of Study / Specialization *","skill_label":"Skill Category *",
        "select_trade":"-- Select your trade --","select_level":"-- Select level --","select_type":"-- Select type --",
        "phone_label_reg":"Phone Number *","whatsapp_label":"WhatsApp Number","email_label":"Email *",
        "password_label":"Password *","confirm_pw_label":"Confirm Password *",
        "cert_upload_label":"Certificate / Proof of Qualification *","cert_number_label":"Certificate / Diploma Number *",
        "bio_label":"Short Bio / Experience","photo_label":"Profile Photo","create_btn":"Create My Profile",
        "login_title":"Technician Log In","login_hint":"Log in to view, edit, or delete your profile.",
        "login_btn":"Log In","no_profile":"Don't have a profile yet?","signup_link":"Sign up here",
        "profile_title":"My Profile","edit_btn":"Edit Profile","delete_btn":"Delete Profile",
        "cert_label":"Certificate:","view_file":"View uploaded file",
        "access_granted":"Access granted! You can now view all technician contacts for the next {hours} hours.",
        # — password reset + account messages —
        "reset_email_required":"Please enter a valid email address.",
        "reset_if_exists":"If an account exists for {email}, a 6-digit reset code has been sent to it. The code expires in 5 minutes. Please also check your spam folder.",
        "reset_mail_unavailable":"Our email service is temporarily unavailable, so we could not send your code. Please try again later or write to {support}.",
        "reset_temp_error":"A temporary error occurred. Please try again.",
        "reset_code_required":"Please enter the 6-digit code from your email.",
        "reset_code_wrong":"That code is incorrect or has expired. Please check your email and try again, or request a new code.",
        "reset_too_many":"Too many incorrect attempts. For your security, please request a new code.",
        "reset_pw_weak":"Password must be 8+ characters with uppercase, lowercase, number and symbol.",
        "reset_pw_mismatch":"Passwords do not match.",
        "reset_pw_done":"Your password has been reset successfully. You can now log in.",
        "account_suspended":"This account has been suspended. Please contact TechConnect support at {support}.",
        "reset_email_subject":"TechConnect — Your Password Reset Code",
        "reset_email_hello":"Hello",
        "reset_email_intro":"Use the code below to reset your password. It expires in 5 minutes.",
        "reset_email_ignore":"If you did not request this, you can safely ignore this email.",
        "reset_email_help":"Need help? Write to {support}.",
        "already_active":"You already have active access. Contacts are visible.","expired":"expired — refresh page",
    },
    "fr": {
        "nav_home":"Accueil","nav_find":"Trouver un Technicien","nav_signup":"S'inscrire comme Technicien",
        "nav_login":"Se Connecter","nav_profile":"Mon Profil","nav_logout":"Se Déconnecter","nav_plans":"Plans & Tarifs",
        "hero_title":"Trouvez le Bon Technicien.<br>Résolvez Tout.",
        "hero_subtitle":"Connecter les diplômés techniques rwandais avec les clients qui ont besoin de leurs compétences — partout au pays.",
        "problem_label":"LE PROBLÈME","problem_title":"Des diplômés sans emploi. Des clients sans aide.",
        "problem_p1":"Chaque année, des milliers de jeunes Rwandais obtiennent leur diplôme dans des écoles TVET et des universités avec de vraies compétences techniques. Pourtant, beaucoup passent des mois ou des années sans trouver un emploi stable.",
        "problem_p2":"En même temps, les propriétaires et les entreprises à travers le Rwanda peinent à trouver un technicien qualifié et de confiance quand ils en ont besoin.",
        "problem_p3":"TechConnect a été créé pour combler ce fossé — donner de la visibilité aux diplômés et offrir aux clients un moyen rapide de trouver la bonne personne près d'eux.",
        "vision_label":"VISION À LONG TERME","vision_title":"La plateforme d'emplois techniques la plus fiable du Rwanda.",
        "vision_intro":"Notre vision est un Rwanda où aucun technicien qualifié ne reste sans emploi parce que personne ne sait qu'il existe.",
        "vision_1_title":"Autonomiser les diplômés","vision_1_body":"Donner à chaque diplômé technique un profil professionnel vérifié que les clients peuvent trouver et approuver.",
        "vision_2_title":"Correspondance locale","vision_2_body":"Mettre en relation les clients avec le technicien le plus proche, par province, district et secteur dans tout le Rwanda.",
        "vision_3_title":"Qualité vérifiée","vision_3_body":"Chaque profil est soutenu par un vrai certificat ou diplôme, vérifié avant d'être publié.",
        "vision_4_title":"Impact national","vision_4_body":"Réduire le chômage des jeunes dans le secteur technique tout en améliorant l'accès aux services pour tous les Rwandais.",
        "how_label":"COMMENT ÇA MARCHE","how_title":"Simple. Rapide. Fiable.",
        "step1_title":"Le technicien s'inscrit","step1_body":"Un diplômé crée un profil avec sa qualification, son métier, sa localisation, ses coordonnées et télécharge son certificat.",
        "step2_title":"Le client recherche","step2_body":"Toute personne ayant besoin d'un technicien ouvre TechConnect, sélectionne un métier et recherche par district.",
        "step3_title":"Ils se connectent","step3_body":"Le client voit le profil complet du technicien — nom, qualification, localisation, téléphone et WhatsApp — et le contacte directement.",
        "counter_text":"techniciens vérifiés ont rejoint TechConnect","welcome_back":"Bon retour",
        "find_title":"Trouver un Technicien","find_hint":"Filtrez par métier et localisation pour trouver la bonne personne près de vous.",
        "access_active":"Accès complet actif — tous les contacts sont visibles. Expire dans :","access_locked":"Les coordonnées sont masquées. Payez 200 RWF pour débloquer tous les contacts pendant 24 heures.",
        "unlock_btn":"Débloquer — 200 RWF","trade_label":"Métier / Catégorie","all_trades":"Tous les métiers",
        "filter_location":"▼ Filtrer par localisation (optionnel)","hide_location":"▲ Masquer les filtres",
        "province_label":"Province","all_provinces":"Toutes les provinces","district_label":"District",
        "all_districts":"Tous les districts","select_province":"Sélectionnez d'abord la province",
        "sector_label":"Secteur","all_sectors":"Tous les secteurs","select_district":"Sélectionnez d'abord le district",
        "search_btn":"Rechercher","clear_btn":"Effacer","showing_all":"Affichage de tous les techniciens","showing":"Affichage :","found":"trouvé(s)",
        "qualification_label":"Qualification :","degree_in":"Licence en","certificate_in":"Certificat en",
        "unlock_contact":"Payer 200 RWF pour débloquer","no_technicians":"Aucun technicien trouvé.",
        "try_removing":"Essayez de supprimer des filtres, ou","signup_first":"soyez le premier à vous inscrire ici",
        "verified":"Vérifié","pending":"En attente de vérification",
        "pay_title":"Débloquer tous les contacts des techniciens",
        "pay_intro":"Payez <strong>{price} RWF</strong> pour obtenir un accès de <strong>{hours} heures</strong> à toutes les coordonnées des techniciens sur TechConnect.",
        "pay_step1":"Étape 1 — Envoyez {price} RWF à :","mtn_title":"MTN MoMo Pay",
        "mtn_body":"Composez <code>*182*8*1*1578942*200#</code> sur votre téléphone pour payer via MTN Mobile Money.",
        "airtel_title":"Airtel Money","airtel_body":"Composez <code>*185*9*1*{number}*{price}#</code> ou envoyez <strong>{price} RWF</strong> au <strong>{number}</strong> via l'application Airtel Money.",
        "bank_title":"Banque en ligne","bank_body":"Transférez {price} RWF au numéro mobile <strong>{number}</strong> via l'option de transfert mobile money de votre banque.",
        "sms_hint":"Après le paiement, vous recevrez un SMS de confirmation avec un code de transaction. Gardez ce code pour l'étape 2.",
        "pay_step2":"Étape 2 — Entrez votre confirmation de paiement :",
        "phone_label":"Votre numéro de téléphone (celui utilisé pour payer) *","phone_placeholder":"ex. 0788123456",
        "code_label":"Code de confirmation de votre SMS *","code_placeholder":"ex. TXN123456789",
        "code_hint":"C'est l'identifiant de transaction dans le SMS reçu après le paiement.",
        "confirm_btn":"Confirmer le paiement et débloquer l'accès","access_hint":"Une fois confirmé, votre accès dure <strong>{hours} heures</strong> dans ce navigateur.",
        "register_title":"Inscription du Technicien","register_hint":"Remplissez vos coordonnées pour que les clients près de vous puissent vous trouver.",
        "fullname_label":"Nom complet *","qual_type_label":"Type de qualification *","qual_degree":"Diplôme / Diplôme Avancé (L6+)","qual_cert":"Certificat Professionnel","qual_diploma":"Certificat TVET Avancé V (L5)",
        "degree_level_label":"Niveau du diplôme *","field_label":"Domaine d'études / Spécialisation *","skill_label":"Catégorie de compétence *",
        "select_trade":"-- Sélectionnez votre métier --","select_level":"-- Sélectionnez le niveau --","select_type":"-- Sélectionnez le type --",
        "phone_label_reg":"Numéro de téléphone *","whatsapp_label":"Numéro WhatsApp","email_label":"Email *",
        "password_label":"Mot de passe *","confirm_pw_label":"Confirmer le mot de passe *",
        "cert_upload_label":"Certificat / Preuve de qualification *","cert_number_label":"Numéro du certificat / diplôme *",
        "bio_label":"Courte biographie / Expérience","photo_label":"Photo de profil","create_btn":"Créer mon profil",
        "login_title":"Connexion du Technicien","login_hint":"Connectez-vous pour voir, modifier ou supprimer votre profil.",
        "login_btn":"Se Connecter","no_profile":"Pas encore de profil ?","signup_link":"Inscrivez-vous ici",
        "profile_title":"Mon Profil","edit_btn":"Modifier le Profil","delete_btn":"Supprimer le Profil",
        "cert_label":"Certificat :","view_file":"Voir le fichier téléchargé",
        "access_granted":"Accès accordé ! Vous pouvez voir toutes les coordonnées pendant {hours} heures.",
        # — réinitialisation du mot de passe + messages du compte —
        "reset_email_required":"Veuillez saisir une adresse e-mail valide.",
        "reset_if_exists":"Si un compte existe pour {email}, un code de réinitialisation à 6 chiffres vient d'y être envoyé. Le code expire dans 5 minutes. Pensez aussi à vérifier vos courriers indésirables.",
        "reset_mail_unavailable":"Notre service d'e-mail est temporairement indisponible, nous n'avons donc pas pu envoyer votre code. Veuillez réessayer plus tard ou écrire à {support}.",
        "reset_temp_error":"Une erreur temporaire s'est produite. Veuillez réessayer.",
        "reset_code_required":"Veuillez saisir le code à 6 chiffres reçu par e-mail.",
        "reset_code_wrong":"Ce code est incorrect ou a expiré. Vérifiez votre e-mail et réessayez, ou demandez un nouveau code.",
        "reset_too_many":"Trop de tentatives incorrectes. Pour votre sécurité, veuillez demander un nouveau code.",
        "reset_pw_weak":"Le mot de passe doit contenir 8 caractères ou plus, avec majuscule, minuscule, chiffre et symbole.",
        "reset_pw_mismatch":"Les mots de passe ne correspondent pas.",
        "reset_pw_done":"Votre mot de passe a été réinitialisé avec succès. Vous pouvez maintenant vous connecter.",
        "account_suspended":"Ce compte a été suspendu. Veuillez contacter le support TechConnect à {support}.",
        "reset_email_subject":"TechConnect — Votre code de réinitialisation",
        "reset_email_hello":"Bonjour",
        "reset_email_intro":"Utilisez le code ci-dessous pour réinitialiser votre mot de passe. Il expire dans 5 minutes.",
        "reset_email_ignore":"Si vous n'êtes pas à l'origine de cette demande, vous pouvez ignorer cet e-mail.",
        "reset_email_help":"Besoin d'aide ? Écrivez à {support}.",
        "already_active":"Vous avez déjà un accès actif. Les contacts sont visibles.","expired":"expiré — actualisez la page",
    }
}

def get_lang():
    return session.get("lang", "en")

def get_t():
    return TRANSLATIONS.get(get_lang(), TRANSLATIONS["en"])

@app.context_processor
def inject_lang():
    lang = get_lang()
    return {"lang": lang, "t": get_t(), "support_email": SUPPORT_EMAIL}


@app.route("/select-plan")
def select_plan():
    """Subscription plan selection page shown after registration."""
    return render_template("select_plan.html", technician=current_technician())


@app.route("/set-lang/<lang>")
def set_lang(lang):
    if lang in ("en", "fr"):
        session["lang"] = lang
    return redirect(request.referrer or url_for("home"))


SKILL_CATEGORIES = [
    # Construction & Civil
    "Masonry / Construction",
    "Carpentry & Joinery",
    "Land Surveying / Subdivision",
    "Road & Highway Construction",
    "Painting & Decoration",
    "Roofing",
    "Tiling & Flooring",
    "Welding & Metal Fabrication",
    # Electrical & Energy
    "Electrical Installation",
    "Solar / Renewable Energy",
    "Electronics Repair",
    "Refrigeration & Air Conditioning",
    # Plumbing & Water
    "Plumbing",
    "Water Supply & Sanitation",
    "Irrigation Systems",
    # Mechanical & Auto
    "Auto Mechanics",
    "Motorcycle Mechanics",
    "Auto Electrical",
    "Panel Beating & Spray Painting",
    "Heavy Machinery Operation",
    # ICT & Digital
    "Computer Repair & Maintenance",
    "Networking & IT Support",
    "Software Development",
    "Phone Repair",
    "CCTV / Security Systems Installation",
    # Textile & Crafts
    "Tailoring / Fashion Design",
    "Shoemaking & Leatherwork",
    "Hairdressing & Beauty",
    "Furniture Making",
    # Food & Agro-processing
    "Catering & Food Production",
    "Agro-mechanization",
    "Cold Chain / Food Storage Systems",
    # Other
    "Other",
]

DEGREE_LEVELS = ["Advanced TVET Certificate V (L5)", "Degree / Advanced Diploma (L6+)", "Professional Certificate"]


def is_strong_password(password):
    """At least 8 characters, with an uppercase, lowercase, number, and symbol."""
    if len(password) < 8:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_symbol


def capitalize_name(name):
    """Capitalize the first letter of each word, as a server-side safety net
    in case the browser's JavaScript auto-capitalize didn't run."""
    return " ".join(word[:1].upper() + word[1:] for word in name.split(" ") if word)


# Keywords that suggest a document IS a degree document, vs a certificate
# document. Note: the word "Diploma" alone is ambiguous in Rwanda's system
# (it's used for both A1 TVET diplomas and old-style "Advanced Diplomas"),
# so the type check leans on the qualification LEVEL words (A2/A1/Bachelor/
# Masters/PhD) rather than the word "diploma" or "certificate" by themselves.
DEGREE_TYPE_KEYWORDS = ["bachelor", "b.sc", "bsc", "master", "msc", "m.sc",
                         "phd", "doctor of philosophy", "university", " a0 ", " a1 ", "degree"]
CERTIFICATE_TYPE_KEYWORDS = ["certificate", "diploma", " l5 ", " l4 ", " l3 ", "tvet", "vocational",
                              "rtb", "polytechnic", "vocational training centre", "senior six", "s6"]

# Common short connector words to ignore when comparing the field of study
# against the document text, so we only compare meaningful words.
STOPWORDS = {"and", "the", "for", "with", "from", "this", "that", "program",
             "level", "course", "technology", "studies", "study"}


def fields_relate_to_each_other(skill_category, degree_field):
    """Check that the typed Field of Study and the chosen Skill Category
    are actually talking about the same trade, before we even look at the
    certificate. e.g. Field of Study 'Plumbing' + Skill Category 'Land
    Surveying / Subdivision' should fail this check, since neither word
    set overlaps with the other at all."""
    skill_words = extract_keywords(skill_category)
    field_words = extract_keywords(degree_field)
    if not skill_words or not field_words:
        # If either side has no meaningful words to compare (e.g. a very
        # short field name), don't block on this check alone.
        return True
    # Direct overlap, or one side's words contain the other's as substrings
    # (handles cases like "Land Surveying" vs "Surveying").
    if skill_words & field_words:
        return True
    for s in skill_words:
        for f in field_words:
            if s in f or f in s:
                return True
    return False


def extract_text_from_file(filepath):
    """Pull plain text out of an uploaded image or PDF using OCR.
    Returns an empty string if OCR isn't available or extraction fails,
    so the rest of the app can keep working without it."""
    if not OCR_AVAILABLE:
        return ""
    try:
        ext = filepath.rsplit(".", 1)[1].lower()
        if ext == "pdf":
            pages = convert_from_path(filepath, dpi=200, first_page=1, last_page=1)
            if not pages:
                return ""
            return pytesseract.image_to_string(pages[0])
        else:
            return pytesseract.image_to_string(Image.open(filepath))
    except Exception as e:
        # If Tesseract isn't installed on this computer, or the file is
        # unreadable, just skip the automatic check rather than crashing.
        # (Logged so it's visible in the terminal while debugging.)
        print(f"[OCR DEBUG] extract_text_from_file FAILED for {filepath!r}: {type(e).__name__}: {e}", flush=True)
        return ""


def extract_keywords(*phrases):
    """Turn a skill category / field-of-study string into a set of
    meaningful lowercase words to search for in the document text."""
    combined = " ".join(phrases).lower()
    combined = re.sub(r"[^a-z0-9\s]", " ", combined)
    words = {w for w in combined.split() if len(w) > 3 and w not in STOPWORDS}
    return words



def verify_technician_certificate(file_path, form_name, form_trade, form_cert_code, is_foreign=False):
    """
    5-Point Strict Verification Engine.
    Attempts QR + live portal verification first.
    Falls back gracefully to OCR keyword matching if QR/portal unavailable.
    Returns a check dict compatible with check_certificate_document output.
    """

    # ── STEP 1: Try QR code scanning (requires pyzbar) ──────────────────────
    qr_url = None
    if QR_AVAILABLE and OCR_AVAILABLE:
        try:
            # Handle both image and PDF inputs
            ext = file_path.rsplit(".", 1)[-1].lower()
            if ext == "pdf":
                pages = convert_from_path(file_path, dpi=200, first_page=1, last_page=1)
                img_for_qr = pages[0] if pages else None
            else:
                img_for_qr = Image.open(file_path)

            if img_for_qr:
                decoded_objs = decode_qr(img_for_qr)
                if decoded_objs:
                    qr_url = decoded_objs[0].data.decode("utf-8").strip()
                    print(f"[QR] Found QR payload: {qr_url}", flush=True)
        except Exception as e:
            print(f"[QR] QR scan failed (non-fatal, falling back to OCR): {e}", flush=True)
            qr_url = None

    # ── STEP 2: Try live NESA/RTB portal verification if QR found ───────────
    if qr_url and PORTAL_AVAILABLE:
        trusted_domains = ["nesa.gov.rw", "rtb.gov.rw", "hec.gov.rw", "irembo.gov.rw", "graduate.nesa.gov.rw"]
        if any(domain in qr_url.lower() for domain in trusted_domains):
            try:
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                response = requests.get(qr_url, headers=headers, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, "html.parser")
                    portal_text = soup.get_text().lower()

                    # Check name match
                    name_parts = [p.lower() for p in form_name.split() if len(p) > 2]
                    name_ok = all(part in portal_text for part in name_parts)

                    # Check cert number match
                    clean_cert = re.sub(r"[^a-z0-9]", "", form_cert_code.lower())
                    cert_ok = not clean_cert or clean_cert in re.sub(r"[^a-z0-9]", "", portal_text)

                    # Check trade/field match
                    trade_kws = [kw.lower() for kw in form_trade.split() if len(kw) > 2]
                    trade_ok = any(kw in portal_text for kw in trade_kws)

                    if name_ok and cert_ok and trade_ok:
                        print("[NESA] ✅ Certificate verified via official NESA portal.", flush=True)
                        return {"ocr_ran": True, "type_ok": True, "field_ok": True,
                                "matched_keywords": ["nesa_verified"], "nesa_verified": True}
                    else:
                        errors = []
                        if not name_ok: errors.append("name mismatch")
                        if not cert_ok: errors.append("certificate number mismatch")
                        if not trade_ok: errors.append("field of study mismatch")
                        print(f"[NESA] ❌ Portal check failed: {', '.join(errors)}", flush=True)
                        return {"ocr_ran": True, "type_ok": False, "field_ok": False,
                                "matched_keywords": [],
                                "error": f"Official NESA portal rejection: {', '.join(errors)}."}
            except Exception as e:
                print(f"[NESA] Portal unreachable (falling back to OCR): {e}", flush=True)
                # Fall through to OCR check below

    # ── STEP 3: Fall back to OCR keyword matching ────────────────────────────
    print("[VERIFY] Using OCR keyword fallback (QR/portal unavailable).", flush=True)
    return check_certificate_document_ocr(file_path, form_trade, form_cert_code)


def check_certificate_document_ocr(filepath, skill_category, degree_field):
    """OCR-based document check used as fallback when QR/portal unavailable."""
    text = extract_text_from_file(filepath)
    if not text.strip():
        # Cannot read document — pass gracefully rather than block valid uploads
        return {"ocr_ran": False, "type_ok": True, "field_ok": True, "matched_keywords": []}

    text_lower = " " + text.lower().replace("\n", " ") + " "

    # Type check — look for NESA/TVET specific phrases from the real diploma
    tvet_l5_phrases = [
        "rwanda technical certificate of education",
        "advanced tvet certificate v",
        "tvet certificate v",
        "certificate v",
        "national examination and school inspection",
        "nesa",
    ]
    degree_phrases = [
        "bachelor", "master", "phd", "doctor", "university",
        "advanced diploma", "higher education",
    ]
    cert_phrases = [
        "certificate", "diploma", "tvet", "vocational", "rtb", "polytechnic",
    ]

    type_ok = (
        any(phrase in text_lower for phrase in tvet_l5_phrases) or
        any(phrase in text_lower for phrase in degree_phrases) or
        any(phrase in text_lower for phrase in cert_phrases)
    )

    # Field check — match skill category and degree field keywords against OCR text
    field_keywords = extract_keywords(skill_category, degree_field)
    matched = [word for word in field_keywords if word in text_lower]
    field_ok = len(matched) > 0 if field_keywords else True

    return {"ocr_ran": True, "type_ok": type_ok, "field_ok": field_ok, "matched_keywords": matched}


def check_certificate_document(filepath, qualification_type, degree_level, skill_category, degree_field):
    """Run the automatic document check. Returns a dict with:
      - ocr_ran: whether OCR actually ran (False if unavailable/failed)
      - type_ok: whether the document text matches the claimed qualification type
      - field_ok: whether the document text mentions the claimed field/skill
      - matched_keywords: which words from their field were actually found
    If OCR didn't run, all checks default to True (we don't block someone
    just because OCR isn't installed on this computer)."""
    text = extract_text_from_file(filepath)
    if not text.strip():
        return {"ocr_ran": False, "type_ok": True, "field_ok": True, "matched_keywords": []}

    # Pad with spaces so short tokens like "A2" can be matched as whole words
    text_lower = " " + text.lower().replace("\n", " ") + " "

    # First, check for the SPECIFIC level they chose (most reliable signal).
    # OCR commonly misreads "1" as "l" and "0" as "O", so we check both forms.
    level_ok = True
    if degree_level:
        clean_level = degree_level.lower().replace("'", "")
        ocr_variant = clean_level.replace("1", "l").replace("0", "o")
        candidates = {f" {clean_level} ", f" {ocr_variant} "}
        normalized_text = text_lower.replace("'", "")
        level_ok = any(candidate in normalized_text for candidate in candidates)

    # Fall back to broader type keywords if the specific level wasn't found
    expected_type_words = DEGREE_TYPE_KEYWORDS if qualification_type == "Degree / Advanced Diploma (L6+)" else CERTIFICATE_TYPE_KEYWORDS
    type_keyword_ok = any(word in text_lower for word in expected_type_words)

    type_ok = level_ok or type_keyword_ok

    field_keywords = extract_keywords(skill_category, degree_field)
    matched = [word for word in field_keywords if word in text_lower]
    field_ok = len(matched) > 0 if field_keywords else True

    return {"ocr_ran": True, "type_ok": type_ok, "field_ok": field_ok, "matched_keywords": matched}

# Load Rwanda's province -> district -> sector structure once at startup
with open(LOCATIONS_PATH, encoding="utf-8") as f:
    RWANDA_LOCATIONS = json.load(f)


# ── Inline SVG icons (sprite lives in templates/_icons.html) ──────────────────
from markupsafe import Markup, escape as _escape
_ICON_NAME_RE = re.compile(r"^[a-z0-9-]+$")


def icon(name, cls=""):
    """Render an inline SVG icon: {{ icon('home') }} or {{ icon('lock', 'ic-md ic-t') }}."""
    if not _ICON_NAME_RE.match(name or ""):
        return Markup("")
    extra = (" " + str(_escape(cls))) if cls else ""
    return Markup(
        f'<svg class="ic{extra}" fill="none" stroke="currentColor" stroke-width="1.75" '
        f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
        f'<use href="#i-{name}"/></svg>'
    )


app.jinja_env.globals["icon"] = icon


_SCHEMA_READY = False
_SCHEMA_LOCK = threading.Lock()


def _raw_connect():
    """Plain connection to the absolute DB path - no schema logic."""
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def get_db_connection():
    """Open a connection, making sure the schema exists first (once per process).

    This is what makes the app safe under Gunicorn on Render: the
    `if __name__ == "__main__"` block never runs there, and the SQLite file
    is brand new after every deploy/restart on the ephemeral filesystem.
    """
    global _SCHEMA_READY
    if not _SCHEMA_READY:
        with _SCHEMA_LOCK:
            if not _SCHEMA_READY:
                init_db()
                _SCHEMA_READY = True
    return _raw_connect()


def init_db():
    conn = _raw_connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS technicians (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            qualification_type TEXT NOT NULL DEFAULT 'Advanced TVET Certificate V (L5)',
            degree_level TEXT,
            degree TEXT NOT NULL,
            skill_category TEXT NOT NULL,
            phone TEXT NOT NULL,
            whatsapp TEXT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            province TEXT NOT NULL,
            district TEXT NOT NULL,
            sector TEXT NOT NULL,
            bio TEXT,
            photo_filename TEXT,
            certificate_filename TEXT,
            certificate_number TEXT,
            verification_status TEXT NOT NULL DEFAULT 'Pending Review',
            created_at TEXT DEFAULT (datetime('now')),
            reset_token TEXT DEFAULT NULL,
            token_expiration TEXT DEFAULT NULL
        )
    """)
    # ── New tables ──────────────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS portfolio_images (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            technician_id INTEGER NOT NULL,
            image_url     TEXT NOT NULL,
            caption       TEXT DEFAULT '',
            created_at    TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (technician_id) REFERENCES technicians(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            technician_id INTEGER NOT NULL,
            client_name   TEXT NOT NULL DEFAULT 'Anonymous',
            rating        INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
            comment       TEXT DEFAULT '',
            created_at    TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (technician_id) REFERENCES technicians(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS site_feedback (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            rating     INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
            comment    TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # ── Migrate existing technicians table ───────────────────────────────────
    for col, defn in [
        ("reset_token",    "TEXT DEFAULT NULL"),
        ("token_expiration","TEXT DEFAULT NULL"),
        ("reset_attempts", "INTEGER DEFAULT 0"),
        ("is_available",   "INTEGER DEFAULT 1"),
        ("avg_rating",     "REAL DEFAULT 0"),
        ("review_count",   "INTEGER DEFAULT 0"),
    ]:
        try:
            conn.execute(f"ALTER TABLE technicians ADD COLUMN {col} {defn}")
        except Exception:
            pass  # Already exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS payment_claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT NOT NULL,
            code TEXT NOT NULL,
            claimed_at TEXT DEFAULT (datetime('now')),
            ip TEXT
        )
    """)
    admin_portal.ensure_schema(conn)      # subscriptions, unlock ledger, retention alerts, audit log
    conn.commit()
    conn.close()


def allowed_file(filename, allowed_set):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_set


def save_upload(file_obj, upload_dir, allowed_set):
    """Save an uploaded file with a unique name. Returns the filename, or None."""
    if not file_obj or file_obj.filename == "":
        return None
    if not allowed_file(file_obj.filename, allowed_set):
        return None
    ext = file_obj.filename.rsplit(".", 1)[1].lower()
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    file_obj.save(os.path.join(upload_dir, unique_name))
    return unique_name


def current_technician():
    """Return the logged-in technician's row, or None."""
    tech_id = session.get("technician_id")
    if not tech_id:
        return None
    conn = get_db_connection()
    tech = conn.execute("SELECT * FROM technicians WHERE id = ?", (tech_id,)).fetchone()
    conn.close()
    if tech is not None and tech["is_suspended"]:
        session.pop("technician_id", None)          # suspended while logged in -> signed out
        return None
    return tech


@app.route("/")
def home():
    conn = get_db_connection()
    technician_count = conn.execute("SELECT COUNT(*) AS c FROM technicians").fetchone()["c"]
    conn.close()
    return render_template("home.html", technician=current_technician(), technician_count=technician_count)


# ---------- Location API (for cascading dropdowns) ----------

@app.route("/api/districts")
def api_districts():
    """Given ?province=X, return the list of districts in that province."""
    province = request.args.get("province", "")
    districts = list(RWANDA_LOCATIONS.get(province, {}).keys())
    return jsonify(districts)


@app.route("/api/sectors")
def api_sectors():
    """Given ?province=X&district=Y, return the list of sectors."""
    province = request.args.get("province", "")
    district = request.args.get("district", "")
    sectors = RWANDA_LOCATIONS.get(province, {}).get(district, [])
    return jsonify(sectors)


# ---------- Registration ----------

@app.route("/register", methods=["GET", "POST"])
def register():
    """Step 1 — Personal Contact Information."""
    if request.method == "POST":
        full_name = capitalize_name(request.form.get("full_name", "").strip())
        phone     = request.form.get("phone", "").strip()
        whatsapp  = request.form.get("whatsapp", "").strip()
        email     = request.form.get("email", "").strip().lower()

        errors = []
        if not full_name:
            errors.append("Full name is required.")
        if not phone:
            errors.append("Phone number is required.")
        if not email:
            errors.append("Email address is required.")
        if email:
            conn = get_db_connection()
            existing = conn.execute("SELECT id FROM technicians WHERE email = ?", (email,)).fetchone()
            conn.close()
            if existing:
                errors.append("An account with that email already exists. Try logging in instead.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register_step1.html", t=get_t(), lang=get_lang(), technician=current_technician())

        session["reg_full_name"] = full_name
        session["reg_phone"]     = phone
        session["reg_whatsapp"]  = whatsapp
        session["reg_email"]     = email
        return redirect(url_for("register_step2"))

    return render_template("register_step1.html", t=get_t(), lang=get_lang(), technician=current_technician())


@app.route("/register/step2", methods=["GET", "POST"])
def register_step2():
    """Step 2 — Professional Qualifications & Certificate Upload."""
    if not session.get("reg_email"):
        return redirect(url_for("register"))

    if request.method == "POST":
        qualification_type = request.form.get("qualification_type", "").strip()
        degree_level       = request.form.get("degree_level", "").strip()
        degree             = request.form.get("degree", "").strip().upper()
        skill_category     = request.form.get("skill_category", "").strip()
        certificate_number = request.form.get("certificate_number", "").strip()
        bio                = request.form.get("bio", "").strip()

        VALID_QUAL_TYPES = [
            "Advanced TVET Certificate V (L5)",
            "Professional Certificate",
            "Degree / Advanced Diploma (L6+)",
        ]
        errors = []
        if qualification_type not in VALID_QUAL_TYPES:
            errors.append("Please choose a valid qualification type.")
        if not degree:
            errors.append("Field of Study / Specialization is required.")
        if not skill_category:
            errors.append("Please choose a Skill Category.")
        if degree and skill_category and not fields_relate_to_each_other(skill_category, degree):
            errors.append(
                f"\"{degree}\" doesn't seem related to \"{skill_category}\". "
                "Please make sure your Field of Study and Skill Category describe the same trade."
            )

        certificate_file     = request.files.get("certificate")
        certificate_provided = bool(certificate_file and certificate_file.filename)
        if not certificate_provided and not session.get("reg_certificate_filename"):
            errors.append("Please upload your certificate or diploma.")
        if certificate_provided and not certificate_number:
            errors.append("Please enter the certificate/diploma number printed on your document.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register_step2.html",
                skill_categories=SKILL_CATEGORIES, degree_levels=DEGREE_LEVELS,
                t=get_t(), lang=get_lang(), technician=current_technician())

        # Handle certificate upload & OCR/QR verification
        if certificate_provided:
            certificate_filename = save_upload(certificate_file, UPLOAD_CERT_DIR, ALLOWED_CERT_EXT)
            if not certificate_filename:
                flash("Certificate file couldn't be saved — please use PDF, PNG, or JPG under 5MB.", "error")
                return render_template("register_step2.html",
                    skill_categories=SKILL_CATEGORIES, degree_levels=DEGREE_LEVELS,
                    t=get_t(), lang=get_lang(), technician=current_technician())

            cert_path = os.path.join(UPLOAD_CERT_DIR, certificate_filename)
            is_foreign = any(x in (degree_level or "") for x in ("Bachelor", "Master", "PhD", "L6"))
            check = verify_technician_certificate(
                cert_path, session["reg_full_name"], degree, certificate_number, is_foreign=is_foreign
            )
            print(f"[STEP2 VERIFY] {check}", flush=True)
            # Only certificates confirmed by the live NESA/RTB portal earn the
            # "Verified" badge; OCR-only acceptances stay "Pending Review".
            session["reg_verified"] = bool(check.get("nesa_verified"))

            if check.get("nesa_verified"):
                print("[STEP2] ✅ Accepted via NESA portal.", flush=True)
            elif check["ocr_ran"] and not check["type_ok"]:
                os.remove(cert_path)
                flash(check.get("error") or
                      f"The uploaded document doesn't look like a valid {qualification_type} document.", "error")
                return render_template("register_step2.html",
                    skill_categories=SKILL_CATEGORIES, degree_levels=DEGREE_LEVELS,
                    t=get_t(), lang=get_lang(), technician=current_technician())
            elif check["ocr_ran"] and not check["field_ok"]:
                os.remove(cert_path)
                flash(check.get("error") or
                      f"We couldn't find \"{degree}\" on the uploaded document. "
                      "Please upload the correct certificate.", "error")
                return render_template("register_step2.html",
                    skill_categories=SKILL_CATEGORIES, degree_levels=DEGREE_LEVELS,
                    t=get_t(), lang=get_lang(), technician=current_technician())

            session["reg_certificate_filename"] = certificate_filename

        # Handle optional photo
        photo_file = request.files.get("photo")
        if photo_file and photo_file.filename:
            photo_filename = save_upload(photo_file, UPLOAD_PHOTO_DIR, ALLOWED_PHOTO_EXT)
            if photo_filename:
                session["reg_photo_filename"] = photo_filename

        session["reg_qualification_type"] = qualification_type
        session["reg_degree_level"]       = degree_level
        session["reg_degree"]             = degree
        session["reg_skill_category"]     = skill_category
        session["reg_certificate_number"] = certificate_number
        session["reg_bio"]                = bio
        return redirect(url_for("register_step3"))

    return render_template("register_step2.html",
        skill_categories=SKILL_CATEGORIES, degree_levels=DEGREE_LEVELS,
        t=get_t(), lang=get_lang(), technician=current_technician())


@app.route("/register/step3", methods=["GET", "POST"])
def register_step3():
    """Step 3 — Geographic Location."""
    if not session.get("reg_skill_category"):
        return redirect(url_for("register_step2"))

    if request.method == "POST":
        province = request.form.get("province", "").strip()
        district = request.form.get("district", "").strip()
        sector   = request.form.get("sector", "").strip()

        errors = []
        if not province: errors.append("Please choose your Province.")
        if not district: errors.append("Please choose your District.")
        if not sector:   errors.append("Please choose your Sector.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register_step3.html",
                provinces=list(RWANDA_LOCATIONS.keys()),
                t=get_t(), lang=get_lang(), technician=current_technician())

        session["reg_province"] = province
        session["reg_district"] = district
        session["reg_sector"]   = sector
        return redirect(url_for("register_step4"))

    return render_template("register_step3.html",
        provinces=list(RWANDA_LOCATIONS.keys()),
        t=get_t(), lang=get_lang(), technician=current_technician())


@app.route("/register/step4", methods=["GET", "POST"])
def register_step4():
    """Step 4 — Account Security & Final DB Insertion."""
    if not session.get("reg_province"):
        return redirect(url_for("register_step3"))

    if request.method == "POST":
        password         = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        errors = []
        if not is_strong_password(password):
            errors.append("Password must be 8+ characters with uppercase, lowercase, number and symbol.")
        if password != confirm_password:
            errors.append("Passwords do not match.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register_step4.html", t=get_t(), lang=get_lang(), technician=current_technician())

        # Final DB insertion
        full_name            = session.get("reg_full_name", "")
        phone                = session.get("reg_phone", "")
        whatsapp             = session.get("reg_whatsapp", "")
        email                = session.get("reg_email", "")
        qualification_type   = session.get("reg_qualification_type", "")
        degree_level         = session.get("reg_degree_level", "")
        degree               = session.get("reg_degree", "")
        skill_category       = session.get("reg_skill_category", "")
        certificate_number   = session.get("reg_certificate_number", "")
        bio                  = session.get("reg_bio", "")
        photo_filename       = session.get("reg_photo_filename", None)
        certificate_filename = session.get("reg_certificate_filename", "")
        province             = session.get("reg_province", "")
        district             = session.get("reg_district", "")
        sector               = session.get("reg_sector", "")
        password_hash        = generate_password_hash(password)

        conn = get_db_connection()
        existing = conn.execute("SELECT id FROM technicians WHERE email = ?", (email,)).fetchone()
        if existing:
            conn.close()
            flash("An account with that email already exists.", "error")
            return redirect(url_for("register"))

        cursor = conn.execute(
            """INSERT INTO technicians
                (full_name, qualification_type, degree_level, degree, skill_category,
                 phone, whatsapp, email, password_hash,
                 province, district, sector, bio,
                 photo_filename, certificate_filename, certificate_number,
                 verification_status, subscription_plan, subscription_expires)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (full_name, qualification_type, degree_level, degree, skill_category,
             phone, whatsapp, email, password_hash,
             province, district, sector, bio,
             photo_filename, certificate_filename, certificate_number,
             "Verified" if session.get("reg_verified") else "Pending Review",
             "trial", admin_portal.to_db(admin_portal.utcnow() + timedelta(days=admin_portal.TRIAL_DAYS))),
        )
        conn.commit()
        new_id = cursor.lastrowid
        conn.close()

        # Clear all registration session keys
        for key in ["reg_full_name","reg_phone","reg_whatsapp","reg_email",
                    "reg_qualification_type","reg_degree_level","reg_degree",
                    "reg_skill_category","reg_certificate_number","reg_bio",
                    "reg_photo_filename","reg_certificate_filename","reg_verified",
                    "reg_province","reg_district","reg_sector"]:
            session.pop(key, None)

        session["technician_id"] = new_id
        flash(f"Welcome, {full_name}! Your profile is live. Choose a plan to stay listed after your 7-day free trial.", "success")
        return redirect(url_for("select_plan"))

    return render_template("register_step4.html", t=get_t(), lang=get_lang(), technician=current_technician())


# ---------- Login / Logout ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db_connection()
        tech = conn.execute("SELECT * FROM technicians WHERE email = ?", (email,)).fetchone()
        conn.close()

        if tech and check_password_hash(tech["password_hash"], password):
            if tech["is_suspended"]:
                flash(get_t()["account_suspended"].format(support=SUPPORT_EMAIL), "error")
                return render_template("login.html")
            session["technician_id"] = tech["id"]
            flash(f"Welcome back, {tech['full_name']}!", "success")
            return redirect(url_for("my_profile"))
        else:
            flash("Incorrect email or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("technician_id", None)
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


# ---------- My profile: view / edit / delete ----------

@app.route("/certificate/<path:filename>")
def certificate_file(filename):
    """Certificates are private: only the owning technician or the signed-in admin can open one.
    Everyone else gets a plain 404 (so the file's existence is not revealed)."""
    if secure_filename(filename) != filename:
        abort(404)
    allowed = admin_portal.is_admin()
    if not allowed:
        tech = current_technician()
        allowed = bool(tech and tech["certificate_filename"] == filename)
    if not allowed:
        abort(404)
    resp = send_from_directory(UPLOAD_CERT_DIR, filename)
    resp.headers["Cache-Control"] = "private, no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/my-profile")
def my_profile():
    tech = current_technician()
    if not tech:
        flash("Please log in to view your profile.", "error")
        return redirect(url_for("login"))
    portfolio, reviews = [], []
    conn = get_db_connection()
    try:
        try:
            portfolio = conn.execute(
                "SELECT * FROM portfolio_images WHERE technician_id = ? ORDER BY created_at DESC",
                (tech["id"],)
            ).fetchall()
        except sqlite3.OperationalError as e:
            print(f"[MY_PROFILE] portfolio query failed: {e}", flush=True)
        try:
            reviews = conn.execute(
                "SELECT * FROM reviews WHERE technician_id = ? ORDER BY created_at DESC",
                (tech["id"],)
            ).fetchall()
        except sqlite3.OperationalError as e:
            print(f"[MY_PROFILE] reviews query failed: {e}", flush=True)
    finally:
        conn.close()
    return render_template("my_profile.html",
        technician=tech, portfolio=portfolio, reviews=reviews,
        t=get_t(), lang=get_lang())


@app.route("/my-profile/edit", methods=["GET", "POST"])
def edit_profile():
    tech = current_technician()
    if not tech:
        flash("Please log in to edit your profile.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        full_name = capitalize_name(request.form.get("full_name", "").strip())
        qualification_type = request.form.get("qualification_type", "").strip()
        degree_level = request.form.get("degree_level", "").strip()
        degree = request.form.get("degree", "").strip()
        skill_category = request.form.get("skill_category", "").strip()
        phone = request.form.get("phone", "").strip()
        whatsapp = request.form.get("whatsapp", "").strip()
        province = request.form.get("province", "").strip()
        district = request.form.get("district", "").strip()
        sector = request.form.get("sector", "").strip()
        bio = request.form.get("bio", "").strip()
        certificate_number = request.form.get("certificate_number", "").strip()

        errors = []
        if not full_name:
            errors.append("Full name is required.")
        if qualification_type not in ("Advanced TVET Certificate V (L5)", "Professional Certificate", "Degree / Advanced Diploma (L6+)"):
            errors.append("Please choose a qualification type: Advanced TVET Certificate V (L5), Professional Certificate, or Degree / Advanced Diploma (L6+).")
        if degree_level and degree_level not in DEGREE_LEVELS:
            errors.append("Please choose your degree level.")
        if qualification_type in ("Advanced TVET Certificate V (L5)", "Professional Certificate"):
            degree_level = ""
        if not degree:
            errors.append("Field of study / specialization is required.")
        if not skill_category:
            errors.append("Please choose a skill category.")
        if degree and skill_category and not fields_relate_to_each_other(skill_category, degree):
            errors.append(
                f"\"{degree}\" doesn't seem related to the Skill Category \"{skill_category}\" you selected. "
                "Please make sure your Field of Study and Skill Category describe the same trade."
            )
        if not phone:
            errors.append("Phone number is required.")
        if not province or not district or not sector:
            errors.append("Please complete the location fields.")
        new_cert_file = request.files.get("certificate")
        new_cert_provided = bool(new_cert_file and new_cert_file.filename)
        if not tech["certificate_filename"] and not new_cert_provided:
            errors.append("Please upload your certificate or diploma — a profile cannot be active without proof of qualification.")
        if new_cert_provided and not certificate_number:
            errors.append("Please enter the certificate/diploma number printed on your document.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template(
                "edit_profile.html",
                technician=tech,
                skill_categories=SKILL_CATEGORIES,
                degree_levels=DEGREE_LEVELS,
                provinces=list(RWANDA_LOCATIONS.keys()),
            )

        conn = get_db_connection()

        new_photo = save_upload(request.files.get("photo"), UPLOAD_PHOTO_DIR, ALLOWED_PHOTO_EXT)
        new_cert = save_upload(request.files.get("certificate"), UPLOAD_CERT_DIR, ALLOWED_CERT_EXT)

        # Whichever certificate will end up on file after this save -- a
        # freshly uploaded one, or the one they already had -- gets checked
        # against the (possibly just-changed) qualification/field/skill.
        cert_to_check = new_cert if new_cert else tech["certificate_filename"]
        verification_status = tech["verification_status"]
        if cert_to_check:
            cert_path = os.path.join(UPLOAD_CERT_DIR, cert_to_check)
            check = verify_technician_certificate(
                cert_path, tech["full_name"], degree, certificate_number or tech["certificate_number"] or ""
            )
            print(f"[EDIT VERIFY] -> {check}", flush=True)
            if check.get("nesa_verified"):
                verification_status = "Verified"
            elif new_cert:
                verification_status = "Pending Review"

            if check.get("nesa_verified"):
                print("[EDIT VERIFY] ✅ Accepted via NESA portal.", flush=True)
            elif check["ocr_ran"] and not check["type_ok"]:
                if new_cert:
                    os.remove(cert_path)
                conn.close()
                flash(
                    check.get("error") or
                    f"The certificate on file doesn't look like a valid {qualification_type} document. "
                    "Please upload the correct document, or double check your Qualification Type.",
                    "error",
                )
                return render_template(
                    "edit_profile.html",
                    technician=tech,
                    skill_categories=SKILL_CATEGORIES,
                    degree_levels=DEGREE_LEVELS,
                    provinces=list(RWANDA_LOCATIONS.keys()),
                )
            elif check["ocr_ran"] and not check["field_ok"]:
                if new_cert:
                    os.remove(cert_path)
                conn.close()
                flash(
                    check.get("error") or
                    f"We couldn't find \"{degree}\" mentioned anywhere on the certificate on file. "
                    "If you changed your Field of Study or Skill Category, please also upload a "
                    "matching certificate.",
                    "error",
                )
                return render_template(
                    "edit_profile.html",
                    technician=tech,
                    skill_categories=SKILL_CATEGORIES,
                    degree_levels=DEGREE_LEVELS,
                    provinces=list(RWANDA_LOCATIONS.keys()),
                )

        photo_filename = new_photo if new_photo else tech["photo_filename"]
        certificate_filename = new_cert if new_cert else tech["certificate_filename"]
        # Keep the old certificate number unless they typed a new one
        final_certificate_number = certificate_number if certificate_number else tech["certificate_number"]

        conn.execute(
            """
            UPDATE technicians SET
                full_name = ?, qualification_type = ?, degree_level = ?, degree = ?, skill_category = ?, phone = ?, whatsapp = ?,
                province = ?, district = ?, sector = ?, bio = ?,
                photo_filename = ?, certificate_filename = ?, certificate_number = ?,
                verification_status = ?
            WHERE id = ?
            """,
            (full_name, qualification_type, degree_level, degree, skill_category, phone, whatsapp,
             province, district, sector, bio,
             photo_filename, certificate_filename, final_certificate_number,
             verification_status, tech["id"]),
        )
        conn.commit()
        conn.close()

        flash("Your profile has been updated.", "success")
        return redirect(url_for("my_profile"))

    return render_template(
        "edit_profile.html",
        technician=tech,
        skill_categories=SKILL_CATEGORIES,
        degree_levels=DEGREE_LEVELS,
        provinces=list(RWANDA_LOCATIONS.keys()),
    )


@app.route("/my-profile/delete", methods=["POST"])
def delete_profile():
    tech = current_technician()
    if not tech:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    conn = get_db_connection()
    conn.execute("DELETE FROM technicians WHERE id = ?", (tech["id"],))
    conn.commit()
    conn.close()

    session.pop("technician_id", None)
    flash("Your profile has been deleted.", "success")
    return redirect(url_for("home"))


# ---------- Client payment / access system ----------

PAYMENT_NUMBER = "0794419258"
ACCESS_DURATION_HOURS = 24
ACCESS_PRICE_RWF = 200


def _clear_client_access():
    for k in ("client_access_expiry", "client_phone", "client_code", "client_unlock_id"):
        session.pop(k, None)


def client_has_access():
    """True while this browser holds a valid paid unlock.  The ledger is checked on every call,
    so an admin who voids a payment cuts the client's access immediately."""
    expiry = session.get("client_access_expiry")
    if not expiry or _time.time() >= expiry:
        _clear_client_access()
        return False
    unlock_id = session.get("client_unlock_id")
    if unlock_id is None:
        return True            # session issued before the ledger existed: honoured until it expires (max 24h)
    conn = get_db_connection()
    try:
        valid = admin_portal.unlock_is_valid(conn, unlock_id)
    except sqlite3.Error:
        valid = True           # never lock out a paying client because of a transient database error
    finally:
        conn.close()
    return valid               # voided -> denied now; if the admin restores it, access simply resumes


def access_expires_in():
    """Return seconds remaining on current access, or 0."""
    expiry = session.get("client_access_expiry", 0)
    return max(0, int(expiry - _time.time()))


@app.route("/pay", methods=["GET", "POST"])
def pay():
    """Payment instruction page and code submission."""
    import time

    # Already has access — redirect straight to technicians
    if client_has_access():
        flash("You already have active access. Contacts are visible.", "success")
        return redirect(url_for("list_technicians"))

    tech_id = request.values.get("tech", type=int)          # which technician's card the client clicked "unlock" on

    def _pay_page(status=200):
        return render_template("pay.html", payment_number=PAYMENT_NUMBER, price=ACCESS_PRICE_RWF,
                               hours=ACCESS_DURATION_HOURS, form_data=request.form, tech_id=tech_id), status

    if request.method == "POST":
        phone_n = admin_portal.normalize_phone(request.form.get("phone", ""))
        tnx_n = admin_portal.normalize_tnx(request.form.get("code", ""))

        errors = []
        if not phone_n:
            errors.append("Please enter the Rwandan mobile number you paid from (for example 0788123456).")
        if not 6 <= len(tnx_n) <= 32:
            errors.append("Please enter the transaction code from your payment SMS (6 to 32 letters and numbers).")
        if errors:
            for e in errors:
                flash(e, "error")
            return _pay_page()

        # Every code can be used exactly once, ever.  The UNIQUE index in the ledger makes this
        # race-proof: two simultaneous requests with the same code can't both succeed.
        conn = get_db_connection()
        try:
            result = admin_portal.claim_unlock(conn, phone_n, tnx_n, technician_id=tech_id, ip=request.remote_addr)
        except sqlite3.OperationalError:
            flash("We are a little busy right now. Please try again in a moment.", "error")
            return _pay_page()
        finally:
            conn.close()

        if not result["ok"]:
            if result["reason"] == "reused":
                flash("This transaction code has already been used. Each payment code unlocks access once, "
                      "so please pay again to get a new code.", "error")
            else:
                flash("We could not read those details. Please check them and try again.", "error")
            return _pay_page()

        # Grant access in this browser for exactly the period recorded in the ledger
        session["client_access_expiry"] = calendar.timegm(result["expires_at"].utctimetuple())
        session["client_phone"] = result["phone"]
        session["client_code"] = result["tnx"]
        session["client_unlock_id"] = result["id"]
        t = get_t()
        flash(t["access_granted"].format(hours=ACCESS_DURATION_HOURS), "success")
        return redirect(url_for("list_technicians"))

    return render_template("pay.html",
        payment_number=PAYMENT_NUMBER,
        price=ACCESS_PRICE_RWF,
        hours=ACCESS_DURATION_HOURS,
        form_data={}, tech_id=tech_id)


# ---------- Public technician listing ----------

def tech_is_public(conn, tech):
    """Suspended accounts are never public.  If the admin switched on 'enforce expiry',
    technicians without an active plan are hidden too."""
    if tech is None or tech["is_suspended"]:
        return False
    if admin_portal.get_setting(conn, "enforce_expiry", "0") == "1":
        exp = admin_portal.from_db(tech["subscription_expires"])
        return bool(exp and exp > admin_portal.utcnow())
    return True


@app.route("/technicians")
def list_technicians():
    search_skill = request.args.get("skill", "").strip()
    search_province = request.args.get("province", "").strip()
    search_district = request.args.get("district", "").strip()
    search_sector = request.args.get("sector", "").strip()
    search_available = request.args.get("available", "") == "1"
    search_verified = request.args.get("verified", "") == "1"

    query = "SELECT * FROM technicians"
    conditions = []
    params = []

    if search_skill:
        conditions.append("skill_category = ?")
        params.append(search_skill)
    if search_province:
        conditions.append("province = ?")
        params.append(search_province)
    if search_district:
        conditions.append("district = ?")
        params.append(search_district)
    if search_sector:
        conditions.append("sector = ?")
        params.append(search_sector)
    if search_available:
        conditions.append("COALESCE(is_available, 1) = 1")
    if search_verified:
        conditions.append("verification_status = 'Verified'")

    _c = get_db_connection()
    try:
        conditions.append("COALESCE(is_suspended, 0) = 0")
        if admin_portal.get_setting(_c, "enforce_expiry", "0") == "1":
            conditions.append("subscription_expires IS NOT NULL AND subscription_expires > datetime('now')")
    finally:
        _c.close()

    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    # Sort: available first, then by avg_rating desc, then newest
    query += " ORDER BY COALESCE(is_available,1) DESC, COALESCE(avg_rating,0) DESC, created_at DESC"

    conn = get_db_connection()
    try:
        technicians = conn.execute(query, params).fetchall()
    except Exception as qe:
        print(f"[LIST_TECHNICIANS ERROR] {qe}", flush=True)
        # Fallback: try without ORDER BY columns that may not exist yet
        fallback_query = query.replace(
            "ORDER BY COALESCE(is_available,1) DESC, COALESCE(avg_rating,0) DESC, created_at DESC",
            "ORDER BY created_at DESC"
        )
        try:
            technicians = conn.execute(fallback_query, params).fetchall()
        except Exception as fe:
            print(f"[LIST_TECHNICIANS FALLBACK ERROR] {fe}", flush=True)
            technicians = []

    # Get portfolio image counts per technician for "View Portfolio" button
    port_counts = {}
    try:
        if technicians:
            ids = ",".join(str(t["id"]) for t in technicians)
            rows = conn.execute(
                f"SELECT technician_id, COUNT(*) AS cnt FROM portfolio_images WHERE technician_id IN ({ids}) GROUP BY technician_id"
            ).fetchall()
            port_counts = {r["technician_id"]: r["cnt"] for r in rows}
    except Exception:
        port_counts = {}
    conn.close()

    # Trades with the most client reviews float to the top of the filter list;
    # ties and un-reviewed trades keep their original order.
    ordered_categories = list(SKILL_CATEGORIES)
    try:
        c2 = get_db_connection()
        demand = {r["skill_category"]: r["n"] for r in c2.execute(
            "SELECT t.skill_category, COUNT(r.id) AS n FROM reviews r "
            "JOIN technicians t ON t.id = r.technician_id GROUP BY t.skill_category").fetchall()}
        c2.close()
        ordered_categories.sort(key=lambda cat: -demand.get(cat, 0))  # stable sort
    except Exception as e:
        print(f"[CATEGORY ORDER] skipped: {e}", flush=True)

    return render_template(
        "technicians.html",
        technicians=technicians,
        skill_categories=ordered_categories,
        provinces=list(RWANDA_LOCATIONS.keys()),
        search_skill=search_skill,
        search_province=search_province,
        search_district=search_district,
        search_sector=search_sector,
        search_available=search_available,
        search_verified=search_verified,
        has_access=client_has_access(),
        access_seconds=access_expires_in(),
        port_counts=port_counts,
    )


# (The admin console lives in admin_portal.py and is mounted at /admin below.)


# ══════════════════════════════════════════════════════════════════════════════
# PASSWORD RESET — 4-STEP FLOW
# ══════════════════════════════════════════════════════════════════════════════

RESET_CODE_MINUTES = 5           # how long a code stays valid
RESET_RESEND_SECONDS = 60        # minimum gap between two e-mails for the same account
RESET_MAX_ATTEMPTS = 5           # wrong guesses before the code is destroyed
RESET_VERIFIED_SECONDS = 600     # time allowed to choose a new password after the code was accepted
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def build_reset_email(lang, name, code):
    """Reset e-mail in the user's language.  -> (subject, html, plain_text)"""
    tr = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    help_line = tr["reset_email_help"].format(support=SUPPORT_EMAIL)
    safe_name = _escape(name)
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;">
      <div style="background:#0F172A;padding:20px 28px;border-radius:12px 12px 0 0;">
        <h2 style="color:white;margin:0;">TechConnect</h2>
      </div>
      <div style="background:#f8fafc;padding:28px;border-radius:0 0 12px 12px;border:1px solid #e2e8f0;">
        <p style="color:#0F172A;font-size:1rem;">{tr["reset_email_hello"]} <strong>{safe_name}</strong>,</p>
        <p style="color:#475569;">{tr["reset_email_intro"]}</p>
        <div style="background:#0F172A;border-radius:10px;padding:20px;text-align:center;margin:24px 0;">
          <span style="color:white;font-size:2.2rem;font-weight:800;letter-spacing:8px;">{code}</span>
        </div>
        <p style="color:#94a3b8;font-size:0.82rem;">{tr["reset_email_ignore"]}</p>
        <p style="color:#94a3b8;font-size:0.82rem;">{_escape(help_line)}</p>
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;">
        <p style="color:#94a3b8;font-size:0.78rem;margin:0;">The Tech Connection &nbsp;&middot;&nbsp; Kigali, Rwanda</p>
      </div>
    </div>"""
    text = (f"{tr['reset_email_hello']} {name},\n\n{tr['reset_email_intro']}\n\n    {code}\n\n"
            f"{tr['reset_email_ignore']}\n{help_line}\n\nThe Tech Connection - Kigali, Rwanda\n")
    return tr["reset_email_subject"], html, text


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Step 1 - ask for the account e-mail and send a 6-digit code BY E-MAIL.
    The answer is identical whether or not an account exists (no account enumeration), the code is
    never written to the logs in production, and the send happens in the background so response time
    does not reveal whether an e-mail was sent."""
    t = get_t()

    def page():
        return render_template("forgot_password.html", t=t, lang=get_lang(), technician=current_technician())

    if request.method != "POST":
        return page()

    email = request.form.get("email", "").strip().lower()
    if not email or len(email) > 254 or not _EMAIL_RE.match(email):
        flash(t["reset_email_required"], "error")
        return page()

    # If the server itself cannot send mail, say so honestly (this does not depend on the address entered,
    # so it reveals nothing about accounts).  In local development we carry on and print the code instead.
    problem = mail_problem()
    if problem and IS_PRODUCTION:
        mail_log.error("a password reset was requested but e-mail cannot be sent: %s", problem)
        flash(t["reset_mail_unavailable"].format(support=SUPPORT_EMAIL), "error")
        return page()

    code, tech = None, None
    conn = None
    try:
        conn = get_db_connection()
        tech = conn.execute(
            "SELECT id, full_name, reset_token, token_expiration FROM technicians "
            "WHERE email = ? AND COALESCE(is_suspended, 0) = 0", (email,)).fetchone()
        if tech:
            recent = False                                    # one code per minute per account (stops e-mail flooding)
            issued = admin_portal.from_db(tech["token_expiration"]) if tech["reset_token"] else None
            if issued:
                recent = (admin_portal.utcnow() - (issued - timedelta(minutes=RESET_CODE_MINUTES))).total_seconds() < RESET_RESEND_SECONDS
            if not recent:
                code = f"{secrets.randbelow(900000) + 100000}"
                conn.execute(
                    "UPDATE technicians SET reset_token = ?, token_expiration = ?, reset_attempts = 0 WHERE id = ?",
                    (code, admin_portal.to_db(admin_portal.utcnow() + timedelta(minutes=RESET_CODE_MINUTES)), tech["id"]))
                conn.commit()
    except Exception as db_err:
        mail_log.error("password-reset database error: %s", db_err)
        flash(t["reset_temp_error"], "error")
        return page()
    finally:
        if conn:
            conn.close()

    if code and tech:
        subject, html, text = build_reset_email(get_lang(), tech["full_name"], code)
        if problem:        # only reachable outside production (see above)
            print(f"[DEV ONLY - e-mail not configured: {problem}] reset code for {email} is {code}", flush=True)
        else:
            mail_log.info("reset code issued for %s; sending e-mail", _mask_email(email))
            send_email_async(email, subject, html, text)

    session["reset_email"] = email
    flash(t["reset_if_exists"].format(email=email), "success")
    return redirect(url_for("verify_reset_code"))


@app.route("/verify-reset-code", methods=["GET", "POST"])
def verify_reset_code():
    """Step 2 - check the 6-digit code.  Wrong, expired and unknown-account all look the same, and the
    number of wrong guesses is limited so the code cannot be brute-forced."""
    if not session.get("reset_email"):
        return redirect(url_for("forgot_password"))
    t = get_t()

    def page():
        return render_template("verify_code.html", t=t, lang=get_lang(), technician=current_technician())

    if request.method != "POST":
        return page()

    email = session["reset_email"]
    entered = re.sub(r"\D", "", request.form.get("code", ""))
    if not entered:
        flash(t["reset_code_required"], "error")
        return page()

    conn = get_db_connection()
    try:
        tech = conn.execute(
            "SELECT id, reset_token, token_expiration, COALESCE(reset_attempts, 0) AS attempts "
            "FROM technicians WHERE email = ?", (email,)).fetchone()
        live = False
        if tech and tech["reset_token"] and tech["attempts"] < RESET_MAX_ATTEMPTS:
            exp = admin_portal.from_db(tech["token_expiration"])
            live = bool(exp and admin_portal.utcnow() <= exp)
        if live and hmac.compare_digest(entered, tech["reset_token"]):
            conn.execute("UPDATE technicians SET reset_attempts = 0 WHERE id = ?", (tech["id"],))
            conn.commit()
            session["reset_verified"] = True
            session["reset_verified_until"] = _time.time() + RESET_VERIFIED_SECONDS
            session.pop("reset_guesses", None)
            return redirect(url_for("reset_password"))

        if tech and tech["reset_token"]:                      # a real pending code: count the wrong guess
            attempts = tech["attempts"] + 1
            too_many = attempts >= RESET_MAX_ATTEMPTS
            if too_many:
                conn.execute("UPDATE technicians SET reset_token = NULL, token_expiration = NULL, reset_attempts = 0 WHERE id = ?", (tech["id"],))
            else:
                conn.execute("UPDATE technicians SET reset_attempts = ? WHERE id = ?", (attempts, tech["id"]))
            conn.commit()
        else:                                                 # no such account / no code: behave the same way
            session["reset_guesses"] = session.get("reset_guesses", 0) + 1
            too_many = session["reset_guesses"] >= RESET_MAX_ATTEMPTS
    finally:
        conn.close()

    if too_many:
        session.pop("reset_email", None)
        session.pop("reset_guesses", None)
        flash(t["reset_too_many"], "error")
        return redirect(url_for("forgot_password"))
    flash(t["reset_code_wrong"], "error")
    return page()


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """Step 3 - choose the new password (only shortly after the code was accepted)."""
    verified = (session.get("reset_email") and session.get("reset_verified")
                and session.get("reset_verified_until", 0) > _time.time())
    if not verified:
        session.pop("reset_verified", None)
        session.pop("reset_verified_until", None)
        return redirect(url_for("forgot_password"))
    t = get_t()

    def page():
        return render_template("reset_password.html", t=t, lang=get_lang(), technician=current_technician())

    if request.method == "POST":
        password = request.form.get("password", "")
        if not is_strong_password(password):
            flash(t["reset_pw_weak"], "error")
            return page()
        if password != request.form.get("confirm_password", ""):
            flash(t["reset_pw_mismatch"], "error")
            return page()

        conn = get_db_connection()
        try:
            conn.execute(
                "UPDATE technicians SET password_hash = ?, reset_token = NULL, token_expiration = NULL, reset_attempts = 0 "
                "WHERE email = ?", (generate_password_hash(password), session["reset_email"]))
            conn.commit()
        finally:
            conn.close()
        for k in ("reset_email", "reset_verified", "reset_verified_until", "reset_guesses"):
            session.pop(k, None)
        flash(t["reset_pw_done"], "success")
        return redirect(url_for("login"))

    return page()


@app.route("/api/technician/<int:tech_id>/preview")
def technician_preview(tech_id):
    """Public profile preview for the search-page modal.
    Deliberately excludes phone, WhatsApp and email - those stay behind the
    200 RWF unlock."""
    conn = get_db_connection()
    try:
        tech = conn.execute("SELECT * FROM technicians WHERE id = ?", (tech_id,)).fetchone()
        if not tech_is_public(conn, tech):
            return jsonify({"error": "not found"}), 404
        try:
            images = conn.execute(
                "SELECT image_url, caption FROM portfolio_images WHERE technician_id = ? ORDER BY created_at DESC",
                (tech_id,)
            ).fetchall()
        except sqlite3.OperationalError:
            images = []
        try:
            reviews = conn.execute(
                "SELECT client_name, rating, comment, created_at FROM reviews WHERE technician_id = ? ORDER BY created_at DESC LIMIT 5",
                (tech_id,)
            ).fetchall()
        except sqlite3.OperationalError:
            reviews = []
    finally:
        conn.close()

    if tech["qualification_type"] == "Degree / Advanced Diploma (L6+)":
        qualification = f"{tech['degree_level'] or 'Degree'} in {tech['degree']}"
    else:
        qualification = f"{tech['qualification_type']} in {tech['degree']}"

    return jsonify({
        "id": tech["id"],
        "full_name": tech["full_name"],
        "skill_category": tech["skill_category"],
        "qualification": qualification,
        "qualification_type": tech["qualification_type"],
        "location": f"{tech['sector']}, {tech['district']}, {tech['province']}",
        "bio": tech["bio"] or "",
        "is_available": 1 if (tech["is_available"] is None or tech["is_available"]) else 0,
        "verified": tech["verification_status"] == "Verified",
        "avg_rating": tech["avg_rating"] or 0,
        "review_count": tech["review_count"] or 0,
        "photo": url_for("static", filename="uploads/photos/" + tech["photo_filename"]) if tech["photo_filename"] else "",
        "images": [{"url": url_for("static", filename=i["image_url"]), "caption": i["caption"] or ""} for i in images],
        "reviews": [{"name": r["client_name"], "rating": r["rating"], "comment": r["comment"] or "", "date": (r["created_at"] or "")[:10]} for r in reviews],
    })

# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 1 — AVAILABILITY TOGGLE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/toggle-availability", methods=["POST"])
def toggle_availability():
    """Flip is_available between 0 and 1 for the logged-in technician."""
    tech = current_technician()
    if not tech:
        return jsonify({"error": "Not logged in"}), 401
    conn = get_db_connection()
    new_val = 0 if tech["is_available"] else 1
    conn.execute("UPDATE technicians SET is_available = ? WHERE id = ?", (new_val, tech["id"]))
    conn.commit()
    conn.close()
    label = "Available for Hire" if new_val else "Currently Booked"
    return jsonify({"is_available": new_val, "label": label})


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 2 — PORTFOLIO UPLOAD & DELETE
# ══════════════════════════════════════════════════════════════════════════════

UPLOAD_PORTFOLIO_DIR = os.path.join(BASE_DIR, "static", "uploads", "portfolio")
os.makedirs(UPLOAD_PORTFOLIO_DIR, exist_ok=True)
ALLOWED_PORTFOLIO_EXT = {".jpg", ".jpeg", ".png", ".webp", ".gif"}

@app.route("/portfolio/upload", methods=["POST"])
def portfolio_upload():
    """Upload one portfolio image with an optional caption."""
    tech = current_technician()
    if not tech:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    image_file = request.files.get("portfolio_image")
    caption    = request.form.get("caption", "").strip()[:140]

    if not image_file or not image_file.filename:
        flash("Please select an image to upload.", "error")
        return redirect(url_for("my_profile"))

    filename = save_upload(image_file, UPLOAD_PORTFOLIO_DIR, ALLOWED_PORTFOLIO_EXT)
    if not filename:
        flash("Invalid file — please use JPG, PNG, or WEBP under 5 MB.", "error")
        return redirect(url_for("my_profile"))

    image_url = f"uploads/portfolio/{filename}"
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO portfolio_images (technician_id, image_url, caption) VALUES (?, ?, ?)",
        (tech["id"], image_url, caption)
    )
    conn.commit()
    conn.close()
    flash("Portfolio image uploaded successfully.", "success")
    return redirect(url_for("my_profile"))


@app.route("/portfolio/delete/<int:image_id>", methods=["POST"])
def portfolio_delete(image_id):
    """Delete one portfolio image (owner only)."""
    tech = current_technician()
    if not tech:
        return redirect(url_for("login"))
    conn = get_db_connection()
    row = conn.execute(
        "SELECT * FROM portfolio_images WHERE id = ? AND technician_id = ?",
        (image_id, tech["id"])
    ).fetchone()
    if row:
        # Remove file from disk
        full_path = os.path.join(BASE_DIR, "static", row["image_url"])
        try:
            if os.path.exists(full_path):
                os.remove(full_path)
        except Exception:
            pass
        conn.execute("DELETE FROM portfolio_images WHERE id = ?", (image_id,))
        conn.commit()
        flash("Image removed from your portfolio.", "success")
    conn.close()
    return redirect(url_for("my_profile"))


@app.route("/portfolio/<int:tech_id>")
def portfolio_view(tech_id):
    """Public portfolio page for a technician."""
    conn = get_db_connection()
    tech   = conn.execute("SELECT * FROM technicians WHERE id = ?", (tech_id,)).fetchone()
    images = conn.execute(
        "SELECT * FROM portfolio_images WHERE technician_id = ? ORDER BY created_at DESC",
        (tech_id,)
    ).fetchall()
    visible = tech_is_public(conn, tech)
    conn.close()
    if not visible:
        flash("Technician not found.", "error")
        return redirect(url_for("list_technicians"))
    return render_template("portfolio_view.html",
        tech=tech, images=images,
        t=get_t(), lang=get_lang(), technician=current_technician())


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 3 — REVIEWS & SITE FEEDBACK
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/review/<int:tech_id>", methods=["POST"])
def submit_review(tech_id):
    """Submit a star rating + written review for a technician."""
    client_name = request.form.get("client_name", "Anonymous").strip()[:60] or "Anonymous"
    comment     = request.form.get("comment", "").strip()[:500]
    try:
        rating = int(request.form.get("rating", 0))
        if rating < 1 or rating > 5:
            raise ValueError
    except (ValueError, TypeError):
        flash("Please select a rating between 1 and 5 stars.", "error")
        return redirect(url_for("portfolio_view", tech_id=tech_id))

    conn = get_db_connection()
    # Check technician exists
    tech = conn.execute("SELECT id, is_suspended, subscription_expires FROM technicians WHERE id = ?", (tech_id,)).fetchone()
    if not tech_is_public(conn, tech):
        conn.close()
        flash("Technician not found.", "error")
        return redirect(url_for("list_technicians"))

    conn.execute(
        "INSERT INTO reviews (technician_id, client_name, rating, comment) VALUES (?, ?, ?, ?)",
        (tech_id, client_name, rating, comment)
    )
    # Update denormalised avg_rating + review_count on technician row
    stats = conn.execute(
        "SELECT COUNT(*) AS cnt, AVG(rating) AS avg FROM reviews WHERE technician_id = ?",
        (tech_id,)
    ).fetchone()
    conn.execute(
        "UPDATE technicians SET review_count = ?, avg_rating = ? WHERE id = ?",
        (stats["cnt"], round(stats["avg"], 1), tech_id)
    )
    conn.commit()
    conn.close()
    flash("Thank you for your feedback!", "success")
    return redirect(url_for("portfolio_view", tech_id=tech_id))


@app.route("/feedback", methods=["GET", "POST"])
def site_feedback():
    """General platform feedback page."""
    if request.method == "POST":
        comment = request.form.get("comment", "").strip()[:500]
        try:
            rating = int(request.form.get("rating", 0))
            if rating < 1 or rating > 5:
                raise ValueError
        except (ValueError, TypeError):
            flash("Please select a rating between 1 and 5 stars.", "error")
            return render_template("site_feedback.html",
                t=get_t(), lang=get_lang(), technician=current_technician())
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO site_feedback (rating, comment) VALUES (?, ?)", (rating, comment)
        )
        conn.commit()
        conn.close()
        flash("Thank you for helping us improve TechConnect!", "success")
        return redirect(url_for("home"))
    return render_template("site_feedback.html",
        t=get_t(), lang=get_lang(), technician=current_technician())


# ══════════════════════════════════════════════════════
# LEGAL & POLICY PAGES
# ══════════════════════════════════════════════════════

@app.route("/terms")
def terms():
    return render_template("terms.html", technician=current_technician())

@app.route("/privacy")
def privacy():
    return render_template("privacy.html", technician=current_technician())

@app.route("/verification-policy")
def verification_policy():
    return render_template("verification_policy.html", technician=current_technician())

@app.route("/cookie-policy")
def cookie_policy():
    return render_template("cookie_policy.html", technician=current_technician())




# Warm schema at import (runs under Gunicorn too)
try:
    get_db_connection().close()
except Exception as _e:
    print(f"[STARTUP] schema init failed: {_e}", flush=True)


# Admin console + background subscription-reminder scheduler
admin_portal.init_app(app, db=get_db_connection, mailer=send_email_safe,
                      mail_ready=lambda: mail_problem() is None, mail_problem=mail_problem)


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)

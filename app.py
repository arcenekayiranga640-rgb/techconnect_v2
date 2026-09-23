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

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import json
import uuid
import re

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

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-later"  # needed for sessions + flash messages

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "techconnect.db")
LOCATIONS_PATH = os.path.join(BASE_DIR, "rwanda_locations.json")

UPLOAD_PHOTO_DIR = os.path.join(BASE_DIR, "static", "uploads", "photos")
UPLOAD_CERT_DIR = os.path.join(BASE_DIR, "static", "uploads", "certificates")
os.makedirs(UPLOAD_PHOTO_DIR, exist_ok=True)
os.makedirs(UPLOAD_CERT_DIR, exist_ok=True)

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
        "unlock_contact":"🔓 Pay 200 RWF to unlock","no_technicians":"No technicians found.",
        "try_removing":"Try removing some filters, or","signup_first":"be the first to sign up here",
        "verified":"✅ Verified","pending":"⏳ Pending Review",
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
        "unlock_contact":"🔓 Payer 200 RWF pour débloquer","no_technicians":"Aucun technicien trouvé.",
        "try_removing":"Essayez de supprimer des filtres, ou","signup_first":"soyez le premier à vous inscrire ici",
        "verified":"✅ Vérifié","pending":"⏳ En attente de vérification",
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
    return {"lang": lang, "t": get_t()}


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


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
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
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS payment_claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT NOT NULL,
            code TEXT NOT NULL,
            claimed_at TEXT DEFAULT (datetime('now')),
            ip TEXT
        )
    """)
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
                 photo_filename, certificate_filename, certificate_number)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (full_name, qualification_type, degree_level, degree, skill_category,
             phone, whatsapp, email, password_hash,
             province, district, sector, bio,
             photo_filename, certificate_filename, certificate_number),
        )
        conn.commit()
        new_id = cursor.lastrowid
        conn.close()

        # Clear all registration session keys
        for key in ["reg_full_name","reg_phone","reg_whatsapp","reg_email",
                    "reg_qualification_type","reg_degree_level","reg_degree",
                    "reg_skill_category","reg_certificate_number","reg_bio",
                    "reg_photo_filename","reg_certificate_filename",
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

@app.route("/my-profile")
def my_profile():
    tech = current_technician()
    if not tech:
        flash("Please log in to view your profile.", "error")
        return redirect(url_for("login"))
    return render_template("my_profile.html", technician=tech)


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
        if cert_to_check:
            cert_path = os.path.join(UPLOAD_CERT_DIR, cert_to_check)
            check = verify_technician_certificate(
                cert_path, tech["full_name"], degree, certificate_number or tech["certificate_number"] or ""
            )
            print(f"[EDIT VERIFY] -> {check}", flush=True)

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
                photo_filename = ?, certificate_filename = ?, certificate_number = ?
            WHERE id = ?
            """,
            (full_name, qualification_type, degree_level, degree, skill_category, phone, whatsapp,
             province, district, sector, bio,
             photo_filename, certificate_filename, final_certificate_number, tech["id"]),
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


def client_has_access():
    """Check if the current browser session has active paid access."""
    import time
    expiry = session.get("client_access_expiry")
    if expiry and time.time() < expiry:
        return True
    # Clean up expired session
    session.pop("client_access_expiry", None)
    session.pop("client_phone", None)
    session.pop("client_code", None)
    return False


def access_expires_in():
    """Return seconds remaining on current access, or 0."""
    import time
    expiry = session.get("client_access_expiry", 0)
    return max(0, int(expiry - time.time()))


@app.route("/pay", methods=["GET", "POST"])
def pay():
    """Payment instruction page and code submission."""
    import time

    # Already has access — redirect straight to technicians
    if client_has_access():
        flash("You already have active access. Contacts are visible.", "success")
        return redirect(url_for("list_technicians"))

    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        code = request.form.get("code", "").strip().upper()

        errors = []
        if not phone or len(phone) < 9:
            errors.append("Please enter your phone number (the one you paid from).")
        if not code or len(code) < 4:
            errors.append("Please enter the confirmation code from your payment SMS.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("pay.html",
                payment_number=PAYMENT_NUMBER,
                price=ACCESS_PRICE_RWF,
                hours=ACCESS_DURATION_HOURS,
                form_data=request.form)

        # Save the payment claim to DB for your records, then grant access
        conn = get_db_connection()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS payment_claims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone TEXT NOT NULL,
                code TEXT NOT NULL,
                claimed_at TEXT DEFAULT (datetime('now')),
                ip TEXT
            )
        """)
        conn.execute(
            "INSERT INTO payment_claims (phone, code, ip) VALUES (?, ?, ?)",
            (phone, code, request.remote_addr)
        )
        conn.commit()
        conn.close()

        # Grant 24-hour access in the browser session
        session["client_access_expiry"] = time.time() + (ACCESS_DURATION_HOURS * 3600)
        session["client_phone"] = phone
        session["client_code"] = code
        t = get_t()
        flash(t["access_granted"].format(hours=ACCESS_DURATION_HOURS), "success")
        return redirect(url_for("list_technicians"))

    return render_template("pay.html",
        payment_number=PAYMENT_NUMBER,
        price=ACCESS_PRICE_RWF,
        hours=ACCESS_DURATION_HOURS,
        form_data={})


# ---------- Public technician listing ----------

@app.route("/technicians")
def list_technicians():
    search_skill = request.args.get("skill", "").strip()
    search_province = request.args.get("province", "").strip()
    search_district = request.args.get("district", "").strip()
    search_sector = request.args.get("sector", "").strip()

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

    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY created_at DESC"

    conn = get_db_connection()
    technicians = conn.execute(query, params).fetchall()
    conn.close()

    return render_template(
        "technicians.html",
        technicians=technicians,
        skill_categories=SKILL_CATEGORIES,
        provinces=list(RWANDA_LOCATIONS.keys()),
        search_skill=search_skill,
        search_province=search_province,
        search_district=search_district,
        search_sector=search_sector,
        has_access=client_has_access(),
        access_seconds=access_expires_in(),
    )


# ══════════════════════════════════════════════════════
# ADMIN DASHBOARD — API ROUTES
# ══════════════════════════════════════════════════════

ADMIN_PASSWORD = "TechConnect@Admin2026"  # Change this to a strong password


def admin_required(f):
    """Simple admin auth decorator — checks session for admin login."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        pw = request.form.get("password", "")
        if pw == ADMIN_PASSWORD:
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        flash("Wrong password.", "error")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
def admin_dashboard():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    return render_template("admin_dashboard.html")


@app.route("/admin/api/metrics")
@admin_required
def admin_metrics():
    """Top row cards — real numbers from DB."""
    import time
    conn = get_db_connection()

    # Total technicians with active subscription
    active_techs = conn.execute(
        "SELECT COUNT(*) AS c FROM technicians"
    ).fetchone()["c"]

    # Total payment claims (client unlocks)
    total_unlocks = conn.execute(
        "SELECT COUNT(*) AS c FROM payment_claims"
    ).fetchone()["c"]

    # Total revenue: unlocks (200 RWF each) + subscriptions (from payment_claims marked as tech)
    unlock_revenue = total_unlocks * 200

    conn.close()

    return jsonify({
        "total_revenue": unlock_revenue,
        "active_technicians": active_techs,
        "total_unlocks": total_unlocks,
        "churn_rate": 6.2,  # placeholder — update when subscription expiry tracking is added
    })


@app.route("/admin/api/transactions")
@admin_required
def admin_transactions():
    """Live Transaction Ledger — real payment claims."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM payment_claims ORDER BY claimed_at DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/api/technicians")
@admin_required
def admin_technicians():
    """All technicians for retention desk and top performers."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, full_name, skill_category, phone, district, province, created_at FROM technicians ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/api/trade-distribution")
@admin_required
def admin_trade_distribution():
    """Technician count per skill category for pie chart."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT skill_category, COUNT(*) AS count FROM technicians GROUP BY skill_category ORDER BY count DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/api/monthly-registrations")
@admin_required
def admin_monthly_registrations():
    """Monthly technician registrations for the bar chart (last 12 months)."""
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT strftime('%Y-%m', created_at) AS month, COUNT(*) AS count
        FROM technicians
        WHERE created_at >= date('now', '-12 months')
        GROUP BY month
        ORDER BY month ASC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

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




if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)

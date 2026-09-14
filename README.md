# TechConnect v2 — Technician Registration with Login, Real Rwanda Locations, and Document Checking

## What's in this version
1. **Login system** — set a password at sign-up, log back in to edit/delete your profile.
2. **Real Rwanda location data** — Province -> District -> Sector cascading dropdowns
   using the real official structure (5 provinces, 30 districts, 416 sectors).
3. **File uploads** — profile photo and certificate (PDF or image).
4. **Qualification details** — choose Degree (A2/A1/Bachelor's/Masters/PhD) or
   Certificate, plus 33 specific Rwanda technical trade categories.
5. **Strong password rules** — 8+ characters, uppercase, lowercase, number, symbol,
   shown live as you type.
6. **Automatic document checking (NEW)** — when a certificate is uploaded, the
   system reads the text inside it (OCR) and checks:
   - Does it look like the right TYPE of document (a Degree-level document vs
     a Certificate-level one)?
   - Does it mention the field of study they typed (e.g. if they say
     "Plumbing" but the document is clearly about "Accounting", it gets
     blocked with an error)?

   **Important limitation:** this does NOT verify a certificate is genuine
   or not expired — that would require connecting to RTB's or a university's
   real records, which we don't have access to. It only catches *obvious*
   mismatches (wrong document type, or completely unrelated field). A
   skilled forger could still pass this check. Real verification still
   needs a human to manually check the certificate number against
   official records — that's why every certificate upload still shows
   a "Pending Review" badge until manually confirmed.

## REQUIRED: Installing Tesseract OCR (for the document check to work)

The automatic document check needs a program called **Tesseract OCR**
installed on your computer — this is separate from Python/Flask.

**Without it, the app still works completely fine** — registration,
login, uploads, everything — the document check is just skipped
silently. Nothing breaks if you don't install it.

### To install Tesseract on Windows:
1. Go to: https://github.com/UB-Mannheim/tesseract/wiki
2. Download the Windows installer (e.g. `tesseract-ocr-w64-setup-...exe`)
3. Run the installer. **Important:** note the install path it shows
   (usually `C:\Program Files\Tesseract-OCR`).
4. During or after install, add that folder to your Windows PATH:
   - Press Windows key, type "environment variables", open
     "Edit the system environment variables"
   - Click "Environment Variables"
   - Under "System variables", find "Path", click Edit, click New,
     paste in `C:\Program Files\Tesseract-OCR`
   - Click OK on all windows
5. Close and reopen any Command Prompt windows so the change takes effect.
6. Test it worked by running: `tesseract --version`

You'll also need one more Python package for reading PDFs specifically
(not needed for image uploads like JPG/PNG):
```
py -m pip install pdf2image
```
PDF reading additionally needs a tool called **Poppler** — if you only
ever upload photos of certificates (not PDFs), you can skip this part.

## How to run it
1. Make sure Python 3 and Flask are installed:
   py -m pip install flask pytesseract pillow pdf2image
2. From this folder, run:
   py app.py
3. Open your browser to: http://127.0.0.1:5000

## Files
- app.py — the Flask application (routes, login, database, uploads, OCR checks)
- rwanda_locations.json — the real province/district/sector data
- templates/ — all the HTML pages
- static/uploads/photos/ — uploaded profile photos land here
- static/uploads/certificates/ — uploaded certificates land here
- techconnect.db — created automatically the first time you run the app

## Important note about your old data
Each version upgrade has changed the database structure. If you're
updating from an older version, delete your existing techconnect.db
file and let the app create a fresh one — old profiles won't carry over.

## Suggested next steps
1. Add the client-side request form (the person who NEEDS a technician).
2. Add a simple payment placeholder before showing full contact info.
3. Build a simple admin page where you can review "Pending Review"
   certificates and manually mark them "Verified".
4. Replace text-based district search with real GPS-based distance
   calculation.

"# techconnect_v2" 

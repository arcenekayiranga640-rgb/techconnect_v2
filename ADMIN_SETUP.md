# TechConnect admin portal: setup notes

Admin console: `https://<your-site>/admin`  (local: `http://127.0.0.1:5001/admin`)

## 1. Files in this update
| File | What it is |
|---|---|
| `app.py` | Updated: secure secret key, trial on sign-up, TNX ledger in `/pay`, suspended-account handling, private certificates, mounts the admin console |
| `admin_portal.py` | NEW: the whole admin console (routes, database tables, reminder engine, CSV export) |
| `templates/admin/*` | NEW: 16 admin pages |
| `templates/_icons.html`, `technicians.html`, `my_profile.html`, `pay.html` | Updated (new icons, `?tech=` on unlock links, private certificate link, hidden field on the pay form) |

**Delete these two old files from your repo** (replaced by `templates/admin/`):
`templates/admin_dashboard.html` and `templates/admin_login.html`

## 2. Set these environment variables on Render (Environment tab)
| Variable | Why |
|---|---|
| `SECRET_KEY` | Signs login cookies. Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ADMIN_PASSWORD` | Your admin password (the built-in default is public). Passwords changed inside the portal live in the database, which Render's free tier erases on restart, so the variable is the durable one. |
| `MAIL_PASSWORD` | Gmail app password. The old one is in your Git history: **create a new app password and revoke the old one.** |
| `SITE_URL` (optional) | Used in reminder-email links |

`requirements.txt` must contain: `Flask`, `gunicorn`, `Flask-Mail` (plus what you already have: `requests`, `beautifulsoup4`, `Pillow`).

## 3. What happens on first start
* New database tables/columns are created automatically (nothing to run by hand).
* Existing technicians get a 7-day trial counted from their sign-up date.
* Certificates saved under `static/uploads/certificates/` are moved to a private folder.
* Every user is signed out once (the session key changed).
* The reminder check runs about 45 seconds after start, then hourly.

## 4. Things this does NOT do (yet)
* **Payment codes are not verified with MoMo.** The ledger guarantees each code works once, ever, but it cannot tell whether a real payment happened. Use Clients > TNX lookup and "Void" to police it, or integrate the MoMo API.
* **Technicians cannot pay for a plan themselves.** The buttons on the "Choose your plan" page still lead to the client payment page. Plans are activated by you under Technicians > Subscription (cash / MoMo / bank).
* On Render's free tier the database is erased at every restart. Use Export Data regularly.
* The admin console is English only.

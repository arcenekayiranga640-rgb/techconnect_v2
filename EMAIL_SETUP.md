# TechConnect: e-mail setup (password-reset codes, reminders, test e-mails)

## READ THIS FIRST: Render's FREE plan blocks SMTP

Since 26 September 2025, **free Render web services cannot connect to SMTP ports 25, 465 or 587**
([Render changelog](https://render.com/changelog/free-web-services-will-no-longer-allow-outbound-traffic-to-smtp-ports)).
Gmail SMTP uses 587 (or 465), so on the free plan the connection simply times out. That is the most likely reason the reset
code only ever appeared in your logs. **No environment variable can fix this on the free plan.** Choose one:

| | Option A: paid Render instance | Option B: stay free, send over HTTPS |
|---|---|---|
| Cost | from about $7 / month | free (Brevo free tier) |
| Uses | Gmail SMTP (variables below) | Brevo HTTPS API (`BREVO_API_KEY`) |
| Setup | upgrade the web service, set the variables | create a Brevo account, verify the sender, set one variable |

(Port 25 stays blocked on every Render plan; you do not need it.)

---

## Option A: Gmail SMTP (needs a PAID Render instance)

### 1. Create a Google App Password (Gmail will NOT accept the normal password)
1. Sign in to the Google account `techconnectsupport13@gmail.com`.
2. Turn on **2-Step Verification** (Google Account > Security). App passwords do not exist without it.
3. Google Account > Security > **App passwords** (or search "App passwords" in the account search box).
4. Name it "TechConnect", click **Create**. Google shows a **16-character** password in four groups.
5. Copy it. Spaces do not matter: TechConnect strips them for you.

### 2. Render > your service > Environment: add these variables
| Variable | Value | Notes |
|---|---|---|
| `MAIL_SERVER` | `smtp.gmail.com` | default; you may omit it |
| `MAIL_PORT` | `587` | default; you may omit it |
| `MAIL_USE_TLS` | `true` | default; you may omit it |
| `MAIL_USERNAME` | `techconnectsupport13@gmail.com` | default; you may omit it |
| **`MAIL_PASSWORD`** | *the 16-character App Password* | **required, no default** |
| `MAIL_DEFAULT_SENDER` | `techconnectsupport13@gmail.com` | default; "Name <address>" also works |

Only `MAIL_PASSWORD` is strictly required. (Port 465 is also supported: set `MAIL_PORT=465`; SSL switches on automatically.)
Save: Render redeploys by itself.

---

## Option B: free plan + Brevo (HTTPS, port 443 is never blocked)
1. Create a free account at brevo.com.
2. Add `techconnectsupport13@gmail.com` as a **sender** and click the confirmation link Brevo e-mails to it.
3. Create an **API key** (Brevo: SMTP & API > API keys). Menu names can change slightly.
4. Render > Environment: add `BREVO_API_KEY` = the key. Nothing else is needed (leave the `MAIL_*` variables unset).

Note: mail sent "from" a gmail.com address by a third-party service can land in spam. The permanent fix is a sender on your
own domain (for example `support@yourdomain`), verified in Brevo, set as `MAIL_DEFAULT_SENDER`.

---

## After you deploy: check it works
1. **Render > Logs**, look near startup for one of these lines:
   * `[MAIL INFO] ready: smtp.gmail.com:587 via STARTTLS as techconnectsupport13@gmail.com ...`  (Option A)
   * `[MAIL INFO] ready: sending over the Brevo HTTPS API ...`  (Option B)
   * `[MAIL ERROR] NOT READY: MAIL_PASSWORD is not set ...`  (something is missing: fix and redeploy)
2. **Admin > Settings > Email test**: send yourself a message. Settings also shows why e-mail is unavailable, if it is.
3. Request a reset on `/forgot-password` with a real technician e-mail. You should get the code within seconds.

## Troubleshooting: what the logs mean
| Log message contains | Meaning / fix |
|---|---|
| `MAIL_PASSWORD is not set` | Add the App Password variable (Option A) or `BREVO_API_KEY` (Option B). |
| `REJECTED THE LOGIN` | Wrong App Password, 2-Step Verification is off, or `MAIL_USERNAME` is not the account that created it. Make a new App Password. |
| `FREE web services block outbound SMTP` | You are on the free plan: use Option A (upgrade) or Option B (Brevo). |
| `could not reach smtp.gmail.com:587` | Network blocked or wrong `MAIL_SERVER` / `MAIL_PORT`. |
| `TLS/SSL problem` | Use port 587 with `MAIL_USE_TLS=true`, or port 465 with `MAIL_USE_SSL=true`. |
| `REJECTED THE API KEY` | `BREVO_API_KEY` is wrong or revoked. |
| `must be added and verified under Senders` | Verify the sender address in Brevo. |
| `sender address was refused` | `MAIL_DEFAULT_SENDER` must be the Gmail account (or one of its aliases). |

## What changed in the password-reset flow
* The code is **e-mailed** and **never written to the logs on Render** (locally, with no mail configured, it is printed for development only and marked DEV ONLY).
* The reply is **identical whether or not the account exists**, so nobody can discover who is registered.
* 5 wrong guesses destroy the code; a new e-mail needs a 60-second gap; codes last 5 minutes.
* If the server itself cannot send mail, users are told so honestly (English/French) instead of being told a code was sent.
* E-mails and messages are bilingual (English/French) and use the support address `techconnectsupport13@gmail.com`.
* **`Flask-Mail` is no longer used.** The standard library sends the mail, so a missing package can no longer silently stop e-mail. You may remove it from `requirements.txt`.
* The Gmail password that used to be written in `app.py` is **gone**. Revoke that old App Password in your Google account, because it stays in your Git history.

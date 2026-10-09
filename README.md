# Sooda — Buy & Sell in Pakistan

An OLX-style classifieds marketplace. **Live demo:** open `index.html`
— it's the entire site in one file (no build step, no server needed).

## The single-file site (`index.html`)

The whole marketplace — homepage with search & filters, 14 categories,
ad detail pages with photo galleries, post-an-ad, login/signup, My Ads
dashboard, and favorites — in one self-contained HTML file (~70KB).

- Just open it in a browser, or host it anywhere static (GitHub Pages,
  Netlify, Vercel, any shared hosting).
- Demo login: **demo@sooda.pk** / **demo1234**
- Ads you post are saved in the browser (localStorage). 12 demo ads are
  baked in so it feels alive on first open.

## The full-stack version (`server/`)

A real Node.js + Express + SQLite backend with true user accounts
(bcrypt), photo uploads, and a JSON API. Run it with:

```bash
npm install
npm run seed   # adds 12 demo ads (categories auto-create)
npm start      # → http://localhost:3000
```

Production notes: set a real `SESSION_SECRET` env var, swap the
in-memory session store for Redis/SQLite store, serve over HTTPS, and
back up `sooda.db` regularly.

## Phone verification (Twilio SMS / WhatsApp)

Signup ends with a phone-verification step. The server sends a 6-digit code
via Twilio and the user must enter it before they can post ads.

Set these environment variables (never commit them):

| Variable | Purpose |
|---|---|
| `TWILIO_ACCOUNT_SID` | From twilio.com/console |
| `TWILIO_AUTH_TOKEN` | From twilio.com/console |
| `TWILIO_SMS_NUMBER` | Your Twilio number, e.g. `+15551234567` |
| `TWILIO_WHATSAPP_NUMBER` | Your WhatsApp-enabled Twilio sender, e.g. `+14155238886` |
| `TWILIO_TEST_MODE=1` | Optional: `/api/auth/phone/request` returns the code in the response instead of sending (for automated tests — never in production) |

Pakistani mobiles are normalized automatically (`0300…` → `+92300…`).
Codes are SHA-256 hashed at rest, expire after 10 minutes, allow 5 attempts,
and resends are rate-limited to one per minute.

## Deploying the single-file site to GitHub Pages

1. Push this repo to GitHub (public).
2. Repo → Settings → Pages → Deploy from branch → `main`, folder `/ (root)`.
3. Your site is live at `https://<username>.github.io/sooda/`.

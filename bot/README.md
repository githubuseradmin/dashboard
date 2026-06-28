# Dashboard Telegram bot

A small [aiogram](https://aiogram.dev/) process that powers the dashboard's
Telegram integration. It shares the web app's database and `app.telegram`
helpers and handles the **inbound** side:

- `/start <token>` — link a Telegram account to a dashboard user
  (the token comes from **Settings → Telegram → Link Telegram**),
- the **Confirm / Deny** buttons on a sign-in request,
- a button that opens the **Mini App**.

Outbound messages (the sign-in prompt and notifications) are sent directly by
the Flask app over the Bot HTTP API, so the bot is only needed for the parts
above.

## Setup

1. Create a bot with [@BotFather](https://t.me/BotFather); copy the token and
   note the bot's `@username`.
2. In the dashboard `.env` set at least:
   ```ini
   TELEGRAM_BOT_TOKEN=123456:your-token
   TELEGRAM_BOT_USERNAME=your_bot
   SECRET_KEY=...            # MUST match the web app
   DATABASE_URL=...          # MUST be the same DB the web app uses
   # Optional Mini App (Telegram needs HTTPS):
   TELEGRAM_WEBAPP_URL=https://your-domain/tg/app
   ```
3. Install deps (same venv as the web app, plus aiogram):
   ```bash
   pip install -r requirements.txt -r bot/requirements.txt
   ```
4. Run the bot (from the dashboard directory):
   ```bash
   python -m bot.run_bot
   ```

`SECRET_KEY` and `DATABASE_URL` **must** match the web app — the bot verifies
link tokens with `SECRET_KEY` and reads/writes the same `users` /
`login_requests` tables.

## Mini App / login over HTTPS

Telegram only opens Web Apps and only accepts a login bot domain over HTTPS.
For local development, expose the dashboard with a tunnel (e.g. Cloudflare
Tunnel or `ngrok`) and point `TELEGRAM_WEBAPP_URL` at `https://<tunnel>/tg/app`.

"""Telegram bot for the dashboard (aiogram 3.x).

Runs as a separate long-lived process and shares the dashboard's database and
``app.telegram`` helpers. It handles the *inbound* side of the integration:

* ``/start <link_token>`` -- connect a Telegram account to a dashboard user
  (the token is the stateless signed link generated in Settings),
* the Confirm / Deny buttons on a sign-in request,
* a button that opens the Mini App.

Outbound messages (the sign-in prompt, notifications) are sent directly by the
Flask app via the Bot HTTP API, so this process is only needed for the inbound
parts above.

Run it from the dashboard directory (same venv as the web app, plus aiogram):

    python -m bot.run_bot            # or: python bot/run_bot.py

Environment (shared with the web app, typically via .env):
    TELEGRAM_BOT_TOKEN, SECRET_KEY, DATABASE_URL, TELEGRAM_WEBAPP_URL,
    TELEGRAM_LINK_TTL
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone

# Make the sibling ``app`` package importable and resolve a relative sqlite path
# against the dashboard root, so the bot opens the *same* database file the web
# app uses regardless of the current working directory.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    from dotenv import load_dotenv

    load_dotenv(os.path.join(ROOT, ".env"))
except Exception:  # pragma: no cover - dotenv is optional
    pass

import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from app import telegram as tg
from app.models import LoginRequest, LoginRequestStatus, User

try:
    from aiogram import Bot, Dispatcher, F
    from aiogram.filters import CommandObject, CommandStart
    from aiogram.types import (
        CallbackQuery,
        InlineKeyboardButton,
        InlineKeyboardMarkup,
        Message,
        WebAppInfo,
    )
except ImportError:  # pragma: no cover - clearer message than a raw traceback
    sys.exit("aiogram is required: pip install -r bot/requirements.txt")


TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
SECRET = os.environ.get("SECRET_KEY", "dev-insecure-change-me")
WEBAPP_URL = os.environ.get("TELEGRAM_WEBAPP_URL", "")
LINK_TTL = int(os.environ.get("TELEGRAM_LINK_TTL", "600"))

# Database: same URL as the web app; resolve a relative sqlite path to ROOT.
DB_URL = os.environ.get("DATABASE_URL", "sqlite:///dashboard.db")
if DB_URL.startswith("sqlite:///") and not DB_URL.startswith("sqlite:////"):
    DB_URL = "sqlite:///" + os.path.join(ROOT, DB_URL[len("sqlite:///") :])

_connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite") else {}
engine = sa.create_engine(DB_URL, future=True, pool_pre_ping=True, connect_args=_connect_args)
Session = sessionmaker(bind=engine, future=True, expire_on_commit=False)

dp = Dispatcher()


def _naive_utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _webapp_kb() -> InlineKeyboardMarkup | None:
    """A button that opens the Mini App, if a WebApp URL is configured."""
    if not WEBAPP_URL:
        return None
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="📊 Open dashboard", web_app=WebAppInfo(url=WEBAPP_URL))]
        ]
    )


@dp.message(CommandStart(deep_link=True))
async def on_start_link(message: Message, command: CommandObject) -> None:
    """Connect this Telegram account to the dashboard user from the link token."""
    user_id = tg.parse_link_token(command.args or "", max_age=LINK_TTL, secret=SECRET)
    if user_id is None:
        await message.answer("This link is invalid or has expired. Generate a new one in Settings.")
        return

    with Session() as session:
        user = session.get(User, user_id)
        if user is None:
            await message.answer("Account not found.")
            return
        # One Telegram account links to at most one dashboard user.
        clash = session.scalar(
            sa.select(User).where(User.telegram_id == message.from_user.id)
        )
        if clash is not None and clash.id != user.id:
            await message.answer("This Telegram account is already linked to another user.")
            return
        user.telegram_id = message.from_user.id
        user.telegram_username = message.from_user.username
        session.commit()
        name = user.name

    await message.answer(
        f"✅ Linked to <b>{name}</b>.\n"
        "You can now approve sign-ins here and receive notifications.",
        parse_mode="HTML",
        reply_markup=_webapp_kb(),
    )


@dp.message(CommandStart())
async def on_start(message: Message) -> None:
    """Greeting for a plain /start (no link token)."""
    await message.answer(
        "👋 This bot is the companion for your dashboard.\n\n"
        "Open <b>Settings → Telegram</b> on the website and press "
        "<i>Link Telegram</i> to connect your account.",
        parse_mode="HTML",
        reply_markup=_webapp_kb(),
    )


@dp.callback_query(F.data.startswith("tgl:"))
async def on_login_decision(callback: CallbackQuery) -> None:
    """Handle the Confirm / Deny buttons on a sign-in request."""
    try:
        _, action, token = callback.data.split(":", 2)
    except ValueError:
        await callback.answer("Bad request.", show_alert=True)
        return

    with Session() as session:
        req = session.scalar(sa.select(LoginRequest).where(LoginRequest.token == token))
        if req is None:
            await callback.answer("Sign-in request not found.", show_alert=True)
            return
        user = session.get(User, req.user_id)
        if user is None or user.telegram_id != callback.from_user.id:
            await callback.answer("This request isn't yours.", show_alert=True)
            return
        if not req.is_actionable:
            await callback.answer("This request has expired or was already handled.")
            await _safe_edit(callback, "⌛ This sign-in request is no longer active.")
            return
        approved = action == "a"
        req.status = LoginRequestStatus.APPROVED if approved else LoginRequestStatus.DENIED
        req.resolved_at = _naive_utcnow()
        session.commit()

    await callback.answer("Approved ✅" if approved else "Denied ❌")
    await _safe_edit(
        callback,
        "✅ Sign-in approved. You can return to the website."
        if approved
        else "❌ Sign-in denied.",
    )


async def _safe_edit(callback: CallbackQuery, text: str) -> None:
    """Edit the prompt message, ignoring 'message not modified' style errors."""
    try:
        await callback.message.edit_text(text)
    except Exception:
        pass


async def main() -> None:
    if not TOKEN:
        sys.exit("Set TELEGRAM_BOT_TOKEN (in .env or the environment) before starting the bot.")
    bot = Bot(TOKEN)
    print("Dashboard bot is polling. Press Ctrl+C to stop.")
    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass

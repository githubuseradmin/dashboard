"""Telegram Mini App: a small in-Telegram view of the user's account.

Flask serves both the page (``/tg/app``) and its JSON API (``/api/telegram/*``)
so they share an origin (no CORS). These requests are authenticated by
validating the Telegram WebApp ``initData`` HMAC, not a session cookie, so the
API routes are exempt from the session CSRF guard (see the app factory).
"""

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from flask import Blueprint, jsonify, render_template, request

from .. import telegram as tg
from ..extensions import db
from ..models import (
    AuditLog,
    LoginRequest,
    LoginRequestStatus,
    SupportTicket,
    TicketStatus,
    User,
)

telegram_bp = Blueprint("telegram", __name__)


def _authenticate(data: dict) -> User | None:
    """Return the linked ``User`` for a request's validated initData, or None."""
    parsed = tg.validate_init_data(data.get("initData", ""))
    if not parsed or not parsed.get("user"):
        return None
    tg_id = parsed["user"].get("id")
    if tg_id is None:
        return None
    return db.session.scalar(sa.select(User).where(User.telegram_id == int(tg_id)))


@telegram_bp.route("/tg/app")
def mini_app():
    """Serve the standalone Mini App shell (rendered inside Telegram)."""
    return render_template("telegram/app.html")


@telegram_bp.route("/api/telegram/me", methods=["POST"])
def api_me():
    """Return the authenticated user's profile, stats and pending sign-ins."""
    data = request.get_json(silent=True) or {}
    user = _authenticate(data)
    if user is None:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    open_tickets = (
        db.session.scalar(
            sa.select(sa.func.count())
            .select_from(SupportTicket)
            .where(
                SupportTicket.user_id == user.id,
                SupportTicket.status != TicketStatus.CLOSED,
            )
        )
        or 0
    )
    events = db.session.scalars(
        sa.select(AuditLog)
        .where(AuditLog.user_id == user.id)
        .order_by(AuditLog.created_at.desc())
        .limit(5)
    ).all()
    pending = [
        p
        for p in db.session.scalars(
            sa.select(LoginRequest)
            .where(
                LoginRequest.user_id == user.id,
                LoginRequest.status == LoginRequestStatus.PENDING,
            )
            .order_by(LoginRequest.created_at.desc())
        ).all()
        if not p.is_expired
    ]

    return jsonify(
        {
            "ok": True,
            "user": {
                "name": user.name,
                "username": user.username,
                "role": user.role.label,
                "telegram_username": user.telegram_username,
            },
            "stats": {
                "open_tickets": open_tickets,
                "two_factor": bool(user.totp_enabled),
                "role": user.role.label,
                "notify": bool(user.telegram_notify),
            },
            "events": [
                {
                    "action": e.action,
                    "detail": e.detail,
                    "at": e.created_at.isoformat(),
                }
                for e in events
            ],
            "pending_logins": [
                {"token": p.token, "ip": p.ip, "at": p.created_at.isoformat()}
                for p in pending
            ],
        }
    )


@telegram_bp.route("/api/telegram/approve", methods=["POST"])
def api_approve():
    """Approve or deny a pending sign-in from inside the Mini App."""
    data = request.get_json(silent=True) or {}
    user = _authenticate(data)
    if user is None:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    token = (data.get("token") or "").strip()
    decision = (data.get("decision") or "approve").strip()
    req = db.session.scalar(
        sa.select(LoginRequest).where(
            LoginRequest.token == token, LoginRequest.user_id == user.id
        )
    )
    if req is None or not req.is_actionable:
        return jsonify({"ok": False, "error": "not_actionable"}), 400

    req.status = (
        LoginRequestStatus.APPROVED
        if decision == "approve"
        else LoginRequestStatus.DENIED
    )
    req.resolved_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.add(
        AuditLog(
            user_id=user.id,
            action="login_telegram_miniapp",
            detail=req.status.value,
        )
    )
    db.session.commit()
    return jsonify({"ok": True, "status": req.status.value})

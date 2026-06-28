"""Application factory.

``create_app`` wires configuration, the database, blueprints, error handlers
and template helpers into a fully configured Flask application. Importing this
module has no side effects -- nothing happens until the factory is called.
"""

from __future__ import annotations

from flask import Flask, render_template

from .config import resolve_config
from .extensions import db
from .security import current_user, get_csrf_token, validate_csrf


def create_app(config_name: str | None = None) -> Flask:
    """Build and return a configured Flask application instance."""
    app = Flask(__name__)
    app.config.from_object(resolve_config(config_name))

    # Bind extensions to this app instance.
    db.init_app(app)

    _register_blueprints(app)
    _register_template_helpers(app)
    _register_csrf_protection(app)
    _register_error_handlers(app)

    return app


def _register_blueprints(app: Flask) -> None:
    """Attach every feature blueprint to the application."""
    from .blueprints.auth import auth_bp
    from .blueprints.dashboard import dashboard_bp
    from .blueprints.admin import admin_bp
    from .blueprints.support import support_bp
    from .blueprints.telegram import telegram_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(support_bp)
    app.register_blueprint(telegram_bp)


def _register_template_helpers(app: Flask) -> None:
    """Expose helpers and globals to all Jinja2 templates."""

    @app.context_processor
    def inject_globals():
        # ``current_user`` and ``csrf_token`` are available in every template.
        return {
            "current_user": current_user(),
            "csrf_token": get_csrf_token,
            "app_name": app.config.get("APP_NAME", "Dashboard"),
        }


def _register_csrf_protection(app: Flask) -> None:
    """Reject unsafe HTTP methods that lack a valid CSRF token.

    All state-changing requests (POST/PUT/PATCH/DELETE) must carry a token that
    matches the one stored in the session, submitted either as the
    ``csrf_token`` form field or the ``X-CSRFToken`` header (for HTMX).
    """

    @app.before_request
    def csrf_protect():
        from flask import request, abort

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            # CSRF can be globally disabled for the test suite.
            if app.config.get("WTF_CSRF_ENABLED", True) is False:
                return
            # The Telegram Mini App API authenticates each call via the
            # WebApp initData HMAC (not a session cookie), so it is exempt
            # from the session CSRF guard.
            if request.path.startswith("/api/telegram/"):
                return
            submitted = request.form.get("csrf_token") or request.headers.get(
                "X-CSRFToken"
            )
            if not validate_csrf(submitted):
                abort(400, description="Invalid or missing CSRF token.")


def _register_error_handlers(app: Flask) -> None:
    """Friendly HTML pages for the common error codes."""

    @app.errorhandler(400)
    def bad_request(error):  # noqa: ANN001
        return render_template("errors/error.html", code=400, message=str(error)), 400

    @app.errorhandler(403)
    def forbidden(error):  # noqa: ANN001
        return (
            render_template(
                "errors/error.html",
                code=403,
                message="You do not have permission to view this page.",
            ),
            403,
        )

    @app.errorhandler(404)
    def not_found(error):  # noqa: ANN001
        return (
            render_template(
                "errors/error.html",
                code=404,
                message="The page you are looking for does not exist.",
            ),
            404,
        )

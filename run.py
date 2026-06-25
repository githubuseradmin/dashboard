"""Development entry point.

Run with ``python run.py`` and open http://127.0.0.1:5000/dashboard.
For production, serve the ``app`` object with a WSGI server such as gunicorn:

    gunicorn "app:create_app()"
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

# Load environment variables from a local .env file if present.
load_dotenv()

from app import create_app  # noqa: E402  (import after load_dotenv on purpose)

app = create_app()


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=app.config.get("DEBUG", False))

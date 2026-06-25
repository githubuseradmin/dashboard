English | [Русский](README.ru.md)

# Dashboard

A polished, modern-but-simple full-stack web **dashboard with authentication**,
built to be a realistic starter you can actually build on. It ships a complete
account system (registration, login, optional TOTP two-factor authentication),
a social-network-style shell (top bar + sidebar), role-based access control, an
admin area for managing users, and a small support-ticket system — all on a
clean, layered architecture with **stdlib-first, dependency-light** choices.

The UI uses **HTMX** for snappy partial tab updates (no SPA framework), a custom
**light/dark** CSS design system (no CSS framework), and server-rendered Jinja2
templates.

---

## Features

- **Authentication**
  - Email/username + password registration and login.
  - Passwords hashed with **bcrypt** (via passlib), never stored in plaintext.
  - **Optional TOTP two-factor authentication** (Google Authenticator, Authy,
    1Password, …): enable in Settings with a scannable **QR code** (rendered by
    segno), then required as a second step at login.
- **Roles & access control** — four roles (`user`, `supporter`, `moderator`,
  `admin`) enforced **server-side** with `login_required` / `role_required`
  decorators. The UI only hides links; the server is the source of truth.
- **Dashboard shell** — sticky top bar with a user menu (Profile, Settings,
  Logout) and a left sidebar (Home, Profile, Support, Settings, and Admin for
  staff). Tab switches are fetched as **HTMX partials** for instant updates.
- **Profile & Settings** — edit display name; change password; enable/disable 2FA.
- **Admin area** (moderator/admin) — searchable user list, change roles,
  activate/deactivate accounts, headline stats. Includes guard rails (you
  cannot deactivate yourself or remove the last admin).
- **Support tickets** — users open tickets and reply in a thread; support staff
  (supporter/moderator/admin) see a queue and manage statuses (open / pending /
  closed).
- **Security done right** — bcrypt hashes, **CSRF protection on every form**
  (manual signed token, also sent via the `X-CSRFToken` header for HTMX),
  hardened session cookies (HttpOnly, SameSite=Lax, optional Secure),
  parameterized queries via SQLAlchemy, friendly 400/403/404 pages.
- **DB-agnostic** — SQLite by default; switch to MySQL with a single env var.
- **Light/dark theme** — toggle persisted in `localStorage`; works without JS.

---

## Architecture

```mermaid
flowchart TD
    Browser["Browser (HTMX + Jinja2 templates)"]
    subgraph Flask["Flask application (application factory)"]
        Factory["create_app()\nconfig - extensions - blueprints\nCSRF before_request - error handlers"]
        subgraph BP["Blueprints"]
            Auth["auth\nregister / login / 2FA / logout"]
            Dash["dashboard\nhome / profile / settings / 2FA"]
            Admin["admin\nusers / roles / activation / stats"]
            Support["support\ntickets / thread / status"]
        end
        Security["security.py\nbcrypt - TOTP - CSRF\nlogin_required / role_required"]
        Models["models.py\nUser - SupportTicket\nTicketMessage - AuditLog"]
        Ext["extensions.py\nDatabase (SQLAlchemy 2.x)"]
    end
    DB[("SQLite (default)\nor MySQL via DATABASE_URL")]

    Browser <--> Factory
    Factory --> BP
    BP --> Security
    BP --> Models
    Security --> Models
    Models --> Ext
    Ext <--> DB
```

**Request lifecycle (example: open the Admin tab as a moderator)**

1. HTMX issues `GET /dashboard/admin/` with an `HX-Request` header and the
   `X-CSRFToken` header attached by `app.js`.
2. `role_required(MODERATOR, ADMIN)` resolves the current user from the signed
   session cookie and authorizes (or returns 403).
3. The view queries users via SQLAlchemy and renders the **partial**
   `partials/admin_users.html` (because it is an HTMX request), which is swapped
   into `#main` — no full-page reload.

---

## Project layout

```
dashboard/
├── run.py                     # Dev entry point: python run.py
├── seed.py                    # Create tables + seed demo users (prints creds)
├── requirements.txt
├── .env.example               # Copy to .env and edit
├── .gitignore
├── app/
│   ├── __init__.py            # create_app(): the application factory
│   ├── config.py              # Env-driven config (dev / prod / testing)
│   ├── extensions.py          # SQLAlchemy 2.x Database + bcrypt compat shim
│   ├── models.py              # User, SupportTicket, TicketMessage, AuditLog
│   ├── security.py            # Hashing, TOTP, CSRF, login_required/role_required
│   ├── blueprints/
│   │   ├── auth.py            # register / login (+2FA) / logout
│   │   ├── dashboard.py       # home / profile / settings / 2FA management
│   │   ├── admin.py           # user management + stats (staff only)
│   │   └── support.py         # ticket list / thread / status changes
│   ├── templates/
│   │   ├── base.html          # Top bar + sidebar shell (and auth shell)
│   │   ├── auth/ dashboard/ admin/ support/ errors/
│   │   └── partials/          # HTMX-swappable fragments + flashes
│   └── static/
│       ├── css/styles.css     # Custom light/dark design system
│       ├── js/app.js          # Theme toggle, user menu, HTMX CSRF header
│       └── vendor/htmx.min.js # Vendored HTMX (see note below)
└── tests/
    └── test_security.py       # unittest: hashing, TOTP, CSRF, role gating
```

---

## Quick start

> Requires **Python 3.10+**.

```bash
# 1) Create and activate a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

# 2) Install dependencies
pip install -r requirements.txt

# 3) (optional) Configure environment
cp .env.example .env        # then edit SECRET_KEY etc.

# 4) Create the database and seed a demo admin (+ sample accounts)
python seed.py

# 5) Run the development server
python run.py
```

Then open <http://127.0.0.1:5000/dashboard>. Visiting it while signed out shows
the **login screen** with a link to register.

### Demo credentials (printed by `seed.py`)

| Role      | Login                   | Password         |
|-----------|-------------------------|------------------|
| Admin     | `admin@example.com`     | `Admin12345!`    |
| Supporter | `supporter@example.com` | `Support12345!`  |
| User      | `member@example.com`    | `Member12345!`   |

Example `seed.py` output:

```
============================================================
Database ready. Demo credentials:
------------------------------------------------------------
  ADMIN     login: admin@example.com
            password: Admin12345!
  SUPPORTER login: supporter@example.com
            password: Support12345!
  USER      login: member@example.com
            password: Member12345!
============================================================
Start the app with:  python run.py
Then open:           http://127.0.0.1:5000/dashboard
============================================================
```

> Change `SEED_ADMIN_PASSWORD` (and friends) in `.env` to seed different
> credentials. The demo passwords are for local development only — never reuse
> them in production.

---

## Switching to MySQL

The app is database-agnostic through SQLAlchemy. To use MySQL/MariaDB:

1. Install a driver (PyMySQL is already listed, commented, in
   `requirements.txt`):
   ```bash
   pip install PyMySQL
   ```
2. Set `DATABASE_URL` to a PyMySQL URL, e.g. in `.env`:
   ```env
   DATABASE_URL=mysql+pymysql://user:password@127.0.0.1:3306/dashboard?charset=utf8mb4
   ```
3. Create the schema against the new database:
   ```bash
   python seed.py
   ```

No code changes are required — only the env var.

---

## Configuration reference

All settings are environment-driven (see `.env.example`):

| Variable                | Default                    | Purpose                                            |
|-------------------------|----------------------------|----------------------------------------------------|
| `FLASK_ENV`             | `development`              | Profile: `development` / `production` / `testing`. |
| `SECRET_KEY`            | dev placeholder            | Signs session cookies and CSRF tokens. **Set this.** |
| `DATABASE_URL`          | `sqlite:///dashboard.db`  | Any SQLAlchemy URL (SQLite, MySQL, …).             |
| `APP_NAME`              | `Dashboard`               | Shown in the UI and used as the 2FA issuer.        |
| `BCRYPT_ROUNDS`         | `12`                      | bcrypt work factor (cost).                         |
| `SESSION_COOKIE_SECURE` | `false` (dev)             | Set `true` behind HTTPS to mark cookies Secure.    |
| `SESSION_LIFETIME_DAYS` | `7`                       | Session lifetime.                                  |
| `HOST` / `PORT`         | `127.0.0.1` / `5000`      | Dev server bind address.                           |

---

## HTMX: vendored vs. CDN

HTMX is **vendored** into `app/static/vendor/htmx.min.js` (HTMX 1.9.12) and
loaded locally from `base.html`. This keeps the app fully offline-capable and
avoids a third-party runtime dependency. To use a CDN instead, replace the
script tag in `app/templates/base.html` with:

```html
<script src="https://unpkg.com/htmx.org@1.9.12" defer></script>
```

---

## Running in production

Use a real WSGI server (do not use the Flask dev server in production):

```bash
pip install gunicorn
gunicorn "app:create_app()" --bind 0.0.0.0:8000
```

Set `FLASK_ENV=production`, a strong `SECRET_KEY`, and `SESSION_COOKIE_SECURE=true`
behind HTTPS.

---

## Security notes

- **Passwords** are hashed with bcrypt (passlib `CryptContext`); the work factor
  is configurable via `BCRYPT_ROUNDS`. Plaintext passwords are never stored or
  logged.
- **2FA secrets** are stored only as the base32 shared secret and never rendered
  into logs. The setup page shows a QR for the standard `otpauth://` URI plus a
  manual key; the secret never leaves the server in any other form.
- **CSRF**: every state-changing request (`POST`/`PUT`/`PATCH`/`DELETE`) must
  carry a per-session signed token, validated in a `before_request` hook. HTMX
  requests send it via the `X-CSRFToken` header.
- **Sessions** use signed cookies with `HttpOnly` + `SameSite=Lax`, and `Secure`
  when enabled. Logging in clears the session (prevents fixation); a deactivated
  account is treated as logged out on the next request.
- **Authorization** is enforced server-side via decorators; templates only hide
  links for convenience.
- **SQL** uses parameterized SQLAlchemy queries throughout — no string-built SQL.

### bcrypt / MarkupSafe compatibility note

`app/extensions.py` contains a small, well-documented compatibility shim so that
passlib 1.7.4 works with bcrypt ≥ 4.1/5.x (newer bcrypt removed
`__about__.__version__` and raises on >72-byte probe strings used by passlib's
startup self-test). `requirements.txt` also pins `MarkupSafe != 3.0.3`, whose
prebuilt C extension is broken on some Python 3.14 alpha builds. Both notes are
inline in the code; on stable Python you may not need either, but they make the
project robust across environments.

---

## Running the tests

```bash
python -m unittest discover -s tests -v
```

The suite (`tests/test_security.py`) uses an **in-memory SQLite** app and covers:

- bcrypt password hashing and verification (salted, unique, rejects wrong/malformed),
- TOTP secret generation and code verification (accepts current, rejects wrong),
- TOTP QR rendering returns an embeddable SVG (and never leaks the secret),
- CSRF token round-trip,
- **server-side `role_required` gating** (anonymous → login, wrong role → 403,
  right role → 200, deactivated user → logged out).

If Flask/SQLAlchemy are not installed, you can still validate every module
compiles:

```bash
python -m py_compile $(git ls-files '*.py')   # or pass the .py paths explicitly
```

---

## License

Provided as a starter/demo. Use it freely as a foundation for your own project.

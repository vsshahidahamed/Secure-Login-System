# Secure Login App

Simple Flask-based secure login example with:

- Registration and login using Argon2-hashed passwords (`argon2-cffi`)
- SQLAlchemy ORM to avoid SQL injection risks
- Session management via `Flask-Login` with logout
- Optional TOTP-based 2FA via `pyotp`

Getting started

1. Create and activate a virtual environment (recommended).

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. (Optional) Set a strong `SECRET_KEY`:

```powershell
$env:SECRET_KEY = 'your-strong-secret'
```

3. Run the app:

```powershell
python "app.py"
```

4. Visit `http://127.0.0.1:5000/` to register and test.

Notes
- This example uses SQLAlchemy ORM queries (no raw SQL) to protect against SQL injection.
- Passwords are hashed with Argon2; do not store plaintext passwords.
- 2FA provisioning URI is shown in the settings page after enabling 2FA — paste into an authenticator app.
- For production: set `SECRET_KEY`, disable `debug`, and run behind a proper WSGI server.

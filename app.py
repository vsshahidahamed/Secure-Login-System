import os
import re
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from argon2 import PasswordHasher, exceptions as argon2_exceptions
import pyotp

BASE_DIR = os.path.dirname(__file__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

ph = PasswordHasher()

email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)

    def get_id(self):
        return str(self.id)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def validate_registration(username, email, password):
    if not username or len(username) < 3:
        return 'Username must be at least 3 characters.'
    if not email or not email_re.match(email):
        return 'Invalid email address.'
    if not password or len(password) < 8:
        return 'Password must be at least 8 characters.'
    return None


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        err = validate_registration(username, email, password)
        if err:
            flash(err, 'danger')
            return redirect(url_for('register'))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('register'))

        password_hash = ph.hash(password)
        user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')

        # allow login by username or email
        user = User.query.filter((User.username == identifier) | (User.email == identifier.lower())).first()
        if not user:
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

        try:
            ph.verify(user.password_hash, password)
        except argon2_exceptions.VerifyMismatchError:
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))
        except Exception:
            flash('Authentication error.', 'danger')
            return redirect(url_for('login'))

        # If user has 2FA enabled, store pending id in session and ask for code
        if user.totp_secret:
            session['pre_2fa_user_id'] = user.id
            return redirect(url_for('two_factor'))

        login_user(user)
        flash('Logged in successfully.', 'success')
        return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/two-factor', methods=['GET', 'POST'])
def two_factor():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = User.query.get(int(user_id))
    if not user or not user.totp_secret:
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code, valid_window=1):
            session.pop('pre_2fa_user_id', None)
            login_user(user)
            flash('2FA verification succeeded.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid 2FA code.', 'danger')
            return redirect(url_for('two_factor'))

    # show simple form to enter the code
    return render_template('2fa_verify.html')


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'enable_2fa' and not current_user.totp_secret:
            secret = pyotp.random_base32()
            current_user.totp_secret = secret
            db.session.commit()
            provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name='SecureApp')
            flash('2FA enabled. Add the account to your authenticator app using the provisioning URI shown below.', 'success')
            return render_template('settings.html', provisioning_uri=provisioning_uri)
        elif action == 'disable_2fa' and current_user.totp_secret:
            current_user.totp_secret = None
            db.session.commit()
            flash('2FA disabled.', 'success')
            return redirect(url_for('settings'))

    return render_template('settings.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))


if __name__ == '__main__':
    # ensure DB exists
    with app.app_context():
        db.create_all()
    app.run(debug=True)

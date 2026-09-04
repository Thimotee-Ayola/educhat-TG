import os
import sqlite3
import secrets
import base64
import io
from datetime import datetime

from flask import Flask, request, redirect, url_for, render_template, session, jsonify, flash
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from cryptography.fernet import Fernet

from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    AttestationObject, AuthenticatorData, CollectedClientData,
)
from fido2 import cbor
from fido2.utils import websafe_decode, websafe_encode


# ---------------------------------------------------------------------------
# Aide : conversion des données WebAuthn (contiennent des octets bruts) en
# JSON lisible par le navigateur, et inversement. C'est la seule partie qui
# doit obligatoirement transiter par un peu de JavaScript côté navigateur,
# car c'est le navigateur qui parle directement au capteur d'empreinte/visage
# de l'appareil (Android, iPhone, Windows Hello) — aucun langage serveur, Python
# inclus, ne peut lire ce capteur directement pour des raisons de sécurité.
# ---------------------------------------------------------------------------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).decode().rstrip("=")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def to_jsonable(obj):
    """Convertit récursivement un objet WebAuthn (avec des bytes) en JSON,
    en marquant chaque valeur binaire pour que le JavaScript sache la
    reconvertir en ArrayBuffer avant de parler au capteur biométrique."""
    if isinstance(obj, (bytes, bytearray)):
        return {"$bytes": b64url_encode(obj)}
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    return obj

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB_PATH = os.environ.get("DB_PATH", "educhat.db")

# Le RP_ID doit être le nom de domaine EXACT de ton appli une fois déployée
# (sans https:// ni port), ex: "educhat-togo.onrender.com"
RP_ID = os.environ.get("RP_ID", "localhost")
RP_NAME = "EduChat Togo"
ORIGIN = os.environ.get("ORIGIN", f"https://{RP_ID}")

fido_server = Fido2Server(PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME))

# Clé de chiffrement des messages au repos (à remplacer par une vraie clé secrète en prod)
FERNET_KEY = os.environ.get("FERNET_KEY", Fernet.generate_key().decode())
fernet = Fernet(FERNET_KEY.encode())

login_manager = LoginManager(app)
login_manager.login_view = "login"


# ---------------------------------------------------------------------------
# Base de données
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            totp_confirmed INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_token TEXT UNIQUE NOT NULL,
            credential_id TEXT,
            public_key BLOB,
            sign_count INTEGER DEFAULT 0,
            name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            ciphertext BLOB NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS backup_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )
    conn.commit()
    conn.close()


class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.password_hash = row["password_hash"]
        self.totp_secret = row["totp_secret"]
        self.totp_confirmed = row["totp_confirmed"]


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return User(row) if row else None


def get_user_by_username(username):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


# ---------------------------------------------------------------------------
# Inscription
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if len(password) < 8:
            flash("Le mot de passe doit contenir au moins 8 caractères.")
            return redirect(url_for("register"))

        if get_user_by_username(username):
            flash("Ce nom d'utilisateur est déjà pris.")
            return redirect(url_for("register"))

        totp_secret = pyotp.random_base32()
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), totp_secret),
        )
        conn.commit()
        conn.close()

        session["pending_username"] = username
        return redirect(url_for("setup_2fa"))

    return render_template("register.html")


@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    username = session.get("pending_username")
    if not username:
        return redirect(url_for("register"))

    row = get_user_by_username(username)
    totp = pyotp.TOTP(row["totp_secret"])

    if request.method == "POST":
        code = request.form["code"]
        if totp.verify(code):
            conn = get_db()
            conn.execute("UPDATE users SET totp_confirmed = 1 WHERE username = ?", (username,))

            # Génère 10 codes de secours à usage unique (pour les appareils
            # sans capteur biométrique NI code de verrouillage configuré)
            raw_codes = [secrets.token_hex(4) for _ in range(10)]
            for c in raw_codes:
                conn.execute(
                    "INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)",
                    (row["id"], generate_password_hash(c)),
                )
            conn.commit()
            conn.close()

            user = User(get_user_by_username(username))
            login_user(user)
            session.pop("pending_username", None)
            session["backup_codes_display"] = raw_codes
            return redirect(url_for("show_backup_codes"))
        flash("Code invalide, réessaie.")

    uri = totp.provisioning_uri(name=username, issuer_name=RP_NAME)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template("setup_2fa.html", qr_b64=qr_b64, secret=row["totp_secret"])


# ---------------------------------------------------------------------------
# Connexion
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        row = get_user_by_username(username)

        if not row or not check_password_hash(row["password_hash"], password):
            flash("Identifiants incorrects.")
            return redirect(url_for("login"))

        device_token = request.cookies.get("device_token")
        conn = get_db()
        known_device = None
        if device_token:
            known_device = conn.execute(
                "SELECT * FROM devices WHERE user_id = ? AND device_token = ?",
                (row["id"], device_token),
            ).fetchone()
        conn.close()

        session["auth_user_id"] = row["id"]

        if known_device:
            return redirect(url_for("verify_2fa"))
        else:
            # Appareil inconnu : empreinte/visage obligatoire avant tout le reste
            return redirect(url_for("verify_device"))

    return render_template("login.html")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    user_id = session.get("auth_user_id")
    if not user_id:
        return redirect(url_for("login"))

    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    totp = pyotp.TOTP(row["totp_secret"])

    if request.method == "POST":
        if totp.verify(request.form["code"]):
            user = User(row)
            login_user(user)
            session.pop("auth_user_id", None)
            return redirect(url_for("dashboard"))
        flash("Code invalide.")

    return render_template("verify_2fa.html")


# ---------------------------------------------------------------------------
# Vérification par empreinte / visage (WebAuthn) pour nouvel appareil
# ---------------------------------------------------------------------------
@app.route("/backup-codes")
@login_required
def show_backup_codes():
    codes = session.pop("backup_codes_display", None)
    if not codes:
        return redirect(url_for("dashboard"))
    return render_template("backup_codes.html", codes=codes)


@app.route("/setup-device")
@login_required
def setup_device():
    return render_template("setup_device.html")


from fido2.webauthn import PublicKeyCredentialDescriptor, AuthenticatorAttachment


@app.route("/webauthn/register/begin", methods=["POST"])
@login_required
def webauthn_register_begin():
    user_entity = PublicKeyCredentialUserEntity(
        id=str(current_user.id).encode(),
        name=current_user.username,
        display_name=current_user.username,
    )
    options, state = fido_server.register_begin(
        user_entity,
        user_verification="required",
        authenticator_attachment=AuthenticatorAttachment.PLATFORM,
    )
    session["webauthn_state"] = state
    # dict(options) donne la représentation "clé -> valeur" standard WebAuthn
    # (rp, user, challenge, pubKeyCredParams...) ; to_jsonable convertit les
    # octets bruts en base64url pour que le JavaScript puisse les lire.
    return jsonify(to_jsonable(dict(options)))


@app.route("/webauthn/register/complete", methods=["POST"])
@login_required
def webauthn_register_complete():
    data = request.get_json()
    client_data = CollectedClientData(b64url_decode(data["response"]["clientDataJSON"]))
    att_obj = AttestationObject(b64url_decode(data["response"]["attestationObject"]))
    auth_data = fido_server.register_complete(session["webauthn_state"], client_data, att_obj)

    device_token = secrets.token_urlsafe(32)
    conn = get_db()
    conn.execute(
        "INSERT INTO devices (user_id, device_token, credential_id, public_key, sign_count, name) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            current_user.id,
            device_token,
            b64url_encode(auth_data.credential_data.credential_id),
            auth_data.credential_data.public_key,
            auth_data.counter,
            data.get("device_name", "Appareil"),
        ),
    )
    conn.commit()
    conn.close()

    resp = jsonify({"status": "ok"})
    resp.set_cookie("device_token", device_token, max_age=60 * 60 * 24 * 365, httponly=True, samesite="Lax")
    return resp


@app.route("/verify-device", methods=["GET"])
def verify_device():
    if not session.get("auth_user_id"):
        return redirect(url_for("login"))
    return render_template("verify_device.html")


@app.route("/verify-device/backup-code", methods=["POST"])
def verify_device_backup_code():
    user_id = session.get("auth_user_id")
    if not user_id:
        return redirect(url_for("login"))

    entered = request.form["code"].strip()
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM backup_codes WHERE user_id = ? AND used = 0", (user_id,)
    ).fetchall()

    match = None
    for r in rows:
        if check_password_hash(r["code_hash"], entered):
            match = r
            break

    if not match:
        conn.close()
        flash("Code de secours invalide ou déjà utilisé.")
        return redirect(url_for("verify_device"))

    conn.execute("UPDATE backup_codes SET used = 1 WHERE id = ?", (match["id"],))
    # Ce nouvel appareil devient un appareil de confiance : on lui propose
    # d'activer l'empreinte/visage tout de suite s'il est disponible.
    device_token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO devices (user_id, device_token, credential_id, public_key, sign_count, name) "
        "VALUES (?, ?, NULL, NULL, 0, ?)",
        (user_id, device_token, "Appareil (code de secours)"),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    user = User(row)
    login_user(user)
    session.pop("auth_user_id", None)

    resp = redirect(url_for("verify_2fa"))
    resp.set_cookie("device_token", device_token, max_age=60 * 60 * 24 * 365, httponly=True, samesite="Lax")
    return resp


@app.route("/webauthn/authenticate/begin", methods=["POST"])
def webauthn_authenticate_begin():
    user_id = session.get("auth_user_id")
    if not user_id:
        return jsonify({"status": "error"}), 401

    conn = get_db()
    creds = conn.execute("SELECT * FROM devices WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=b64url_decode(c["credential_id"]))
        for c in creds if c["credential_id"]
    ]
    options, state = fido_server.authenticate_begin(allow_credentials, user_verification="required")
    session["webauthn_state"] = state
    return jsonify(to_jsonable(dict(options)))


@app.route("/webauthn/authenticate/complete", methods=["POST"])
def webauthn_authenticate_complete():
    user_id = session.get("auth_user_id")
    if not user_id:
        return jsonify({"status": "error"}), 401

    conn = get_db()
    creds = conn.execute("SELECT * FROM devices WHERE user_id = ?", (user_id,)).fetchall()

    data = request.get_json()
    credential_id = b64url_decode(data["id"])
    matching = [c for c in creds if c["credential_id"] and b64url_decode(c["credential_id"]) == credential_id]
    if not matching:
        conn.close()
        return jsonify({"status": "error", "message": "Appareil non reconnu."}), 400

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=b64url_decode(c["credential_id"]))
        for c in creds if c["credential_id"]
    ]
    client_data = CollectedClientData(b64url_decode(data["response"]["clientDataJSON"]))
    auth_data = AuthenticatorData(b64url_decode(data["response"]["authenticatorData"]))
    signature = b64url_decode(data["response"]["signature"])

    fido_server.authenticate_complete(
        session["webauthn_state"],
        allow_credentials,
        credential_id,
        client_data,
        auth_data,
        signature,
    )

    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    user = User(row)
    login_user(user)
    session.pop("auth_user_id", None)

    resp = jsonify({"status": "ok", "redirect": url_for("verify_2fa")})
    resp.set_cookie(
        "device_token", matching[0]["device_token"],
        max_age=60 * 60 * 24 * 365, httponly=True, samesite="Lax",
    )
    return resp


# ---------------------------------------------------------------------------
# Tableau de bord & chat
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    users = conn.execute(
        "SELECT id, username FROM users WHERE id != ?", (current_user.id,)
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", users=users)


@app.route("/chat/<int:other_id>", methods=["GET", "POST"])
@login_required
def chat(other_id):
    conn = get_db()
    other = conn.execute("SELECT * FROM users WHERE id = ?", (other_id,)).fetchone()
    if not other:
        conn.close()
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        text = request.form["message"].strip()
        if text:
            ciphertext = fernet.encrypt(text.encode())
            conn.execute(
                "INSERT INTO messages (sender_id, receiver_id, ciphertext) VALUES (?, ?, ?)",
                (current_user.id, other_id, ciphertext),
            )
            conn.commit()

    rows = conn.execute(
        "SELECT * FROM messages WHERE (sender_id = ? AND receiver_id = ?) "
        "OR (sender_id = ? AND receiver_id = ?) ORDER BY id ASC",
        (current_user.id, other_id, other_id, current_user.id),
    ).fetchall()
    conn.close()

    messages = [
        {
            "text": fernet.decrypt(r["ciphertext"]).decode(),
            "mine": r["sender_id"] == current_user.id,
            "time": r["timestamp"],
        }
        for r in rows
    ]
    return render_template("chat.html", other=other, messages=messages)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


init_db()

if __name__ == "__main__":
    app.run(debug=True, port=5000)

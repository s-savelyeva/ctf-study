import os
import json
import base64
import hashlib
import hmac
import secrets
from pathlib import Path

from flask import (
    Flask, request, render_template, redirect, url_for,
    make_response, Response
)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------
FLAGS = {
    "none":      os.environ.get("FLAG_NONE",      "CTF{alg_none_signature_bypass}"),
    "weak":      os.environ.get("FLAG_WEAK",      "CTF{weak_hmac_secret_cracked}"),
    "confusion": os.environ.get("FLAG_CONFUSION", "CTF{rs256_to_hs256_confusion}"),
}

WEAK_SECRET = "supersecret"   # специально слабый, есть в rockyou
CHALLENGES  = ("none", "weak", "confusion")

# ---------------------------------------------------------------------------
# Персистентное состояние (RSA-ключ + секрет для challenge "none")
# ---------------------------------------------------------------------------
STATE_DIR = Path(os.environ.get("STATE_DIR", "/app/state"))
STATE_DIR.mkdir(parents=True, exist_ok=True)

_rsa_path = STATE_DIR / "rsa.pem"
if _rsa_path.exists():
    _private_key = serialization.load_pem_private_key(_rsa_path.read_bytes(), password=None)
else:
    _private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _rsa_path.write_bytes(_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
_public_key = _private_key.public_key()
PUBLIC_PEM = _public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

_none_secret_path = STATE_DIR / "none_secret.bin"
if _none_secret_path.exists():
    NONE_CHALLENGE_SECRET = _none_secret_path.read_bytes()
else:
    NONE_CHALLENGE_SECRET = secrets.token_bytes(32)
    _none_secret_path.write_bytes(NONE_CHALLENGE_SECRET)

# ---------------------------------------------------------------------------
# Base64url / JWT helpers
# ---------------------------------------------------------------------------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    pad = b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def make_token(payload: dict, alg: str = "HS256", secret: bytes | None = None) -> str:
    header = {"alg": alg, "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()

    if alg == "none":
        sig = ""
    elif alg == "HS256":
        if secret is None:
            raise ValueError("secret required")
        sig = b64url_encode(hmac.new(secret, signing_input, hashlib.sha256).digest())
    elif alg == "RS256":
        sig = b64url_encode(_private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256()))
    else:
        raise ValueError(f"unsupported alg: {alg}")

    return f"{h}.{p}.{sig}"

def parse_token(token: str):
    if not token or token.count(".") != 2:
        return None
    h, p, s = token.split(".")
    try:
        header  = json.loads(b64url_decode(h))
        payload = json.loads(b64url_decode(p))
    except Exception:
        return None
    return header, payload, f"{h}.{p}".encode(), s

# ---------------------------------------------------------------------------
# Уязвимые верификаторы — по одному на каждый челлендж
# ---------------------------------------------------------------------------
def verify_none(token):
    """VULN #1: alg:none — пропускаем проверку подписи."""
    parsed = parse_token(token)
    if not parsed:
        return None
    header, payload, signing_input, sig = parsed

    alg = header.get("alg", "HS256")
    if alg == "none":
        return payload                     # <-- полный bypass

    if alg == "HS256":
        expected = hmac.new(NONE_CHALLENGE_SECRET, signing_input, hashlib.sha256).digest()
        try:
            if hmac.compare_digest(expected, b64url_decode(sig)):
                return payload
        except Exception:
            pass
    return None

def verify_weak(token):
    """VULN #2: слабый HMAC-секрет (брутфорсится)."""
    parsed = parse_token(token)
    if not parsed:
        return None
    header, payload, signing_input, sig = parsed
    if header.get("alg") != "HS256":
        return None
    expected = hmac.new(WEAK_SECRET.encode(), signing_input, hashlib.sha256).digest()
    try:
        if hmac.compare_digest(expected, b64url_decode(sig)):
            return payload
    except Exception:
        pass
    return None

def verify_confusion(token):
    """VULN #3: RS256→HS256. Публичный ключ используется как HMAC-секрет."""
    parsed = parse_token(token)
    if not parsed:
        return None
    header, payload, signing_input, sig = parsed
    alg = header.get("alg", "RS256")

    if alg == "RS256":
        try:
            _public_key.verify(
                b64url_decode(sig), signing_input,
                padding.PKCS1v15(), hashes.SHA256()
            )
            return payload
        except Exception:
            return None

    if alg == "HS256":
        expected = hmac.new(PUBLIC_PEM, signing_input, hashlib.sha256).digest()  # <-- confusion
        try:
            if hmac.compare_digest(expected, b64url_decode(sig)):
                return payload
        except Exception:
            pass
    return None

VERIFIERS = {
    "none":      verify_none,
    "weak":      verify_weak,
    "confusion": verify_confusion,
}

SIGNERS = {
    "none":      lambda p: make_token(p, "HS256", NONE_CHALLENGE_SECRET),
    "weak":      lambda p: make_token(p, "HS256", WEAK_SECRET.encode()),
    "confusion": lambda p: make_token(p, "RS256"),
}

# ---------------------------------------------------------------------------
# Роуты
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/challenge/<name>", methods=["GET", "POST"])
def challenge(name):
    if name not in CHALLENGES:
        return "Not found", 404

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        if not username:
            return render_template("login.html", challenge=name, error="Введите имя")

        payload = {"username": username, "role": "user", "challenge": name}
        token = SIGNERS[name](payload)

        resp = make_response(redirect(url_for("dashboard", name=name)))
        resp.set_cookie(f"token_{name}", token, httponly=False, samesite="Lax")
        return resp

    return render_template("login.html", challenge=name)

@app.route("/challenge/<name>/dashboard")
def dashboard(name):
    if name not in CHALLENGES:
        return "Not found", 404
    token = request.cookies.get(f"token_{name}")
    if not token:
        return redirect(url_for("challenge", name=name))

    payload = VERIFIERS[name](token)
    if not payload or payload.get("challenge") != name:
        return render_template("login.html", challenge=name, error="Невалидный токен")

    return render_template("dashboard.html", challenge=name, payload=payload, token=token)

@app.route("/challenge/<name>/admin")
def admin(name):
    if name not in CHALLENGES:
        return "Not found", 404
    token = request.cookies.get(f"token_{name}")
    if not token:
        return render_template("admin.html", challenge=name, payload=None, flag=None, error="Нет токена")

    payload = VERIFIERS[name](token)
    if not payload:
        return render_template("admin.html", challenge=name, payload=None, flag=None, error="Невалидный токен")

    if payload.get("role") != "admin" or payload.get("challenge") != name:
        return render_template("admin.html", challenge=name, payload=payload, flag=None,
                               error="Требуется роль admin")

    return render_template("admin.html", challenge=name, payload=payload,
                           flag=FLAGS[name], error=None)

@app.route("/challenge/confusion/pubkey")
def pubkey():
    return Response(PUBLIC_PEM, mimetype="application/x-pem-file")

@app.route("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
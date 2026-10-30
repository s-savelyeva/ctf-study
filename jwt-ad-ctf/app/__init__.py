"""JWT Attack/Defense CTF сервис.

Содержит три intentional-уязвимых сервиса (каждый на своём порту):

  :8001  "Legacy Gateway"  — уязвимость ``alg: none`` (сервер принимает
          токены без подписи).
  :8002  "Vault API"       — слабый секрет HS256 (словарь), доступен
          брутфорс; флаг выдаёт роль admin.
  :8003  "Secure Portal"   — RS256, публичный ключ опубликован по /public.pem;
          уязвимость подмены алгоритма RS256 -> HS256 (ключ используется как
          HMAC-секрет).

Все три приложения собираются одной фабрикой и имеют общий современный UI.
"""
from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass

from flask import Flask, jsonify, render_template, request

from .jwt_utils import (
    JwtError,
    b64url_encode,
    decode_jwt_unverified,
    encode_jwt_hs256,
    generate_rsa_keypair,
    json_bytes,
    verify_hs256,
    verify_rs256,
)


@dataclass
class User:
    username: str
    password: str
    role: str




def _register_common(app: Flask) -> Flask:
    """Общие эндпоинты для A/D: healthcheck и index по умолчанию."""

    @app.route("/healthz")
    @app.route("/health")
    def healthz():
        return jsonify({"ok": True, "service": app.config["SERVICE"]["name"],
                        "vuln": app.config["SERVICE"]["vuln"]})

    return app

# ---------------------------------------------------------------------------
# Сервис 1: alg:none  (Legacy Gateway)
# ---------------------------------------------------------------------------

def create_alg_none_app(flag: str) -> Flask:
    app = Flask("alg_none_gateway", template_folder=os.path.join(os.path.dirname(__file__), "templates"),
                static_folder=os.path.join(os.path.dirname(__file__), "static"))
    app.config["SECRET_KEY"] = secrets.token_hex(16)
    app.config["SERVICE"] = {
        "id": "alg-none",
        "name": "Legacy Gateway",
        "port": 8001,
        "vuln": "alg: none",
        "description": "Старый шлюз доступа. Библиотека проверки токенов здесь "
                       "доверяет полю alg из заголовка JWT.",
    }

    users = {"guest": User("guest", "guest", "user")}

    @app.route("/")
    def index():
        return render_template("index.html", service=app.config["SERVICE"], state=_state(request))

    @app.route("/api/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        u = users.get(data.get("username", ""))
        if not u or u.password != data.get("password"):
            return jsonify({"ok": False, "error": "Неверный логин или пароль"}), 401
        payload = {"sub": u.username, "role": u.role, "iat": int(time.time())}
        token = encode_jwt_hs256(payload, app.config.setdefault("HS_SECRET", secrets.token_hex(32)))
        return jsonify({"ok": True, "token": token, "role": u.role})

    @app.route("/api/admin")
    def admin():
        token = _bearer()
        if not token:
            return jsonify({"ok": False, "error": "Требуется Authorization: Bearer <token>"}), 401
        try:
            header, payload, signature, signing_input = decode_jwt_unverified(token)
        except JwtError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        # === УЯЗВИМОСТЬ: если alg == "none"/"" — подпись не проверяется вовсе ===
        alg = str(header.get("alg", "")).lower()
        if alg in ("none", ""):
            role = str(payload.get("role", "user"))
            if role != "admin":
                return jsonify({"ok": False, "error": f"Роль '{role}' не имеет доступа"}), 403
            return jsonify({"ok": True, "flag": flag, "role": role,
                            "message": "Доступ разрешён (подпись не проверялась)"})

        # Обычная ветка: гостевой токен проходит, админский без валидной подписи — нет
        secret = app.config.get("HS_SECRET")
        if secret and verify_hs256(signing_input, signature, secret) and payload.get("sub") in users:
            return jsonify({"ok": False,
                            "error": "Флаг доступен только роли admin. Попробуйте подделать токен."}), 403
        return jsonify({"ok": False, "error": "Недействительная подпись токена"}), 401

    return _register_common(app)


# ---------------------------------------------------------------------------
# Сервис 2: слабый секрет / брутфорс  (Vault API)
# ---------------------------------------------------------------------------

WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin", "letmein", "changeme",
    "jwt", "test", "secret123", "flag", "vault", "hunter2", "iloveyou",
    "passw0rd", "default", "root", "toor", "supersecret", "github",
]


def create_bruteforce_app(flag: str) -> Flask:
    app = Flask("bruteforce_vault", template_folder=os.path.join(os.path.dirname(__file__), "templates"),
                static_folder=os.path.join(os.path.dirname(__file__), "static"))
    app.config["SECRET_KEY"] = secrets.token_hex(16)
    # Секрет выбран из короткого «частотного» словаря — это и есть уязвимость.
    # Полный список, используемый атакующими (jwt-cracker / hashcat), лежит в
    # scripts/secret_wordlist.txt; все кандидаты намеренно слабые.
    app.config["HS_SECRET"] = secrets.choice([
        "jwt-secret-key", "administrator", "ctf2026", "s3cr3t",
        "secret", "password", "123456", "qwerty", "admin", "letmein",
        "changeme", "jwt", "test", "secret123", "flag", "vault",
        "hunter2", "iloveyou", "passw0rd", "default", "root", "toor",
        "supersecret", "github", "trustno1", "dragon", "monkey",
    ])
    app.config["SERVICE"] = {
        "id": "bruteforce",
        "name": "Vault API",
        "port": 8002,
        "vuln": "Слабый секрет HS256 (брутфорс)",
        "description": "API хранилища секретов. Токены подписаны HMAC-ключом, "
                       "который админы выбрали из частотного списка паролей.",
    }

    @app.route("/")
    def index():
        return render_template("index.html", service=app.config["SERVICE"], state=_state(request))

    @app.route("/api/token")
    def issue_token():
        """Выдаёт гостевой токен, чтобы у команды был образец для атаки."""
        payload = {"sub": "guest", "role": "user", "iat": int(time.time())}
        token = encode_jwt_hs256(payload, app.config["HS_SECRET"])
        return jsonify({"ok": True, "token": token,
                        "hint": "Подпись — HS256. А что если перебрать секрет?"})

    @app.route("/api/vault")
    def vault():
        token = _bearer()
        if not token:
            return jsonify({"ok": False, "error": "Требуется Authorization: Bearer <token>"}), 401
        try:
            header, payload, signature, signing_input = decode_jwt_unverified(token)
        except JwtError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        if str(header.get("alg", "")).upper() != "HS256":
            return jsonify({"ok": False, "error": "Ожидается алгоритм HS256"}), 400

        # Проверка настоящим секретом
        if verify_hs256(signing_input, signature, app.config["HS_SECRET"]):
            if str(payload.get("role")) == "admin":
                return jsonify({"ok": True, "flag": flag, "role": "admin"})
            return jsonify({"ok": False,
                            "error": "Хранилище закрыто: нужна роль admin (сейчас "
                                     f"'{payload.get('role', 'user')}')"}), 403
        return jsonify({"ok": False, "error": "Недействительная подпись"}), 401

    return _register_common(app)


# ---------------------------------------------------------------------------
# Сервис 3: RS256 -> HS256  (Secure Portal)
# ---------------------------------------------------------------------------

def create_rs256_app(flag: str) -> Flask:
    app = Flask("rs256_portal", template_folder=os.path.join(os.path.dirname(__file__), "templates"),
                static_folder=os.path.join(os.path.dirname(__file__), "static"))
    app.config["SECRET_KEY"] = secrets.token_hex(16)
    private_pem, public_pem = generate_rsa_keypair()
    app.config["RSA_PRIVATE"] = private_pem
    app.config["RSA_PUBLIC"] = public_pem
    app.config["SERVICE"] = {
        "id": "rs256-hs256",
        "name": "Secure Portal",
        "port": 8003,
        "vuln": "Подмена алгоритма RS256 → HS256",
        "description": "Портал с «криптографически стойкой» подписью RS256. Публичный "
                       "ключ открыт всем. Но библиотека сама выбирает способ проверки по alg.",
    }

    @app.route("/")
    def index():
        return render_template("index.html", service=app.config["SERVICE"], state=_state(request))

    @app.route("/public.pem")
    def public_key():
        from flask import Response
        return Response(app.config["RSA_PUBLIC"].decode(), mimetype="text/plain",
                        headers={"Content-Disposition": "attachment; filename=public.pem"})

    @app.route("/api/token")
    def issue_token():
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        key = serialization.load_pem_private_key(app.config["RSA_PRIVATE"], None)
        payload = {"sub": "employee", "role": "user", "iat": int(time.time())}
        hdr = {"alg": "RS256", "typ": "JWT"}
        signing_input = f"{b64url_encode(json_bytes(hdr))}.{b64url_encode(json_bytes(payload))}"
        sig = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        token = f"{signing_input}.{b64url_encode(sig)}"
        return jsonify({"ok": True, "token": token,
                        "hint": "alg=RS256. Публичный ключ лежит на /public.pem 🤔"})

    @app.route("/api/dashboard")
    def dashboard():
        token = _bearer()
        if not token:
            return jsonify({"ok": False, "error": "Требуется Authorization: Bearer <token>"}), 401
        try:
            header, payload, signature, signing_input = decode_jwt_unverified(token)
        except JwtError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        alg = str(header.get("alg", "")).upper()

        # === УЯЗВИМОСТЬ: сервер доверяет alg из заголовка и для HS256
        #     использует публичный RSA-ключ как HMAC-секрет (key confusion) ===
        if alg == "HS256":
            if verify_hs256(signing_input, signature, app.config["RSA_PUBLIC"].decode()):
                if str(payload.get("role")) == "admin":
                    return jsonify({"ok": True, "flag": flag, "role": "admin"})
                return jsonify({"ok": False, "error": "Нужна роль admin"}), 403
            return jsonify({"ok": False, "error": "Недействительная подпись"}), 401

        if alg == "RS256":
            if not verify_rs256(app.config["RSA_PUBLIC"], signing_input, signature):
                return jsonify({"ok": False, "error": "Недействительная подпись RS256"}), 401
            return jsonify({"ok": False,
                            "error": "Токен валиден, но панель администратора требует "
                                     "роль admin. Подпишите новый? 😉"}), 403

        return jsonify({"ok": False, "error": f"Неподдерживаемый алгоритм: {alg or '—'}"}), 400

    return _register_common(app)


# ---------------------------------------------------------------- shared ----

def _bearer() -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.args.get("token")


def _state(req) -> dict:
    return {"origin": req.host_url.rstrip("/")}


SERVICES = [
    ("ALG_NONE_FLAG", 8001, create_alg_none_app, "alg-none"),
    ("BRUTEFORCE_FLAG", 8002, create_bruteforce_app, "bruteforce"),
    ("RS256_FLAG", 8003, create_rs256_app, "rs256-hs256"),
]


def make_app(service_index: int) -> Flask:
    env_name, _port, factory, slug = SERVICES[service_index]
    flag = os.environ.get(env_name) or f"FLAG{{{slug}_{secrets.token_hex(8)}}}"
    return factory(flag)


# Convenience entrypoints (gunicorn app:app / python -m app.<name>)
alg_none_app = make_app(0)
bruteforce_app = make_app(1)
rs256_app = make_app(2)

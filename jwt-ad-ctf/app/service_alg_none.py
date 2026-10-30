"""Точка входа сервиса :8001 (Legacy Gateway, уязвимость alg:none)."""
from app import alg_none_app as app  # noqa: F401  (для gunicorn `app.service_alg_none:app`)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001, debug=False)

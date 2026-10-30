"""Точка входа сервиса :8002 (Vault API, слабый секрет HS256 / брутфорс)."""
from app import bruteforce_app as app  # noqa: F401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8002, debug=False)

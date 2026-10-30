"""Точка входа сервиса :8003 (Secure Portal, подмена RS256 -> HS256)."""
from app import rs256_app as app  # noqa: F401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8003, debug=False)

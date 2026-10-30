"""Запуск всех трёх сервисов одним процессом (для разработки/демо).

    python run_all.py [--host 0.0.0.0]

Продакшен A/D обычно запускает каждый сервис отдельно (gunicorn + systemd),
см. scripts/run_services.sh и Dockerfile.
"""
from __future__ import annotations

import argparse
import threading

from app import make_app


def main() -> None:
    parser = argparse.ArgumentParser(description="JWT AD-CTF: все сервисы сразу")
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    ports = [8001, 8002, 8003]
    threads = []
    for idx, port in enumerate(ports):
        app = make_app(idx)
        t = threading.Thread(
            target=app.run,
            kwargs={"host": args.host, "port": port, "debug": False,
                    "use_reloader": False},
            daemon=True,
        )
        t.start()
        threads.append(t)
        print(f"[+] http://{args.host}:{port} запущен")

    print("[*] Нажмите Ctrl+C для остановки")
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        print("\n[-] Остановка")


if __name__ == "__main__":
    main()

#!/usr/bin/env bash
# Запуск трёх сервисов как отдельных процессов gunicorn (продакшен-вариант для A/D).
set -euo pipefail
cd "$(dirname "$0")/.."

HOST=${HOST:-0.0.0.0}

echo "[*] :8001 Legacy Gateway (alg:none)"
gunicorn --bind "$HOST:8001" --workers 2 --threads 2 \
    --access-logfile - --error-logfile - \
    'app.service_alg_none:app' &
P1=$!

echo "[*] :8002 Vault API (bruteforce HS256)"
gunicorn --bind "$HOST:8002" --workers 2 --threads 2 \
    --access-logfile - --error-logfile - \
    'app.service_bruteforce:app' &
P2=$!

echo "[*] :8003 Secure Portal (RS256->HS256)"
gunicorn --bind "$HOST:8003" --workers 2 --threads 2 \
    --access-logfile - --error-logfile - \
    'app.service_rs256:app' &
P3=$!

trap 'kill $P1 $P2 $P3 2>/dev/null' INT TERM
wait

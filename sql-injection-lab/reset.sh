#!/usr/bin/env bash
# =============================================================
# Перезапуск лабы "с нуля": чистая БД + свежные флаги.
# Использование между раундами A/D:
#   ./reset.sh                       # дефолтные флаги из db/init
#   ./reset.sh flags.txt             # свои флаги (по одному в строке)
# flags.txt может содержать любые SQL-инсерты — они добавятся
# после применения db/init/*.sql к чистой базе.
# =============================================================
set -euo pipefail
cd "$(dirname "$0")"

FLAGS_FILE="${1:-}"

echo "[i] Останавливаю контейнеры и удаляю том с данными MySQL..."
docker compose down -v

echo "[i] Стартую db + web (init-скрипты применятся автоматически)..."
docker compose up -d --build

echo "[i] Жду готовности MySQL..."
for i in $(seq 1 60); do
    if docker compose exec -T db mysqladmin ping -h localhost -uroot -p"${DB_ROOT_PASS:-ctf_root_pass}" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

if [[ -n "$FLAGS_FILE" ]]; then
    echo "[i] Загружаю мои флаги из $FLAGS_FILE..."
    n=1
    while IFS= read -r flag; do
        [[ -z "$flag" ]] && continue
        docker compose exec -T db mysql -uroot -p"${DB_ROOT_PASS:-ctf_root_pass}" ctf_lab \
            -e "REPLACE INTO secrets (id, name, flag, owner, category) VALUES ($n, 'Flag #$n', '$flag', 'team_$( [ $((n%2)) -eq 0 ] && echo blue || echo red )', 'A/D');"
        n=$((n+1))
    done < "$FLAGS_FILE"
    echo "[i] Загружено флагов: $((n-1))"
fi

echo "[i] Проверяю веб-сервис..."
sleep 3
curl -fsS "http://localhost:${WEB_PORT:-8000}/health" && echo " -> OK" || echo " -> веб ещё стартует, проверьте: docker compose logs web"

echo "[✓] Лаба готова: http://localhost:${WEB_PORT:-8000} (порты/пароли — в .env)"

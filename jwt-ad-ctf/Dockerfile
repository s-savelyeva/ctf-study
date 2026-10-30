FROM python:3.12-slim

WORKDIR /srv/jwt-ad-ctf
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY app ./app
COPY run_all.py .

# Флаги задаются через ENV (ALG_NONE_FLAG, BRUTEFORCE_FLAG, RS256_FLAG);
# если не заданы — генерируются случайные при старте.
EXPOSE 8001 8002 8003

# Для A/D лучше запускать каждый сервис отдельным контейнером/юнитом
# (см. scripts/run_services.sh). Здесь — все три в одном процессе.
CMD ["python", "run_all.py", "--host", "0.0.0.0"]

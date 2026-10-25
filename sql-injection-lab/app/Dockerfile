FROM python:3.12-slim

WORKDIR /srv/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

ENV FLASK_APP=app.py \
    APP_PORT=8000

EXPOSE 8000

# Простая команда запуска — участникам легко читать и менять
CMD ["python", "app.py"]

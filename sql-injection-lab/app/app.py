#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import html
import os
import time

from flask import Flask, request, session, render_template_string, redirect, url_for
import mysql.connector
from mysql.connector import Error as MySQLError
from mysql.connector import InterfaceError, OperationalError

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "ctf-insecure-dev-key")

DB_HOST = os.environ.get("DB_HOST", "db")
DB_USER = os.environ.get("DB_USER", "root")
DB_PASS = os.environ.get("DB_PASS", "ctf_root_pass")
DB_NAME = os.environ.get("DB_NAME", "ctf_lab")


def get_db():
    last_error = None
    for attempt in range(8):
        try:
            return mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASS,
                database=DB_NAME,
                charset="utf8mb4",
                collation="utf8mb4_unicode_ci",
                connection_timeout=5,
                autocommit=True,
            )
        except (OperationalError, InterfaceError) as exc:
            last_error = exc
            time.sleep(1 + attempt)
    if last_error is not None:
        raise last_error
    raise RuntimeError("cannot connect to database")


PAGE = """
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }} — Staff Journal</title>
  <style>
    :root {
      --bg: #0b1020;
      --bg-elev: #121a2f;
      --card: rgba(18, 26, 47, 0.86);
      --line: rgba(148, 163, 184, 0.18);
      --text: #e8eefc;
      --muted: #93a0bb;
      --accent: #6ee7c5;
      --accent-2: #8b9cff;
      --danger: #fb7185;
      --ok: #4ade80;
      --warn: #fbbf24;
      --shadow: 0 24px 60px rgba(2, 6, 23, 0.45);
      --radius: 18px;
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; min-height: 100%; }
    body {
      font-family: "Segoe UI", Inter, system-ui, sans-serif;
      color: var(--text);
      background:
        radial-gradient(1200px 500px at 10% -10%, rgba(110, 231, 197, 0.14), transparent 55%),
        radial-gradient(900px 420px at 100% 0%, rgba(139, 156, 255, 0.16), transparent 50%),
        var(--bg);
    }
    .wrap { width: min(960px, calc(100% - 32px)); margin: 32px auto 48px; }
    header {
      display: flex; align-items: flex-start; justify-content: space-between;
      gap: 16px; margin-bottom: 20px;
    }
    .brand { display: flex; gap: 14px; align-items: center; }
    .logo {
      width: 44px; height: 44px; border-radius: 14px;
      display: grid; place-items: center;
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      color: #04231a; font-weight: 800;
      box-shadow: 0 10px 30px rgba(110, 231, 197, 0.25);
    }
    h1 { margin: 0; font-size: 1.35rem; letter-spacing: -0.02em; }
    .sub { margin: 4px 0 0; color: var(--muted); font-size: 0.92rem; }
    nav { display: flex; flex-wrap: wrap; gap: 8px; }
    nav a {
      color: var(--text); text-decoration: none;
      padding: 8px 12px; border-radius: 999px;
      border: 1px solid var(--line); background: rgba(255,255,255,0.03);
    }
    nav a:hover { border-color: rgba(110, 231, 197, 0.45); }
    .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 24px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
    }
    h2 { margin: 0 0 14px; font-size: 1.2rem; }
    p { color: var(--muted); line-height: 1.55; }
    label { display: block; margin: 0 0 6px; color: var(--muted); font-size: 0.86rem; }
    .field { margin-bottom: 14px; }
    input {
      width: 100%; padding: 12px 14px; border-radius: 12px;
      border: 1px solid var(--line); background: #0d1426; color: var(--text);
      outline: none;
    }
    input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(110, 231, 197, 0.15); }
    .row { display: flex; gap: 10px; align-items: center; }
    .row input { flex: 1; }
    button {
      border: 0; cursor: pointer; font-weight: 700;
      padding: 12px 16px; border-radius: 12px;
      background: linear-gradient(135deg, var(--accent), #34d399);
      color: #04231a;
    }
    button:hover { filter: brightness(1.05); }
    table { border-collapse: collapse; width: 100%; margin-top: 16px; }
    th, td { border-bottom: 1px solid var(--line); padding: 10px 12px; text-align: left; }
    th { color: var(--muted); font-size: 0.78rem; letter-spacing: 0.04em; text-transform: uppercase; }
    tr:hover td { background: rgba(255,255,255,0.02); }
    .err { color: var(--danger); }
    .ok { color: var(--ok); }
    .flag { color: var(--warn); font-weight: 700; }
    code, .chip {
      display: inline-block; background: #0d1426; border: 1px solid var(--line);
      padding: 4px 8px; border-radius: 8px; color: var(--accent);
    }
    .hints { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
    .foot { margin-top: 18px; color: #64748b; font-size: 0.8rem; }
    a { color: var(--accent-2); }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div class="brand">
        <div class="logo">SJ</div>
        <div>
          <h1>Журнал сотрудников</h1>
          <p class="sub">CTF Attack/Defense lab · patch it or lose your flags</p>
        </div>
      </div>
      <nav>
        <a href="/">Главная</a>
        {% if session.user %}
          <a href="/users/search">Поиск</a>
          {% if session.is_admin %}<a href="/admin">Админка</a>{% endif %}
          <a href="/logout">Выйти ({{ session.user }})</a>
        {% else %}
          <a href="/login">Вход</a>
        {% endif %}
      </nav>
    </header>
    <section class="card">
      {{ content | safe }}
    </section>
    <p class="foot">vulnerable-by-design · MySQL 8.4 · Flask</p>
  </div>
</body>
</html>
"""


def page(title, content, status=200):
    return render_template_string(PAGE, title=title, content=content), status


def is_logged_in():
    return bool(session.get("user"))


def html_table(headers, rows):
    head = "".join("<th>%s</th>" % html.escape(str(h)) for h in headers)
    body = []
    for row in rows:
        cells = []
        for idx, cell in enumerate(row):
            css = ""
            if idx < len(headers) and headers[idx] == "Flag":
                css = " class='flag'"
            cells.append("<td%s>%s</td>" % (css, html.escape("" if cell is None else str(cell))))
        body.append("<tr>%s</tr>" % "".join(cells))
    return "<table><tr>%s</tr>%s</table>" % (head, "".join(body))


# ------------------------------------------------------------------ #
#  Главная                                                            #
# ------------------------------------------------------------------ #
@app.route("/")
def index():
    if not is_logged_in():
        return redirect(url_for("login"))
    name = session["user"]
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT username, email, is_admin, created_at "
        "FROM users WHERE username LIKE '%%%s%%' LIMIT 1" % name
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    info = ""
    if row:
        info = html_table(
            ["Логин", "Email", "Админ"],
            [(row["username"], row["email"], "да" if row["is_admin"] else "нет")],
        )
    return page(
        "Главная",
        "<h2>Привет, %s!</h2>%s<p><a href='/users/search'>Найти сотрудника</a></p>"
        % (html.escape(str(name)), info),
    )


# ------------------------------------------------------------------ #
#  Вход                                                               #
# ------------------------------------------------------------------ #
LOGIN_FORM = """
<h2>Вход в систему</h2>
<form method="post" action="/login">
  <div class="field">
    <label for="username">Логин</label>
    <input id="username" name="username" autocomplete="username" placeholder="например, alice">
  </div>
  <div class="field">
    <label for="password">Пароль</label>
    <input id="password" name="password" type="password" autocomplete="current-password" placeholder="например, alice123">
  </div>
  <button type="submit">Войти</button>
</form>
<p class="err">__ERROR__</p>
<div class="hints">
  <span class="chip">Креды для входа:</span>
  <span class="chip">alice / alice123</span>
  <span class="chip">bob / bob123</span>
</div>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        query = ("SELECT * FROM users WHERE username = '" + username +
                 "' AND password = MD5(CONCAT('" + password + "', salt))")
        try:
            conn = get_db()
            cur = conn.cursor(dictionary=True)
            cur.execute(query)
            user = cur.fetchone()
            cur.close()
            conn.close()
            if user:
                session["user"] = user["username"]
                session["is_admin"] = bool(user["is_admin"])
                return redirect(url_for("index"))
            error = "Неверный логин или пароль."
        except MySQLError as e:
            # Специально показываем ошибку БД — подсказка для атакующих
            error = "Ошибка БД: %s" % e
    return page("Вход", LOGIN_FORM.replace("__ERROR__", html.escape(error)))


# ------------------------------------------------------------------ #
#  Поиск сотрудников                                                  #
# ------------------------------------------------------------------ #
SEARCH_FORM = """
<h2>Поиск сотрудников</h2>
<form method="get" action="/users/search" class="row">
  <input name="q" value="__Q__" placeholder="имя или часть имени">
  <button type="submit">Искать</button>
</form>
__RESULT__
"""


@app.route("/users/search")
def search():
    if not is_logged_in():
        return redirect(url_for("login"))
    q = request.args.get("q", "")
    result_html = ""
    if q:
        query = "SELECT id, username, email, is_admin FROM users WHERE username LIKE '%%%s%%'" % q
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(query)
            rows = cur.fetchall()
            cur.close()
            conn.close()
            if rows:
                result_html = html_table(["ID", "Логин", "Email", "Админ"], rows)
            else:
                result_html = "<p class='ok'>Никого не нашлось.</p>"
        except MySQLError as e:
            result_html = "<p class='err'>Ошибка SQL: %s</p>" % html.escape(str(e))
    return page(
        "Поиск",
        SEARCH_FORM.replace("__Q__", html.escape(q, quote=True)).replace("__RESULT__", result_html),
    )


# ------------------------------------------------------------------ #
#  Админка (здесь живут флаги)                                        #
# ------------------------------------------------------------------ #
@app.route("/admin")
def admin():
    if not is_logged_in():
        return redirect(url_for("login"))
    if not session.get("is_admin"):
        return page("Отказано", "<h2 class='err'>Доступ запрещён. Нужны права администратора.</h2>", 403)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name, flag, owner FROM secrets")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return page(
        "Админка",
        "<h2>Секретные записи</h2>" + html_table(["Название", "Flag", "Владелец"], rows),
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/health")
def health():
    try:
        conn = get_db()
        conn.close()
        return "OK", 200
    except MySQLError:
        return "DB DOWN", 503


if __name__ == "__main__":
    # debug=off, чтобы участники не могли RCE через werkzeug console
    app.run(host="0.0.0.0", port=int(os.environ.get("APP_PORT", 8000)))

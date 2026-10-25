#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTF A/D учебная лаба: сервис "Журнал сотрудников" с SQL-инъекцией.

УЯЗВИМОСТИ (намеренные, задача защиты — их найти и запатчить):
  1. /login        — конкатенация user/password прямо в SQL (классика).
  2. /users/search — UNION-based инъекция в параметре ?q=.
  3. /               — имя пользователя из сессии попадает в LIKE '%...%' напрямую.
  4. Приложение подключается к MySQL пользователем root (лишние привилегии).

ФЛАГ лежит в таблице secrets и виден только администратору на /admin.
"""

import os

from flask import Flask, request, session, render_template_string, redirect, url_for
import mysql.connector
from mysql.connector import Error as MySQLError

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "ctf-insecure-dev-key")

DB_HOST = os.environ.get("DB_HOST", "db")
DB_USER = os.environ.get("DB_USER", "root")
DB_PASS = os.environ.get("DB_PASS", "ctf_root_pass")
DB_NAME = os.environ.get("DB_NAME", "ctf_lab")


def get_db():
    return mysql.connector.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME
    )


# ------------------------------------------------------------------ #
#  HTML-шаблон (всё в одной строке ради простоты раздачи)             #
# ------------------------------------------------------------------ #
PAGE = """
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>{{ title }} — CTF Staff Journal</title>
  <style>
    body { font-family: Arial, sans-serif; background: #1e1e2e; color: #ddd; margin: 2rem auto; max-width: 760px; }
    h1, h2 { color: #f5c2e7; }
    a, .link { color: #89b4fa; }
    nav a { margin-right: 1rem; }
    input, button { padding: .4rem; margin: .2rem 0; border-radius: 4px; border: 1px solid #555; background: #313244; color: #eee; }
    table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
    th, td { border: 1px solid #45475a; padding: .5rem; text-align: left; }
    th { background: #313244; }
    .err { color: #f38ba8; }
    .ok  { color: #a6e3a1; }
    .flag { color: #f9e2af; font-weight: bold; }
    code { background: #313244; padding: 2px 6px; border-radius: 4px; }
    .box { background: #181825; border: 1px solid #45475a; border-radius: 8px; padding: 1rem; margin-top: 1rem; }
  </style>
</head>
<body>
  <h1>🗂 Журнал сотрудников <small style="font-size:.5em">(CTF A/D lab)</small></h1>
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
  <div class="box">
  {% block_content %}
  {{ content | safe }}
  {% endblock %}
  </div>
  <p style="color:#666;font-size:.8em">vulnerable-by-design · patch it or lose your flags</p>
</body>
</html>
"""


def page(title, content):
    return render_template_string(PAGE.replace("{% block_content %}", "")
                                  .replace("{% endblock %}", ""),
                                  title=title, content=content)


def is_logged_in():
    return bool(session.get("user"))


# ------------------------------------------------------------------ #
#  Главная                                                            #
# ------------------------------------------------------------------ #
@app.route("/")
def index():
    if not is_logged_in():
        return redirect(url_for("login"))
    name = session["user"]
    # !!! УЯЗВИМОСТЬ №3: name подставляется в запрос напрямую !!!
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT username, email, is_admin, created_at "
        "FROM users WHERE username LIKE '%%%s%%' LIMIT 1" % name
    )
    row = cur.fetchone()
    cur.close(); conn.close()

    info = ""
    if row:
        info = ("<table><tr><th>Логин</th><th>Email</th><th>Админ</th></tr>"
                "<tr><td>%s</td><td>%s</td><td>%s</td></tr></table>"
                % (row["username"], row["email"], "да" if row["is_admin"] else "нет"))
    return page("Главная",
                "<h2>Привет, %s!</h2>%s<p><a href='/users/search'>Найти сотрудника</a></p>"
                % (name, info))


# ------------------------------------------------------------------ #
#  Вход                                                               #
# ------------------------------------------------------------------ #
LOGIN_FORM = """
<h2>Вход в систему</h2>
<form method="post" action="/login">
  <div>Логин: <input name="username" placeholder="например, alice"></div>
  <div>Пароль: <input name="password" type="password" placeholder="например, alice123"></div>
  <button type="submit">Войти</button>
</form>
<p class="err">%s</p>
<p><code>admin / admin123</code>, <code>alice / alice123</code>, <code>bob / bob123</code></p>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # !!! УЯЗВИМОСТЬ №1: знаменитая строка ниже — SQL-инъекция !!!
        query = ("SELECT * FROM users WHERE username = '" + username +
                 "' AND password = MD5(CONCAT('" + password + "', salt))")
        try:
            conn = get_db()
            cur = conn.cursor(dictionary=True)
            cur.execute(query)
            user = cur.fetchone()
            cur.close(); conn.close()
            if user:
                session["user"] = user["username"]
                session["is_admin"] = bool(user["is_admin"])
                return redirect(url_for("index"))
            error = "Неверный логин или пароль."
        except MySQLError as e:
            # Специально показываем ошибку БД — подсказка для атакующих
            error = "Ошибка БД: %s" % e
    return page("Вход", LOGIN_FORM % error)


# ------------------------------------------------------------------ #
#  Поиск сотрудников                                                  #
# ------------------------------------------------------------------ #
SEARCH_FORM = """
<h2>Поиск сотрудников</h2>
<form method="get" action="/users/search">
  <input name="q" value="%s" placeholder="имя или часть имени">
  <button type="submit">Искать</button>
</form>
%s
"""


@app.route("/users/search")
def search():
    if not is_logged_in():
        return redirect(url_for("login"))
    q = request.args.get("q", "")
    result_html = ""
    if q:
        # !!! УЯЗВИМОСТЬ №2: q идёт прямо в SQL, видны все колонки !!!
        query = "SELECT id, username, email, is_admin FROM users WHERE username LIKE '%%%s%%'" % q
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(query)
            rows = cur.fetchall()
            cur.close(); conn.close()
            if rows:
                body = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % r for r in rows)
                result_html = ("<table><tr><th>ID</th><th>Логин</th><th>Email</th><th>Админ</th></tr>"
                               + body + "</table>")
            else:
                result_html = "<p class='ok'>Никого не нашлось.</p>"
        except MySQLError as e:
            result_html = "<p class='err'>Ошибка SQL: %s</p>" % e
    return page("Поиск", SEARCH_FORM % (q, result_html))


# ------------------------------------------------------------------ #
#  Админка (здесь живут флаги)                                        #
# ------------------------------------------------------------------ #
@app.route("/admin")
def admin():
    if not is_logged_in():
        return redirect(url_for("login"))
    if not session.get("is_admin"):
        return page("Отказано", "<h2 class='err'>Доступ запрещён. Нужны права администратора.</h2>"), 403

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name, flag, owner FROM secrets")
    rows = cur.fetchall()
    cur.close(); conn.close()
    table = "".join("<tr><td>%s</td><td class='flag'>%s</td><td>%s</td></tr>" % r for r in rows)
    return page("Админка",
                "<h2>🚩 Секретные записи</h2>"
                "<table><tr><th>Название</th><th>Flag</th><th>Владелец</th></tr>%s</table>" % table)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------ #
#  Healthcheck для docker-compose                                     #
# ------------------------------------------------------------------ #
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

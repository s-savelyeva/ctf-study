-- ============================================================
-- Структура базы данных для лабы "SQL Injection" (Attack/Defense)
-- СУБД: MySQL 8.0 (совместимо с MariaDB)
-- Исполняется автоматически при первом старте контейнера mysql
-- (каталог db/init монтируется в /docker-entrypoint-initdb.d).
-- ============================================================

CREATE DATABASE IF NOT EXISTS ctf_lab
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE ctf_lab;

-- ------------------------------------------------------------
-- Таблица пользователей (обычные участники игры, без флага)
-- ------------------------------------------------------------
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    username   VARCHAR(50)  NOT NULL UNIQUE,
    password   VARCHAR(255) NOT NULL,           -- md5(password + salt)
    salt       VARCHAR(32)  NOT NULL,
    email      VARCHAR(100),
    is_admin   TINYINT(1)   NOT NULL DEFAULT 0,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE = InnoDB;

-- ------------------------------------------------------------
-- Таблица секретов (FLAG'и). Именно её защищают/атакуют.
-- Перед началом игры замените флаги на актуальные, либо
-- подмените этот init-скрипт своим (см. README.md).
-- ------------------------------------------------------------
DROP TABLE IF EXISTS secrets;
CREATE TABLE secrets (
    id        INT AUTO_INCREMENT PRIMARY KEY,
    name      VARCHAR(100) NOT NULL,
    flag      VARCHAR(255) NOT NULL,
    owner     VARCHAR(50)  NOT NULL,
    category  VARCHAR(50)  NOT NULL DEFAULT 'A/D'
) ENGINE = InnoDB;

-- ------------------------------------------------------------
-- Пользователи (пароль хранится как md5(password + salt)):
--   admin / admin123
--   alice / alice123
--   bob   / bob123
-- ------------------------------------------------------------
INSERT INTO users (username, password, salt, email, is_admin) VALUES
('admin', MD5(CONCAT('admin123', 'a1b2c3d4e5f6')), 'a1b2c3d4e5f6', 'admin@ctf.local', 1),
('alice', MD5(CONCAT('alice123', 'z9y8x7w6v5u4')), 'z9y8x7w6v5u4', 'alice@ctf.local', 0),
('bob',   MD5(CONCAT('bob123',   'm1n2o3p4q5r6')), 'm1n2o3p4q5r6', 'bob@ctf.local',   0);

-- ------------------------------------------------------------
-- Флаги (примеры для тренировки, замените своими)
-- ------------------------------------------------------------
INSERT INTO secrets (name, flag, owner, category) VALUES
('Main flag',            'FLAG{sql_inj_m4in_fl4g_2026}',  'team_red',  'A/D'),
('Backup flag',          'FLAG{b4ckup_fl4g_d0_n0t_l34k}', 'team_red',  'A/D'),
('Admin dashboard flag', 'FLAG{adm1n_p4n3l_fl4g_x7}',     'team_blue', 'A/D');

-- ------------------------------------------------------------
-- Пользователь БД только для чтения. Приложением НЕ используется
-- намеренно (приложение подключается как root) — это одна из
-- уязвимостей. Защитники могут переключить приложение на него
-- как часть патча (см. README.md, раздел "Варианты защиты").
-- ------------------------------------------------------------
CREATE USER IF NOT EXISTS 'ctf_readonly'@'%' IDENTIFIED BY 'readonly_pass_123';
GRANT SELECT ON ctf_lab.* TO 'ctf_readonly'@'%';
FLUSH PRIVILEGES;

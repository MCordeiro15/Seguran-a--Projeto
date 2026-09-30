CREATE DATABASE IF NOT EXISTS seguranca_web
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE seguranca_web;


CREATE TABLE IF NOT EXISTS utilizadores (
    id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username       VARCHAR(30)  NOT NULL,
    email          VARCHAR(254) NOT NULL,
    password_hash  VARCHAR(255) NOT NULL,
    criado_em      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ultimo_login   DATETIME     NULL,
    UNIQUE KEY uq_username (username),
    UNIQUE KEY uq_email (email)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS tentativas (
    id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    tipo           ENUM('login', 'registo') NOT NULL,
    ip             VARBINARY(16) NOT NULL,
    identificador  VARCHAR(254)  NOT NULL,
    sucesso        TINYINT(1)    NOT NULL,
    criado_em      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_ip (tipo, ip, criado_em),
    KEY idx_identificador (tipo, identificador, criado_em)
) ENGINE=InnoDB;

CREATE USER IF NOT EXISTS 'segweb_app'@'localhost' IDENTIFIED BY 'Mudar_Esta_Pass_2026!';
GRANT SELECT, INSERT, UPDATE, DELETE ON seguranca_web.* TO 'segweb_app'@'localhost';
FLUSH PRIVILEGES;

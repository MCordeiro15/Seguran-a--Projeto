# Projeto Segurança Web — Registo e Login seguros

Aplicação em PHP + HTML + CSS + MySQL com uma página de registo e uma de login,
protegidas contra os ataques mais comuns.

## Requisitos

- PHP 8.1 ou superior (com `pdo_mysql`)
- MySQL 8 ou MariaDB

## Instalação

1. **Criar a base de dados** (na pasta do projeto):

   ```bash
   mysql -u root -p < database/schema.sql
   ```

   Isto cria a base `seguranca_web`, as tabelas `utilizadores` e `tentativas`,
   e o utilizador MySQL `segweb_app` com privilégios mínimos.

2. **Credenciais**: se alterares a palavra-passe do utilizador `segweb_app`
   no `schema.sql`, altera-a também em `config/config.php`
   (ou define as variáveis de ambiente `DB_HOST`, `DB_USER`, `DB_PASS`...).

3. **Arrancar o servidor** (a pasta `public/` é a única exposta ao browser):

   ```bash
   php -S localhost:8000 -t public
   ```

   Abrir <http://localhost:8000>.

   Com XAMPP/MAMP pode-se colocar a pasta inteira no `htdocs`: o `.htaccess`
   da raiz bloqueia `config/`, `includes/` e `database/`.

## Estrutura

```
Projeto/
├── database/schema.sql     → tabelas e utilizador MySQL
├── config/config.php       → credenciais e limites
├── includes/
│   ├── bootstrap.php       → carregado por todas as páginas
│   ├── db.php              → ligação PDO
│   ├── security.php        → funções de segurança
│   └── layout.php          → HTML comum
└── public/
    ├── register.php        → registo
    ├── login.php           → login
    ├── dashboard.php       → área protegida
    ├── logout.php
    ├── index.php
    └── css/style.css
```

## Proteções implementadas

| Ataque | Proteção |
|---|---|
| SQL Injection | PDO com prepared statements reais (`EMULATE_PREPARES = false`) |
| XSS | Escape de todo o output com `htmlspecialchars`; CSP estrita sem JavaScript |
| CSRF | Token por sessão, verificação de `Origin`/`Sec-Fetch-Site`, cookie `SameSite=Strict` |
| Roubo de palavras-passe | Hash Argon2id (fallback bcrypt), rehash automático |
| Palavras-passe fracas | Mín. 12 caracteres, maiúsculas, minúsculas, números, símbolos, lista de comuns |
| Força bruta | Limite de falhas por IP e por conta (tabela `tentativas`) |
| Enumeração de utilizadores | Mensagem genérica e tempo de resposta constante |
| Session hijacking / fixation | `session_regenerate_id`, cookies `HttpOnly`/`Secure`, strict mode, timeouts, ligação ao User-Agent |
| Clickjacking | `X-Frame-Options: DENY` e `frame-ancestors 'none'` |
| Bots | Honeypot e tempo mínimo de preenchimento |
| Fuga de informação | Erros nunca mostrados ao utilizador; config fora da pasta pública |
| Privilégios excessivos na BD | Utilizador MySQL só com `SELECT, INSERT, UPDATE, DELETE` |

<?php
declare(strict_types=1);

// Credenciais lidas de variáveis de ambiente (preferível) com valores por omissão
// para desenvolvimento local. Esta pasta NÃO deve estar acessível pelo browser.
define('DB_HOST', getenv('DB_HOST') ?: '127.0.0.1');
define('DB_PORT', (int) (getenv('DB_PORT') ?: 3306));
define('DB_NAME', getenv('DB_NAME') ?: 'seguranca_web');
define('DB_USER', getenv('DB_USER') ?: 'segweb_app');
define('DB_PASS', getenv('DB_PASS') ?: 'Mudar_Esta_Pass_2026!');

// Sessão
const SESSAO_INATIVIDADE = 900;    // 15 minutos sem atividade => logout
const SESSAO_MAXIMA      = 28800;  // 8 horas no máximo, mesmo com atividade
const SESSAO_REGENERAR   = 300;    // novo ID de sessão a cada 5 minutos

// Limites contra força bruta
const LOGIN_JANELA          = 900; // 15 minutos
const LOGIN_MAX_FALHAS_IP   = 10;
const LOGIN_MAX_FALHAS_CONTA = 5;
const REGISTO_JANELA        = 3600; // 1 hora
const REGISTO_MAX_IP        = 5;

// Tempo mínimo (segundos) entre mostrar e submeter um formulário (anti-bot)
const FORMULARIO_TEMPO_MIN = 2;

// Hash de palavras-passe: Argon2id se disponível, senão bcrypt
define('PASSWORD_ALGO', defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT);
define('PASSWORD_OPCOES', PASSWORD_ALGO === PASSWORD_BCRYPT
    ? ['cost' => 12]
    : ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1]);

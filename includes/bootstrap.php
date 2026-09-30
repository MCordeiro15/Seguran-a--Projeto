<?php
declare(strict_types=1);

// Nunca mostrar erros ao utilizador (revelam caminhos, SQL, versões...). Apenas registar.
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('expose_php', '0');
error_reporting(E_ALL);

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/layout.php';

set_exception_handler(static function (Throwable $ex): void {
    error_log('[SegWeb] ' . $ex);
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: text/html; charset=UTF-8');
    }
    echo '<!DOCTYPE html><html lang="pt"><head><meta charset="UTF-8"><title>Erro</title></head>'
        . '<body><h1>Ocorreu um erro interno.</h1><p>Tente novamente mais tarde.</p></body></html>';
});

// Apenas GET e POST são aceites.
$metodo = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (!in_array($metodo, ['GET', 'POST'], true)) {
    http_response_code(405);
    header('Allow: GET, POST');
    exit;
}

header('Content-Type: text/html; charset=UTF-8');
enviar_cabecalhos_seguranca();
iniciar_sessao();

<?php
declare(strict_types=1);

// =====================================================================
//  Utilitários gerais
// =====================================================================

/** Escapa texto para HTML (proteção contra XSS). Usar SEMPRE ao imprimir dados. */
function e(string $texto): string
{
    return htmlspecialchars($texto, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
}

/** Lê um campo POST garantindo que é string (evita arrays injetados: campo[]=x). */
function post(string $campo): string
{
    $valor = $_POST[$campo] ?? '';
    return is_string($valor) ? $valor : '';
}

function redirecionar(string $destino): never
{
    header('Location: ' . $destino, true, 303);
    exit;
}

function is_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;
}

/** Usa apenas REMOTE_ADDR: cabeçalhos como X-Forwarded-For podem ser forjados. */
function ip_cliente(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

// =====================================================================
//  Cabeçalhos HTTP de segurança
// =====================================================================

function enviar_cabecalhos_seguranca(): void
{
    header_remove('X-Powered-By');

    // Sem JavaScript, sem recursos externos, sem inline styles, sem iframes.
    header("Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; "
        . "form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    header('X-Frame-Options: DENY');                       // clickjacking (browsers antigos)
    header('X-Content-Type-Options: nosniff');             // MIME sniffing
    header('Referrer-Policy: same-origin');                // Referer nunca é enviado para outros sites
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

    if (is_https()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

// =====================================================================
//  Sessão
// =====================================================================

function iniciar_sessao(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_strict_mode', '1');   // rejeita IDs de sessão não gerados pelo servidor (fixation)
    ini_set('session.use_only_cookies', '1');  // nunca aceitar o ID pela URL
    ini_set('session.use_trans_sid', '0');
    ini_set('session.cookie_httponly', '1');

    $https = is_https();
    // O prefixo __Host- obriga o browser a exigir Secure, Path=/ e sem Domain.
    session_name($https ? '__Host-SEGWEB' : 'SEGWEB');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $https,
        'httponly' => true,       // inacessível a JavaScript
        'samesite' => 'Strict',   // não é enviado em pedidos cross-site (CSRF)
    ]);

    session_start();
}

function impressao_digital(): string
{
    return hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
}

function autenticar_sessao(int $idUtilizador, string $username): void
{
    // Novo ID de sessão após login => impede session fixation.
    session_regenerate_id(true);

    $agora = time();
    $_SESSION = [
        'uid'              => $idUtilizador,
        'username'         => $username,
        'inicio'           => $agora,
        'ultima_atividade' => $agora,
        'regenerado'       => $agora,
        'impressao'        => impressao_digital(),
        'csrf'             => bin2hex(random_bytes(32)),
    ];
}

function terminar_sessao(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires'  => time() - 42000,
            'path'     => $p['path'],
            'domain'   => $p['domain'],
            'secure'   => $p['secure'],
            'httponly' => $p['httponly'],
            'samesite' => $p['samesite'],
        ]);
    }

    session_destroy();
}

function utilizador_autenticado(): bool
{
    if (empty($_SESSION['uid'])) {
        return false;
    }

    $agora = time();
    $valida = ($agora - (int) ($_SESSION['ultima_atividade'] ?? 0)) <= SESSAO_INATIVIDADE
        && ($agora - (int) ($_SESSION['inicio'] ?? 0)) <= SESSAO_MAXIMA
        && hash_equals((string) ($_SESSION['impressao'] ?? ''), impressao_digital());

    if (!$valida) {
        terminar_sessao();
        iniciar_sessao();
        return false;
    }

    $_SESSION['ultima_atividade'] = $agora;

    if ($agora - (int) $_SESSION['regenerado'] > SESSAO_REGENERAR) {
        session_regenerate_id(true);
        $_SESSION['regenerado'] = $agora;
    }

    return true;
}

function exigir_login(): void
{
    if (!utilizador_autenticado()) {
        flash_definir('erro', 'Precisa de iniciar sessão para aceder a essa página.');
        redirecionar('login.php');
    }
}

// =====================================================================
//  Mensagens "flash" (sobrevivem a um redirecionamento)
// =====================================================================

function flash_definir(string $tipo, string $mensagem): void
{
    $_SESSION['flash'] = ['tipo' => $tipo, 'mensagem' => $mensagem];
}

function flash_obter(): ?array
{
    $flash = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    return $flash;
}

// =====================================================================
//  CSRF + verificação de origem
// =====================================================================

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_campo(): string
{
    return '<input type="hidden" name="csrf" value="' . e(csrf_token()) . '">';
}

/** Rejeita pedidos vindos de outros sites (defesa em profundidade além do token). */
function origem_valida(): bool
{
    $site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? null;
    if ($site !== null && !in_array($site, ['same-origin', 'none'], true)) {
        return false;
    }

    $origem = $_SERVER['HTTP_ORIGIN'] ?? null;
    if ($origem === null) {
        return true;
    }

    $partes = parse_url($origem);
    if (!is_array($partes) || empty($partes['host'])) {
        return false;
    }
    $hostOrigem = $partes['host'] . (isset($partes['port']) ? ':' . $partes['port'] : '');

    return hash_equals(strtolower($_SERVER['HTTP_HOST'] ?? ''), strtolower($hostOrigem));
}

function pedido_valido(): bool
{
    $token = post('csrf');
    return origem_valida()
        && isset($_SESSION['csrf'])
        && $token !== ''
        && hash_equals($_SESSION['csrf'], $token);
}

// =====================================================================
//  Anti-bot: honeypot + tempo mínimo de preenchimento
// =====================================================================

function marcar_formulario(string $nome): void
{
    $_SESSION['formularios'][$nome] = time();
}

function formulario_humano(string $nome): bool
{
    $inicio = $_SESSION['formularios'][$nome] ?? null;
    return post('website') === ''   // campo escondido que só os bots preenchem
        && is_int($inicio)
        && (time() - $inicio) >= FORMULARIO_TEMPO_MIN;
}

// =====================================================================
//  Limitação de tentativas (força bruta / credential stuffing)
// =====================================================================

function registar_tentativa(string $tipo, string $identificador, bool $sucesso): void
{
    $st = db()->prepare('INSERT INTO tentativas (tipo, ip, identificador, sucesso) VALUES (?, ?, ?, ?)');
    $st->execute([$tipo, inet_pton(ip_cliente()), mb_substr($identificador, 0, 254), (int) $sucesso]);

    // Limpeza ocasional de registos antigos
    if (random_int(1, 100) === 1) {
        db()->exec('DELETE FROM tentativas WHERE criado_em < (NOW() - INTERVAL 1 DAY)');
    }
}

/**
 * Devolve true se o IP ou o identificador (conta) excederam o limite na janela.
 * Com $soFalhas = false contam-se todas as tentativas (útil para o registo).
 */
function limite_excedido(string $tipo, string $identificador, int $maxIp, int $maxConta, int $janela, bool $soFalhas = true): bool
{
    $ip = inet_pton(ip_cliente());
    $filtroSucesso = $soFalhas ? 'AND sucesso = 0' : '';

    $st = db()->prepare(
        "SELECT COALESCE(SUM(ip = ?), 0) AS por_ip,
                COALESCE(SUM(identificador = ?), 0) AS por_conta
           FROM tentativas
          WHERE tipo = ? $filtroSucesso
            AND criado_em > (NOW() - INTERVAL ? SECOND)
            AND (ip = ? OR identificador = ?)"
    );
    $st->execute([$ip, $identificador, $tipo, $janela, $ip, $identificador]);
    $r = $st->fetch();

    return (int) $r['por_ip'] >= $maxIp
        || ($maxConta > 0 && $identificador !== '' && (int) $r['por_conta'] >= $maxConta);
}

// =====================================================================
//  Validação do registo
// =====================================================================

const PASSWORDS_COMUNS = [
    'password', 'password123', 'password1234', '123456789012', 'qwertyuiop12', 'qwerty123456',
    'iloveyou1234', 'admin1234567', 'welcome12345', 'letmein12345', 'palavrapasse', 'benfica12345',
    'portugal1234', 'sporting1234', 'fcporto12345', 'abc123456789', '111111111111', '000000000000',
];

/** @return string[] lista de erros (vazia se válido) */
function validar_registo(string $username, string $email, string $password, string $confirmacao): array
{
    $erros = [];

    if (!preg_match('/^[A-Za-z0-9_]{3,30}$/D', $username)) {
        $erros[] = 'O nome de utilizador deve ter 3 a 30 caracteres (letras, números ou _).';
    }

    if (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        $erros[] = 'Introduza um endereço de email válido.';
    }

    $tamanho = mb_strlen($password, 'UTF-8');
    if ($tamanho < 12 || $tamanho > 128) {
        $erros[] = 'A palavra-passe deve ter entre 12 e 128 caracteres.';
    } elseif (PASSWORD_ALGO === PASSWORD_BCRYPT && strlen($password) > 72) {
        $erros[] = 'A palavra-passe não pode exceder 72 bytes.';
    }

    if (!preg_match('/\p{Ll}/u', $password) || !preg_match('/\p{Lu}/u', $password)
        || !preg_match('/\d/', $password) || !preg_match('/[^\p{L}\d]/u', $password)) {
        $erros[] = 'A palavra-passe deve conter maiúsculas, minúsculas, números e símbolos.';
    }

    $minuscula = mb_strtolower($password, 'UTF-8');
    if (in_array($minuscula, PASSWORDS_COMUNS, true)) {
        $erros[] = 'Essa palavra-passe é demasiado comum.';
    }

    if ($username !== '' && str_contains($minuscula, mb_strtolower($username, 'UTF-8'))) {
        $erros[] = 'A palavra-passe não pode conter o nome de utilizador.';
    }

    if (!hash_equals($password, $confirmacao)) {
        $erros[] = 'As palavras-passe não coincidem.';
    }

    return $erros;
}

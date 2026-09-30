<?php
declare(strict_types=1);

require __DIR__ . '/../includes/bootstrap.php';

if (utilizador_autenticado()) {
    redirecionar('dashboard.php');
}

$erros = [];
$identificador = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $identificador = mb_strtolower(trim(post('identificador')), 'UTF-8');
    $password = post('password');

    if (!pedido_valido()) {
        $erros[] = 'Pedido inválido ou expirado. Tente novamente.';
    } elseif (!formulario_humano('login')) {
        $erros[] = 'Pedido rejeitado. Aguarde uns segundos e tente novamente.';
    } elseif ($identificador === '' || $password === '' || mb_strlen($identificador) > 254 || mb_strlen($password) > 128) {
        $erros[] = 'Credenciais inválidas.';
    } elseif (limite_excedido('login', $identificador, LOGIN_MAX_FALHAS_IP, LOGIN_MAX_FALHAS_CONTA, LOGIN_JANELA)) {
        $erros[] = 'Demasiadas tentativas falhadas. Aguarde 15 minutos e tente novamente.';
    } else {
        $st = db()->prepare('SELECT id, username, password_hash, ultimo_login FROM utilizadores WHERE username = ? OR email = ? LIMIT 1');
        $st->execute([$identificador, $identificador]);
        $utilizador = $st->fetch();

        if ($utilizador === false) {
            // Gasta o mesmo tempo que uma verificação real, para não revelar
            // pela latência se a conta existe (timing attack / enumeração).
            password_hash($password, PASSWORD_ALGO, PASSWORD_OPCOES);
            $valido = false;
        } else {
            $valido = password_verify($password, $utilizador['password_hash']);
        }

        registar_tentativa('login', $identificador, $valido);

        if ($valido) {
            $id = (int) $utilizador['id'];

            // Atualiza o hash se o algoritmo/custo tiver mudado desde o registo.
            if (password_needs_rehash($utilizador['password_hash'], PASSWORD_ALGO, PASSWORD_OPCOES)) {
                db()->prepare('UPDATE utilizadores SET password_hash = ? WHERE id = ?')
                    ->execute([password_hash($password, PASSWORD_ALGO, PASSWORD_OPCOES), $id]);
            }

            db()->prepare('UPDATE utilizadores SET ultimo_login = NOW() WHERE id = ?')->execute([$id]);
            db()->prepare("DELETE FROM tentativas WHERE tipo = 'login' AND identificador = ? AND sucesso = 0")
                ->execute([$identificador]);

            autenticar_sessao($id, $utilizador['username']);
            $_SESSION['login_anterior'] = $utilizador['ultimo_login'];

            redirecionar('dashboard.php');
        }

        // Mensagem única: não distingue "utilizador inexistente" de "palavra-passe errada".
        $erros[] = 'Credenciais inválidas.';
    }
}

marcar_formulario('login');
layout_inicio('Login');
?>
<h1>Iniciar sessão</h1>
<p class="subtitulo">Entre com o seu nome de utilizador ou email.</p>

<?php mostrar_erros($erros); ?>

<form method="post" action="login.php" novalidate>
    <?= csrf_campo() ?>

    <div class="honeypot" aria-hidden="true">
        <label for="website">Website</label>
        <input type="text" id="website" name="website" tabindex="-1" autocomplete="off">
    </div>

    <label for="identificador">Utilizador ou email</label>
    <input type="text" id="identificador" name="identificador" value="<?= e($identificador) ?>"
           required maxlength="254" autocomplete="username">

    <label for="password">Palavra-passe</label>
    <input type="password" id="password" name="password"
           required maxlength="128" autocomplete="current-password">

    <button type="submit">Entrar</button>
</form>

<p class="rodape">Ainda não tem conta? <a href="register.php">Registar</a></p>
<?php layout_fim();

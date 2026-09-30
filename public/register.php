<?php
declare(strict_types=1);

require __DIR__ . '/../includes/bootstrap.php';

if (utilizador_autenticado()) {
    redirecionar('dashboard.php');
}

$erros = [];
$username = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim(post('username'));
    $email = mb_strtolower(trim(post('email')), 'UTF-8');
    $password = post('password');
    $confirmacao = post('password_confirmacao');

    if (!pedido_valido()) {
        $erros[] = 'Pedido inválido ou expirado. Tente novamente.';
    } elseif (!formulario_humano('registo')) {
        $erros[] = 'Pedido rejeitado. Aguarde uns segundos e tente novamente.';
    } elseif (limite_excedido('registo', '', REGISTO_MAX_IP, 0, REGISTO_JANELA, false)) {
        $erros[] = 'Foram feitos demasiados registos a partir deste endereço. Tente mais tarde.';
    } else {
        $erros = validar_registo($username, $email, $password, $confirmacao);

        if (!$erros) {
            try {
                $st = db()->prepare('INSERT INTO utilizadores (username, email, password_hash) VALUES (?, ?, ?)');
                $st->execute([$username, $email, password_hash($password, PASSWORD_ALGO, PASSWORD_OPCOES)]);
            } catch (PDOException $ex) {
                if ($ex->getCode() !== '23000') {
                    throw $ex;
                }
                // Mensagem genérica: não indicar qual dos campos já existe.
                $erros[] = 'Não foi possível criar a conta com esses dados. Escolha outro nome de utilizador ou email.';
            }

            // Só contam para o limite os pedidos que chegam a tentar criar a conta,
            // para que erros de preenchimento não bloqueiem o utilizador.
            registar_tentativa('registo', $email, !$erros);
        }

        if (!$erros) {
            flash_definir('sucesso', 'Conta criada com sucesso! Já pode iniciar sessão.');
            redirecionar('login.php');
        }
    }
}

marcar_formulario('registo');
layout_inicio('Registo');
?>
<h1>Criar conta</h1>
<p class="subtitulo">Preencha os dados para se registar.</p>

<?php mostrar_erros($erros); ?>

<form method="post" action="register.php" autocomplete="on" novalidate>
    <?= csrf_campo() ?>

    <!-- Honeypot: invisível para humanos, bots tendem a preenchê-lo -->
    <div class="honeypot" aria-hidden="true">
        <label for="website">Website</label>
        <input type="text" id="website" name="website" tabindex="-1" autocomplete="off">
    </div>

    <label for="username">Nome de utilizador</label>
    <input type="text" id="username" name="username" value="<?= e($username) ?>"
           required minlength="3" maxlength="30" pattern="[A-Za-z0-9_]{3,30}" autocomplete="username">

    <label for="email">Email</label>
    <input type="email" id="email" name="email" value="<?= e($email) ?>"
           required maxlength="254" autocomplete="email">

    <label for="password">Palavra-passe</label>
    <input type="password" id="password" name="password"
           required minlength="12" maxlength="128" autocomplete="new-password">

    <label for="password_confirmacao">Confirmar palavra-passe</label>
    <input type="password" id="password_confirmacao" name="password_confirmacao"
           required minlength="12" maxlength="128" autocomplete="new-password">

    <ul class="requisitos">
        <li>Entre 12 e 128 caracteres</li>
        <li>Maiúsculas e minúsculas</li>
        <li>Pelo menos um número e um símbolo</li>
        <li>Não pode conter o nome de utilizador</li>
    </ul>

    <button type="submit">Registar</button>
</form>

<p class="rodape">Já tem conta? <a href="login.php">Iniciar sessão</a></p>
<?php layout_fim();

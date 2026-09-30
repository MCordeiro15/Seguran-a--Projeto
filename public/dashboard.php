<?php
declare(strict_types=1);

require __DIR__ . '/../includes/bootstrap.php';

exigir_login();

$st = db()->prepare('SELECT username, email, criado_em FROM utilizadores WHERE id = ?');
$st->execute([$_SESSION['uid']]);
$utilizador = $st->fetch();

if ($utilizador === false) {
    terminar_sessao();
    redirecionar('login.php');
}

$loginAnterior = $_SESSION['login_anterior'] ?? null;

layout_inicio('Área reservada');
?>
<h1>Olá, <?= e($utilizador['username']) ?>!</h1>
<p class="subtitulo">Está autenticado numa área protegida.</p>

<dl class="detalhes">
    <dt>Email</dt>
    <dd><?= e($utilizador['email']) ?></dd>
    <dt>Conta criada em</dt>
    <dd><?= e($utilizador['criado_em']) ?></dd>
    <dt>Último acesso anterior</dt>
    <dd><?= $loginAnterior !== null ? e((string) $loginAnterior) : 'Primeiro acesso' ?></dd>
</dl>

<form method="post" action="logout.php">
    <?= csrf_campo() ?>
    <button type="submit" class="secundario">Terminar sessão</button>
</form>
<?php layout_fim();

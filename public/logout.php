<?php
declare(strict_types=1);

require __DIR__ . '/../includes/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !pedido_valido()) {
    redirecionar(utilizador_autenticado() ? 'dashboard.php' : 'login.php');
}

terminar_sessao();
iniciar_sessao();
session_regenerate_id(true);
flash_definir('sucesso', 'Sessão terminada com sucesso.');
redirecionar('login.php');

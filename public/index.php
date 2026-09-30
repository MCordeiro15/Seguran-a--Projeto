<?php
declare(strict_types=1);

require __DIR__ . '/../includes/bootstrap.php';

redirecionar(utilizador_autenticado() ? 'dashboard.php' : 'login.php');

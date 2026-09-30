<?php
declare(strict_types=1);

function layout_inicio(string $titulo): void
{
    ?>
<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="referrer" content="same-origin">
    <title><?= e($titulo) ?> · Segurança Web</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
<main class="cartao">
    <?php
    $flash = flash_obter();
    if ($flash !== null) {
        echo '<div class="alerta alerta-' . e($flash['tipo']) . '">' . e($flash['mensagem']) . '</div>';
    }
}

/** @param string[] $erros */
function mostrar_erros(array $erros): void
{
    if (!$erros) {
        return;
    }
    echo '<div class="alerta alerta-erro"><ul>';
    foreach ($erros as $erro) {
        echo '<li>' . e($erro) . '</li>';
    }
    echo '</ul></div>';
}

function layout_fim(): void
{
    ?>
</main>
</body>
</html>
    <?php
}

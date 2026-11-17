<?php
declare(strict_types=1);

require_once __DIR__ . '/src/bootstrap.php';

use App\AuthHandler;
use App\Settings;

$settings = Settings::fromEnv(__DIR__);
$boot = AuthHandler::bootstrapRequest($settings, $_COOKIE, $_SERVER);
if (!$boot['ok']) {
    AuthHandler::emitJsonResponse($boot);
    exit;
}

AuthHandler::emitJsonResponse([
    'status' => 200,
    'headers' => [],
    'body' => ['ok' => true, 'version' => Settings::APP_VERSION],
]);

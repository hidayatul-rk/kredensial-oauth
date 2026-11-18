<?php
declare(strict_types=1);

require_once __DIR__ . '/src/bootstrap.php';

use App\AuthHandler;
use App\Settings;

$settings = Settings::fromEnv(__DIR__);
$jsonBody = AuthHandler::readJsonBody($_SERVER);

$response = AuthHandler::handleDataUtamaRequest(
    $settings,
    $_POST,
    $_COOKIE,
    $_SERVER,
    $jsonBody
);

AuthHandler::emitJsonResponse($response);

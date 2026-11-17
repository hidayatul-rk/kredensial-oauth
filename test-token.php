<?php
declare(strict_types=1);

require_once __DIR__ . '/src/bootstrap.php';

use App\AuthHandler;
use App\Settings;

$settings = Settings::fromEnv(__DIR__);

$jsonBody = null;
$contentType = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
if (str_contains($contentType, 'application/json')) {
    $raw = file_get_contents('php://input');
    if (is_string($raw) && trim($raw) !== '') {
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $jsonBody = $decoded;
        }
    }
}

$response = AuthHandler::handleTokenRequest(
    $settings,
    $_POST,
    $_COOKIE,
    $_SERVER,
    $jsonBody
);

AuthHandler::emitJsonResponse($response);

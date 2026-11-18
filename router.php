<?php
declare(strict_types=1);

$path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';

// Blokir akses langsung ke folder internal, tes, dan file konfigurasi/rahasia.
if (
    preg_match('#^/(?:src|tests)(?:/|$)#i', $path) === 1
    || preg_match('#^/\.#', $path) === 1
    || in_array($path, ['/router.php', '/README.md'], true)
) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Not Found';
    return true;
}

// Layani aset statis secara langsung.
if (str_starts_with($path, '/static/') && is_file(__DIR__ . $path)) {
    return false;
}

if ($path === '/' || $path === '/index.php') {
    require __DIR__ . '/index.php';
    return true;
}

if ($path === '/test-token' || $path === '/login' || $path === '/test-token.php') {
    require __DIR__ . '/test-token.php';
    return true;
}

if ($path === '/datautama' || $path === '/datautama.php') {
    require __DIR__ . '/datautama.php';
    return true;
}

if ($path === '/version' || $path === '/version.php') {
    require __DIR__ . '/version.php';
    return true;
}

http_response_code(404);
header('Content-Type: text/plain; charset=utf-8');
echo 'Not Found';
return true;

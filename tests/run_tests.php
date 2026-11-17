<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/src/bootstrap.php';

use App\AuthHandler;
use App\BknClient;
use App\EnvLoader;
use App\Security;
use App\Settings;

function assertTrue(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException('Assertion failed: ' . $message);
    }
}

function assertSameValue(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException(
            sprintf('%s (expected %s, got %s)', $message, var_export($expected, true), var_export($actual, true))
        );
    }
}

function removeDirRecursive(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }
    $items = scandir($dir);
    if ($items === false) {
        return;
    }
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($path)) {
            removeDirRecursive($path);
        } else {
            @unlink($path);
        }
    }
    @rmdir($dir);
}

$tests = [];

$tests['env_loader_parses_dotenv'] = static function (): void {
    $tmpFile = tempnam(sys_get_temp_dir(), 'env_test_');
    assertTrue($tmpFile !== false, 'tempnam failed');
    file_put_contents($tmpFile, "# komentar\nTEST_BKN_KEY_1=\"nilai satu\"\nTEST_BKN_KEY_2='nilai dua'\nTEST_BKN_KEY_3=polos # inline\n");
    try {
        putenv('TEST_BKN_KEY_1');
        putenv('TEST_BKN_KEY_2');
        putenv('TEST_BKN_KEY_3');
        unset($_ENV['TEST_BKN_KEY_1'], $_ENV['TEST_BKN_KEY_2'], $_ENV['TEST_BKN_KEY_3']);

        EnvLoader::load($tmpFile);
        assertSameValue('nilai satu', getenv('TEST_BKN_KEY_1'), 'Double quoted env parsed');
        assertSameValue('nilai dua', getenv('TEST_BKN_KEY_2'), 'Single quoted env parsed');
        assertSameValue('polos', getenv('TEST_BKN_KEY_3'), 'Inline comment stripped');
    } finally {
        @unlink($tmpFile);
        putenv('TEST_BKN_KEY_1');
        putenv('TEST_BKN_KEY_2');
        putenv('TEST_BKN_KEY_3');
        unset($_ENV['TEST_BKN_KEY_1'], $_ENV['TEST_BKN_KEY_2'], $_ENV['TEST_BKN_KEY_3']);
    }
};

$tests['resolve_token_url_security'] = static function (): void {
    assertSameValue(
        'https://apimws.bkn.go.id/oauth2/token',
        BknClient::resolveTokenUrl('https://apimws.bkn.go.id/oauth2/token', 'https://apimws.bkn.go.id/oauth2/token'),
        'Valid HTTPS token URL accepted'
    );

    $invalidCases = [
        ['http://apimws.bkn.go.id/oauth2/token', null],
        ['https://user:pass@apimws.bkn.go.id/oauth2/token', null],
        ['https://apimws.bkn.go.id/oauth2/token#frag', null],
        ['https://apimws.bkn.go.id/oauth2/token', 'https://evil.example.com/oauth2/token'],
    ];

    foreach ($invalidCases as [$configured, $requested]) {
        $threw = false;
        try {
            BknClient::resolveTokenUrl($configured, $requested);
        } catch (\InvalidArgumentException $e) {
            $threw = true;
        }
        assertTrue($threw, 'Expected InvalidArgumentException for ' . $configured . ' / ' . (string) $requested);
    }
};

$tests['fetch_token_success_and_errors'] = static function (): void {
    $captured = [];
    $okTransport = static function (string $url, array $headers, array $params, int $timeout) use (&$captured): array {
        $captured = compact('url', 'headers', 'params', 'timeout');
        return [
            'status' => 200,
            'body' => json_encode(['access_token' => 'tok-123', 'expires_in' => 3600]),
        ];
    };

    $basic = BknClient::buildBasicAuth('client-a', 'secret-b');
    $res = BknClient::fetchTokenFromUrl(
        'https://apimws.bkn.go.id/oauth2/token',
        'https://apimws.bkn.go.id/oauth2/token',
        $basic,
        'client_credentials',
        15,
        $okTransport
    );

    assertSameValue('tok-123', $res['access_token'], 'Access token parsed');
    assertSameValue(3600, $res['expires_in'], 'Expires in parsed');
    assertSameValue('https://apimws.bkn.go.id/oauth2/token', $captured['url'], 'Target URL');
    assertSameValue(['grant_type' => 'client_credentials'], $captured['params'], 'Grant type payload');
    assertTrue(
        in_array('Authorization: Basic ' . base64_encode('client-a:secret-b'), $captured['headers'], true),
        'Basic Auth header sent'
    );

    // HTTP 401
    $err401 = false;
    try {
        BknClient::fetchTokenFromUrl(
            'https://apimws.bkn.go.id/oauth2/token',
            null,
            $basic,
            'client_credentials',
            15,
            static fn(): array => ['status' => 401, 'body' => 'invalid_client']
        );
    } catch (\RuntimeException $e) {
        $err401 = str_contains($e->getMessage(), 'HTTP 401');
    }
    assertTrue($err401, 'HTTP 401 raises RuntimeException');

    // Invalid JSON
    $errJson = false;
    try {
        BknClient::fetchTokenFromUrl(
            'https://apimws.bkn.go.id/oauth2/token',
            null,
            $basic,
            'client_credentials',
            15,
            static fn(): array => ['status' => 200, 'body' => '<html>oops</html>']
        );
    } catch (\RuntimeException $e) {
        $errJson = str_contains($e->getMessage(), 'bukan JSON yang valid');
    }
    assertTrue($errJson, 'Non-JSON 200 raises RuntimeException');
};

$tests['auth_handler_csrf_validation_rate_limit_and_basic_auth'] = static function (): void {
    $rlDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'bkn_kred_test_' . bin2hex(random_bytes(4));
    $settings = new Settings(loginRateMax: 2, loginRateWindow: 60.0);
    $server = ['HTTP_HOST' => '127.0.0.1:8000', 'REMOTE_ADDR' => '127.0.0.1', 'REQUEST_METHOD' => 'POST'];

    try {
        // 1. CSRF ditolak bila kosong/salah
        $r403 = AuthHandler::handleTokenRequest($settings, ['username' => 'u', 'password' => 'p'], [], $server, null, null, $rlDir);
        assertSameValue(403, $r403['status'], 'Missing CSRF returns 403');

        // 2. Validasi form kosong
        $cookies = [Security::CSRF_COOKIE_NAME => 'csrf-ok'];
        $serverWithCsrf = $server + [Security::CSRF_HEADER_NAME => 'csrf-ok'];
        $r400 = AuthHandler::handleTokenRequest($settings, [], $cookies, $serverWithCsrf, null, null, $rlDir);
        assertSameValue(400, $r400['status'], 'Empty credentials return 400');

        // 3. Sukses via mocked transport
        $r200 = AuthHandler::handleTokenRequest(
            $settings,
            ['username' => 'cid', 'password' => 'csec', 'token_url' => $settings->tokenUrl],
            $cookies,
            $serverWithCsrf,
            null,
            static fn(): array => ['status' => 200, 'body' => '{"access_token":"xyz","expires_in":1800}'],
            $rlDir
        );
        assertSameValue(200, $r200['status'], 'Valid login returns 200');
        assertSameValue('xyz', $r200['body']['access_token'], 'Token returned');

        // 4. Rate limit terpicu pada percobaan ke-3 (max=2)
        AuthHandler::handleTokenRequest(
            $settings,
            ['username' => 'cid', 'password' => 'bad', 'token_url' => $settings->tokenUrl],
            $cookies,
            $serverWithCsrf,
            null,
            static fn(): array => ['status' => 401, 'body' => 'nope'],
            $rlDir
        );
        $r429 = AuthHandler::handleTokenRequest(
            $settings,
            ['username' => 'cid', 'password' => 'bad', 'token_url' => $settings->tokenUrl],
            $cookies,
            $serverWithCsrf,
            null,
            static fn(): array => ['status' => 401, 'body' => 'nope'],
            $rlDir
        );
        assertSameValue(429, $r429['status'], 'Rate limit returns 429');

        // 5. App Basic Auth gate dan blokir LAN tanpa kredensial
        $protectedSettings = new Settings(appBasicUser: 'op', appBasicPassword: 'pw');
        $r401 = AuthHandler::bootstrapRequest($protectedSettings, [], ['HTTP_HOST' => '127.0.0.1', 'REMOTE_ADDR' => '127.0.0.1'], static function (): void {}, $rlDir);
        assertSameValue(401, $r401['status'] ?? 0, 'Missing app Basic Auth returns 401');

        $rOk = AuthHandler::bootstrapRequest(
            $protectedSettings,
            [],
            ['HTTP_HOST' => '127.0.0.1', 'REMOTE_ADDR' => '127.0.0.1', 'PHP_AUTH_USER' => 'op', 'PHP_AUTH_PW' => 'pw'],
            static function (): void {},
            $rlDir
        );
        assertTrue($rOk['ok'] === true, 'Valid app Basic Auth succeeds');

        $lanDenied = AuthHandler::bootstrapRequest(
            new Settings(),
            [],
            ['HTTP_HOST' => '127.0.0.1', 'REMOTE_ADDR' => '192.168.1.50'],
            static function (): void {},
            $rlDir
        );
        assertSameValue(503, $lanDenied['status'] ?? 0, 'Non-loopback without APP_BASIC_USER returns 503');
    } finally {
        removeDirRecursive($rlDir);
    }
};

$tests['live_php_server_smoke_test'] = static function (): void {
    $sock = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    assertTrue($sock !== false, 'Unable to allocate local port: ' . $errstr);
    $name = stream_socket_get_name($sock, false);
    fclose($sock);
    $port = (int) substr((string) $name, (int) strrpos((string) $name, ':') + 1);
    $root = dirname(__DIR__);

    $cmd = sprintf('"%s" -S 127.0.0.1:%d "%s"', PHP_BINARY, $port, $root . DIRECTORY_SEPARATOR . 'router.php');
    $pipes = [];
    $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root);
    assertTrue(is_resource($proc), 'Failed to start php -S');

    try {
        $baseUrl = 'http://127.0.0.1:' . $port;
        $ready = false;
        for ($i = 0; $i < 25; $i++) {
            $ch = curl_init($baseUrl . '/version');
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2]);
            $body = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_close($ch);
            if ($code === 200 && is_string($body)) {
                $ready = true;
                break;
            }
            usleep(100000);
        }
        assertTrue($ready, 'php -S server did not become ready');

        // 1. GET / + cek CSRF cookie + security headers
        $cookieJar = tempnam(sys_get_temp_dir(), 'bkn_jar_');
        $ch = curl_init($baseUrl . '/');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_COOKIEJAR => $cookieJar,
        ]);
        $raw = (string) curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $hdrSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        $headers = substr($raw, 0, $hdrSize);
        $html = substr($raw, $hdrSize);
        assertSameValue(200, $code, 'GET / status 200');
        assertTrue(str_contains($html, 'Kredensial API BKN'), 'HTML contains title');
        assertTrue(str_contains($html, 'test-token.php'), 'HTML contains test-token.php meta');
        assertTrue(stripos($headers, 'X-Content-Type-Options: nosniff') !== false, 'Security header nosniff present');
        assertTrue(stripos($headers, 'X-Frame-Options: DENY') !== false, 'Security header DENY present');

        preg_match('/<meta name="csrf-token" content="([^"]+)"/', $html, $matches);
        $csrf = $matches[1] ?? '';
        assertTrue($csrf !== '', 'CSRF token meta tag present');

        // 2. Proteksi file sensitif oleh router.php
        foreach (['/.env.example', '/src/BknClient.php', '/tests/run_tests.php'] as $blockedPath) {
            $ch = curl_init($baseUrl . $blockedPath);
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true]);
            curl_exec($ch);
            $bCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_close($ch);
            assertSameValue(404, $bCode, 'Sensitive path blocked: ' . $blockedPath);
        }

        // 3. POST /test-token tanpa CSRF -> 403
        $ch = curl_init($baseUrl . '/test-token');
        curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_POSTFIELDS => '']);
        curl_exec($ch);
        assertSameValue(403, (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE), 'POST without CSRF returns 403');
        curl_close($ch);

        // 4. POST /test-token dengan CSRF valid & input kosong -> 400
        $ch = curl_init($baseUrl . '/test-token');
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_COOKIEFILE => $cookieJar,
            CURLOPT_HTTPHEADER => ['X-CSRF-Token: ' . $csrf],
            CURLOPT_POSTFIELDS => http_build_query(['csrf_token' => $csrf]),
        ]);
        $respBody = (string) curl_exec($ch);
        $respCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        assertSameValue(400, $respCode, 'POST with valid CSRF passes gate to validation (400)');
        assertTrue(str_contains($respBody, 'Username dan password wajib diisi'), 'Validation message returned');

        // 5. Uji BknClient::curlPostForm secara langsung ke endpoint lokal
        $curlRes = BknClient::curlPostForm(
            $baseUrl . '/test-token',
            ['Accept: application/json'],
            ['username' => 'u'],
            5
        );
        assertSameValue(403, $curlRes['status'], 'curlPostForm receives HTTP status from local server');
        assertTrue(str_contains($curlRes['body'], '"error_type":"csrf"'), 'curlPostForm returns JSON body');

        @unlink($cookieJar);
    } finally {
        foreach ($pipes as $p) {
            if (is_resource($p)) {
                fclose($p);
            }
        }
        proc_terminate($proc);
        proc_close($proc);
    }
};

$passed = 0;
foreach ($tests as $name => $fn) {
    $fn();
    $passed++;
    echo "[OK] {$name}\n";
}

echo sprintf("\nSemua %d test PHP lulus.\n", $passed);

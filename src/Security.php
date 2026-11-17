<?php
declare(strict_types=1);

namespace App;

final class Security
{
    public const CSRF_COOKIE_NAME = 'csrf_token';
    public const CSRF_FORM_FIELD = 'csrf_token';
    public const CSRF_HEADER_NAME = 'HTTP_X_CSRF_TOKEN';

    public static function sendSecurityHeaders(): void
    {
        if (headers_sent()) {
            return;
        }
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('Cache-Control: no-store');
    }

    public static function securityHeadersList(): array
    {
        return [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
            'Referrer-Policy' => 'no-referrer',
            'Cache-Control' => 'no-store',
        ];
    }

    public static function extractHostName(string $rawHost): string
    {
        $host = strtolower(trim($rawHost));
        if ($host === '') {
            return '';
        }
        if (str_starts_with($host, '[')) {
            $end = strpos($host, ']');
            if ($end === false) {
                return '';
            }
            return substr($host, 1, $end - 1);
        }
        $colonCount = substr_count($host, ':');
        if ($colonCount === 1) {
            $pos = strpos($host, ':');
            return $pos !== false ? substr($host, 0, $pos) : $host;
        }
        return $host;
    }

    public static function validateTrustedHost(Settings $settings, string $rawHost): bool
    {
        $host = self::extractHostName($rawHost);
        if ($host === '') {
            return false;
        }
        return in_array($host, $settings->trustedHosts, true);
    }

    /**
     * @param array<string, mixed> $server
     * @return array{0: string, 1: string}|null
     */
    public static function extractBasicAuthCredentials(array $server): ?array
    {
        if (isset($server['PHP_AUTH_USER'])) {
            return [(string) $server['PHP_AUTH_USER'], (string) ($server['PHP_AUTH_PW'] ?? '')];
        }

        $authHeader = (string) ($server['HTTP_AUTHORIZATION'] ?? $server['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        if ($authHeader !== '' && stripos($authHeader, 'Basic ') === 0) {
            $decoded = base64_decode(substr($authHeader, 6), true);
            if ($decoded !== false && str_contains($decoded, ':')) {
                [$user, $pass] = explode(':', $decoded, 2);
                return [$user, $pass];
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $server
     * @return array{status: int, headers: array<string, string>, body: array<string, mixed>}|null
     */
    public static function requireAppAuth(
        Settings $settings,
        array $server,
        ?string $rateLimitDir = null
    ): ?array {
        $appUser = $settings->appBasicUser;
        $appPass = $settings->appBasicPassword;
        $remoteAddr = (string) ($server['REMOTE_ADDR'] ?? '');
        $hostName = self::extractHostName((string) ($server['HTTP_HOST'] ?? ''));

        if ($appUser === '' || $appPass === '') {
            $isLoopbackIp = in_array($remoteAddr, ['127.0.0.1', '::1'], true);
            $isLoopbackHost = in_array($hostName, ['127.0.0.1', 'localhost', '::1'], true);
            if ($isLoopbackIp && $isLoopbackHost) {
                return null;
            }

            return [
                'status' => 503,
                'headers' => [],
                'body' => ['ok' => false, 'message' => 'Akses jaringan memerlukan akun aplikasi.'],
            ];
        }

        $creds = self::extractBasicAuthCredentials($server);
        if (
            $creds !== null
            && hash_equals($appUser, $creds[0])
            && hash_equals($appPass, $creds[1])
        ) {
            return null;
        }

        $ip = self::clientIp($settings, $server);
        $limited = self::rateLimitHit('app_auth', $ip, $settings->loginRateMax, $settings->loginRateWindow, $rateLimitDir);
        $status = $limited !== null ? 429 : 401;
        $headers = $limited === null ? ['WWW-Authenticate' => 'Basic realm="Kredensial BKN", charset="UTF-8"'] : [];

        return [
            'status' => $status,
            'headers' => $headers,
            'body' => ['ok' => false, 'message' => $limited ?? 'Autentikasi aplikasi diperlukan.'],
        ];
    }

    /**
     * @param array<string, mixed> $cookies
     */
    public static function ensureCsrfCookie(
        array $cookies,
        bool $cookieSecure,
        ?callable $setCookieFn = null
    ): string {
        $existing = (string) ($cookies[self::CSRF_COOKIE_NAME] ?? '');
        if ($existing !== '') {
            return $existing;
        }

        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $setter = $setCookieFn ?? static function (string $name, string $value, array $options): void {
            if (!headers_sent()) {
                setcookie($name, $value, $options);
            }
        };

        $setter(self::CSRF_COOKIE_NAME, $token, [
            'expires' => 0,
            'path' => '/',
            'secure' => $cookieSecure,
            'httponly' => false,
            'samesite' => 'Strict',
        ]);

        return $token;
    }

    /**
     * @param array<string, mixed> $cookies
     * @param array<string, mixed> $server
     * @param array<string, mixed> $post
     * @param array<string, mixed>|null $jsonBody
     */
    public static function verifyCsrf(
        array $cookies,
        array $server,
        array $post,
        ?array $jsonBody = null
    ): bool {
        $cookieToken = (string) ($cookies[self::CSRF_COOKIE_NAME] ?? '');
        if ($cookieToken === '') {
            return false;
        }

        $sentToken = trim((string) ($server[self::CSRF_HEADER_NAME] ?? ''));
        if ($sentToken === '') {
            $sentToken = trim((string) ($post[self::CSRF_FORM_FIELD] ?? ''));
        }
        if ($sentToken === '' && is_array($jsonBody)) {
            $sentToken = trim((string) ($jsonBody[self::CSRF_FORM_FIELD] ?? ''));
        }

        return $sentToken !== '' && hash_equals($cookieToken, $sentToken);
    }

    /**
     * @param array<string, mixed> $server
     */
    public static function clientIp(Settings $settings, array $server): string
    {
        if ($settings->trustProxy) {
            $fwd = (string) ($server['HTTP_X_FORWARDED_FOR'] ?? '');
            if ($fwd !== '') {
                $parts = explode(',', $fwd);
                $first = trim($parts[0]);
                if ($first !== '') {
                    return $first;
                }
            }
        }
        return (string) ($server['REMOTE_ADDR'] ?? 'unknown');
    }

    public static function rateLimitHit(
        string $bucket,
        string $ip,
        int $maxAttempts,
        float $windowSeconds,
        ?string $storageDir = null
    ): ?string {
        if ($maxAttempts <= 0) {
            return null;
        }

        $dir = $storageDir ?? (sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'bkn_kredensial_rl');
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }

        $file = $dir . DIRECTORY_SEPARATOR . hash('sha256', $bucket . ':' . $ip) . '.json';
        $now = microtime(true);

        $fp = @fopen($file, 'c+');
        if ($fp === false) {
            return null;
        }

        try {
            if (!flock($fp, LOCK_EX)) {
                return null;
            }

            $raw = stream_get_contents($fp);
            $timestamps = [];
            if (is_string($raw) && trim($raw) !== '') {
                $decoded = json_decode($raw, true);
                if (is_array($decoded)) {
                    foreach ($decoded as $ts) {
                        if (is_numeric($ts) && ($now - (float) $ts) <= $windowSeconds) {
                            $timestamps[] = (float) $ts;
                        }
                    }
                }
            }

            if (count($timestamps) >= $maxAttempts) {
                $oldest = min($timestamps);
                $remaining = (int) floor($windowSeconds - ($now - $oldest));
                return sprintf('Terlalu banyak percobaan. Coba lagi dalam %d detik.', max($remaining, 1));
            }

            $timestamps[] = $now;
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($timestamps));
            fflush($fp);
            flock($fp, LOCK_UN);
            return null;
        } finally {
            fclose($fp);
        }
    }

    public static function sanitizeErrorForClient(\Throwable $exc): string
    {
        if ($exc instanceof \InvalidArgumentException) {
            return $exc->getMessage();
        }

        $msg = $exc->getMessage();
        $msg = preg_replace('/[A-Za-z]:\\\\[^\s\'"]+/', '<path>', $msg) ?? $msg;
        $msg = preg_replace('#/(?:home|root|usr|var|etc|opt|tmp|srv)/[^\s\'"]*#', '<path>', $msg) ?? $msg;
        $msg = preg_replace('/\s+/', ' ', trim($msg)) ?? trim($msg);

        if (strlen($msg) > 300) {
            $msg = substr($msg, 0, 300) . '...';
        }

        return $msg !== '' ? $msg : $exc::class;
    }
}

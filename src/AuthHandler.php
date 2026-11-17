<?php
declare(strict_types=1);

namespace App;

final class AuthHandler
{
    /**
     * Validasi akses halaman dan siapkan token CSRF.
     *
     * @param array<string, mixed> $cookies
     * @param array<string, mixed> $server
     * @return array{ok: bool, status?: int, headers?: array<string, string>, body?: array<string, mixed>, csrf_token?: string}
     */
    public static function bootstrapRequest(
        Settings $settings,
        array $cookies,
        array $server,
        ?callable $setCookieFn = null,
        ?string $rateLimitDir = null
    ): array {
        $rawHost = (string) ($server['HTTP_HOST'] ?? '');
        if (!Security::validateTrustedHost($settings, $rawHost)) {
            return [
                'ok' => false,
                'status' => 400,
                'headers' => [],
                'body' => ['ok' => false, 'message' => 'Header Host tidak diizinkan.'],
            ];
        }

        $authFailure = Security::requireAppAuth($settings, $server, $rateLimitDir);
        if ($authFailure !== null) {
            return [
                'ok' => false,
                'status' => $authFailure['status'],
                'headers' => $authFailure['headers'],
                'body' => $authFailure['body'],
            ];
        }

        $csrfToken = Security::ensureCsrfCookie($cookies, $settings->cookieSecure, $setCookieFn);
        return ['ok' => true, 'csrf_token' => $csrfToken];
    }

    /**
     * Tangani endpoint POST /test-token dan /login dengan PHP cURL.
     *
     * @param array<string, mixed> $post
     * @param array<string, mixed> $cookies
     * @param array<string, mixed> $server
     * @param array<string, mixed>|null $jsonBody
     * @return array{status: int, headers: array<string, string>, body: array<string, mixed>}
     */
    public static function handleTokenRequest(
        Settings $settings,
        array $post,
        array $cookies,
        array $server,
        ?array $jsonBody = null,
        ?callable $transport = null,
        ?string $rateLimitDir = null
    ): array {
        $rawHost = (string) ($server['HTTP_HOST'] ?? '');
        if (!Security::validateTrustedHost($settings, $rawHost)) {
            return [
                'status' => 400,
                'headers' => [],
                'body' => ['ok' => false, 'message' => 'Header Host tidak diizinkan.'],
            ];
        }

        $authFailure = Security::requireAppAuth($settings, $server, $rateLimitDir);
        if ($authFailure !== null) {
            return $authFailure;
        }

        $method = strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET'));
        if ($method !== 'POST') {
            return [
                'status' => 405,
                'headers' => ['Allow' => 'POST'],
                'body' => ['ok' => false, 'message' => 'Method tidak diizinkan. Gunakan POST.'],
            ];
        }

        if (!Security::verifyCsrf($cookies, $server, $post, $jsonBody)) {
            return [
                'status' => 403,
                'headers' => [],
                'body' => [
                    'ok' => false,
                    'message' => 'Sesi halaman kedaluwarsa atau token keamanan tidak valid. Muat ulang halaman lalu coba lagi.',
                    'error_type' => 'csrf',
                ],
            ];
        }

        $username = trim((string) ($post['username'] ?? ''));
        $password = trim((string) ($post['password'] ?? ''));
        $tokenUrl = trim((string) ($post['token_url'] ?? ''));
        $grantType = trim((string) ($post['grant_type'] ?? $settings->grantType));

        if ($username === '' || $password === '') {
            return [
                'status' => 400,
                'headers' => [],
                'body' => ['ok' => false, 'message' => 'Username dan password wajib diisi'],
            ];
        }
        if ($tokenUrl === '') {
            return [
                'status' => 400,
                'headers' => [],
                'body' => ['ok' => false, 'message' => 'Token URL wajib diisi'],
            ];
        }

        $ip = Security::clientIp($settings, $server);
        $limited = Security::rateLimitHit('login', $ip, $settings->loginRateMax, $settings->loginRateWindow, $rateLimitDir);
        if ($limited !== null) {
            return [
                'status' => 429,
                'headers' => [],
                'body' => ['ok' => false, 'message' => $limited],
            ];
        }

        $basicAuth = BknClient::buildBasicAuth($username, $password);

        try {
            $result = BknClient::fetchTokenFromUrl(
                $settings->tokenUrl,
                $tokenUrl,
                $basicAuth,
                $grantType,
                $settings->timeout,
                $transport
            );

            return [
                'status' => 200,
                'headers' => [],
                'body' => [
                    'ok' => true,
                    'message' => sprintf('Login berhasil. Token berlaku ±%d detik.', $result['expires_in']),
                    'access_token' => $result['access_token'],
                    'expires_in' => $result['expires_in'],
                ],
            ];
        } catch (\Throwable $exc) {
            return [
                'status' => 400,
                'headers' => [],
                'body' => [
                    'ok' => false,
                    'message' => 'Gagal login: ' . Security::sanitizeErrorForClient($exc),
                ],
            ];
        }
    }

    /**
     * @param array{status: int, headers?: array<string, string>, body: array<string, mixed>} $response
     */
    public static function emitJsonResponse(array $response): void
    {
        Security::sendSecurityHeaders();
        http_response_code($response['status']);
        header('Content-Type: application/json; charset=utf-8');
        foreach ($response['headers'] ?? [] as $name => $value) {
            header($name . ': ' . $value);
        }
        echo json_encode($response['body'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
}

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
        $gateFailure = self::validatePostRequest($settings, $post, $cookies, $server, $jsonBody, $rateLimitDir);
        if ($gateFailure !== null) {
            return $gateFailure;
        }

        $username = trim((string) ($post['username'] ?? $jsonBody['username'] ?? ''));
        $password = trim((string) ($post['password'] ?? $jsonBody['password'] ?? ''));
        $tokenUrl = trim((string) ($post['token_url'] ?? $jsonBody['token_url'] ?? ''));
        $grantType = trim((string) ($post['grant_type'] ?? $jsonBody['grant_type'] ?? $settings->grantType));

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
     * Tangani endpoint POST /datautama untuk mengambil Data Utama PNS SIASN BKN.
     *
     * @param array<string, mixed> $post
     * @param array<string, mixed> $cookies
     * @param array<string, mixed> $server
     * @param array<string, mixed>|null $jsonBody
     * @return array{status: int, headers: array<string, string>, body: array<string, mixed>}
     */
    public static function handleDataUtamaRequest(
        Settings $settings,
        array $post,
        array $cookies,
        array $server,
        ?array $jsonBody = null,
        ?callable $transport = null,
        ?string $rateLimitDir = null
    ): array {
        $gateFailure = self::validatePostRequest($settings, $post, $cookies, $server, $jsonBody, $rateLimitDir);
        if ($gateFailure !== null) {
            return $gateFailure;
        }

        $nip = trim((string) ($post['nip'] ?? $jsonBody['nip'] ?? ''));
        $accessToken = trim((string) ($post['access_token'] ?? $jsonBody['access_token'] ?? ''));
        $authHeaderToken = trim((string) ($post['auth_header_token'] ?? $jsonBody['auth_header_token'] ?? ''));
        $dataUtamaUrl = trim((string) ($post['data_utama_url'] ?? $jsonBody['data_utama_url'] ?? ''));

        if ($nip === '') {
            return [
                'status' => 400,
                'headers' => [],
                'body' => ['ok' => false, 'message' => 'NIP wajib diisi'],
            ];
        }
        if ($accessToken === '') {
            return [
                'status' => 400,
                'headers' => [],
                'body' => ['ok' => false, 'message' => 'Authorization Token wajib diisi'],
            ];
        }

        $ip = Security::clientIp($settings, $server);
        $limited = Security::rateLimitHit('datautama', $ip, $settings->loginRateMax, $settings->loginRateWindow, $rateLimitDir);
        if ($limited !== null) {
            return [
                'status' => 429,
                'headers' => [],
                'body' => ['ok' => false, 'message' => $limited],
            ];
        }

        try {
            $result = BknClient::fetchDataUtama(
                $settings->dataUtamaUrl,
                $dataUtamaUrl !== '' ? $dataUtamaUrl : null,
                $nip,
                $accessToken,
                $authHeaderToken !== '' ? $authHeaderToken : null,
                $settings->timeout,
                $transport
            );

            $payload = $result['payload'];
            $isLogicalFail = (isset($payload['code']) && is_numeric($payload['code']) && (int) $payload['code'] === 0)
                || (isset($payload['success']) && $payload['success'] === false);

            if ($isLogicalFail) {
                $bknMsg = is_string($payload['message'] ?? null) && trim($payload['message']) !== ''
                    ? trim($payload['message'])
                    : 'Respons diterima dari server BKN.';
                $message = sprintf('Respons BKN untuk NIP %s: %s', $result['nip'], $bknMsg);
            } else {
                $message = sprintf('Data utama NIP %s berhasil diambil.', $result['nip']);
            }

            return [
                'status' => 200,
                'headers' => [],
                'body' => [
                    'ok' => true,
                    'message' => $message,
                    'nip' => $result['nip'],
                    'endpoint' => $result['url'],
                    'data' => $payload,
                ],
            ];
        } catch (\Throwable $exc) {
            return [
                'status' => 400,
                'headers' => [],
                'body' => [
                    'ok' => false,
                    'message' => 'Gagal mengambil data utama: ' . Security::sanitizeErrorForClient($exc),
                ],
            ];
        }
    }

    /**
     * Baca payload JSON dari request body bila Content-Type adalah application/json.
     *
     * @param array<string, mixed> $server
     * @return array<string, mixed>|null
     */
    public static function readJsonBody(array $server): ?array
    {
        $contentType = strtolower((string) ($server['CONTENT_TYPE'] ?? ''));
        if (!str_contains($contentType, 'application/json')) {
            return null;
        }

        $raw = file_get_contents('php://input');
        if (!is_string($raw) || trim($raw) === '') {
            return null;
        }

        $decoded = json_decode($raw, true);
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Validasi Host, Basic Auth aplikasi, method POST, dan CSRF token.
     *
     * @param array<string, mixed> $post
     * @param array<string, mixed> $cookies
     * @param array<string, mixed> $server
     * @param array<string, mixed>|null $jsonBody
     * @return array{status: int, headers: array<string, string>, body: array<string, mixed>}|null
     */
    private static function validatePostRequest(
        Settings $settings,
        array $post,
        array $cookies,
        array $server,
        ?array $jsonBody,
        ?string $rateLimitDir
    ): ?array {
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

        return null;
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

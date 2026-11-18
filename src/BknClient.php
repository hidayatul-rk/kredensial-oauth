<?php
declare(strict_types=1);

namespace App;

final class BknClient
{
    /**
     * Buat string Basic Auth (base64 dari username:password).
     */
    public static function buildBasicAuth(string $username, string $password): string
    {
        return base64_encode($username . ':' . $password);
    }

    /**
     * Batasi pengiriman Basic Auth ke URL token HTTPS yang dikonfigurasi server.
     */
    public static function resolveTokenUrl(string $configuredUrl, ?string $requestedUrl = null): string
    {
        $configured = self::assertSafeHttpsUrl($configuredUrl, 'BKN_TOKEN_URL');

        if ($requestedUrl !== null && trim($requestedUrl) !== '' && trim($requestedUrl) !== $configured) {
            throw new \InvalidArgumentException(
                'Token URL pada form harus sama dengan BKN_TOKEN_URL yang dikonfigurasi server.'
            );
        }

        return $configured;
    }

    /**
     * Validasi format NIP PNS (9 sampai 18 digit angka) agar aman disisipkan ke path URL.
     */
    public static function validateNip(string $nip): string
    {
        $clean = trim($nip);
        if ($clean === '') {
            throw new \InvalidArgumentException('NIP wajib diisi.');
        }
        if (preg_match('/^\d{9,18}$/', $clean) !== 1) {
            throw new \InvalidArgumentException('NIP harus berupa 9 sampai 18 digit angka.');
        }

        return $clean;
    }

    /**
     * Pastikan template URL Data Utama menampilkan placeholder {nip}.
     */
    public static function formatDataUtamaTemplate(string $configuredUrl): string
    {
        $trimmed = rtrim(trim($configuredUrl), '/');
        if ($trimmed === '') {
            return '';
        }
        if (str_contains($trimmed, '{nip}')) {
            return $trimmed;
        }

        return $trimmed . '/{nip}';
    }

    /**
     * Bangun URL endpoint Data Utama HTTPS dari konfigurasi server dan NIP yang tervalidasi.
     */
    public static function resolveDataUtamaUrl(
        string $configuredUrl,
        string $nip,
        ?string $requestedUrl = null
    ): string {
        $configured = self::assertSafeHttpsUrl($configuredUrl, 'BKN_DATA_UTAMA_URL');
        $cleanNip = self::validateNip($nip);
        $template = self::formatDataUtamaTemplate($configured);
        $targetUrl = str_replace('{nip}', $cleanNip, $template);

        if ($requestedUrl !== null && trim($requestedUrl) !== '') {
            $requested = rtrim(trim($requestedUrl), '/');
            $allowed = [
                rtrim($configured, '/'),
                rtrim($template, '/'),
                rtrim($targetUrl, '/'),
            ];
            if (!in_array($requested, $allowed, true)) {
                throw new \InvalidArgumentException(
                    'Data Utama URL pada form harus sama dengan BKN_DATA_UTAMA_URL yang dikonfigurasi server.'
                );
            }
        }

        return self::assertSafeHttpsUrl($targetUrl, 'BKN_DATA_UTAMA_URL');
    }

    /**
     * Kirim request POST application/x-www-form-urlencoded memakai PHP cURL.
     *
     * @param string[] $headers
     * @param array<string, string> $formParams
     * @return array{status: int, body: string}
     */
    public static function curlPostForm(
        string $url,
        array $headers,
        array $formParams,
        int $timeout = 30
    ): array {
        $encoded = http_build_query($formParams, '', '&', PHP_QUERY_RFC3986);
        return self::curlRequest('POST', $url, $headers, $encoded, $timeout);
    }

    /**
     * Kirim request GET memakai PHP cURL.
     *
     * @param string[] $headers
     * @return array{status: int, body: string}
     */
    public static function curlGet(
        string $url,
        array $headers,
        int $timeout = 30
    ): array {
        return self::curlRequest('GET', $url, $headers, null, $timeout);
    }

    /**
     * POST ke endpoint oauth2/token menggunakan Basic Auth untuk mengambil access_token.
     *
     * @return array{access_token: string, expires_in: int, expires_at: int}
     */
    public static function fetchTokenFromUrl(
        string $configuredUrl,
        ?string $requestedUrl,
        string $basicAuth,
        string $grantType = 'client_credentials',
        int $timeout = 30,
        ?callable $transport = null
    ): array {
        $safeUrl = self::resolveTokenUrl($configuredUrl, $requestedUrl);
        $effectiveGrantType = trim($grantType) !== '' ? trim($grantType) : 'client_credentials';

        $headers = [
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json',
            'Authorization: Basic ' . $basicAuth,
        ];
        $formParams = ['grant_type' => $effectiveGrantType];

        $sender = $transport ?? [self::class, 'curlPostForm'];
        $response = $sender($safeUrl, $headers, $formParams, $timeout);

        self::assertHttpSuccess($response, 'server token BKN');
        $rawBody = (string) ($response['body'] ?? '');
        $decoded = self::decodeJsonArray($rawBody, 'server token BKN');

        $token = $decoded['access_token'] ?? null;
        if (!is_string($token) || trim($token) === '') {
            $snippet = substr($rawBody, 0, 500);
            throw new \RuntimeException('access_token tidak ditemukan pada response: ' . $snippet);
        }

        $rawExpires = $decoded['expires_in'] ?? 3600;
        $expiresIn = is_numeric($rawExpires) ? (int) $rawExpires : 3600;
        if ($expiresIn <= 0) {
            $expiresIn = 3600;
        }

        return [
            'access_token' => $token,
            'expires_in' => $expiresIn,
            'expires_at' => time() + $expiresIn,
        ];
    }

    /**
     * GET ke endpoint SIASN BKN Data Utama PNS dengan header Authorization dan Auth.
     *
     * @return array{nip: string, url: string, http_status: int, payload: array<string, mixed>}
     */
    public static function fetchDataUtama(
        string $configuredUrl,
        ?string $requestedUrl,
        string $nip,
        string $accessToken,
        ?string $authHeaderToken = null,
        int $timeout = 30,
        ?callable $transport = null
    ): array {
        $safeUrl = self::resolveDataUtamaUrl($configuredUrl, $nip, $requestedUrl);
        $cleanNip = self::validateNip($nip);
        $parsedAccess = self::parseBearerToken($accessToken, 'Authorization Token');

        $authorizationHeader = 'Bearer ' . $parsedAccess['token'];
        $customAuth = $authHeaderToken !== null ? trim($authHeaderToken) : '';
        if ($customAuth !== '') {
            $parsedAuth = self::parseBearerToken($customAuth, 'Auth Header Token');
            $authScheme = $parsedAuth['scheme'] ?? 'bearer';
            $authHeader = $authScheme . ' ' . $parsedAuth['token'];
        } else {
            $authHeader = 'bearer ' . $parsedAccess['token'];
        }

        $headers = [
            'Accept: application/json',
            'Authorization: ' . $authorizationHeader,
            'Auth: ' . $authHeader,
        ];

        $sender = $transport ?? [self::class, 'curlGet'];
        $response = $sender($safeUrl, $headers, $timeout);

        self::assertHttpSuccess($response, 'server Data Utama BKN');
        $statusCode = (int) ($response['status'] ?? 0);
        $rawBody = (string) ($response['body'] ?? '');
        $decoded = self::decodeJsonArray($rawBody, 'server Data Utama BKN');

        return [
            'nip' => $cleanNip,
            'url' => $safeUrl,
            'http_status' => $statusCode,
            'payload' => $decoded,
        ];
    }

    private static function assertSafeHttpsUrl(string $url, string $configName): string
    {
        $trimmed = trim($url);
        $parts = parse_url($trimmed);

        if (
            !is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || empty($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['fragment'])
        ) {
            throw new \InvalidArgumentException(
                $configName . ' harus berupa URL HTTPS yang valid tanpa kredensial atau fragmen.'
            );
        }

        return $trimmed;
    }

    /**
     * @return array{scheme: ?string, token: string}
     */
    private static function parseBearerToken(string $rawToken, string $fieldLabel): array
    {
        $trimmed = trim($rawToken);
        if (preg_match('/[\x00-\x1F\x7F]/', $trimmed) === 1) {
            throw new \InvalidArgumentException($fieldLabel . ' mengandung karakter tidak valid.');
        }
        if ($trimmed === '') {
            throw new \InvalidArgumentException($fieldLabel . ' wajib diisi.');
        }
        if (preg_match('/^bearer$/i', $trimmed) === 1) {
            throw new \InvalidArgumentException($fieldLabel . ' belum berisi nilai token.');
        }
        if (preg_match('/^(bearer)\s+(.+)$/i', $trimmed, $matches) === 1) {
            $inner = trim($matches[2]);
            if ($inner === '') {
                throw new \InvalidArgumentException($fieldLabel . ' wajib diisi.');
            }
            return ['scheme' => $matches[1], 'token' => $inner];
        }

        return ['scheme' => null, 'token' => $trimmed];
    }

    /**
     * @param string[] $headers
     * @return array{status: int, body: string}
     */
    private static function curlRequest(
        string $method,
        string $url,
        array $headers,
        ?string $body,
        int $timeout
    ): array {
        if (!function_exists('curl_init')) {
            throw new \RuntimeException('Ekstensi PHP cURL tidak aktif pada server ini.');
        }

        $ch = curl_init($url);
        if ($ch === false) {
            throw new \RuntimeException('Gagal menginisialisasi koneksi cURL ke server BKN.');
        }

        try {
            $options = [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT => max(1, $timeout),
                CURLOPT_CONNECTTIMEOUT => min(max(1, $timeout), 15),
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_HTTPHEADER => $headers,
            ];

            if (strtoupper($method) === 'POST') {
                $options[CURLOPT_POST] = true;
                $options[CURLOPT_POSTFIELDS] = $body ?? '';
            } else {
                $options[CURLOPT_HTTPGET] = true;
            }

            curl_setopt_array($ch, $options);

            $responseBody = curl_exec($ch);
            $errno = curl_errno($ch);
            $error = curl_error($ch);
            $statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $redirectUrl = (string) (curl_getinfo($ch, CURLINFO_REDIRECT_URL) ?: '');

            if ($responseBody === false || $errno !== 0) {
                throw self::mapCurlError($errno, $error);
            }

            return [
                'status' => $statusCode,
                'body' => (string) $responseBody,
                'redirect_url' => $redirectUrl,
            ];
        } finally {
            curl_close($ch);
        }
    }

    /**
     * @param array<string, mixed> $response
     */
    private static function assertHttpSuccess(array $response, string $serverLabel): void
    {
        $statusCode = (int) ($response['status'] ?? 0);
        if ($statusCode >= 200 && $statusCode < 300) {
            return;
        }

        $rawBody = trim((string) ($response['body'] ?? ''));
        $redirectUrl = trim((string) ($response['redirect_url'] ?? ''));
        if ($redirectUrl !== '' && $statusCode >= 300 && $statusCode < 400) {
            throw new \RuntimeException(
                sprintf('HTTP %d dari %s (redirect ke %s).', $statusCode, $serverLabel, $redirectUrl)
            );
        }

        $detail = substr($rawBody, 0, 500);
        throw new \RuntimeException(
            sprintf('HTTP %d dari %s: %s', $statusCode, $serverLabel, $detail !== '' ? $detail : '(body kosong)')
        );
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodeJsonArray(string $rawBody, string $serverLabel): array
    {
        $decoded = json_decode($rawBody, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException('Respons ' . $serverLabel . ' bukan JSON yang valid.');
        }
        if (!is_array($decoded)) {
            throw new \RuntimeException('Format respons ' . $serverLabel . ' tidak valid.');
        }

        return $decoded;
    }

    private static function mapCurlError(int $errno, string $error): \RuntimeException
    {
        if ($errno === CURLE_OPERATION_TIMEDOUT) {
            return new \RuntimeException('Koneksi atau respons server token BKN timeout.');
        }
        if (in_array($errno, [CURLE_SSL_CONNECT_ERROR, CURLE_PEER_FAILED_VERIFICATION, CURLE_SSL_CACERT_BADFILE], true)) {
            return new \RuntimeException('Gagal verifikasi SSL/TLS dengan server BKN.');
        }
        if ($errno === CURLE_COULDNT_CONNECT || $errno === CURLE_COULDNT_RESOLVE_HOST) {
            return new \RuntimeException('Tidak dapat terhubung ke server BKN (koneksi ditolak/gagal resolve host).');
        }
        $clean = trim($error);
        return new \RuntimeException($clean !== '' ? ('Kesalahan cURL ke server BKN: ' . $clean) : 'Terjadi kesalahan jaringan cURL ke server BKN.');
    }
}

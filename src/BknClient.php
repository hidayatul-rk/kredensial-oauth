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
        $configured = trim($configuredUrl);
        $parts = parse_url($configured);

        if (
            !is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || empty($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['fragment'])
        ) {
            throw new \InvalidArgumentException(
                'BKN_TOKEN_URL harus berupa URL HTTPS yang valid tanpa kredensial atau fragmen.'
            );
        }

        if ($requestedUrl !== null && trim($requestedUrl) !== '' && trim($requestedUrl) !== $configured) {
            throw new \InvalidArgumentException(
                'Token URL pada form harus sama dengan BKN_TOKEN_URL yang dikonfigurasi server.'
            );
        }

        return $configured;
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
        if (!function_exists('curl_init')) {
            throw new \RuntimeException('Ekstensi PHP cURL tidak aktif pada server ini.');
        }

        $ch = curl_init($url);
        if ($ch === false) {
            throw new \RuntimeException('Gagal menginisialisasi koneksi cURL ke server BKN.');
        }

        try {
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT => max(1, $timeout),
                CURLOPT_CONNECTTIMEOUT => min(max(1, $timeout), 15),
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_POSTFIELDS => http_build_query($formParams, '', '&', PHP_QUERY_RFC3986),
            ]);

            $responseBody = curl_exec($ch);
            $errno = curl_errno($ch);
            $error = curl_error($ch);
            $statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

            if ($responseBody === false || $errno !== 0) {
                throw self::mapCurlError($errno, $error);
            }

            return [
                'status' => $statusCode,
                'body' => (string) $responseBody,
            ];
        } finally {
            curl_close($ch);
        }
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

        $statusCode = (int) ($response['status'] ?? 0);
        $rawBody = (string) ($response['body'] ?? '');

        if ($statusCode < 200 || $statusCode >= 300) {
            $detail = substr(trim($rawBody), 0, 500);
            throw new \RuntimeException(
                sprintf('HTTP %d dari server token BKN: %s', $statusCode, $detail !== '' ? $detail : '(body kosong)')
            );
        }

        $decoded = json_decode($rawBody, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException('Respons server token BKN bukan JSON yang valid.');
        }
        if (!is_array($decoded)) {
            throw new \RuntimeException('Format respons server token BKN tidak valid.');
        }

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

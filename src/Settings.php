<?php
declare(strict_types=1);

namespace App;

final class Settings
{
    public const APP_VERSION = '1.0.0';

    public string $bknHost;
    public string $bknApiHost;
    public string $tokenPath;
    public string $tokenUrl;
    public string $dataUtamaPath;
    public string $dataUtamaUrl;
    public string $grantType;
    public int $timeout;
    public string $appBasicUser;
    public string $appBasicPassword;
    /** @var string[] */
    public array $trustedHosts;
    public bool $trustProxy;
    public bool $cookieSecure;
    public int $loginRateMax;
    public float $loginRateWindow;

    public function __construct(
        string $bknHost = 'https://apimws.bkn.go.id',
        string $tokenPath = '/oauth2/token',
        string $tokenUrl = '',
        string $grantType = 'client_credentials',
        int $timeout = 30,
        string $appBasicUser = '',
        string $appBasicPassword = '',
        array $trustedHosts = ['127.0.0.1', 'localhost', '::1'],
        bool $trustProxy = false,
        bool $cookieSecure = false,
        int $loginRateMax = 10,
        float $loginRateWindow = 60.0,
        string $dataUtamaPath = '/apisiasn/1.0/pns/data-utama',
        string $dataUtamaUrl = '',
        string $bknApiHost = ''
    ) {
        $this->bknHost = rtrim(trim($bknHost), '/');
        $this->tokenPath = trim($tokenPath) !== '' ? trim($tokenPath) : '/oauth2/token';
        $explicitUrl = trim($tokenUrl);
        $this->tokenUrl = $explicitUrl !== '' ? $explicitUrl : ($this->bknHost . $this->tokenPath);

        $explicitApiHost = rtrim(trim($bknApiHost), '/');
        if ($explicitApiHost !== '') {
            $this->bknApiHost = $explicitApiHost;
        } elseif ($this->bknHost === 'https://apimws.bkn.go.id') {
            // Gateway API SIASN pada apimws.bkn.go.id menggunakan port 8243 (port 443 hanya untuk /oauth2/token & console).
            $this->bknApiHost = 'https://apimws.bkn.go.id:8243';
        } else {
            $this->bknApiHost = $this->bknHost;
        }

        $rawDataUtamaPath = trim($dataUtamaPath);
        $this->dataUtamaPath = $rawDataUtamaPath !== ''
            ? ('/' . ltrim(rtrim($rawDataUtamaPath, '/'), '/'))
            : '/apisiasn/1.0/pns/data-utama';
        $explicitDataUtamaUrl = rtrim(trim($dataUtamaUrl), '/');
        $this->dataUtamaUrl = $explicitDataUtamaUrl !== ''
            ? $explicitDataUtamaUrl
            : ($this->bknApiHost . $this->dataUtamaPath);

        $this->grantType = trim($grantType) !== '' ? trim($grantType) : 'client_credentials';
        $this->timeout = max(1, $timeout);
        $this->appBasicUser = trim($appBasicUser);
        $this->appBasicPassword = $appBasicPassword;
        $this->trustedHosts = $trustedHosts;
        $this->trustProxy = $trustProxy;
        $this->cookieSecure = $cookieSecure;
        $this->loginRateMax = max(0, $loginRateMax);
        $this->loginRateWindow = max(1.0, $loginRateWindow);
    }

    public static function fromEnv(?string $baseDir = null): self
    {
        $root = $baseDir ?? dirname(__DIR__);
        EnvLoader::load($root . DIRECTORY_SEPARATOR . '.env');

        $trustedRaw = self::env('APP_TRUSTED_HOSTS', '');
        if ($trustedRaw === '') {
            $trustedRaw = self::env('TRUSTED_HOSTS', '127.0.0.1,localhost,::1');
        }
        $trustedHosts = array_values(array_filter(
            array_map(static fn(string $h): string => strtolower(trim($h)), explode(',', $trustedRaw)),
            static fn(string $h): bool => $h !== ''
        ));
        if ($trustedHosts === []) {
            $trustedHosts = ['127.0.0.1', 'localhost', '::1'];
        }

        return new self(
            bknHost: self::env('BKN_HOST', 'https://apimws.bkn.go.id'),
            tokenPath: self::env('BKN_TOKEN_PATH', '/oauth2/token'),
            tokenUrl: self::env('BKN_TOKEN_URL', ''),
            grantType: self::env('BKN_GRANT_TYPE', 'client_credentials'),
            timeout: (int) self::env('TIMEOUT', '30'),
            appBasicUser: self::env('APP_BASIC_USER', ''),
            appBasicPassword: self::env('APP_BASIC_PASSWORD', ''),
            trustedHosts: $trustedHosts,
            trustProxy: self::env('TRUST_PROXY', '0') === '1',
            cookieSecure: self::env('COOKIE_SECURE', '0') === '1',
            loginRateMax: (int) self::env('LOGIN_RATE_MAX', '10'),
            loginRateWindow: (float) self::env('LOGIN_RATE_WINDOW', '60'),
            dataUtamaPath: self::env('BKN_DATA_UTAMA_PATH', '/apisiasn/1.0/pns/data-utama'),
            dataUtamaUrl: self::env('BKN_DATA_UTAMA_URL', ''),
            bknApiHost: self::env('BKN_API_HOST', '')
        );
    }

    private static function env(string $key, string $default): string
    {
        if (array_key_exists($key, $_ENV)) {
            return (string) $_ENV[$key];
        }
        $val = getenv($key);
        return $val !== false ? (string) $val : $default;
    }
}

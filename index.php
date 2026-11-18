<?php
declare(strict_types=1);

require_once __DIR__ . '/src/bootstrap.php';

use App\AuthHandler;
use App\BknClient;
use App\Security;
use App\Settings;

$settings = Settings::fromEnv(__DIR__);
$boot = AuthHandler::bootstrapRequest($settings, $_COOKIE, $_SERVER);
if (!$boot['ok']) {
    AuthHandler::emitJsonResponse($boot);
    exit;
}

Security::sendSecurityHeaders();
header('Content-Type: text/html; charset=utf-8');

$e = static fn(string $value): string => htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$csrfToken = (string) $boot['csrf_token'];
$dataUtamaTemplateUrl = BknClient::formatDataUtamaTemplate($settings->dataUtamaUrl);
?>
<!doctype html>
<html lang="id">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="csrf-token" content="<?= $e($csrfToken) ?>" />
    <meta name="test-token-url" content="test-token.php" />
    <meta name="data-utama-url" content="datautama.php" />
    <title>Kredensial API BKN - SIASN</title>
    <script>
        try {
            const savedTheme = localStorage.getItem("bkn_kredensial_theme");
            document.documentElement.dataset.theme = savedTheme === "dark" || savedTheme === "light"
                ? savedTheme
                : (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
        } catch (_) {
            document.documentElement.dataset.theme = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
        }
    </script>
    <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='5' fill='%231f4e79'/%3E%3Cpath d='M15 7a4 4 0 1 0-3.87 5L7 16.13V19h2.87l1.13-1.13V16h1.87l1.26-1.26A4 4 0 0 0 15 7Z' stroke='white' stroke-width='1.7' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E" />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="static/css/app.css" />
</head>
<body>
    <header class="topbar">
        <div class="brand">
            <span class="brand-mark" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="15" cy="9" r="4"/><path d="M12.2 11.8 6 18v3h3l1.5-1.5V18H12l1.2-1.2"/></svg>
            </span>
            <div class="brand-text">
                <h1>Kredensial API BKN</h1>
                <span class="brand-sub">SIASN BKN &middot; OAuth2 (PHP cURL) &middot; <span class="app-ver" title="Versi aplikasi">v<?= $e(Settings::APP_VERSION) ?></span></span>
            </div>
        </div>
        <div class="topbar-actions">
            <button type="button" class="theme-toggle" id="themeToggle" aria-pressed="false">
                <svg class="theme-icon-light" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>
                <svg class="theme-icon-dark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20.4 14.2A8.5 8.5 0 0 1 9.8 3.6 8.5 8.5 0 1 0 20.4 14.2Z"/></svg>
                <span id="themeLabel">Tema: Terang</span>
            </button>
            <div class="conn" id="connStatus" role="status" aria-live="polite">
                <span class="dot" id="connDot" aria-hidden="true"></span>
                <span id="connText">Token belum diuji</span>
            </div>
        </div>
    </header>

    <main class="stage">
        <section class="card" aria-labelledby="cardTitle">
            <div class="card-head">
                <h2 id="cardTitle">Kredensial API BKN</h2>
                <span class="card-sub"><?= $e($settings->grantType) ?></span>
            </div>
            <div class="card-body">
                <p class="settings-note">Gunakan Client ID dan Client Secret untuk mengambil token OAuth2 BKN secara otomatis melalui PHP cURL, atau tempel token secara manual.</p>

                <form id="credentialsForm" onsubmit="event.preventDefault(); testToken();">
                    <div class="form-group">
                        <label for="username">Username (Client ID)</label>
                        <input type="text" id="username" placeholder="OAuth2 Username" autocomplete="username" />
                    </div>
                    <div class="form-group">
                        <label for="password">Password (Client Secret)</label>
                        <div class="input-box">
                            <input type="password" id="password" placeholder="OAuth2 Password" autocomplete="current-password" />
                            <div class="input-actions">
                                <button type="button" class="toggle-vis" onclick="toggleVis('password', this)" aria-pressed="false">Lihat</button>
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="tokenUrl">Token URL</label>
                        <div class="hint">Diatur oleh server melalui <code>BKN_TOKEN_URL</code>.</div>
                        <input type="text" id="tokenUrl" value="<?= $e($settings->tokenUrl) ?>" readonly />
                    </div>

                    <button type="submit" class="btn btn-outline btn-full" id="btnTestToken">Uji Login &amp; Ambil Token</button>
                    <div id="tokenResult" class="conn-result" role="status" aria-live="polite"></div>
                </form>

                <hr class="divider" />

                <div class="form-group">
                    <label for="accessToken">Authorization Token</label>
                    <div class="hint">Terisi otomatis bila uji login berhasil.</div>
                    <div class="input-box">
                        <input type="password" id="accessToken" placeholder="Bearer ..." />
                        <div class="input-actions">
                            <button type="button" class="toggle-vis" onclick="toggleVis('accessToken', this)" aria-pressed="false">Lihat</button>
                            <button type="button" class="toggle-vis" onclick="copyToken('accessToken', this)">Salin</button>
                        </div>
                    </div>
                </div>
                <div class="form-group">
                    <label for="authHeaderToken">Auth Header Token</label>
                    <div class="hint">Header <code>Auth</code> khusus SIASN. Kosongkan bila sama.</div>
                    <div class="input-box">
                        <input type="password" id="authHeaderToken" placeholder="Kosongkan bila sama" />
                        <div class="input-actions">
                            <button type="button" class="toggle-vis" onclick="toggleVis('authHeaderToken', this)" aria-pressed="false">Lihat</button>
                            <button type="button" class="toggle-vis" onclick="copyToken('authHeaderToken', this)">Salin</button>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section class="card" aria-labelledby="dataUtamaTitle">
            <div class="card-head">
                <h2 id="dataUtamaTitle">Uji Data Utama PNS (SIASN)</h2>
                <span class="card-sub">GET /pns/data-utama/{nip}</span>
            </div>
            <div class="card-body">
                <p class="settings-note">Masukkan NIP PNS untuk mengambil data utama dari API SIASN BKN menggunakan <strong>Authorization Token</strong> dan <strong>Auth Header Token</strong> di atas.</p>

                <form id="dataUtamaForm" onsubmit="event.preventDefault(); fetchDataUtama();">
                    <div class="form-group">
                        <label for="nipInput">NIP PNS</label>
                        <div class="hint">Masukkan 9 sampai 18 digit angka NIP (contoh: <code>198612262009121001</code>).</div>
                        <input type="text" id="nipInput" inputmode="numeric" maxlength="18" placeholder="18 digit NIP PNS" autocomplete="off" />
                    </div>
                    <div class="form-group">
                        <label for="dataUtamaUrl">Data Utama URL</label>
                        <div class="hint">Diatur oleh server melalui <code>BKN_DATA_UTAMA_URL</code> atau <code>BKN_API_HOST</code> + <code>BKN_DATA_UTAMA_PATH</code>.</div>
                        <input type="text" id="dataUtamaUrl" value="<?= $e($dataUtamaTemplateUrl) ?>" readonly />
                    </div>

                    <button type="submit" class="btn btn-primary btn-full" id="btnFetchDataUtama">Ambil Data Utama</button>
                    <div id="dataUtamaResult" class="conn-result" role="status" aria-live="polite"></div>
                </form>

                <div id="dataUtamaResponsePanel" class="response-panel" hidden>
                    <hr class="divider" />
                    <div class="response-head">
                        <span class="response-title">Respons Data Utama</span>
                        <div class="response-actions">
                            <button type="button" class="toggle-vis" id="btnCopyDataUtama" onclick="copyDataUtamaJson(this)">Salin JSON</button>
                            <button type="button" class="toggle-vis" onclick="clearDataUtamaResult()">Bersihkan</button>
                        </div>
                    </div>
                    <div id="dataUtamaSummary" class="summary-grid" hidden></div>
                    <pre id="dataUtamaJson" class="json-output"></pre>
                </div>
            </div>
        </section>
    </main>

    <script src="static/js/theme.js" defer></script>
    <script src="static/js/api.js" defer></script>
    <script src="static/js/credentials.js" defer></script>
</body>
</html>

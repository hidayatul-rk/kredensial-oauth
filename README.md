# Kredensial API BKN (PHP cURL)

Aplikasi web **PHP + cURL** mandiri (tanpa dependency eksternal / Composer) yang hanya mengambil modul **Kredensial API BKN** dari proyek `bkn-diklat-import-web` untuk menguji login OAuth2 (`client_credentials`) dan menyalin token API SIASN BKN.

## Kebutuhan

- PHP 8.1+ (teruji pada PHP 8.2.12 XAMPP) dengan ekstensi `curl` dan `json` aktif.

## Fitur

- Form **Kredensial API BKN**:
  - `Username (Client ID)`
  - `Password (Client Secret)` dengan tombol `Lihat` / `Sembunyikan`
  - `Token URL` yang dikunci ke konfigurasi server (`.env`, default `https://apimws.bkn.go.id/oauth2/token`)
  - Tombol **Uji Login & Ambil Token** melalui `POST test-token.php` (atau `/test-token` / `/login`) menggunakan PHP `curl_init`
  - `Authorization Token` (terisi otomatis saat uji login berhasil) dengan tombol `Lihat` dan `Salin`
  - `Auth Header Token` (opsional untuk header `Auth` SIASN) dengan tombol `Lihat` dan `Salin`
- Form **Uji Data Utama PNS (SIASN)**:
  - Input `NIP PNS` (9 sampai 18 digit angka)
  - `Data Utama URL` yang dikunci ke konfigurasi server (`.env`, default `https://apimws.bkn.go.id:8243/apisiasn/1.0/pns/data-utama/{nip}`)
  - Tombol **Ambil Data Utama** melalui `POST datautama.php` (atau `/datautama`) menggunakan PHP `curl_init` dengan header `Authorization: Bearer ...` dan `Auth: bearer ...`
  - Ringkasan data pegawai & panel JSON dengan tombol `Salin JSON` dan `Bersihkan`
- Indikator status koneksi real-time pada topbar dan toggle tema **Terang / Gelap** (`localStorage`).
- Pengamanan bawaan: proteksi CSRF, validasi URL token HTTPS (anti-SSRF), rate limiting percobaan login, validasi `Host` header, security headers, dan HTTP Basic Auth opsional untuk akses non-loopback.

## Konfigurasi Environment

Salin `.env.example` menjadi `.env` bila ingin menyesuaikan konfigurasi (saat memakai `run.bat`, file `.env` dibuat otomatis dari `.env.example` jika belum ada):

```powershell
Copy-Item .env.example .env
```

### Variabel Endpoint & OAuth2 BKN
- `BKN_HOST` — host OAuth2 BKN (default `https://apimws.bkn.go.id`)
- `BKN_TOKEN_PATH` — path token OAuth2 (default `/oauth2/token`)
- `BKN_TOKEN_URL` — URL token HTTPS penuh; bila kosong memakai `BKN_HOST` + `BKN_TOKEN_PATH`
- `BKN_API_HOST` — host API Gateway SIASN BKN (default `https://apimws.bkn.go.id:8243` saat `BKN_HOST` memakai `https://apimws.bkn.go.id`)
- `BKN_DATA_UTAMA_PATH` — path endpoint Data Utama PNS SIASN (default `/apisiasn/1.0/pns/data-utama`)
- `BKN_DATA_UTAMA_URL` — URL Data Utama HTTPS penuh; bila kosong memakai `BKN_API_HOST` + `BKN_DATA_UTAMA_PATH` (mendukung placeholder `{nip}`)
- `BKN_GRANT_TYPE` — tipe grant OAuth2 (default `client_credentials`)
- `TIMEOUT` — timeout request cURL dalam detik (default `30`)

### Variabel Keamanan Server
- `APP_BASIC_USER`, `APP_BASIC_PASSWORD` — akun HTTP Basic Auth untuk aplikasi; **wajib diisi** bila diakses selain dari loopback (`127.0.0.1`, `localhost`, `::1`)
- `APP_TRUSTED_HOSTS` — daftar host yang diizinkan pada header `Host` (default `127.0.0.1,localhost,::1`)
- `TRUST_PROXY` — isi `1` hanya bila aplikasi berada di belakang reverse proxy tepercaya (untuk membaca `X-Forwarded-For`)
- `COOKIE_SECURE` — isi `1` bila aplikasi dilayani melalui HTTPS agar cookie CSRF ditandai `Secure`
- `LOGIN_RATE_MAX`, `LOGIN_RATE_WINDOW` — batas percobaan login per IP dan jendela waktunya dalam detik (default `10` percobaan per `60` detik; isi `0` untuk menonaktifkan)

## Cara Menjalankan

### 1. Menggunakan `run.bat` (Windows)

Klik ganda `run.bat` atau jalankan di terminal:

```powershell
.\run.bat
```

`run.bat` akan mendeteksi PHP (dari `PATH` atau `C:\xampp\php\php.exe`), memastikan ekstensi `curl` dan `json` aktif, membuat `.env` dari `.env.example` bila belum ada, menjalankan server lokal di `http://127.0.0.1:8000`, dan membuka browser otomatis. Anda juga dapat menentukan port lain:

```powershell
.\run.bat 8080
```

### 2. Menggunakan PHP Built-in Server Manual

```powershell
php -S 127.0.0.1:8000 router.php
```

Lalu buka `http://127.0.0.1:8000` di browser.

### 3. Menggunakan Apache (XAMPP)

Salin atau arahkan folder ini ke `htdocs` (misalnya `C:\xampp\htdocs\kredential-oauth`), lalu buka `http://localhost/kredential-oauth/`. File `.htaccess` sudah disertakan untuk memblokir akses langsung ke `src/`, `tests/`, dan file bertitik (`.env`, `.env.example`).

## Endpoint Internal

- `GET /` (`index.php`) — halaman utama UI Kredensial API BKN
- `POST /test-token.php` (alias `/test-token`, `/login` via `router.php`/`.htaccess`) — menukar `username` & `password` dengan `access_token` OAuth2 BKN melalui PHP cURL
- `POST /datautama.php` (alias `/datautama` via `router.php`/`.htaccess`) — mengambil Data Utama PNS SIASN BKN (`GET` ke URL BKN terkonfigurasi) memakai `nip`, `access_token`, dan opsional `auth_header_token`
- `GET /version.php` (alias `/version`) — mengembalikan versi aplikasi (`1.0.0`) dalam format JSON

## Keamanan Kredensial & Hardening

- **File `.env` tidak di-commit.** `.gitignore` mengabaikan `.env`, `*.env`, dan `.env.*` (kecuali `.env.example`). Jangan pernah menyimpan `Client Secret` atau token asli di dalam repository.
- **Tujuan token tetap & wajib HTTPS.** `BknClient::resolveTokenUrl()` menolak URL non-HTTPS, URL berisi kredensial/fragmen, serta URL pada form yang tidak cocok dengan konfigurasi server; `CURLOPT_FOLLOWLOCATION` juga dinonaktifkan (`false`).
- **Verifikasi SSL/TLS aktif.** PHP cURL menjalankan `CURLOPT_SSL_VERIFYPEER => true` dan `CURLOPT_SSL_VERIFYHOST => 2`.
- **Proteksi CSRF.** Request `POST` wajib mengirim token CSRF yang cocok antara cookie `csrf_token` dan header `X-CSRF-Token` atau field `csrf_token`.
- **Pembatasan host & jaringan.** Header `Host` divalidasi terhadap `APP_TRUSTED_HOSTS`, dan akses dari IP non-loopback ditolak dengan HTTP `503` bila `APP_BASIC_USER`/`APP_BASIC_PASSWORD` belum diatur.
- **Header keamanan & sanitasi error.** Setiap respons menyertakan `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, dan `Cache-Control: no-store`. Path absolut server disaring dari pesan error.

## Struktur Kode

- `index.php` — halaman antarmuka web utama
- `test-token.php` — endpoint JSON untuk permintaan token OAuth2
- `datautama.php` — endpoint JSON untuk pengambilan Data Utama PNS SIASN BKN
- `version.php` — endpoint JSON informasi versi aplikasi
- `router.php` — router PHP built-in server (termasuk blokir path sensitif)
- `run.bat` — launcher server lokal Windows
- `.htaccess` — aturan perlindungan folder/file & rewrite untuk Apache
- `src/EnvLoader.php` — parser file `.env` tanpa dependency eksternal
- `src/Settings.php` — pembaca konfigurasi environment dan versi aplikasi
- `src/BknClient.php` — pembentuk header Basic Auth, validasi URL token, dan client PHP cURL
- `src/Security.php` — proteksi CSRF, validasi `Host`, Basic Auth aplikasi, rate limiter, dan sanitasi error
- `src/AuthHandler.php` — koordinator request halaman dan endpoint token
- `src/bootstrap.php` — loader modul di `src/`
- `static/css/app.css` — stylesheet tema terang & gelap
- `static/js/theme.js`, `api.js`, `credentials.js` — pengelola tema, helper CSRF, uji token, toggle lihat/sembunyikan, dan salin token
- `tests/run_tests.php` — rangkaian pengujian otomatis CLI & smoke test server lokal

## Menjalankan Pengujian

```powershell
php tests/run_tests.php
```

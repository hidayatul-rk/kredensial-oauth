@echo off
setlocal
cd /d "%~dp0"
title Kredensial API BKN - Server Lokal

set "PORT=8000"
if not "%~1"=="" set "PORT=%~1"

for /f "delims=0123456789" %%A in ("%PORT%") do (
    echo [ERROR] Port tidak valid: %PORT%
    pause
    exit /b 1
)
if %PORT% lss 1 (
    echo [ERROR] Port tidak valid: %PORT%
    pause
    exit /b 1
)
if %PORT% gtr 65535 (
    echo [ERROR] Port tidak valid: %PORT%
    pause
    exit /b 1
)

set "PHP_BIN="
where php >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%I in ('where php') do (
        if not defined PHP_BIN set "PHP_BIN=%%I"
    )
)
if not defined PHP_BIN (
    if exist "C:\xampp\php\php.exe" set "PHP_BIN=C:\xampp\php\php.exe"
)
if not defined PHP_BIN (
    echo [ERROR] PHP tidak ditemukan di PATH maupun C:\xampp\php\php.exe.
    echo         Pastikan PHP 8.1+ sudah terpasang.
    pause
    exit /b 1
)

"%PHP_BIN%" -r "exit(extension_loaded('curl') && extension_loaded('json') ? 0 : 1);" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Ekstensi PHP curl atau json belum aktif pada %PHP_BIN%.
    pause
    exit /b 1
)

if not exist ".env" (
    if exist ".env.example" (
        copy /Y ".env.example" ".env" >nul
    )
)

"%PHP_BIN%" -r "$fp = @fsockopen('127.0.0.1', %PORT%, $e, $s, 0.2); if ($fp) { fclose($fp); exit(0); } exit(1);" >nul 2>&1
if not errorlevel 1 (
    echo Server sudah berjalan di http://127.0.0.1:%PORT%
    if not "%NO_BROWSER%"=="1" start "" http://127.0.0.1:%PORT%
    echo Tekan sembarang tombol untuk menutup jendela ini...
    pause >nul
    exit /b 0
)

echo.
echo Menjalankan Kredensial API BKN (PHP cURL) di http://127.0.0.1:%PORT%
echo PHP: %PHP_BIN%
echo Tekan Ctrl+C untuk menghentikan server.
echo.

if not "%NO_BROWSER%"=="1" start /b "" cmd /c ping 127.0.0.1 -n 3 ^>nul ^& start "" http://127.0.0.1:%PORT%
"%PHP_BIN%" -S 127.0.0.1:%PORT% router.php

echo.
echo Server dihentikan.
pause

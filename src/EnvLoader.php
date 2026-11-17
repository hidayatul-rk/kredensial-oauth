<?php
declare(strict_types=1);

namespace App;

final class EnvLoader
{
    /**
     * Muat pasangan KEY=VALUE dari file .env ke $_ENV dan getenv() bila belum disetel.
     */
    public static function load(string $filePath): void
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            return;
        }

        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return;
        }

        foreach ($lines as $rawLine) {
            $line = trim($rawLine);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if (str_starts_with($line, 'export ')) {
                $line = trim(substr($line, 7));
            }

            $eqPos = strpos($line, '=');
            if ($eqPos === false) {
                continue;
            }

            $key = trim(substr($line, 0, $eqPos));
            if ($key === '' || !preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $key)) {
                continue;
            }

            $value = trim(substr($line, $eqPos + 1));
            $value = self::unquote($value);

            if (getenv($key) === false && !array_key_exists($key, $_ENV) && !array_key_exists($key, $_SERVER)) {
                putenv($key . '=' . $value);
                $_ENV[$key] = $value;
            }
        }
    }

    private static function unquote(string $value): string
    {
        $len = strlen($value);
        if ($len >= 2) {
            $first = $value[0];
            $last = $value[$len - 1];
            if (($first === '"' && $last === '"') || ($first === "'" && $last === "'")) {
                return substr($value, 1, -1);
            }
        }

        $commentPos = strpos($value, ' #');
        if ($commentPos !== false) {
            return rtrim(substr($value, 0, $commentPos));
        }

        return $value;
    }
}

<?php

declare(strict_types=1);

namespace VerifyBlind\Cache;

/**
 * Small file cache with the PSR-16 get/set shape, for hosts without Redis/APCu. It only ever stores
 * VerifyBlind PUBLIC keys, never tokens or identity codes.
 */
final class FileCache
{
    /** @var string */
    private $dir;

    public function __construct(?string $dir = null)
    {
        $this->dir = rtrim($dir ?? (sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'verifyblind-cache'), '/\\');
    }

    /**
     * @param mixed $default
     * @return mixed
     */
    public function get(string $key, $default = null)
    {
        $raw = @file_get_contents($this->path($key));
        if (false === $raw) {
            return $default;
        }
        $record = json_decode($raw, true);
        if (!is_array($record) || !array_key_exists('v', $record)) {
            return $default;
        }
        $exp = $record['e'] ?? null;
        if (null !== $exp && time() >= (int) $exp) {
            return $default;
        }
        return $record['v'];
    }

    /**
     * @param mixed $value
     * @param int|null $ttl seconds
     */
    public function set(string $key, $value, $ttl = null): bool
    {
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            return false;
        }
        $path = $this->path($key);
        $tmp = $path . '.' . bin2hex(random_bytes(6)) . '.tmp';
        $json = json_encode(['v' => $value, 'e' => null === $ttl ? null : time() + (int) $ttl]);
        if (false === $json || false === @file_put_contents($tmp, $json, LOCK_EX)) {
            return false;
        }
        // rename() is atomic on the same filesystem: readers never see a half-written file.
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            return false;
        }
        return true;
    }

    private function path(string $key): string
    {
        return $this->dir . DIRECTORY_SEPARATOR . 'vb_' . hash('sha256', $key) . '.json';
    }
}

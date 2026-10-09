<?php

declare(strict_types=1);

namespace VerifyBlind\Cache;

/**
 * In-process cache with the PSR-16 get/set shape. Under PHP-FPM / Apache it lives for one request only,
 * so every request fetches the key once; use FileCache or your PSR-16 cache (Redis, APCu, ...) to share it.
 */
final class MemoryCache
{
    /** @var self|null */
    private static $shared;

    /** @var array<string, array{0: mixed, 1: int|null}> */
    private $items = [];

    /** One instance per process, used by Verifier when no cache is given. */
    public static function shared(): self
    {
        if (null === self::$shared) {
            self::$shared = new self();
        }
        return self::$shared;
    }

    /**
     * @param mixed $default
     * @return mixed
     */
    public function get(string $key, $default = null)
    {
        if (!isset($this->items[$key])) {
            return $default;
        }
        [$value, $expiresAt] = $this->items[$key];
        if (null !== $expiresAt && time() >= $expiresAt) {
            unset($this->items[$key]);
            return $default;
        }
        return $value;
    }

    /**
     * @param mixed $value
     * @param int|null $ttl seconds
     */
    public function set(string $key, $value, $ttl = null): bool
    {
        $this->items[$key] = [$value, null === $ttl ? null : time() + (int) $ttl];
        return true;
    }
}

<?php

declare(strict_types=1);

namespace VerifyBlind\Exception;

/**
 * The signed nonce is missing, unknown, expired or already used (replay).
 */
final class NonceException extends VerifyBlindException
{
    public const CODE = 'nonce_invalid';

    public function __construct(string $message, ?\Throwable $previous = null)
    {
        parent::__construct(self::CODE, $message, $previous);
    }

    public function getHttpStatus(): int
    {
        return 401;
    }
}

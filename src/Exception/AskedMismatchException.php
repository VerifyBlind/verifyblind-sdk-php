<?php

declare(strict_types=1);

namespace VerifyBlind\Exception;

/**
 * The signed answer does not match the validations your server asked for this nonce.
 */
final class AskedMismatchException extends VerifyBlindException
{
    public const CODE = 'asked_mismatch';

    public function __construct(string $message, ?\Throwable $previous = null)
    {
        parent::__construct(self::CODE, $message, $previous);
    }

    public function getHttpStatus(): int
    {
        return 401;
    }
}

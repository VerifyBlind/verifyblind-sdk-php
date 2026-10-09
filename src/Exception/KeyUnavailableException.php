<?php

declare(strict_types=1);

namespace VerifyBlind\Exception;

/**
 * The VerifyBlind public key could not be fetched or read. An infrastructure error, not a rejection of the token.
 */
final class KeyUnavailableException extends VerifyBlindException
{
    public const CODE = 'key_unavailable';

    public function __construct(string $message, ?\Throwable $previous = null)
    {
        parent::__construct(self::CODE, $message, $previous);
    }

    public function getHttpStatus(): int
    {
        return 503;
    }
}

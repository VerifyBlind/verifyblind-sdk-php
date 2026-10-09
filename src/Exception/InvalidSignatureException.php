<?php

declare(strict_types=1);

namespace VerifyBlind\Exception;

/**
 * The enclave (or webhook) signature does not verify, even after refreshing the public key once.
 */
final class InvalidSignatureException extends VerifyBlindException
{
    public const CODE = 'bad_signature';

    public function __construct(string $message, ?\Throwable $previous = null)
    {
        parent::__construct(self::CODE, $message, $previous);
    }

    public function getHttpStatus(): int
    {
        return 401;
    }
}

<?php

declare(strict_types=1);

namespace VerifyBlind\Exception;

/**
 * The token (or webhook body) is not in the expected format: base64 of JSON {payload, signature}.
 */
final class InvalidTokenException extends VerifyBlindException
{
    public const CODE = 'bad_token';

    public function __construct(string $message, ?\Throwable $previous = null)
    {
        parent::__construct(self::CODE, $message, $previous);
    }

    public function getHttpStatus(): int
    {
        return 400;
    }
}

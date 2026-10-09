<?php

declare(strict_types=1);

namespace VerifyBlind\Exception;

/**
 * The result comes from a demo card (validations.is_test or TEST_ codes) and test cards are not allowed.
 */
final class TestCardException extends VerifyBlindException
{
    public const CODE = 'test_card';

    public function __construct(string $message, ?\Throwable $previous = null)
    {
        parent::__construct(self::CODE, $message, $previous);
    }

    public function getHttpStatus(): int
    {
        return 403;
    }
}

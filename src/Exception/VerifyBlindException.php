<?php

declare(strict_types=1);

namespace VerifyBlind\Exception;

/**
 * Base class for every error this library throws.
 *
 * `getErrorCode()` returns a stable machine-readable code (e.g. "bad_signature") you can branch on
 * or return to your client. Messages never contain identity codes (user_id / nsbd_id / doc_id).
 */
class VerifyBlindException extends \RuntimeException
{
    /** @var string */
    private $errorCode;

    public function __construct(string $errorCode, string $message, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->errorCode = $errorCode;
    }

    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    /** Suggested HTTP status for your verify endpoint's response. */
    public function getHttpStatus(): int
    {
        return 400;
    }
}

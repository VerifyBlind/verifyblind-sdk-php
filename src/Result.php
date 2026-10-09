<?php

declare(strict_types=1);

namespace VerifyBlind;

/**
 * A result whose enclave signature has been verified.
 *
 * A Result from Verifier::verifyToken() only proves that the enclave signed it. Before you act on it,
 * consume its nonce and check it against what you asked — Verifier::verify() does both.
 *
 * Identity codes (userId / nsbdId / docId) are pseudonymous personal data: store them like other user
 * data, and never log or echo them. __debugInfo() hides them from var_dump() and print_r().
 */
final class Result
{
    /** @var array<string, mixed> */
    private $payload;

    /** @var array<string, mixed>|null */
    private $asked;

    /**
     * @param array<string, mixed> $payload the parsed, signed payload
     * @param array<string, mixed>|null $asked the validations your server stored with the nonce, if checked
     */
    public function __construct(array $payload, ?array $asked = null)
    {
        $this->payload = $payload;
        $this->asked = $asked;
    }

    /** The same result, marked as checked against the validations your server asked. */
    public function withAsked(array $asked): self
    {
        return new self($this->payload, $asked);
    }

    public function nonce(): string
    {
        $n = $this->payload['nonce'] ?? null;
        return is_string($n) ? $n : '';
    }

    /** @return array<string, mixed> the signed validations (age, age_condition, user_id, nsbd_id, doc_id, is_test...) */
    public function validations(): array
    {
        $v = $this->payload['validations'] ?? null;
        return is_array($v) ? $v : [];
    }

    /** The age answer (true = meets the condition), or null when age was not answered. */
    public function age(): ?bool
    {
        $a = $this->validations()['age'] ?? null;
        return is_bool($a) ? $a : null;
    }

    /** The age condition the enclave answered, e.g. "18+". */
    public function ageCondition(): ?string
    {
        return $this->stringField('age_condition');
    }

    /** Stable pseudonymous person code, unique to your partner account. Use it for decisions. */
    public function userId(): ?string
    {
        return $this->stringField('user_id');
    }

    public function nsbdId(): ?string
    {
        return $this->stringField('nsbd_id');
    }

    public function docId(): ?string
    {
        return $this->stringField('doc_id');
    }

    /** True for a demo-card result (only possible for test partners): `is_test: true` or TEST_ codes. */
    public function isTest(): bool
    {
        $v = $this->validations();
        if (true === ($v['is_test'] ?? null)) {
            return true;
        }
        foreach (['user_id', 'nsbd_id', 'doc_id'] as $field) {
            if (isset($v[$field]) && is_string($v[$field]) && 0 === strpos($v[$field], 'TEST_')) {
                return true;
            }
        }
        return false;
    }

    /** @return mixed the additional_data you sent at generate, if any */
    public function additionalData()
    {
        return $this->payload['additional_data'] ?? null;
    }

    /** @return array<string, mixed>|null the validations your server stored with the nonce (null if not checked) */
    public function asked(): ?array
    {
        return $this->asked;
    }

    /** @return array<string, mixed> the whole signed payload */
    public function payload(): array
    {
        return $this->payload;
    }

    /** Hides identity codes from var_dump() / print_r() so they do not end up in logs by accident. */
    public function __debugInfo(): array
    {
        $v = $this->validations();
        foreach (['user_id', 'nsbd_id', 'doc_id'] as $field) {
            if (array_key_exists($field, $v)) {
                $v[$field] = '[redacted]';
            }
        }
        return ['nonce' => $this->nonce(), 'validations' => $v, 'asked' => $this->asked];
    }

    private function stringField(string $name): ?string
    {
        $value = $this->validations()[$name] ?? null;
        return is_string($value) && '' !== $value ? $value : null;
    }
}

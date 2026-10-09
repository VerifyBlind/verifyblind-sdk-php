<?php

declare(strict_types=1);

namespace VerifyBlind\Tests;

/** Stands in for the VerifyBlind API's public-key endpoints and counts the calls. */
final class FakeHttp
{
    /** @var string|null base64 SPKI served at /api/public/enclave-key */
    public $enclaveSpki;

    /** @var string|null PEM served in {public_key} at /api/public/webhook-signing-key */
    public $webhookPem;

    /** @var string[] */
    public $calls = [];

    public function __invoke(string $url): string
    {
        $this->calls[] = $url;
        if ('/api/public/enclave-key' === parse_url($url, PHP_URL_PATH) && null !== $this->enclaveSpki) {
            return $this->enclaveSpki;
        }
        if ('/api/public/webhook-signing-key' === parse_url($url, PHP_URL_PATH) && null !== $this->webhookPem) {
            return json_encode(['public_key' => $this->webhookPem]);
        }
        throw new \RuntimeException('HTTP 503');
    }
}

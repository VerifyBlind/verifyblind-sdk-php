<?php

declare(strict_types=1);

namespace VerifyBlind\Tests;

use PHPUnit\Framework\TestCase;
use VerifyBlind\Cache\MemoryCache;
use VerifyBlind\Exception\AskedMismatchException;
use VerifyBlind\Exception\InvalidSignatureException;
use VerifyBlind\Exception\InvalidTokenException;
use VerifyBlind\Exception\KeyUnavailableException;
use VerifyBlind\Exception\NonceException;
use VerifyBlind\Exception\TestCardException;
use VerifyBlind\Verifier;

final class VerifierTest extends TestCase
{
    /** @var FakeHttp */
    private $http;

    /** @var MemoryCache */
    private $cache;

    protected function setUp(): void
    {
        $this->http = new FakeHttp();
        $this->http->enclaveSpki = TestKeys::spki('enclave');
        $this->cache = new MemoryCache();
    }

    private function verifier(array $options = []): Verifier
    {
        return new Verifier($options + ['httpGet' => $this->http, 'cache' => $this->cache]);
    }

    private static function payload(array $validations = ['age' => true, 'age_condition' => '18+'], string $nonce = 'n-1'): array
    {
        return ['nonce' => $nonce, 'validations' => $validations, 'issued_at' => 1756512000];
    }

    /** A nonce store like the one the app keeps: get-and-delete. */
    private static function store(array $entries): callable
    {
        return function (string $nonce) use (&$entries): ?array {
            if (!array_key_exists($nonce, $entries)) {
                return null;
            }
            $asked = $entries[$nonce];
            unset($entries[$nonce]);
            return $asked;
        };
    }

    // ── signature ───────────────────────────────────────────────────────────

    public function testValidTokenVerifies(): void
    {
        $result = $this->verifier()->verifyToken(TestKeys::token('enclave', self::payload()));

        self::assertSame('n-1', $result->nonce());
        self::assertTrue($result->age());
        self::assertSame('18+', $result->ageCondition());
        self::assertSame(['https://api.verifyblind.com/api/public/enclave-key'], $this->http->calls);
    }

    public function testOpensslMadeSignatureVerifies(): void
    {
        // Fixtures made with the openssl CLI (rsa_pss_saltlen:32), independent of phpseclib's signer.
        $f = __DIR__ . '/fixtures';
        $payload = file_get_contents("$f/payload.json");
        self::assertTrue(Verifier::verifySignature($payload, trim(file_get_contents("$f/signature.b64")), Verifier::spkiToPem(file_get_contents("$f/enclave-pubkey.b64"))));
        self::assertFalse(Verifier::verifySignature($payload, trim(file_get_contents("$f/signature-salt16.b64")), Verifier::spkiToPem(file_get_contents("$f/enclave-pubkey.b64"))));
        self::assertFalse(Verifier::verifySignature($payload, trim(file_get_contents("$f/signature.b64")), Verifier::spkiToPem(file_get_contents("$f/other-pubkey.b64"))));
        self::assertFalse(Verifier::verifySignature(str_replace('18+', '21+', $payload), trim(file_get_contents("$f/signature.b64")), Verifier::spkiToPem(file_get_contents("$f/enclave-pubkey.b64"))));
    }

    /** @dataProvider wrongSalts */
    public function testOtherSaltLengthsAreRejected(int $salt): void
    {
        $this->expectException(InvalidSignatureException::class);
        $this->verifier()->verifyToken(TestKeys::token('enclave', self::payload(), $salt));
    }

    public function wrongSalts(): array
    {
        return ['salt 0' => [0], 'salt 16' => [16], 'salt 20' => [20], 'salt 64' => [64]];
    }

    public function testTamperedPayloadIsRejected(): void
    {
        $signed = json_decode(base64_decode(TestKeys::token('enclave', self::payload())), true);
        $signed['payload'] = str_replace('18+', '1+', $signed['payload']);

        $this->expectException(InvalidSignatureException::class);
        $this->verifier()->verifyToken(base64_encode(json_encode($signed)));
    }

    public function testSignatureFromAnotherKeyIsRejected(): void
    {
        $this->expectException(InvalidSignatureException::class);
        $this->verifier()->verifyToken(TestKeys::token('attacker', self::payload()));
    }

    public function testUrlSafeBase64WithoutPaddingIsAccepted(): void
    {
        $token = rtrim(strtr(TestKeys::token('enclave', self::payload()), '+/', '-_'), '=');
        self::assertSame('n-1', $this->verifier()->verifyToken($token)->nonce());
    }

    /** @dataProvider malformedTokens */
    public function testMalformedTokensAreRejected(string $token): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verifyToken($token);
    }

    public function malformedTokens(): array
    {
        return [
            'empty' => [''],
            'not base64' => ['%%%not-base64%%%'],
            'not json' => [base64_encode('hello')],
            'no signature' => [base64_encode(json_encode(['payload' => '{}']))],
            'payload not a string' => [base64_encode(json_encode(['payload' => ['nonce' => 'x'], 'signature' => 'AAAA']))],
        ];
    }

    public function testSignedPayloadThatIsNotAnObjectIsRejected(): void
    {
        $json = '"just a string"';
        $token = base64_encode(json_encode(['payload' => $json, 'signature' => TestKeys::sign('enclave', $json)]));

        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verifyToken($token);
    }

    // ── key cache and refresh ──────────────────────────────────────────────

    public function testKeyIsCachedBetweenCalls(): void
    {
        $v = $this->verifier();
        $v->verifyToken(TestKeys::token('enclave', self::payload()));
        $v->verifyToken(TestKeys::token('enclave', self::payload()));
        self::assertCount(1, $this->http->calls);
    }

    public function testRotatedKeyIsRefreshedOnceAndRetried(): void
    {
        $v = $this->verifier();
        $v->verifyToken(TestKeys::token('enclave', self::payload())); // caches the old key

        // The enclave restarts and signs with a new key.
        $this->http->enclaveSpki = TestKeys::spki('enclave-restarted');
        $result = $v->verifyToken(TestKeys::token('enclave-restarted', self::payload()));

        self::assertSame('n-1', $result->nonce());
        self::assertCount(2, $this->http->calls);
    }

    public function testForcedRefreshIsThrottled(): void
    {
        $v = $this->verifier();
        $v->verifyToken(TestKeys::token('enclave', self::payload()));
        foreach ([1, 2, 3] as $_) {
            try {
                $v->verifyToken(TestKeys::token('attacker', self::payload()));
                self::fail('bad signature accepted');
            } catch (InvalidSignatureException $e) {
            }
        }
        // 1 initial fetch + 1 forced refresh; the next bad tokens do not reach the network.
        self::assertCount(2, $this->http->calls);
    }

    public function testFreshlyFetchedKeyIsNotFetchedTwice(): void
    {
        try {
            $this->verifier()->verifyToken(TestKeys::token('attacker', self::payload()));
            self::fail('bad signature accepted');
        } catch (InvalidSignatureException $e) {
        }
        self::assertCount(1, $this->http->calls);
    }

    public function testKeyEndpointDownIsAnInfrastructureError(): void
    {
        $this->http->enclaveSpki = null;
        try {
            $this->verifier()->verifyToken(TestKeys::token('enclave', self::payload()));
            self::fail('no exception');
        } catch (KeyUnavailableException $e) {
            self::assertSame('key_unavailable', $e->getErrorCode());
            self::assertSame(503, $e->getHttpStatus());
        }
    }

    public function testUnreadableKeyIsAnInfrastructureError(): void
    {
        $this->http->enclaveSpki = 'bm90IGEga2V5';
        $this->expectException(KeyUnavailableException::class);
        $this->verifier()->verifyToken(TestKeys::token('enclave', self::payload()));
    }

    public function testApiUrlOptionIsUsed(): void
    {
        $this->verifier(['apiUrl' => 'https://api.example.test/'])->verifyToken(TestKeys::token('enclave', self::payload()));
        self::assertSame(['https://api.example.test/api/public/enclave-key'], $this->http->calls);
    }

    public function testUnknownOptionIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Verifier(['apiURL' => 'https://typo.test']);
    }

    // ── full verify(): nonce, test card, asked validations ─────────────────

    public function testVerifyConsumesTheNonceExactlyOnce(): void
    {
        $v = $this->verifier();
        $consume = self::store(['n-1' => ['age' => '18+', 'user_id' => true]]);
        $token = TestKeys::token('enclave', self::payload(['age' => true, 'age_condition' => '18+', 'user_id' => 'U1', 'nsbd_id' => 'N1', 'doc_id' => 'D1']));

        $result = $v->verify($token, $consume);
        self::assertSame(['age' => '18+', 'user_id' => true], $result->asked());
        self::assertSame('U1', $result->userId());
        self::assertSame('N1', $result->nsbdId());
        self::assertSame('D1', $result->docId());
        self::assertFalse($result->isTest());

        $this->expectException(NonceException::class);
        $v->verify($token, $consume);
    }

    public function testUnknownNonceIsRejected(): void
    {
        $this->expectException(NonceException::class);
        $this->verifier()->verify(TestKeys::token('enclave', self::payload()), self::store([]));
    }

    public function testPayloadWithoutNonceIsRejected(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify(TestKeys::token('enclave', ['validations' => ['age' => true]]), self::store([]));
    }

    public function testConditionSwapIsRejected(): void
    {
        // The visitor edited "18+" to "1+" in the generate request: the enclave honestly signs age=true for "1+".
        $token = TestKeys::token('enclave', self::payload(['age' => true, 'age_condition' => '1+']));
        try {
            $this->verifier()->verify($token, self::store(['n-1' => ['age' => '18+']]));
            self::fail('condition swap accepted');
        } catch (AskedMismatchException $e) {
            self::assertSame('asked_mismatch', $e->getErrorCode());
        }
    }

    public function testDemoCardIsRejectedByDefault(): void
    {
        $token = TestKeys::token('enclave', self::payload(['user_id' => 'TEST_abc', 'is_test' => true]));
        $this->expectException(TestCardException::class);
        $this->verifier()->verify($token, self::store(['n-1' => ['user_id' => true]]));
    }

    public function testDemoCardIsAcceptedWhenAllowed(): void
    {
        $token = TestKeys::token('enclave', self::payload(['user_id' => 'TEST_abc', 'is_test' => true]));
        $result = $this->verifier(['allowTestCards' => true])->verify($token, self::store(['n-1' => ['user_id' => true]]));
        self::assertTrue($result->isTest());
    }

    // ── webhooks ────────────────────────────────────────────────────────────

    public function testWebhookVerifies(): void
    {
        $this->http->webhookPem = TestKeys::publicPem('webhook');
        $raw = '{"nonce":"n-9","event_type":"CONSENT_WITHDRAWN"}';
        $ts = '1760000000';

        $body = $this->verifier()->verifyWebhook($raw, TestKeys::sign('webhook', "$ts.$raw"), $ts, 1760000100);

        self::assertSame('n-9', $body['nonce']);
        self::assertSame(['https://api.verifyblind.com/api/public/webhook-signing-key'], $this->http->calls);
    }

    public function testWebhookWithOldTimestampIsRejected(): void
    {
        $this->http->webhookPem = TestKeys::publicPem('webhook');
        $raw = '{"nonce":"n-9"}';
        $ts = '1760000000';

        $this->expectException(InvalidSignatureException::class);
        $this->verifier()->verifyWebhook($raw, TestKeys::sign('webhook', "$ts.$raw"), $ts, 1760000000 + 301);
    }

    public function testWebhookWithChangedBodyIsRejected(): void
    {
        $this->http->webhookPem = TestKeys::publicPem('webhook');
        $ts = '1760000000';
        $sig = TestKeys::sign('webhook', $ts . '.{"nonce":"n-9"}');

        $this->expectException(InvalidSignatureException::class);
        $this->verifier()->verifyWebhook('{"nonce":"n-10"}', $sig, $ts, 1760000000);
    }

    public function testWebhookSignedWithEnclaveKeyIsRejected(): void
    {
        $this->http->webhookPem = TestKeys::publicPem('webhook');
        $raw = '{"nonce":"n-9"}';
        $ts = '1760000000';

        $this->expectException(InvalidSignatureException::class);
        $this->verifier()->verifyWebhook($raw, TestKeys::sign('enclave', "$ts.$raw"), $ts, 1760000000);
    }

    public function testWebhookWithoutHeadersIsRejected(): void
    {
        $this->http->webhookPem = TestKeys::publicPem('webhook');
        $this->expectException(InvalidSignatureException::class);
        $this->verifier()->verifyWebhook('{"nonce":"n-9"}', null, null);
    }
}

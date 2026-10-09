<?php

declare(strict_types=1);

namespace VerifyBlind;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use VerifyBlind\Cache\MemoryCache;
use VerifyBlind\Exception\AskedMismatchException;
use VerifyBlind\Exception\InvalidSignatureException;
use VerifyBlind\Exception\InvalidTokenException;
use VerifyBlind\Exception\KeyUnavailableException;
use VerifyBlind\Exception\NonceException;
use VerifyBlind\Exception\TestCardException;

/**
 * Verifies VerifyBlind result tokens and webhook bodies on your server.
 *
 * Signature contract (enclave results and webhooks alike): RSA-PSS, SHA-256, MGF1-SHA-256,
 * salt length exactly 32. PHP's openssl_verify() cannot do PSS, so this uses phpseclib3.
 *
 * This class never logs anything, and its exception messages never contain identity codes.
 */
final class Verifier
{
    public const DEFAULT_API_URL = 'https://api.verifyblind.com';
    public const SALT_LENGTH = 32;

    private const ENCLAVE = 'enclave';
    private const WEBHOOK = 'webhook';

    private const DEFAULTS = [
        // VerifyBlind API base URL.
        'apiUrl' => self::DEFAULT_API_URL,
        // Seconds to cache the enclave public key. Short on purpose: it rotates when the enclave restarts.
        'keyCacheTtl' => 60,
        // Seconds to cache the webhook-signing public key.
        'webhookKeyCacheTtl' => 3600,
        // Minimum seconds between two forced key refreshes, so requests with bad signatures cannot make
        // your server hammer the API. A refresh always happens when no key is cached.
        'refreshInterval' => 30,
        // Any object with PSR-16 get($key, $default) / set($key, $value, $ttl): your PSR-16 cache,
        // VerifyBlind\Cache\FileCache, or null for an in-process MemoryCache.
        'cache' => null,
        // callable(string $url): string — returns the response body of a GET with status 200, throws otherwise.
        // null = built-in fetcher (curl, or file_get_contents when curl is missing).
        'httpGet' => null,
        // HTTP timeout in seconds for the built-in fetcher.
        'timeout' => 5,
        // Accept demo-card results (validations.is_test / TEST_ codes) in verify(). Test setups only.
        'allowTestCards' => false,
        // Allowed clock difference for webhook timestamps, in seconds.
        'webhookTolerance' => 300,
    ];

    /** @var array<string, mixed> */
    private $options;

    /** @var object */
    private $cache;

    /** @var callable */
    private $httpGet;

    /**
     * @param array<string, mixed> $options see DEFAULTS above; unknown keys throw InvalidArgumentException
     */
    public function __construct(array $options = [])
    {
        $unknown = array_diff(array_keys($options), array_keys(self::DEFAULTS));
        if ([] !== $unknown) {
            throw new \InvalidArgumentException('Unknown VerifyBlind option(s): ' . implode(', ', $unknown));
        }
        $this->options = array_merge(self::DEFAULTS, $options);
        $this->options['apiUrl'] = rtrim((string) $this->options['apiUrl'], '/');

        $cache = $this->options['cache'] ?? MemoryCache::shared();
        if (!is_object($cache) || !method_exists($cache, 'get') || !method_exists($cache, 'set')) {
            throw new \InvalidArgumentException('The "cache" option must have PSR-16 get() and set() methods.');
        }
        $this->cache = $cache;

        $httpGet = $this->options['httpGet'];
        if (null !== $httpGet && !is_callable($httpGet)) {
            throw new \InvalidArgumentException('The "httpGet" option must be callable(string $url): string.');
        }
        $this->httpGet = $httpGet ?? function (string $url): string {
            return $this->defaultHttpGet($url);
        };
    }

    /**
     * The whole server-side check in one call: signature, nonce (exactly once), asked validations, demo card.
     *
     * @param string $token the `token` the web widget or mobile SDK gave you
     * @param callable $consumeNonce function(string $nonce): ?array — atomically get-and-delete the nonce you
     *                               stored at generate and return the validations you stored with it
     *                               (e.g. ['age' => '18+', 'user_id' => true]); null if unknown, expired or used
     *
     * @throws InvalidTokenException|InvalidSignatureException|KeyUnavailableException
     * @throws NonceException|TestCardException|AskedMismatchException
     */
    public function verify(string $token, callable $consumeNonce): Result
    {
        $result = $this->verifyToken($token);
        $nonce = $result->nonce();
        if ('' === $nonce) {
            throw new InvalidTokenException('The signed payload has no nonce.');
        }
        $asked = $consumeNonce($nonce);
        if (!is_array($asked)) {
            throw new NonceException('Unknown, expired or already used nonce.');
        }
        if ($result->isTest() && true !== $this->options['allowTestCards']) {
            throw new TestCardException('Demo-card result; set allowTestCards => true only on test setups.');
        }
        $mismatch = self::checkAsked($asked, $result->validations());
        if (null !== $mismatch) {
            throw new AskedMismatchException($mismatch);
        }
        return $result->withAsked($asked);
    }

    /**
     * Checks only the token format and the enclave signature. You still must consume the nonce and call
     * checkAsked() before acting on the result — or use verify(), which does all of it.
     *
     * The enclave key is cached briefly; when a signature fails, the key is refreshed once and the
     * check is retried (the key rotates when the enclave restarts).
     *
     * @throws InvalidTokenException|InvalidSignatureException|KeyUnavailableException
     */
    public function verifyToken(string $token): Result
    {
        $decoded = self::base64Decode($token);
        $signed = null === $decoded ? null : json_decode($decoded, true);
        if (!is_array($signed)
            || !isset($signed['payload'], $signed['signature'])
            || !is_string($signed['payload'])
            || !is_string($signed['signature'])) {
            throw new InvalidTokenException('The token is not base64 of JSON {payload, signature}.');
        }

        if (!$this->verifyWithFreshKey(self::ENCLAVE, $signed['payload'], $signed['signature'])) {
            throw new InvalidSignatureException('The enclave signature is not valid.');
        }

        $payload = json_decode($signed['payload'], true);
        if (!is_array($payload)) {
            throw new InvalidTokenException('The signed payload is not a JSON object.');
        }
        return new Result($payload);
    }

    /**
     * Reads the signed validations against the validations YOUR server stored with the nonce at generate —
     * never against what the browser or app says it asked. Returns an error text, or null when they match.
     *
     * - age asked: `age` must be a boolean AND `age_condition` must equal the asked condition (a visitor who
     *   edits "18+" to "1+" in the generate request gets a signed `age: true` for "1+").
     * - age not asked: no age answer may be present.
     * - user_id asked: a non-empty `user_id` must be present.
     *
     * @param array<string, mixed> $asked e.g. ['age' => '18+', 'user_id' => true]
     * @param array<string, mixed> $validations the signed validations (Result::validations())
     */
    public static function checkAsked(array $asked, array $validations): ?string
    {
        $askedAge = $asked['age'] ?? null;
        if (null === $askedAge) {
            if (array_key_exists('age', $validations) || array_key_exists('age_condition', $validations)) {
                return 'An age answer arrived although age was not asked.';
            }
        } else {
            if (!is_string($askedAge) || '' === trim($askedAge)) {
                return 'The stored age condition is not a valid string.';
            }
            if (!is_bool($validations['age'] ?? null)) {
                return 'The age answer is missing.';
            }
            if (!array_key_exists('age_condition', $validations)) {
                return 'The signed age condition is missing.';
            }
            if ($validations['age_condition'] !== trim($askedAge)) {
                return sprintf(
                    'The answered age condition does not match the asked one (asked %s, answered %s).',
                    trim($askedAge),
                    is_string($validations['age_condition']) ? $validations['age_condition'] : gettype($validations['age_condition'])
                );
            }
        }

        if (!empty($asked['user_id'])) {
            $userId = $validations['user_id'] ?? null;
            if (!is_string($userId) || '' === $userId) {
                return 'The person code (user_id) is missing.';
            }
        }
        return null;
    }

    /**
     * Verifies a webhook from VerifyBlind (revoke notification or pattern B callback) and returns its JSON
     * body. Signed string: "{X-Webhook-Timestamp}.{raw body}", RSA-PSS-SHA256 salt 32, with the key from
     * /api/public/webhook-signing-key. It is not an HMAC with your API key.
     *
     * @param string $rawBody the exact request body (file_get_contents('php://input')), not re-encoded JSON
     * @param string|null $signature the X-Webhook-Signature header (base64)
     * @param string|null $timestamp the X-Webhook-Timestamp header (Unix seconds)
     * @param int|null $now current Unix time, for tests
     * @return array<string, mixed> the body; a revoke body always contains `nonce`
     *
     * @throws InvalidSignatureException|InvalidTokenException|KeyUnavailableException
     */
    public function verifyWebhook(string $rawBody, ?string $signature, ?string $timestamp, ?int $now = null): array
    {
        if (null === $signature || '' === trim($signature) || null === $timestamp || !ctype_digit(trim($timestamp))) {
            throw new InvalidSignatureException('Missing or malformed X-Webhook-Signature / X-Webhook-Timestamp headers.');
        }
        $timestamp = trim($timestamp);
        $now = $now ?? time();
        if (abs($now - (int) $timestamp) > (int) $this->options['webhookTolerance']) {
            throw new InvalidSignatureException('The webhook timestamp is outside the allowed window.');
        }
        if (!$this->verifyWithFreshKey(self::WEBHOOK, $timestamp . '.' . $rawBody, trim($signature))) {
            throw new InvalidSignatureException('The webhook signature is not valid.');
        }
        $body = json_decode($rawBody, true);
        if (!is_array($body)) {
            throw new InvalidTokenException('The webhook body is not a JSON object.');
        }
        return $body;
    }

    /**
     * Low-level check: RSA-PSS, SHA-256, MGF1-SHA-256, salt length exactly 32.
     *
     * Note: calls phpseclib's process-wide RSA::disableSaltLengthDiscovery(); without it phpseclib also
     * accepts signatures made with other salt lengths.
     *
     * @throws KeyUnavailableException when the public key itself cannot be read
     */
    public static function verifySignature(string $data, string $signatureBase64, string $publicKeyPem): bool
    {
        RSA::disableSaltLengthDiscovery();
        try {
            $key = PublicKeyLoader::loadPublicKey($publicKeyPem);
            if (!$key instanceof RSA\PublicKey) {
                throw new \UnexpectedValueException('not an RSA public key');
            }
            $key = $key->withPadding(RSA::SIGNATURE_PSS)
                ->withHash('sha256')
                ->withMGFHash('sha256')
                ->withSaltLength(self::SALT_LENGTH);
        } catch (\Throwable $e) {
            throw new KeyUnavailableException('The VerifyBlind public key cannot be read.', $e);
        }
        $signature = self::base64Decode($signatureBase64);
        if (null === $signature || '' === $signature) {
            return false;
        }
        try {
            return true === $key->verify($data, $signature);
        } catch (\Throwable $e) {
            return false; // malformed signature bytes mean "not verified", not an error
        }
    }

    /** Wraps the base64 SPKI text from /api/public/enclave-key into a PEM public key. */
    public static function spkiToPem(string $spkiBase64): string
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(preg_replace('/\s+/', '', $spkiBase64) ?? '', 64, "\n")
            . '-----END PUBLIC KEY-----';
    }

    private function verifyWithFreshKey(string $kind, string $data, string $signature): bool
    {
        $usedCache = false;
        $pem = $this->publicKey($kind, false, $usedCache);
        try {
            if (self::verifySignature($data, $signature, $pem)) {
                return true;
            }
        } catch (KeyUnavailableException $e) {
            if (!$usedCache) {
                throw $e; // a freshly fetched key is unreadable: refreshing again will not help
            }
        }
        if (!$usedCache) {
            return false; // the key was just fetched: it is current, the signature is simply wrong
        }
        // The cached key may have rotated (enclave restart): refresh once and retry.
        $refreshed = $this->publicKey($kind, true, $usedCache);
        if ($refreshed === $pem) {
            return false;
        }
        return self::verifySignature($data, $signature, $refreshed);
    }

    /**
     * @param bool $usedCache set to true when the returned key came from the cache
     * @return string PEM
     */
    private function publicKey(string $kind, bool $forceRefresh, bool &$usedCache): string
    {
        $cacheKey = 'verifyblind.' . substr(hash('sha256', $this->options['apiUrl']), 0, 16) . '.' . $kind . '_key';
        $cached = $this->cache->get($cacheKey);
        $cached = is_string($cached) && '' !== $cached ? $cached : null;

        if (null !== $cached && !$forceRefresh) {
            $usedCache = true;
            return $cached;
        }
        if (null !== $cached && $forceRefresh && null !== $this->cache->get($cacheKey . '_refreshed')) {
            $usedCache = true;
            return $cached; // refreshed moments ago: do not go to the network again
        }
        if ($forceRefresh && (int) $this->options['refreshInterval'] > 0) {
            $this->cache->set($cacheKey . '_refreshed', 1, (int) $this->options['refreshInterval']);
        }

        $pem = self::ENCLAVE === $kind ? $this->fetchEnclaveKey() : $this->fetchWebhookKey();
        $ttl = self::ENCLAVE === $kind ? $this->options['keyCacheTtl'] : $this->options['webhookKeyCacheTtl'];
        $this->cache->set($cacheKey, $pem, (int) $ttl);
        $usedCache = false;
        return $pem;
    }

    private function fetchEnclaveKey(): string
    {
        $spki = trim($this->get('/api/public/enclave-key'));
        if ('' === $spki) {
            throw new KeyUnavailableException('The enclave public key response is empty.');
        }
        return self::spkiToPem($spki);
    }

    private function fetchWebhookKey(): string
    {
        $json = json_decode($this->get('/api/public/webhook-signing-key'), true);
        $pem = is_array($json) && isset($json['public_key']) && is_string($json['public_key']) ? trim($json['public_key']) : '';
        if ('' === $pem) {
            throw new KeyUnavailableException('The webhook-signing key response has no public_key.');
        }
        return $pem;
    }

    private function get(string $path): string
    {
        try {
            $body = ($this->httpGet)($this->options['apiUrl'] . $path);
        } catch (KeyUnavailableException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new KeyUnavailableException('Could not fetch the VerifyBlind public key.', $e);
        }
        if (!is_string($body)) {
            throw new KeyUnavailableException('Could not fetch the VerifyBlind public key.');
        }
        return $body;
    }

    private function defaultHttpGet(string $url): string
    {
        $timeout = (int) $this->options['timeout'];
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_CONNECTTIMEOUT => $timeout,
                CURLOPT_TIMEOUT => $timeout,
                CURLOPT_HTTPHEADER => ['Accept: */*'],
            ]);
            $body = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
        } else {
            $context = stream_context_create(['http' => [
                'method' => 'GET',
                'timeout' => $timeout,
                'ignore_errors' => true,
                'follow_location' => 0,
            ]]);
            $body = @file_get_contents($url, false, $context);
            $status = 0;
            // $http_response_header is set by file_get_contents in this scope.
            foreach (isset($http_response_header) ? $http_response_header : [] as $line) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                    $status = (int) $m[1];
                }
            }
        }
        if (200 !== $status || !is_string($body)) {
            throw new KeyUnavailableException('Could not fetch the VerifyBlind public key (HTTP ' . $status . ').');
        }
        return $body;
    }

    /** Strict base64 that also accepts the URL-safe alphabet and missing padding. */
    private static function base64Decode(string $value): ?string
    {
        $value = strtr(preg_replace('/\s+/', '', $value) ?? '', '-_', '+/');
        $pad = strlen($value) % 4;
        if (0 !== $pad) {
            $value .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($value, true);
        return false === $decoded ? null : $decoded;
    }
}

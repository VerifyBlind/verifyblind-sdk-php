<?php

declare(strict_types=1);

namespace VerifyBlind\Tests;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

/** Locally generated RSA keys that sign the way the enclave does (PSS, SHA-256, MGF1-SHA-256, salt 32). */
final class TestKeys
{
    /** @var array<string, string> name => private PEM */
    private static $keys = [];

    public static function privatePem(string $name): string
    {
        if (!isset(self::$keys[$name])) {
            $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            openssl_pkey_export($res, $pem);
            self::$keys[$name] = $pem;
        }
        return self::$keys[$name];
    }

    public static function publicPem(string $name): string
    {
        return openssl_pkey_get_details(openssl_pkey_get_private(self::privatePem($name)))['key'];
    }

    /** The enclave-key endpoint body: base64 SPKI without PEM armour. */
    public static function spki(string $name): string
    {
        return preg_replace('/-----[^-]+-----|\s+/', '', self::publicPem($name));
    }

    public static function sign(string $name, string $data, int $saltLength = 32): string
    {
        $key = PublicKeyLoader::loadPrivateKey(self::privatePem($name))
            ->withPadding(RSA::SIGNATURE_PSS)
            ->withHash('sha256')
            ->withMGFHash('sha256')
            ->withSaltLength($saltLength);
        return base64_encode($key->sign($data));
    }

    /** @param array<string, mixed> $payload */
    public static function token(string $name, array $payload, int $saltLength = 32): string
    {
        $json = json_encode($payload);
        return base64_encode(json_encode(['payload' => $json, 'signature' => self::sign($name, $json, $saltLength)]));
    }
}

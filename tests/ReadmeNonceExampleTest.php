<?php

declare(strict_types=1);

namespace VerifyBlind\Tests;

use PHPUnit\Framework\TestCase;
use VerifyBlind\Cache\MemoryCache;
use VerifyBlind\Exception\NonceException;
use VerifyBlind\Verifier;

/** Runs the PDO nonce snippet from README.md against SQLite, end to end with verify(). */
final class ReadmeNonceExampleTest extends TestCase
{
    public function testReadmePdoSnippet(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite not available');
        }
        $pdo = new \PDO('sqlite::memory:');
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $pdo->exec('CREATE TABLE vb_nonces (nonce TEXT PRIMARY KEY, asked TEXT NOT NULL, expires_at INTEGER NOT NULL)');

        // ── README: generate proxy ──
        $nonce = 'n-readme';
        $pdo->prepare('INSERT INTO vb_nonces (nonce, asked, expires_at) VALUES (?, ?, ?)')
            ->execute([$nonce, json_encode(['age' => '18+', 'user_id' => true]), time() + 960]);
        $pdo->prepare('INSERT INTO vb_nonces (nonce, asked, expires_at) VALUES (?, ?, ?)')
            ->execute(['n-expired', json_encode(['age' => '18+']), time() - 1]);

        // ── README: verification ──
        $consume = function (string $nonce) use ($pdo): ?array {
            $q = $pdo->prepare('SELECT asked FROM vb_nonces WHERE nonce = ? AND expires_at > ?');
            $q->execute([$nonce, time()]);
            $asked = $q->fetchColumn();
            $d = $pdo->prepare('DELETE FROM vb_nonces WHERE nonce = ?');
            $d->execute([$nonce]);
            return ($asked !== false && $d->rowCount() === 1) ? json_decode($asked, true) : null;
        };

        $http = new FakeHttp();
        $http->enclaveSpki = TestKeys::spki('enclave');
        $vb = new Verifier(['httpGet' => $http, 'cache' => new MemoryCache()]);
        $token = TestKeys::token('enclave', ['nonce' => $nonce, 'validations' => ['age' => true, 'age_condition' => '18+', 'user_id' => 'U1']]);

        self::assertTrue($vb->verify($token, $consume)->age());
        self::assertNull($consume($nonce), 'replay must find nothing');
        self::assertNull($consume('n-expired'), 'expired nonce must be refused');

        $this->expectException(NonceException::class);
        $vb->verify($token, $consume);
    }
}

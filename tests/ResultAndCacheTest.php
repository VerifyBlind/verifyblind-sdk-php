<?php

declare(strict_types=1);

namespace VerifyBlind\Tests;

use PHPUnit\Framework\TestCase;
use VerifyBlind\Cache\FileCache;
use VerifyBlind\Cache\MemoryCache;
use VerifyBlind\Result;

final class ResultAndCacheTest extends TestCase
{
    public function testAccessors(): void
    {
        $r = new Result(['nonce' => 'n', 'validations' => ['age' => false, 'age_condition' => '18+'], 'additional_data' => ['x' => 1]]);
        self::assertSame('n', $r->nonce());
        self::assertFalse($r->age());
        self::assertSame('18+', $r->ageCondition());
        self::assertNull($r->userId());
        self::assertSame(['x' => 1], $r->additionalData());
        self::assertNull($r->asked());
    }

    public function testTestPrefixMarksDemoCard(): void
    {
        self::assertTrue((new Result(['validations' => ['user_id' => 'TEST_1']]))->isTest());
        self::assertTrue((new Result(['validations' => ['is_test' => true]]))->isTest());
        self::assertFalse((new Result(['validations' => ['is_test' => 'true', 'user_id' => 'xTEST_']]))->isTest());
    }

    public function testDumpingAResultHidesIdentityCodes(): void
    {
        $r = new Result(['nonce' => 'n', 'validations' => ['user_id' => 'SECRET_U', 'nsbd_id' => 'SECRET_N', 'doc_id' => 'SECRET_D']]);
        ob_start();
        var_dump($r);
        $dump = (string) ob_get_clean() . print_r($r, true);
        self::assertStringNotContainsString('SECRET_', $dump);
        self::assertStringContainsString('[redacted]', $dump);
    }

    public function testMemoryCacheExpires(): void
    {
        $c = new MemoryCache();
        $c->set('a', 'v', 60);
        $c->set('b', 'v', 0);
        self::assertSame('v', $c->get('a'));
        self::assertSame('d', $c->get('b', 'd'));
    }

    public function testFileCacheRoundTripAndExpiry(): void
    {
        $dir = sys_get_temp_dir() . '/vb-test-' . bin2hex(random_bytes(4));
        $c = new FileCache($dir);
        self::assertNull($c->get('k'));
        self::assertTrue($c->set('k', "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----", 60));
        self::assertSame("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----", (new FileCache($dir))->get('k'));
        $c->set('gone', 'v', 0);
        self::assertSame('d', $c->get('gone', 'd'));
        array_map('unlink', glob("$dir/*") ?: []);
        rmdir($dir);
    }
}

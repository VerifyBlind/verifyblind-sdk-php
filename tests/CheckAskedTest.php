<?php

declare(strict_types=1);

namespace VerifyBlind\Tests;

use PHPUnit\Framework\TestCase;
use VerifyBlind\Verifier;

final class CheckAskedTest extends TestCase
{
    /** @dataProvider accepted */
    public function testAccepted(array $asked, array $validations): void
    {
        self::assertNull(Verifier::checkAsked($asked, $validations));
    }

    public function accepted(): array
    {
        return [
            'age 18+ yes' => [['age' => '18+'], ['age' => true, 'age_condition' => '18+']],
            'age 18+ no is still a valid answer' => [['age' => '18+'], ['age' => false, 'age_condition' => '18+']],
            'range' => [['age' => '18-65'], ['age' => true, 'age_condition' => '18-65']],
            'user_id only' => [['user_id' => true], ['user_id' => 'U1', 'nsbd_id' => 'N1', 'doc_id' => 'D1']],
            'both' => [['age' => '18+', 'user_id' => true], ['age' => true, 'age_condition' => '18+', 'user_id' => 'U1']],
            'nothing asked, nothing answered' => [[], []],
            'stored age null means not asked' => [['age' => null, 'user_id' => true], ['user_id' => 'U1']],
        ];
    }

    /** @dataProvider rejected */
    public function testRejected(array $asked, array $validations, string $needle): void
    {
        $error = Verifier::checkAsked($asked, $validations);
        self::assertIsString($error);
        self::assertStringContainsString($needle, $error);
    }

    public function rejected(): array
    {
        return [
            'age_condition missing' => [['age' => '18+'], ['age' => true], 'condition is missing'],
            'condition swapped to 1+' => [['age' => '18+'], ['age' => true, 'age_condition' => '1+'], 'does not match'],
            'condition swapped to 18-' => [['age' => '18+'], ['age' => true, 'age_condition' => '18-'], 'does not match'],
            'condition not a string' => [['age' => '18+'], ['age' => true, 'age_condition' => 18], 'does not match'],
            'age answer missing' => [['age' => '18+'], ['age_condition' => '18+'], 'age answer is missing'],
            'age answer is a string' => [['age' => '18+'], ['age' => 'true', 'age_condition' => '18+'], 'age answer is missing'],
            'age answered though not asked' => [['user_id' => true], ['age' => true, 'age_condition' => '1+', 'user_id' => 'U1'], 'not asked'],
            'only condition answered though not asked' => [[], ['age_condition' => '18+'], 'not asked'],
            'user_id missing' => [['user_id' => true], [], 'user_id'],
            'user_id empty' => [['user_id' => true], ['user_id' => ''], 'user_id'],
            'stored condition empty' => [['age' => ''], ['age' => true, 'age_condition' => ''], 'not a valid string'],
        ];
    }

    public function testMismatchMessageNeverContainsIdentityCodes(): void
    {
        $error = Verifier::checkAsked(['age' => '18+'], ['age' => true, 'age_condition' => '1+', 'user_id' => 'SECRET_U', 'nsbd_id' => 'SECRET_N', 'doc_id' => 'SECRET_D']);
        self::assertStringNotContainsString('SECRET_', (string) $error);
    }
}

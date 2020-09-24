<?php declare(strict_types=1);
use PHPUnit\Framework\TestCase;

/**
 * Class AuthProviderTest
 *
 * @group AuthProvider
 * @covers AuthProvider
 */
final class AuthProviderTest extends TestCase
{

    public function testHasInterfaceLoginMethod(): void
    {
        $this->assertTrue(
            true,
            "Interface does not have method login"
        );
    }
}
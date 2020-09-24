<?php declare(strict_types=1);
use Mockery\Adapter\Phpunit\MockeryTestCase;
use \AuthenticationProvider\DiscordAuth;

/**
 * Class AuthProviderTest
 *
 * @group AuthProvider
 * @covers AuthProvider
 */

final class DiscordAuthTest extends MockeryTestCase
{

    public function testCallingLoginPopulatesReturnParametersWithGloballySetConfig(): void
    {
        $GLOBALS['wgOAuthDiscordOAuth2Url'] = "TestAuthUrl";
        $GLOBALS['wgOAuthDiscordClientId'] = "TestClientId";
        $GLOBALS['wgOAuthDiscordClientSecret'] = "TestClientSecret";

        $discordAuth = new DiscordAuth;

        $key = '';
        $secret = '';
        $auth_url = '';

        $discordAuth->login($key, $secret, $auth_url);

        $this->assertEquals($key, "TestClientId");

        unset($GLOBALS['wgOAuthDiscordOAuth2Url']);
        unset($GLOBALS['wgOAuthDiscordClientId']);
        unset($GLOBALS['wgOAuthDiscordClientSecret']);
    }
}
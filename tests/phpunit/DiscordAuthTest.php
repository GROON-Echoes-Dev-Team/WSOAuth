<?php

declare(strict_types=1);

use Mockery\Adapter\Phpunit\MockeryTestCase;
use \AuthenticationProvider\DiscordAuth;
use MediaWiki\Auth\AuthManager;

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

        $discordAuth = new DiscordAuth();

        $key = '';
        $secret = '';
        $auth_url = '';

        $discordAuth->login($key, $secret, $auth_url);

        $this->assertEquals($key, "TestClientId");

        unset($GLOBALS['wgOAuthDiscordOAuth2Url']);
        unset($GLOBALS['wgOAuthDiscordClientId']);
        unset($GLOBALS['wgOAuthDiscordClientSecret']);
    }

    public function testGivenKeyAndSecretGetUserLooksUpUserRolesAndAuthsFromDiscord()
    {
        $mockHttpAdapter = new HTTP_Request2_Adapter_Mock();
        $discordAuth = new DiscordAuth($mockHttpAdapter);
        $errorMessage = false;
        $stubAuthManager = AuthManager::singleton();
        $stubAuthManager->setAuthenticationSessionData('PluggableAuthLoginReturnToQuery', 'hello=code=TestCode');
        $mockHttpAdapter->addResponse(
            "HTTP/1.1 200 OK\r\n" .
                "Connection: close\r\n" .
                "\r\n" .
                '{"access_token":"FakeAccessToken"}',
            'https://discord.com/api/oauth2/token'
        );
        $result = $discordAuth->getUser("TestKey", "TestSecret", $errorMessage);

        $this->assertTrue($result, "getUser failed with message " . $errorMessage);
    }
}

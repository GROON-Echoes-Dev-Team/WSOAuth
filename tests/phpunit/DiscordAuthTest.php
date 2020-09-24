<?php

declare(strict_types=1);

use Mockery\Adapter\Phpunit\MockeryTestCase;
use \AuthenticationProvider\DiscordAuth;
use MediaWiki\Auth\AuthManager;
use RestCord\Model\User;

/**
 * Class AuthProviderTest
 *
 * @group AuthProvider
 * @covers AuthProvider
 */

 final class StubUser {

 }

 final class StubDiscordAdapter implements \AuthenticationProvider\DiscordAdapter {

    public function getUser($userToken){
        $user = new StubUser();
        $user->discriminator = 1234;
        $user->id = 1;
        $user->username = "TestUserName";
        $user->email = "test@google.com";
        return $user;
    }

    public function userHasOneOrMoreValidRolesInGuild($user, $botToken, $guildId, $validRoles){
        return true;
    }

 }

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
        $GLOBALS['wgOAuthDiscordBotToken'] = "TestBotToken";
        $GLOBALS['wgOAuthDiscordGuildId'] = 10023;
        $GLOBALS['wgOAuthDiscordAllowedRoles'] = array("AllowedRoleOne");

        $mockHttpAdapter = new HTTP_Request2_Adapter_Mock();
        $stubDiscordAdapter = new StubDiscordAdapter();
        $discordAuth = new DiscordAuth($mockHttpAdapter, $stubDiscordAdapter);
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

        $this->assertFalse($errorMessage, "getUser failed with message " . $errorMessage);

        unset($GLOBALS['wgOAuthDiscordBotToken']);
        unset($GLOBALS['wgOAuthDiscordGuildId']);
        unset($GLOBALS['wgOAuthDiscordAllowedRoles']);
    }
}

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

 class FixedCsrfTokenProvider implements \AuthenticationProvider\CsrfTokenProvider {
    public function getToken():string {
        return "TestCsrfToken";
    }

 }

final class DiscordAuthTest extends MockeryTestCase
{


    public function testAntiCrsfTokenGetsAppendedAsStateVariableToUrlAndReturnedToBeStoredInSessionAsSecret(): void
    {
        $GLOBALS['wgOAuthDiscordOAuth2Url'] = "TestAuthUrl";

        $mockHttpAdapter = new HTTP_Request2_Adapter_Mock();
        $stubDiscordAdapter = new StubDiscordAdapter();
        $stubDiscordAdapter->userRoles = array("AllowedRoleOne");
        $stubDiscordAdapter->expectedAccessToken = "FakeAccessToken";

        $discordAuth = new DiscordAuth($mockHttpAdapter, $stubDiscordAdapter, new FixedCsrfTokenProvider());

        $key = '';
        $secret = '';
        $auth_url = '';

        $discordAuth->login($key, $secret, $auth_url);

        $this->assertEquals("TestAuthUrl&state=TestCsrfToken", $auth_url);

        unset($GLOBALS['wgOAuthDiscordOAuth2Url']);
    }

    public function testGivenKeyAndSecretGetUserLooksUpUserRolesAndAuthsFromDiscord()
    {
        $GLOBALS['wgOAuthDiscordBotToken'] = "TestBotToken";
        $GLOBALS['wgOAuthDiscordGuildId'] = 10023;
        $GLOBALS['wgOAuthDiscordAllowedRoles'] = array("AllowedRoleOne");
        $GLOBALS['wgOAuthDiscordClientId'] = "TestClientId";
        $GLOBALS['wgOAuthDiscordClientSecret'] = "TestClientSecret";

        $mockHttpAdapter = new HTTP_Request2_Adapter_Mock();
        $stubDiscordAdapter = new StubDiscordAdapter();
        $stubDiscordAdapter->userRoles = array("AllowedRoleOne");
        $stubDiscordAdapter->expectedAccessToken = "FakeAccessToken";
        

        $stubAuthManager = AuthManager::singleton();
        $stubAuthManager->setAuthenticationSessionData('PluggableAuthLoginReturnToQuery', 'code=TestCode&state=FixedCsrfToken');
        $mockHttpAdapter->addResponse(
            "HTTP/1.1 200 OK\r\n" .
                "Connection: close\r\n" .
                "\r\n" .
                '{"access_token":"FakeAccessToken"}',
            'https://discord.com/api/oauth2/token'
        );

        $errorMessage = false;
        $discordAuth = new DiscordAuth($mockHttpAdapter, $stubDiscordAdapter, new FixedCsrfTokenProvider());
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);
        $this->assertFalse($errorMessage, "getUser failed with message " . $errorMessage);

        unset($GLOBALS['wgOAuthDiscordBotToken']);
        unset($GLOBALS['wgOAuthDiscordGuildId']);
        unset($GLOBALS['wgOAuthDiscordAllowedRoles']);
        unset($GLOBALS['wgOAuthDiscordClientId']);
        unset($GLOBALS['wgOAuthDiscordClientSecret']);
    }

    public function testFailsWithErrorIfUserDoesNotHaveRole()
    {
        $GLOBALS['wgOAuthDiscordBotToken'] = "TestBotToken";
        $GLOBALS['wgOAuthDiscordGuildId'] = 10023;
        $GLOBALS['wgOAuthDiscordAllowedRoles'] = array("AllowedRoleOne");
        $GLOBALS['wgOAuthDiscordClientId'] = "TestClientId";
        $GLOBALS['wgOAuthDiscordClientSecret'] = "TestClientSecret";

        $mockHttpAdapter = new HTTP_Request2_Adapter_Mock();
        $stubDiscordAdapter = new StubDiscordAdapter();
        // No Roles
        $stubDiscordAdapter->userRoles = array();
        $stubDiscordAdapter->expectedAccessToken = "FakeAccessToken";
        

        $stubAuthManager = AuthManager::singleton();
        $stubAuthManager->setAuthenticationSessionData('PluggableAuthLoginReturnToQuery', 'code=TestCode&state=FixedCsrfToken');
        $mockHttpAdapter->addResponse(
            "HTTP/1.1 200 OK\r\n" .
                "Connection: close\r\n" .
                "\r\n" .
                '{"access_token":"FakeAccessToken"}',
            'https://discord.com/api/oauth2/token'
        );

        $errorMessage = false;
        $discordAuth = new DiscordAuth($mockHttpAdapter, $stubDiscordAdapter, new FixedCsrfTokenProvider());
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);
        $this->assertEquals($errorMessage, "You do not have permissions to access this wiki. Please authenticate and on Goosefleet Discord and try again.");

        unset($GLOBALS['wgOAuthDiscordBotToken']);
        unset($GLOBALS['wgOAuthDiscordGuildId']);
        unset($GLOBALS['wgOAuthDiscordAllowedRoles']);
    }

    public function testGetUserFailsWithErrorIfUserHasRolesButNoneAreValidToSeeTheWiki()
    {
        $GLOBALS['wgOAuthDiscordBotToken'] = "TestBotToken";
        $GLOBALS['wgOAuthDiscordGuildId'] = 10023;
        $GLOBALS['wgOAuthDiscordAllowedRoles'] = array("Goon");
        $GLOBALS['wgOAuthDiscordClientId'] = "TestClientId";
        $GLOBALS['wgOAuthDiscordClientSecret'] = "TestClientSecret";

        $mockHttpAdapter = new HTTP_Request2_Adapter_Mock();
        $stubDiscordAdapter = new StubDiscordAdapter();
        // Invalid Wiki Roles
        $stubDiscordAdapter->userRoles = array("Guest", "Spy");
        $stubDiscordAdapter->expectedAccessToken = "FakeAccessToken";
        

        $stubAuthManager = AuthManager::singleton();
        $stubAuthManager->setAuthenticationSessionData('PluggableAuthLoginReturnToQuery', 'code=TestCode&state=FixedCsrfToken');
        $mockHttpAdapter->addResponse(
            "HTTP/1.1 200 OK\r\n" .
                "Connection: close\r\n" .
                "\r\n" .
                '{"access_token":"FakeAccessToken"}',
            'https://discord.com/api/oauth2/token'
        );

        $errorMessage = false;
        $discordAuth = new DiscordAuth($mockHttpAdapter, $stubDiscordAdapter, new FixedCsrfTokenProvider());
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);
        $this->assertEquals($errorMessage, "You do not have permissions to access this wiki. Please authenticate and on Goosefleet Discord and try again.");

        unset($GLOBALS['wgOAuthDiscordBotToken']);
        unset($GLOBALS['wgOAuthDiscordGuildId']);
        unset($GLOBALS['wgOAuthDiscordAllowedRoles']);
    }
}

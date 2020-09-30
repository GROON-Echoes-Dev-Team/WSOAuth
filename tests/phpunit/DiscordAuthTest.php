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

class FixedCsrfTokenProvider implements \AuthenticationProvider\CsrfTokenProvider
{
    public function getToken(): string
    {
        return "TestCsrfToken";
    }
}

final class DiscordAuthTest extends MockeryTestCase
{

    private function discordAuthWithMockedHttp()
    {
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
        $config = new \AuthenticationProvider\DiscordAuthConfig(
            "TestAuthUrl",
            "TestClientId",
            "TestClientSecret",
            "https://localhost/wiki/index.php?title=Special:PluggableAuthLogin",
            array("AllowedRoleOne"),
            "TestBotToken",
            10023
        );

        return array(new DiscordAuth($mockHttpAdapter, $stubDiscordAdapter, new FixedCsrfTokenProvider(), $config), $mockHttpAdapter, $stubDiscordAdapter, $stubAuthManager);
    }


    public function testAntiCrsfTokenGetsAppendedAsStateVariableToUrlAndReturnedToBeStoredInSessionAsSecret(): void
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordAdapter, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        $key = '';
        $secret = '';
        $auth_url = '';

        $discordAuth->login($key, $secret, $auth_url);

        $this->assertEquals("TestAuthUrl&state=TestCsrfToken", $auth_url);
        $this->assertEquals("TestCsrfToken", $secret);

    }

    public function testGivenKeyAndSecretGetUserLooksUpUserRolesAndAuthsFromDiscord()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordAdapter, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        $errorMessage = false;
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertFalse($errorMessage, "getUser failed with message " . $errorMessage);
        $this->assertEquals("TestUserName1234", $result['name']);
        $this->assertEquals(1, $result['realname']);
        $this->assertEquals("test@google.com", $result['email']);
    }

    public function testFailsWithErrorIfUserDoesNotHaveRole()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordAdapter, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        // Discord will return saying the user has no roles on the server
        $stubDiscordAdapter->userRoles = array();

        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "You do not have permissions to access this wiki. Please authenticate and on Goosefleet Discord and try again.");
        $this->assertFalse($result);
    }

    public function testGetUserFailsWithErrorIfUserHasRolesButNoneAreValidToSeeTheWiki()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordAdapter, $stubAuthManager) = $this->discordAuthWithMockedHttp();
        // Invalid Wiki Roles
        $stubDiscordAdapter->userRoles = array("Guest", "Spy");

        $errorMessage = false;
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "You do not have permissions to access this wiki. Please authenticate and on Goosefleet Discord and try again.");
        $this->assertFalse($result);
    }

    public function testErrorDisplayedWhenCsrfTokenSentBackToWikiDoesntMatchOneSavedInSession()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordAdapter, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        // FixedCsrfToken is the one provided to getUser as the token stored in the users session, yet WRONGTOKEN is provided on the url back from discord hence this is a possible CSRF attack.
        $stubAuthManager->setAuthenticationSessionData('PluggableAuthLoginReturnToQuery', 'code=TestCode&state=WRONGTOKEN');

        $errorMessage = false;
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "Something went wrong with the redirect back from Discord, please send this error message to @thejanitor in Discord: Error decoding returnToQuery. code=TestCode&amp;state=WRONGTOKEN");
        $this->assertFalse($result);
    }

    public function testMaliciousCodeInRefererUrlIsEscapedInTheErrorMessageDisplayedToUser()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordAdapter, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        $stubAuthManager->setAuthenticationSessionData('PluggableAuthLoginReturnToQuery', "malcious=<IMG SRC=javascript:alert('XSS')>&code=TestCode&state=BadTokenCausingErrorMessageToDisplayWithThisInHtml");

        $errorMessage = false;
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "Something went wrong with the redirect back from Discord, please send this error message to @thejanitor in Discord: Error decoding returnToQuery. malcious=&lt;IMG SRC=javascript:alert('XSS')&gt;&amp;code=TestCode&amp;state=BadTokenCausingErrorMessageToDisplayWithThisInHtml");
        $this->assertFalse($result);
    }

    public function testInvalidCharacterInCodeShowsError()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordAdapter, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        $stubAuthManager->setAuthenticationSessionData('PluggableAuthLoginReturnToQuery', "code=TestCode\<&state=FixedCsrfToken");

        $errorMessage = false;
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "Something went wrong with the redirect back from Discord, please send this error message to @thejanitor in Discord: Error Decoding returnToQuery. code=TestCode\&lt;&amp;state=FixedCsrfToken");
        $this->assertFalse($result);
    }

    public function testInvalidCharacterInStateShowsError()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordAdapter, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        $stubAuthManager->setAuthenticationSessionData('PluggableAuthLoginReturnToQuery', "code=TestCode&state=FixedCsrfToken^^");

        $errorMessage = false;
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "Something went wrong with the redirect back from Discord, please send this error message to @thejanitor in Discord: Error Decoding returnToQuery. code=TestCode&amp;state=FixedCsrfToken^^");
        $errorMessage = false;
    }
}

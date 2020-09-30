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

    private function discordAuthWithMockedHttp($addCorrectDiscordTokenResponse = true)
    {
        $mockHttpAdapter = new HTTP_Request2_Adapter_Mock();
        $stubDiscordRestApi = new StubDiscordRestApi();
        $stubDiscordRestApi->userRoles = array("AllowedRoleOne");
        $stubDiscordRestApi->expectedAccessToken = "FakeAccessToken";


        $stubAuthManager = AuthManager::singleton();
        $stubAuthManager->setAuthenticationSessionData('PluggableAuthLoginReturnToQuery', 'code=TestCode&state=FixedCsrfToken');
        if ($addCorrectDiscordTokenResponse) {
            $mockHttpAdapter->addResponse(
                "HTTP/1.1 200 OK\r\n" .
                    "Connection: close\r\n" .
                    "\r\n" .
                    '{"access_token":"FakeAccessToken"}',
                'https://discord.com/api/oauth2/token'
            );
        }
        $config = new \AuthenticationProvider\DiscordAuthConfig(
            "TestAuthUrl",
            "TestClientId",
            "TestClientSecret",
            "https://localhost/wiki/index.php?title=Special:PluggableAuthLogin",
            array("AllowedRoleOne"),
            "TestBotToken",
            10023,
            "none"
        );

        return array(new DiscordAuth($mockHttpAdapter, $stubDiscordRestApi, new FixedCsrfTokenProvider(), $config), $mockHttpAdapter, $stubDiscordRestApi, $stubAuthManager);
    }


    public function testAntiCrsfTokenGetsAppendedAsStateVariableToUrlAndReturnedToBeStoredInSessionAsSecret(): void
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordRestApi, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        $key = '';
        $secret = '';
        $auth_url = '';

        $discordAuth->login($key, $secret, $auth_url);

        $this->assertEquals("TestAuthUrl&state=TestCsrfToken&prompt=none", $auth_url);
        $this->assertEquals("TestCsrfToken", $secret);
    }

    public function testGivenKeyAndSecretGetUserLooksUpUserRolesAndAuthsFromDiscord()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordRestApi, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        $errorMessage = false;
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertFalse($errorMessage, "getUser failed with message " . $errorMessage);
        $this->assertEquals("TestUserName1234", $result['name']);
        $this->assertEquals(1, $result['realname']);
        $this->assertEquals("test@google.com", $result['email']);
    }

    public function testFailsWithErrorIfDiscordRespondsWithNonOkHttpStatus()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordRestApi, $stubAuthManager) = $this->discordAuthWithMockedHttp(false);

        $mockHttpAdapter->addResponse(
            "HTTP/1.1 500 Internal Server Error\r\n" .
                "Connection: close\r\n",
            'https://discord.com/api/oauth2/token'
        );

        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "Error! Please report this message to @thejanitor on Discord: Error asking Discord Server for user information. The response from Discord was: 500 Internal Server Error");
        $this->assertFalse($result);
    }

    public function testFailsWithErrorIfDiscordRespondsErrorFieldSetInJson()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordRestApi, $stubAuthManager) = $this->discordAuthWithMockedHttp(false);

        $mockHttpAdapter->addResponse(
            "HTTP/1.1 200 OK\r\n" .
                "Connection: close\r\n" .
                "\r\n" .
                '{"error":"The Discord Api is unhappy"}',
            'https://discord.com/api/oauth2/token'
        );

        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "Error! Please report this message to @thejanitor on Discord: Fatal Error asking Discord Server for user information, error in repsonse: {&quot;error&quot;:&quot;The Discord Api is unhappy&quot;}");
        $this->assertFalse($result);
    }

    public function testFailsWithErrorIfDiscordRespondsWithMalformedAccessToken()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordRestApi, $stubAuthManager) = $this->discordAuthWithMockedHttp(false);

        $mockHttpAdapter->addResponse(
            "HTTP/1.1 200 OK\r\n" .
                "Connection: close\r\n" .
                "\r\n" .
                '{"access_token":"< wat sdsadds ^%£"}',
            'https://discord.com/api/oauth2/token'
        );

        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "Error! Please report this message to @thejanitor on Discord: Fatal Error asking Discord Server for user information, access_token malformed: {&quot;access_token&quot;:&quot;&lt; wat sdsadds ^%£&quot;}");
        $this->assertFalse($result);
    }

    public function testFailsWithErrorIfUserDoesNotHaveRole()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordRestApi, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        // Discord will return saying the user has no roles on the server
        $stubDiscordRestApi->userRoles = array();

        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "You do not have permissions to access this wiki. Please authenticate and on Goosefleet Discord and try again.");
        $this->assertFalse($result);
    }

    public function testGetUserFailsWithErrorIfUserHasRolesButNoneAreValidToSeeTheWiki()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordRestApi, $stubAuthManager) = $this->discordAuthWithMockedHttp();
        // Invalid Wiki Roles
        $stubDiscordRestApi->userRoles = array("Guest", "Spy");

        $errorMessage = false;
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "You do not have permissions to access this wiki. Please authenticate and on Goosefleet Discord and try again.");
        $this->assertFalse($result);
    }

    public function testErrorDisplayedWhenCsrfTokenSentBackToWikiDoesntMatchOneSavedInSession()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordRestApi, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        // FixedCsrfToken is the one provided to getUser as the token stored in the users session, yet WRONGTOKEN is provided on the url back from discord hence this is a possible CSRF attack.
        $stubAuthManager->setAuthenticationSessionData('PluggableAuthLoginReturnToQuery', 'code=TestCode&state=WRONGTOKEN');

        $errorMessage = false;
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "Error! Please report this message to @thejanitor on Discord: Something went wrong with the redirect back from Discord - Error decoding returnToQuery. code=TestCode&amp;state=WRONGTOKEN");
        $this->assertFalse($result);
    }

    public function testMaliciousCodeInRefererUrlIsEscapedInTheErrorMessageDisplayedToUser()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordRestApi, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        $stubAuthManager->setAuthenticationSessionData('PluggableAuthLoginReturnToQuery', "malcious=<IMG SRC=javascript:alert('XSS')>&code=TestCode&state=BadTokenCausingErrorMessageToDisplayWithThisInHtml");

        $errorMessage = false;
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "Error! Please report this message to @thejanitor on Discord: Something went wrong with the redirect back from Discord - Error decoding returnToQuery. malcious=&lt;IMG SRC=javascript:alert('XSS')&gt;&amp;code=TestCode&amp;state=BadTokenCausingErrorMessageToDisplayWithThisInHtml");
        $this->assertFalse($result);
    }

    public function testInvalidCharacterInCodeShowsError()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordRestApi, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        $stubAuthManager->setAuthenticationSessionData('PluggableAuthLoginReturnToQuery', "code=TestCode\<&state=FixedCsrfToken");

        $errorMessage = false;
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "Error! Please report this message to @thejanitor on Discord: Something went wrong with the redirect back from Discord - Error Decoding returnToQuery. code=TestCode\&lt;&amp;state=FixedCsrfToken");
        $this->assertFalse($result);
    }

    public function testInvalidCharacterInStateShowsError()
    {
        list($discordAuth, $mockHttpAdapter, $stubDiscordRestApi, $stubAuthManager) = $this->discordAuthWithMockedHttp();

        $stubAuthManager->setAuthenticationSessionData('PluggableAuthLoginReturnToQuery', "code=TestCode&state=FixedCsrfToken^^");

        $errorMessage = false;
        $result = $discordAuth->getUser("TestKey", "FixedCsrfToken", $errorMessage);

        $this->assertEquals($errorMessage, "Error! Please report this message to @thejanitor on Discord: Something went wrong with the redirect back from Discord - Error Decoding returnToQuery. code=TestCode&amp;state=FixedCsrfToken^^");
        $errorMessage = false;
    }
}

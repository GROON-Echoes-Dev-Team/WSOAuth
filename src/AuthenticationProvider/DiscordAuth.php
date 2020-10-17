<?php

namespace AuthenticationProvider;

use Exception;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Logger\LoggerFactory;
use HTTP_Request2;

const RETURNTOQUERY_SESSION_KEY = 'PluggableAuthLoginReturnToQuery';
class DiscordAuth implements \AuthProvider
{

    // Allow injecting these adapters so unit tests can stub out HTTP calls and randomness.
    function __construct($httpAdapter = null, $discordRestApi = null, $csrfTokenProvider = null, $config = null)
    {
        if (!$httpAdapter) {
            $this->httpAdapter = new \HTTP_Request2_Adapter_Socket();
        } else {
            $this->httpAdapter = $httpAdapter;
        }

        if (!$discordRestApi) {
            $this->discordRestApi = new DiscordRestApi();
        } else {
            $this->discordRestApi = $discordRestApi;
        }

        if (!$csrfTokenProvider) {
            $this->csrfTokenProvider = new RandomCsrfTokenProvider();
        } else {
            $this->csrfTokenProvider = $csrfTokenProvider;
        }

        if (!$config) {
            $this->config = DiscordAuthConfig::fromLocalSettingsGlobals();
        } else {
            $this->config = $config;
        }

        $this->logger = LoggerFactory::getInstance('DiscordAuth');
    }

    /**
     * Called by WSOAuth when an unauthed user visits the Wiki as the first step in the OAuth process.
     * 
     * All we do in this step is tell WSOAuth where to direct the user to by setting $auth_url. We also create, store and send
     * a CSRF token to ensure that when the user is sent back from discord.com to the wiki we can verify they were the one who started
     * this process.
     *
     * @param $key Needed for proper three legged OAuth2, however the custom discord flow doesn't require this.
     * @param $secret Stored by WSOAuth in the session for use as a CSRF token later in the process.
     * @param $auth_url The url WSOAuth will redirect the user to starting the authentication flow.
     * @return boolean Returns true on successful login, false otherwise.
     * @internal
     */
    public function login(&$key, &$secret, &$auth_url)
    {
        // Use secret as a CSRF token as it is stored in the users session for retrieval and verification in getUser below.
        $secret = $this->csrfTokenProvider->getToken();
        // Provide state in the auth url so discord passes this back in the returnToQuery url parameter to be verified in getUser.
        // See  https://discord.com/developers/docs/topics/oauth2#state-and-security 
        $auth_url = $this->config->oAuth2Url . "&state=" . $secret . "&prompt=" . $this->config->prompt;
        // Other types of OAuth2 flow require key to be also saved in the session. However discord's does not so we do not use it.
        $key = false;
        return true;
    }


    /**
     * Called as the second step in the OAuth flow. 
     * 
     * The user has now authorized us to access their id and email address on discord.com and has been sent back from there to the wiki. 
     * 
     * Discord has set a query parameter "returnToQuery" in this return direct which contains an access code allowing us 
     * to call discord's REST api directly and obtain the users id and email. 
     * 
     * Using this we then query discord to find the users role on the server to decide if we want to authenticate them into the wiki or not.
     *
     * @param $key Unused by the discord oauth flow.
     * @param $secret A CSRF token set in the login method above.
     * @param string $errorMessage Message shown to the user when there is an error.
     * @return boolean|array Returns an array with at least a 'name' when the user is authenticated, returns false when the user is not authorised or the authentication failed.
     * @internal
     */
    public function getUser($key, $secret, &$errorMessage)
    {
        // WSOAuth stores returnToQuery in the session as the only way for us to access it.
        $code = $this->extractAccessCodeFromSession($secret, $errorMessage);
        if (!$code) {
            return false;
        }

        $token = $this->requestDiscordUserToken($code, $errorMessage);
        if (!$token) {
            return false;
        }

        $user = $this->discordRestApi->getUser($token);

        if ($user && $this->userHasValidWikiRoleOnDiscordServer($user)) {
            $unique_username = $user->username  . $user->discriminator;
            $valid_unique_username = preg_replace("/[^A-Za-z0-9 ]/", '', $unique_username);

            return [
                'name' => $valid_unique_username,
                'realname' => $user->id
            ];
        } else {
            $errorMessage = htmlspecialchars("You do not have permissions to access this wiki. Make sure you are using a discord account with permissions on Goosefleet Discord. You are attempting to use the discord account '{$user->username}' to login, perhaps this is an alt account without permissions? Otherwise please authenticate and on Goosefleet Discord and try again.");
            return false;
        }
    }

    private function extractAccessCodeFromSession($secret, &$errorMessage)
    {
        $authManager = AuthManager::singleton();
        $returnToQuery = $authManager->getAuthenticationSessionData(
            RETURNTOQUERY_SESSION_KEY
        );
        if (!isset($returnToQuery)) {
            $errorMessage = $this->constructSafeErrorMessage("Something went wrong with the redirect back from Discord - returnToQuery Not Set. ");
            return false;
        }
        parse_str($returnToQuery, $decoded_url);

        if (!$this->validReturnToUrl($decoded_url)) {
            $decoded_url = array("code" => $_GET["code"], "state" => $_GET["state"]);
            if(!$this->validReturnToUrl($decoded_url)){
                $errorMessage = $this->constructSafeErrorMessage("Something went wrong with the redirect back from Discord - Error Decoding returnToQuery. returnToQuery=" . $returnToQuery. ", GET_CODE=" . $_GET['code'] . ", state=" . $_GET['state']);
                return false;
            }
        }

        $code = $decoded_url['code'];
        $state = $decoded_url['state'];

        if (hash_equals($state, $secret)) {
            return $code;
        } else {
            $errorMessage = $this->constructSafeErrorMessage("Something went wrong with the redirect back from Discord - Error decoding returnToQuery. " . $returnToQuery);
            return false;
        }
    }

    private function validReturnToUrl($decoded_url): bool
    {
        return array_key_exists('code', $decoded_url)
            && array_key_exists('state', $decoded_url)
            && ctype_alnum($decoded_url['code'])
            && ctype_alnum($decoded_url['state']);
    }

    private function userHasValidWikiRoleOnDiscordServer($user)
    {
        $userRoles = $this->discordRestApi->getServerRolesForUser(
            $user,
            $this->config->botToken,
            $this->config->guildId
        );

        if($userRoles){
            foreach ($userRoles as $userRole) {
                if (\in_array($userRole, $this->config->allowedRoles)) {
                    return true;
                }
            }
        }
        return false;
    }

    private function requestDiscordUserToken($code, &$errorMessage)
    {
        $request = new HTTP_Request2(
            'https://discord.com/api/oauth2/token',
            HTTP_Request2::METHOD_POST,
            array('adapter' => $this->httpAdapter)
        );
        $request->addPostParameter(array(
            'client_id'     => $this->config->clientId,
            'client_secret' => $this->config->clientSecret,
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $this->config->redirectUri,
            'scope'         => 'email identify'
        ));

        try {
            $response = $request->send();
            if (200 == $response->getStatus()) {
                $body = $response->getBody();
                $result_json = json_decode($body);
                if (array_key_exists('error', $result_json)) {
                    $errorMessage = $this->constructSafeErrorMessage('Fatal Error asking Discord Server for user information, error in repsonse: ' . $body);
                    return false;
                }
                if (!ctype_alnum($result_json->access_token)){
                    $errorMessage = $this->constructSafeErrorMessage('Fatal Error asking Discord Server for user information, access_token malformed: ' . $body);
                    return false;
                }
                return $result_json->access_token;
            } else {
                $body = $response->getBody();
                $errorMessage = $this->constructSafeErrorMessage('Error asking Discord Server for user information. The response from Discord was: ' . $response->getStatus() . ' ' .
                    $response->getReasonPhrase() . ' ' . $body);
                return false;
            }
        } catch (\Exception $e) {
            $errorMessage = $this->constructSafeErrorMessage('Fatal Error asking Discord Server for user information: ' . $e->getMessage());
            return false;
        }
    }

    private function constructSafeErrorMessage($message){
        // The message can contain unescaped user input, before displaying it back to the user in an html error message ensure we escape any malicious tags etc.
        return htmlspecialchars("Error! Please report this message to @thejanitor on Discord: " . $message);
    }


    /**
     * Gets called whenever a user is successfully authenticated, so extra attributes about the user can be saved.
     *
     * @param int $id The ID of the User.
     * @return void
     * @internal
     */
    public function saveExtraAttributes($id)
    {
    }

    /**
     * Log out the user and destroy the session.
     *
     * @param \User $user The currently logged in user (i.e. the user that will be logged out).
     * @return void
     * @internal
     */
    public function logout(\User &$user)
    {
    }
}


interface CsrfTokenProvider
{
    public function getToken(): string;
}

class RandomCsrfTokenProvider implements CsrfTokenProvider
{

    public function getToken(): string
    {
        return bin2hex(random_bytes(32));
    }
}

class DiscordAuthConfig
{
    function __construct($oAuth2Url, $clientId, $clientSecret, $redirectUri, $allowedRoles, $botToken, $guildId, $prompt)
    {
        $this->oAuth2Url = $oAuth2Url;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri  = $redirectUri;
        $this->allowedRoles = $allowedRoles;
        $this->botToken = $botToken;
        $this->guildId = $guildId;
        $this->prompt = $prompt;
    }

    private static function validGlobalArg($arg, $expectedType){
        $val = $GLOBALS[$arg];
        if(empty($val) || gettype($val) !== $expectedType){
            throw new WSOAuthDiscordIncorrectlyConfiguredException("Error: $" . $arg . " must be set and of the type " . $expectedType . " in your LocalSettings.php. It is not currently.");
        }
        return $val;
    }

    public static function fromLocalSettingsGlobals()
    {
        // All of the below to be defined in LocalSettings.php by the user of this extension.
        return new DiscordAuthConfig(
            DiscordAuthConfig::validGlobalArg('wgOAuthDiscordOAuth2Url', "string"),
            DiscordAuthConfig::validGlobalArg('wgOAuthDiscordClientId',"integer"),
            DiscordAuthConfig::validGlobalArg('wgOAuthDiscordClientSecret',"string"),
            DiscordAuthConfig::validGlobalArg('wgOAuthDiscordRedirectUri',"string"),
            DiscordAuthConfig::validGlobalArg('wgOAuthDiscordAllowedRoles',"array"),
            DiscordAuthConfig::validGlobalArg('wgOAuthDiscordBotToken',"string"),
            DiscordAuthConfig::validGlobalArg('wgOAuthDiscordGuildId',"integer"),
            DiscordAuthConfig::validGlobalArg('wgOAuthDiscordPrompt',"string")
        );
    }
}

class WSOAuthDiscordIncorrectlyConfiguredException extends Exception{

}

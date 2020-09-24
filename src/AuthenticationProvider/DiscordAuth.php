<?php

namespace AuthenticationProvider;

use MediaWiki\Auth\AuthManager;
use MediaWiki\Logger\LoggerFactory;
use HTTP_Request2;

const RETURNTOURL_SESSION_KEY = 'PluggableAuthLoginReturnToUrl';
const RETURNTOPAGE_SESSION_KEY = 'PluggableAuthLoginReturnToPage';
const RETURNTOQUERY_SESSION_KEY = 'PluggableAuthLoginReturnToQuery';
const EXTRALOGINFIELDS_SESSION_KEY = 'PluggableAuthLoginExtraLoginFields';
const USERNAME_SESSION_KEY = 'PluggableAuthLoginUsername';
const REALNAME_SESSION_KEY = 'PluggableAuthLoginRealname';
const EMAIL_SESSION_KEY = 'PluggableAuthLoginEmail';
const ERROR_SESSION_KEY = 'PluggableAuthLoginError';

class DiscordAuth implements \AuthProvider
{

    // Allow injecting these adapters so unit tests can stub out HTTP calls.
    function __construct($httpAdapter = null, $discordAdapter = null)
    {
        if(!$httpAdapter){
            $this->httpAdapter = new \HTTP_Request2_Adapter_Socket();
        } else {
            $this->httpAdapter = $httpAdapter;
        }

        if(!$discordAdapter){
            $this->discordAdapter = new RealDiscordAdapter();
        } else {
            $this->discordAdapter = $discordAdapter;
        }

        $this->logger = LoggerFactory::getInstance('DiscordAuth');
    }

    /**
     * Log in the user through the external OAuth provider.
     *
     * @param $key
     * @param $secret
     * @param $auth_url
     * @return boolean Returns true on successful login, false otherwise.
     * @internal
     */
    public function login(&$key, &$secret, &$auth_url)
    {
        $secret =  bin2hex(random_bytes(32)); 
        $auth_url = $GLOBALS['wgOAuthDiscordOAuth2Url'] . "&state=" . $secret;
        $key = false; 
        return true;
    }


    /**
     * Get user info from session. Returns false when the request failed or the user is not authorised.
     *
     * @param $key
     * @param $secret
     * @param string $errorMessage Message shown to the user when there is an error.
     * @return boolean|array Returns an array with at least a 'name' when the user is authenticated, returns false when the user is not authorised or the authentication failed.
     * @internal
     */
    public function getUser($key, $secret, &$errorMessage)
    {
        $code = $this->extractAccessCodeFromSession($secret, $errorMessage);
        if(!$code){
            return false;
        }

        $clientId = $GLOBALS['wgOAuthDiscordClientId'];
        $clientSecret = $GLOBALS['wgOAuthDiscordClientSecret'];
        $token = $this->requestDiscordUserToken($clientId, $clientSecret, $code, $errorMessage);
        if (!$token) {
            return false;
        }

        $user = $this->discordAdapter->getUser($token);

        if($this->userHasValidWikiRoleOnDiscordServer($user)) {
            $unique_username = $user->username  . $user->discriminator;

            return [
                'name' => $unique_username, 
                'realname' => $user->id, 
                'email' => $user->email 
            ];
        } else {
            $errorMessage = "You do not have permissions to access this wiki. Please authenticate and on Goosefleet Discord and try again." ;
            return false;
        }
    }

    private function extractAccessCodeFromSession($secret, &$errorMessage){
        $authManager = AuthManager::singleton();
        $returnToQuery = htmlspecialchars($authManager->getAuthenticationSessionData(
            RETURNTOQUERY_SESSION_KEY
        ));
        if (!isset($returnToQuery)) {
            $errorMessage = "Something went wrong with the redirect back from Discord, please send this error message to @thejanitor in Discord: returnToQuery Not Set. ";
            return false;
        }
        parse_str($returnToQuery, $decoded_url);

        if (!array_key_exists('code', $decoded_url) || !array_key_exists('state', $decoded_url)) {
            $errorMessage = "Something went wrong with the redirect back from Discord, please send this error message to @thejanitor in Discord: Error Decoding returnToQuery. " . $returnToQuery;
            return false;
        }
        

        $code = $decoded_url['code'];
        $state = $decoded_url['state'];
        if(hash_equals($state, $secret)) {
            return $code;
        } else {
            $errorMessage = "Something went wrong with the redirect back from Discord, please send this error message to @thejanitor in Discord: Error decoding returnToQuery. " . $returnToQuery;
            return false;
        }
    }

    private function userHasValidWikiRoleOnDiscordServer($user){
        $userRoles = $this->discordAdapter->getServerRolesForUser(
            $user,
            $GLOBALS['wgOAuthDiscordBotToken'], 
            $GLOBALS['wgOAuthDiscordGuildId']);
        
        foreach ($userRoles as $userRole){
            if(\in_array($userRole, $GLOBALS['wgOAuthDiscordAllowedRoles'])){
                return true;
            }
        }
        return false;
    }

    private function requestDiscordUserToken($key, $secret, $code, &$errorMessage)
    {
        $request = new HTTP_Request2(
            'https://discord.com/api/oauth2/token',
            HTTP_Request2::METHOD_POST,
            array('adapter' => $this->httpAdapter)
        );
        $request->addPostParameter([
            'client_id'     => $key,
            'client_secret' => $secret,
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => 'https://localhost/wiki/index.php?title=Special:PluggableAuthLogin',
            'scope'         => 'email identify'
        ]);

        try {
            $response = $request->send();
            if (200 == $response->getStatus()) {
                $body = $response->getBody();
                $result_json = json_decode($body);
                if (array_key_exists('error', $result_json)) {
                    $errorMessage = 'Fatal Error asking Discord Server for user information, error in repsonse: ' . htmlspecialchars($body);
                    return false;
                }
                return $result_json->access_token;
            } else {
                $errorMessage = 'Error asking Discord Server for user information. The response from Discord was: ' . $response->getStatus() . ' ' .
                    $response->getReasonPhrase();
                return false;
            }
        } catch (\Exception $e) {
            $errorMessage = 'Fatal Error asking Discord Server for user information: ' . $e->getMessage();
            return false;
        }
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
